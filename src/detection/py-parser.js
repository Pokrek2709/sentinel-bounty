// Hand-written Python subset parser (Phase 5, round 115):
// tokenizer + recursive-descent parser producing an AST with
// line/column positions. Stdlib-only, synchronous, deterministic,
// and it NEVER executes the code it parses.
//
// Why hand-written: the third language needs structure
// (imports, function definitions, taint flow through
// assignments and calls) that a regex cannot see, and the
// skill installs and verifies offline, so an npm parser is
// out of scope this round. The model is
// `src/detection/sol-parser.js` (round 108): the same
// tokenizer + recursive-descent shape, the same error
// discipline, the same test posture (valid code parses,
// unsupported syntax fails loudly). Python's difference
// from Solidity is indentation: the tokenizer emits
// INDENT / DEDENT / NEWLINE tokens (the classic
// CPython approach), with implicit line continuation
// inside (), [], {} and explicit `\` continuation.
//
// The grammar is a SUBSET (see docs/python-parser-v1.md
// for the full list): modules (import / from-import),
// function definitions, statements (assignment including
// tuple unpacking and annotated assignment, if / elif /
// else, for / while with else, try / except / finally,
// with, return / break / continue / pass / raise /
// assert / del / global / nonlocal), and expressions
// (literals, f-strings, names, attribute / subscript /
// slice, calls with positional / keyword / *args /
// **kwargs, list / dict / set / tuple displays, binary /
// unary / boolean / comparison / conditional). Anything
// outside the subset fails with a PyParseError carrying
// line and column — the caller (the detector) counts that
// record in `skipped`, it NEVER falls back to scanning
// text with a regex.
//
// Safety properties:
// - Comments (#) are stripped by the tokenizer and string
//   contents are single tokens, so sink text inside a
//   comment or a string never becomes a call node.
// - Positions are 1-based line/column, taken from the
//   first token of each node.
// - Class definitions, decorators, lambdas, comprehensions,
//   generator expressions, async / await, yield, the walrus
//   operator, and matrix multiplication are NOT in the
//   subset: code using them fails the parse loudly instead
//   of being scanned approximately (a partial or wrong
//   answer presented as a parse is worse than no answer).
'use strict';

class PyParseError extends Error {
  constructor(message, line, column) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = 'PyParseError';
    this.line = line;
    this.column = column;
  }
}

// Keywords that can never be a binding name. `True`,
// `False`, `None` are literals, not names.
const RESERVED = new Set([
  'and', 'as', 'assert', 'async', 'await', 'break', 'class',
  'continue', 'def', 'del', 'elif', 'else', 'except', 'finally',
  'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda',
  'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try',
  'while', 'with', 'yield', 'True', 'False', 'None',
]);

// Punctuation, longest first — the tokenizer tries them in
// this order at each position.
const PUNCTUATORS = [
  '...', '**=', '//=', '<<=', '>>=', '==', '!=', '<=', '>=',
  '**', '//', '<<', '>>', '+=', '-=', '*=', '/=', '%=', '&=',
  '|=', '^=', ':=', '->', '+', '-', '*', '/', '%', '<', '>',
  '=', '&', '|', '^', '~', '@=', '@', '(', ')', '[', ']', '{',
  '}', ',', ':', ';', '.',
];

function isIdentStart(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_';
}

function isIdentPart(ch) {
  return isIdentStart(ch) || (ch >= '0' && ch <= '9');
}

function isDigit(ch) {
  return ch >= '0' && ch <= '9';
}

function isHexDigit(ch) {
  return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

function isOctDigit(ch) {
  return ch >= '0' && ch <= '7';
}

function isBinDigit(ch) {
  return ch === '0' || ch === '1';
}

// String prefixes (case-insensitive): r, b, f, u, rb, br,
// rf, fr. A prefix immediately followed by a quote opens
// a string literal instead of being a name.
function stringPrefixLength(source, i) {
  const start = i;
  let j = i;
  while (j < source.length && isIdentPart(source[j])) j += 1;
  const word = source.slice(i, j).toLowerCase();
  if (word.length > 2 || word.length === 0) return 0;
  if (!/^[rbuf]+$/.test(word)) return 0;
  if (word.includes('b') && word.includes('f')) return 0;
  if (word.includes('u') && word.length > 1) return 0;
  if (word.includes('f') && word.includes('b')) return 0;
  const next = source[j];
  if (next !== '"' && next !== "'") return 0;
  return j - start;
}

// Tokenize source into { type, value, line, column } tokens.
// type: 'name' | 'number' | 'string' | 'punct' | 'indent' |
// 'dedent' | 'newline' | 'eof'. A string token's value is
// the raw contents between the quotes (escapes NOT decoded
// — the analysis never needs a literal's value, only its
// boundaries); `kind` is 'string' or 'fstring', and
// `prefix` is the lowercased prefix ('' when none).
// `options.baseLine` / `options.baseColumn` shift the
// reported positions (f-string interpolation fragments
// are tokenized separately and re-based to the f-string
// token's position).
function tokenize(source, options) {
  const baseLine = (options && options.baseLine) || 1;
  const baseColumn = (options && options.baseColumn) || 1;
  const tokens = [];
  let i = 0;
  let line = baseLine;
  let column = baseColumn;
  const indentStack = [0];
  let bracketDepth = 0;
  let atLineStart = true;
  // After an explicit `\` continuation the next physical
  // line's indentation is a continuation, not a new
  // block — its indent level must not emit INDENT/DEDENT.
  let suppressIndent = false;

  function advance(n = 1) {
    for (let k = 0; k < n; k += 1) {
      if (source[i] === '\n') { line += 1; column = 1; }
      else column += 1;
      i += 1;
    }
  }

  function position() {
    return { line, column };
  }

  // Width of the leading whitespace at `pos` (a tab moves
  // to the next multiple of 8, as in CPython), and the
  // index just past it.
  function indentWidthAt(pos) {
    let width = 0;
    let j = pos;
    while (j < source.length && (source[j] === ' ' || source[j] === '\t')) {
      if (source[j] === ' ') width += 1;
      else width += 8 - (width % 8);
      j += 1;
    }
    return { width, end: j };
  }

  // Scan a string starting at the quote (or prefix) at
  // `start`; returns { value, raw, kind, prefix, end }
  // where `end` is the index just past the closing quote.
  // Throws PyParseError on an unterminated string. A
  // backslash always skips the next character for
  // termination purposes (in raw strings the backslash
  // stays in the value, but it still prevents the quote
  // from closing the string — the CPython rule).
  function scanString(start) {
    let j = start;
    let prefix = '';
    while (j < source.length && isIdentPart(source[j])) {
      prefix += source[j];
      j += 1;
    }
    prefix = prefix.toLowerCase();
    const quote = source[j];
    const triple = source.startsWith(quote.repeat(3), j);
    const quoteLen = triple ? 3 : 1;
    const isFString = prefix.includes('f');
    let k = j + quoteLen;
    let closed = false;
    while (k < source.length) {
      if (source[k] === '\\') { k += 2; continue; }
      if (triple) {
        if (source.startsWith(quote.repeat(3), k)) { k += 3; closed = true; break; }
        k += 1;
        continue;
      }
      if (source[k] === quote) { k += 1; closed = true; break; }
      if (source[k] === '\n') break;
      k += 1;
    }
    if (!closed) {
      const errLine = line;
      const errColumn = column;
      throw new PyParseError('unterminated string literal', errLine, errColumn);
    }
    const raw = source.slice(start, k);
    const value = raw.slice(prefix.length + quoteLen, raw.length - quoteLen);
    return {
      value,
      raw,
      kind: isFString ? 'fstring' : 'string',
      prefix,
      end: k,
    };
  }

  while (i < source.length) {
    if (atLineStart) {
      if (bracketDepth === 0) {
        // Skip blank and comment-only lines entirely:
        // they emit no NEWLINE and never change the
        // indent level.
        let j = i;
        while (j < source.length && (source[j] === ' ' || source[j] === '\t')) j += 1;
        if (j >= source.length || source[j] === '\n' || source[j] === '#') {
          while (j < source.length && source[j] !== '\n') j += 1;
          if (j < source.length) advance(j - i + 1);
          else i = j;
          continue;
        }
        const { width, end } = indentWidthAt(i);
        if (suppressIndent) {
          suppressIndent = false;
          advance(end - i);
          atLineStart = false;
          continue;
        }
        const top = indentStack[indentStack.length - 1];
        const start = position();
        if (width > top) {
          indentStack.push(width);
          tokens.push({ type: 'indent', value: '', line: start.line, column: start.column });
        } else if (width < top) {
          while (indentStack.length > 1 && indentStack[indentStack.length - 1] > width) {
            indentStack.pop();
            tokens.push({ type: 'dedent', value: '', line: start.line, column: start.column });
          }
          if (indentStack[indentStack.length - 1] !== width) {
            throw new PyParseError('unindent does not match any outer indentation level', start.line, start.column);
          }
        }
        advance(end - i);
        atLineStart = false;
        continue;
      }
      // Inside brackets: indentation is ignored and a
      // line break is an implicit continuation.
      while (i < source.length && (source[i] === ' ' || source[i] === '\t')) advance();
      if (i < source.length && source[i] === '\n') { advance(); continue; }
      if (i < source.length && source[i] === '#') {
        while (i < source.length && source[i] !== '\n') advance();
        continue;
      }
      atLineStart = false;
      continue;
    }

    const ch = source[i];

    // Mid-line whitespace.
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\f' || ch === '\v') {
      advance();
      continue;
    }

    // Comments run to the end of the physical line.
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') advance();
      continue;
    }

    // Explicit line continuation: a backslash immediately
    // before the newline joins the next physical line.
    if (ch === '\\') {
      if (source[i + 1] === '\n') {
        advance(2);
        atLineStart = true;
        suppressIndent = true;
        continue;
      }
      throw new PyParseError('unexpected character "\\"', line, column);
    }

    // Newline: a logical-line terminator outside brackets.
    if (ch === '\n') {
      const start = position();
      advance();
      if (bracketDepth === 0) {
        tokens.push({ type: 'newline', value: '', line: start.line, column: start.column });
      }
      atLineStart = true;
      continue;
    }

    const start = position();

    // Strings (with optional r/b/f/u prefix).
    if (isIdentStart(ch)) {
      const prefixLen = stringPrefixLength(source, i);
      if (prefixLen > 0) {
        const scanned = scanString(i);
        advance(scanned.end - i);
        tokens.push({
          type: 'string', value: scanned.value, raw: scanned.raw,
          kind: scanned.kind, prefix: scanned.prefix, ...start,
        });
        continue;
      }
      let j = i;
      while (j < source.length && isIdentPart(source[j])) j += 1;
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'name', value, ...start });
      continue;
    }

    // Numbers: hex / octal / binary, decimal integers with
    // `_` separators, fractions, exponents, and an
    // optional imaginary `j` suffix.
    if (isDigit(ch) || (ch === '.' && isDigit(source[i + 1] || ''))) {
      let j = i;
      if (source[j] === '0' && (source[j + 1] === 'x' || source[j + 1] === 'X')) {
        j += 2;
        while (j < source.length && (isHexDigit(source[j]) || source[j] === '_')) j += 1;
      } else if (source[j] === '0' && (source[j + 1] === 'o' || source[j + 1] === 'O')) {
        j += 2;
        while (j < source.length && (isOctDigit(source[j]) || source[j] === '_')) j += 1;
      } else if (source[j] === '0' && (source[j + 1] === 'b' || source[j + 1] === 'B')) {
        j += 2;
        while (j < source.length && (isBinDigit(source[j]) || source[j] === '_')) j += 1;
      } else {
        while (j < source.length && (isDigit(source[j]) || source[j] === '_')) j += 1;
        if (source[j] === '.') {
          j += 1;
          while (j < source.length && (isDigit(source[j]) || source[j] === '_')) j += 1;
        }
        if (source[j] === 'e' || source[j] === 'E') {
          let k = j + 1;
          if (source[k] === '+' || source[k] === '-') k += 1;
          if (isDigit(source[k] || '')) {
            j = k;
            while (j < source.length && (isDigit(source[j]) || source[j] === '_')) j += 1;
          }
        }
      }
      if (source[j] === 'j' || source[j] === 'J') j += 1;
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'number', value, ...start });
      continue;
    }

    // Strings without a prefix.
    if (ch === '"' || ch === "'") {
      const scanned = scanString(i);
      advance(scanned.end - i);
      tokens.push({
        type: 'string', value: scanned.value, raw: scanned.raw,
        kind: scanned.kind, prefix: scanned.prefix, ...start,
      });
      continue;
    }

    // Punctuators (longest first).
    let matched = null;
    for (const p of PUNCTUATORS) {
      if (source.startsWith(p, i)) { matched = p; break; }
    }
    if (matched) {
      if (matched === '(' || matched === '[' || matched === '{') bracketDepth += 1;
      if (matched === ')' || matched === ']' || matched === '}') bracketDepth -= 1;
      advance(matched.length);
      tokens.push({ type: 'punct', value: matched, ...start });
      continue;
    }

    throw new PyParseError(`unexpected character ${JSON.stringify(ch)}`, start.line, start.column);
  }

  // End of input: close any open indentation levels.
  const eofPos = position();
  if (tokens.length === 0 || tokens[tokens.length - 1].type !== 'newline') {
    tokens.push({ type: 'newline', value: '', line: eofPos.line, column: eofPos.column });
  }
  while (indentStack.length > 1) {
    indentStack.pop();
    tokens.push({ type: 'dedent', value: '', line: eofPos.line, column: eofPos.column });
  }
  tokens.push({ type: 'eof', value: '', line: eofPos.line, column: eofPos.column });
  return tokens;
}

// --- Parser --------------------------------------------------------------

const AUGMENTED_OPERATORS = new Set([
  '+=', '-=', '*=', '/=', '%=', '**=', '//=', '<<=', '>>=',
  '&=', '|=', '^=',
]);

const COMPARISON_OPERATORS = new Set([
  '==', '!=', '<', '<=', '>', '>=',
]);

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek(offset = 0) {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)];
  }

  next() {
    const token = this.tokens[this.pos];
    if (this.pos < this.tokens.length - 1) this.pos += 1;
    return token;
  }

  at(value) {
    const token = this.peek();
    return (token.type === 'name' || token.type === 'punct') && token.value === value;
  }

  atType(type) {
    return this.peek().type === type;
  }

  atEof() {
    return this.peek().type === 'eof';
  }

  match(value) {
    if (this.at(value)) { this.next(); return true; }
    return false;
  }

  expect(value, what) {
    if (!this.at(value)) {
      const token = this.peek();
      throw new PyParseError(
        `expected ${what || JSON.stringify(value)} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  expectType(type, what) {
    if (!this.atType(type)) {
      const token = this.peek();
      throw new PyParseError(
        `expected ${what || type} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  error(message, token) {
    const at = token || this.peek();
    throw new PyParseError(message, at.line, at.column);
  }

  skipNewlines() {
    while (this.atType('newline')) this.next();
  }

  // A binding name: a `name` token that is NOT reserved.
  parseName(what) {
    const token = this.peek();
    if (token.type !== 'name' || RESERVED.has(token.value)) {
      this.error(`expected ${what || 'a name'}`, token);
    }
    this.next();
    return { type: 'Identifier', name: token.value, line: token.line, column: token.column };
  }

  // A dotted name (`a.b.c`) as a plain string.
  parseDottedName() {
    const first = this.parseName('a module name');
    const parts = [first.name];
    while (this.at('.')) {
      this.next();
      parts.push(this.parseName('a module name').name);
    }
    return parts.join('.');
  }

  parseProgram() {
    const start = this.peek();
    const body = [];
    while (!this.atEof()) {
      this.skipNewlines();
      if (this.atEof()) break;
      if (this.atType('dedent')) this.error('unexpected dedent', this.peek());
      body.push(...this.parseStatement());
    }
    return { type: 'Program', body, line: start.line, column: start.column };
  }

  // Statements until a DEDENT or EOF (inside an indented
  // block). NEWLINE tokens are skipped between statements.
  parseStatementsUntilDedent() {
    const body = [];
    while (!this.atEof() && !this.atType('dedent')) {
      this.skipNewlines();
      if (this.atEof() || this.atType('dedent')) break;
      body.push(...this.parseStatement());
    }
    return body;
  }

  // One statement; returns an ARRAY (a `;`-separated
  // simple-statement line yields several nodes).
  parseStatement() {
    const token = this.peek();
    if (token.type === 'punct' && token.value === '@') {
      this.error('decorators are not supported by the subset parser', token);
    }
    if (token.type === 'name') {
      switch (token.value) {
        case 'def': return [this.parseFunctionDef()];
        case 'if': return [this.parseIf()];
        case 'for': return [this.parseFor()];
        case 'while': return [this.parseWhile()];
        case 'try': return [this.parseTry()];
        case 'with': return [this.parseWith()];
        case 'class':
          this.error('class definitions are not supported by the subset parser', token);
          break;
        case 'async':
          this.error('async / await are not supported by the subset parser', token);
          break;
        default:
          break;
      }
    }
    return this.parseSimpleStatements();
  }

  // A suite after `: `: either simple statements on the
  // same line, or NEWLINE + INDENT + statements + DEDENT.
  parseSuite() {
    if (!this.atType('newline')) {
      const stmts = [];
      for (;;) {
        stmts.push(this.parseSimpleStatement());
        if (this.match(';')) {
          if (this.atType('newline') || this.atEof()) break;
          continue;
        }
        break;
      }
      if (this.atType('newline')) this.next();
      return stmts;
    }
    this.next(); // newline
    this.expectType('indent', 'an indented block');
    const body = this.parseStatementsUntilDedent();
    this.expectType('dedent', 'the end of the indented block');
    return body;
  }

  // One or more simple statements separated by `;`,
  // terminated by NEWLINE. Returns an array of nodes.
  parseSimpleStatements() {
    const stmts = [];
    for (;;) {
      stmts.push(this.parseSimpleStatement());
      if (this.match(';')) {
        if (this.atType('newline') || this.atEof()) break;
        continue;
      }
      break;
    }
    if (this.atType('newline')) this.next();
    else if (!this.atEof() && !this.atType('dedent')) {
      this.error('expected a newline or ";" after the statement', this.peek());
    }
    return stmts;
  }

  parseSimpleStatement() {
    const token = this.peek();
    if (token.type === 'name') {
      switch (token.value) {
        case 'import': return this.parseImport();
        case 'from': return this.parseFromImport();
        case 'return': {
          const start = this.next();
          let value = null;
          if (!this.atType('newline') && !this.at(';') && !this.atEof()) {
            value = this.parseExpressionList();
          }
          return { type: 'Return', value, line: start.line, column: start.column };
        }
        case 'break': {
          const start = this.next();
          return { type: 'Break', line: start.line, column: start.column };
        }
        case 'continue': {
          const start = this.next();
          return { type: 'Continue', line: start.line, column: start.column };
        }
        case 'pass': {
          const start = this.next();
          return { type: 'Pass', line: start.line, column: start.column };
        }
        case 'raise': {
          const start = this.next();
          let exc = null;
          let cause = null;
          if (!this.atType('newline') && !this.at(';') && !this.atEof()) {
            exc = this.parseExpression();
            if (this.at('from')) {
              this.next();
              cause = this.parseExpression();
            }
          }
          return { type: 'Raise', exc, cause, line: start.line, column: start.column };
        }
        case 'assert': {
          const start = this.next();
          const test = this.parseExpression();
          let msg = null;
          if (this.match(',')) msg = this.parseExpression();
          return { type: 'Assert', test, msg, line: start.line, column: start.column };
        }
        case 'del': {
          const start = this.next();
          const targets = this.parseExpressionList();
          if (!isValidTarget(targets)) this.error('invalid deletion target', start);
          return { type: 'Delete', targets, line: start.line, column: start.column };
        }
        case 'global':
        case 'nonlocal': {
          const start = this.next();
          const names = [this.parseName('a name').name];
          while (this.match(',')) names.push(this.parseName('a name').name);
          return {
            type: token.value === 'global' ? 'Global' : 'Nonlocal',
            names, line: start.line, column: start.column,
          };
        }
        case 'yield':
          this.error('yield is not supported by the subset parser', token);
          break;
        case 'await':
          this.error('async / await are not supported by the subset parser', token);
          break;
        default:
          break;
      }
    }
    return this.parseAssignmentOrExpression();
  }

  parseImport() {
    const start = this.next(); // 'import'
    const names = [];
    for (;;) {
      const module = this.parseDottedName();
      let alias = null;
      if (this.at('as')) {
        this.next();
        alias = this.parseName('an import alias').name;
      }
      names.push({ module, alias });
      if (!this.match(',')) break;
    }
    return { type: 'Import', names, line: start.line, column: start.column };
  }

  parseFromImport() {
    const start = this.next(); // 'from'
    let level = 0;
    while (this.at('.')) { this.next(); level += 1; }
    let module = null;
    if (this.peek().type === 'name' && !this.at('import')) {
      module = this.parseDottedName();
    }
    this.expect('import', "'import' after the module name");
    const names = [];
    const parenthesized = this.match('(');
    for (;;) {
      const name = this.parseName('an imported name').name;
      let alias = null;
      if (this.at('as')) {
        this.next();
        alias = this.parseName('an import alias').name;
      }
      names.push({ name, alias });
      if (!this.match(',')) break;
      if (parenthesized && this.at(')')) break;
    }
    if (parenthesized) this.expect(')', "')' after the import list");
    return {
      type: 'ImportFrom', module, level, names,
      line: start.line, column: start.column,
    };
  }

  parseFunctionDef() {
    const start = this.next(); // 'def'
    const name = this.parseName('a function name');
    const params = this.parseParams();
    this.expect(':', "':' after the function header");
    const body = this.parseSuite();
    return {
      type: 'FunctionDef', name: name.name, params, body,
      line: start.line, column: start.column,
    };
  }

  // A parameter list: `(` [param (`,` param)*] `)` where a
  // parameter is `name [':' annotation] ['=' default]`,
  // `*name`, `**name`, a bare `*` (keyword-only marker),
  // or `/` (positional-only marker). Returns [{ name,
  // kind }] with kind 'pos' | 'var_arg' | 'var_kw'.
  parseParams() {
    this.expect('(', "'(' before parameters");
    const params = [];
    while (!this.at(')') && !this.atEof()) {
      if (this.at('/')) { this.next(); if (!this.match(',')) break; continue; }
      if (this.at('*') && this.peek(1).value === ',') {
        this.next();
        if (!this.match(',')) break;
        continue;
      }
      if (this.at('*') && this.peek(1).value === ')') {
        this.next();
        break;
      }
      if (this.at('**')) {
        this.next();
        const name = this.parseName('a parameter name');
        params.push({ name: name.name, kind: 'var_kw' });
      } else if (this.at('*')) {
        this.next();
        const name = this.parseName('a parameter name');
        params.push({ name: name.name, kind: 'var_arg' });
      } else {
        const name = this.parseName('a parameter name');
        if (this.at(':')) {
          this.next();
          this.parseExpression(); // annotation (parsed, not analyzed)
        }
        if (this.at('=')) {
          this.next();
          this.parseExpression(); // default value
        }
        params.push({ name: name.name, kind: 'pos' });
      }
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after parameters");
    return params;
  }

  parseIf() {
    const start = this.next(); // 'if'
    const test = this.parseExpression();
    this.expect(':', "':' after the if test");
    const body = this.parseSuite();
    let orelse = [];
    if (this.at('elif')) {
      orelse = [this.parseIf()];
    } else if (this.at('else')) {
      this.next();
      this.expect(':', "':' after else");
      orelse = this.parseSuite();
    }
    return { type: 'If', test, body, orelse, line: start.line, column: start.column };
  }

  parseFor() {
    const start = this.next(); // 'for'
    const target = this.parseTargetList();
    this.expect('in', "'in' in a for statement");
    const iter = this.parseExpression();
    this.expect(':', "':' after the for header");
    const body = this.parseSuite();
    let orelse = [];
    if (this.at('else')) {
      this.next();
      this.expect(':', "':' after else");
      orelse = this.parseSuite();
    }
    return { type: 'For', target, iter, body, orelse, line: start.line, column: start.column };
  }

  parseWhile() {
    const start = this.next(); // 'while'
    const test = this.parseExpression();
    this.expect(':', "':' after the while test");
    const body = this.parseSuite();
    let orelse = [];
    if (this.at('else')) {
      this.next();
      this.expect(':', "':' after else");
      orelse = this.parseSuite();
    }
    return { type: 'While', test, body, orelse, line: start.line, column: start.column };
  }

  parseTry() {
    const start = this.next(); // 'try'
    this.expect(':', "':' after try");
    const body = this.parseSuite();
    const handlers = [];
    let orelse = [];
    let finalbody = [];
    while (this.at('except')) {
      const handlerStart = this.next();
      let type = null;
      let name = null;
      if (!this.at(':')) {
        type = this.parseExpression();
        if (this.at('as')) {
          this.next();
          name = this.parseName('an exception name').name;
        }
      }
      this.expect(':', "':' after the except clause");
      const handlerBody = this.parseSuite();
      handlers.push({
        type, name, body: handlerBody,
        line: handlerStart.line, column: handlerStart.column,
      });
    }
    if (this.at('else')) {
      this.next();
      this.expect(':', "':' after else");
      orelse = this.parseSuite();
    }
    if (this.at('finally')) {
      this.next();
      this.expect(':', "':' after finally");
      finalbody = this.parseSuite();
    }
    if (handlers.length === 0 && finalbody.length === 0) {
      this.error('try must have at least one except or a finally clause', start);
    }
    return {
      type: 'Try', body, handlers, orelse, finalbody,
      line: start.line, column: start.column,
    };
  }

  parseWith() {
    const start = this.next(); // 'with'
    const items = [];
    for (;;) {
      const context = this.parseExpression();
      let optionalVars = null;
      if (this.at('as')) {
        this.next();
        optionalVars = this.parseTargetList();
      }
      items.push({ context, optionalVars });
      if (!this.match(',')) break;
    }
    this.expect(':', "':' after the with header");
    const body = this.parseSuite();
    return { type: 'With', items, body, line: start.line, column: start.column };
  }

  // An assignment (`a = b`, `a, b = c, d`, `a = b = c`,
  // `a += b`, `x: int = 1`) or a bare expression
  // statement. The left-hand side is parsed as a general
  // expression list first (so `a == 1` still parses as an
  // expression statement), then validated as a target
  // when an assignment operator follows — `x + y = 1`
  // fails loudly instead of parsing as an assignment.
  parseAssignmentOrExpression() {
    const start = this.peek();
    const first = this.parseExpressionList();
    // Annotated assignment: `x: T [= v]` (single target
    // only; the ':' is at statement level here, so it
    // cannot be a slice or a dict key).
    if (this.at(':')) {
      if (!isValidTarget(first) || first.type === 'Tuple' || first.type === 'List') {
        this.error('invalid assignment target', start);
      }
      this.next();
      const annotation = this.parseExpression();
      let value = null;
      if (this.match('=')) value = this.parseExpressionList();
      return {
        type: 'AnnAssign', target: first, annotation, value,
        line: start.line, column: start.column,
      };
    }
    // Augmented assignment (single target only).
    if (this.peek().type === 'punct' && AUGMENTED_OPERATORS.has(this.peek().value)) {
      if (!isValidTarget(first) || first.type === 'Tuple' || first.type === 'List') {
        this.error('invalid assignment target', start);
      }
      const op = this.next().value;
      const value = this.parseExpressionList();
      return {
        type: 'AugAssign', target: first, op, value,
        line: start.line, column: start.column,
      };
    }
    // Plain (possibly chained) assignment.
    if (this.at('=')) {
      if (!isValidTarget(first)) this.error('invalid assignment target', start);
      const targets = [first];
      let value = null;
      while (this.at('=')) {
        this.next();
        // Try to read another target list followed by
        // `=` (a chained assignment); when what follows
        // is not followed by `=`, it IS the value.
        const saved = this.pos;
        try {
          const candidate = this.parseExpressionList();
          if (this.at('=')) {
            if (!isValidTarget(candidate)) this.error('invalid assignment target', start);
            targets.push(candidate);
            continue;
          }
          value = candidate;
          break;
        } catch (error) {
          if (!(error instanceof PyParseError)) throw error;
          this.pos = saved;
          value = this.parseExpressionList();
          break;
        }
      }
      return {
        type: 'Assign', targets, value,
        line: start.line, column: start.column,
      };
    }
    return {
      type: 'Expr', value: first,
      line: start.line, column: start.column,
    };
  }

  // An assignment target list: names, attributes,
  // subscripts, tuples / lists of targets, and starred
  // targets — parsed WITHOUT comparison operators, so
  // `for item in items` does not swallow the `in` as a
  // comparison. A call or a binary expression is not a
  // valid target and fails loudly.
  parseTargetList() {
    const start = this.peek();
    const first = this.parseTarget();
    const elements = [first];
    let sawComma = false;
    while (this.at(',')) {
      sawComma = true;
      this.next();
      if (this.atType('newline') || this.at(';') || this.at(')')
        || this.at(']') || this.at('}') || this.at(':') || this.atEof()) {
        break; // trailing comma
      }
      elements.push(this.parseTarget());
    }
    if (!sawComma) return first;
    return { type: 'Tuple', elts: elements, line: start.line, column: start.column };
  }

  parseTarget() {
    const start = this.peek();
    if (this.at('*')) {
      this.next();
      const value = this.parseTarget();
      return { type: 'Starred', value, line: start.line, column: start.column };
    }
    if (this.at('(')) {
      this.next();
      if (this.at(')')) {
        this.next();
        return { type: 'Tuple', elts: [], line: start.line, column: start.column };
      }
      const first = this.parseTarget();
      const elements = [first];
      while (this.match(',')) {
        if (this.at(')')) break;
        elements.push(this.parseTarget());
      }
      this.expect(')', "')' after a tuple target");
      if (elements.length === 1) return first;
      return { type: 'Tuple', elts: elements, line: start.line, column: start.column };
    }
    if (this.at('[')) {
      this.next();
      const elts = [];
      while (!this.at(']') && !this.atEof()) {
        elts.push(this.parseTarget());
        if (!this.match(',')) break;
      }
      this.expect(']', "']' after a list target");
      return { type: 'List', elts, line: start.line, column: start.column };
    }
    const node = this.parsePostfix();
    if (node.type !== 'Name' && node.type !== 'Attribute' && node.type !== 'Subscript') {
      this.error('invalid assignment target', node);
    }
    return node;
  }

  // An expression list: `expr (, expr)*` with an optional
  // trailing comma. Returns a single node, or a Tuple
  // node when a comma was present.
  parseExpressionList() {
    const start = this.peek();
    const first = this.parseExpression();
    const elements = [first];
    let sawComma = false;
    while (this.at(',')) {
      sawComma = true;
      this.next();
      if (this.atType('newline') || this.at(';') || this.at(')')
        || this.at(']') || this.at('}') || this.at('=') || this.at(':')
        || this.atEof()) {
        break; // trailing comma
      }
      elements.push(this.parseExpression());
    }
    if (!sawComma) return first;
    return { type: 'Tuple', elts: elements, line: start.line, column: start.column };
  }

  // --- Expressions (precedence climbing) -------------------------------

  parseExpression() {
    return this.parseConditional();
  }

  parseConditional() {
    const expr = this.parseOr();
    if (!this.at('if')) return expr;
    const start = this.next();
    const test = this.parseOr();
    this.expect('else', "'else' in a conditional expression");
    const orelse = this.parseConditional();
    return {
      type: 'IfExp', test, body: expr, orelse,
      line: expr.line, column: expr.column,
    };
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.at('or')) {
      this.next();
      const right = this.parseAnd();
      left = { type: 'BoolOp', op: 'or', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseNot();
    while (this.at('and')) {
      this.next();
      const right = this.parseNot();
      left = { type: 'BoolOp', op: 'and', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  parseNot() {
    if (this.at('not')) {
      const start = this.next();
      const operand = this.parseNot();
      return { type: 'UnaryOp', op: 'not', operand, line: start.line, column: start.column };
    }
    return this.parseComparison();
  }

  parseComparison() {
    const left = this.parseBitor();
    const ops = [];
    const comparators = [];
    for (;;) {
      let op = null;
      if (this.peek().type === 'punct' && COMPARISON_OPERATORS.has(this.peek().value)) {
        op = this.next().value;
      } else if (this.at('is')) {
        this.next();
        op = this.at('not') ? 'is not' : 'is';
        if (op === 'is not') this.next();
      } else if (this.at('in')) {
        this.next();
        op = 'in';
      } else if (this.at('not')) {
        this.next();
        this.expect('in', "'in' after 'not'");
        op = 'not in';
      } else {
        break;
      }
      ops.push(op);
      comparators.push(this.parseBitor());
    }
    if (ops.length === 0) return left;
    return {
      type: 'Compare', left, ops, comparators,
      line: left.line, column: left.column,
    };
  }

  parseBitor() {
    let left = this.parseBitxor();
    while (this.at('|')) {
      this.next();
      const right = this.parseBitxor();
      left = { type: 'BinOp', op: '|', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseBitxor() {
    let left = this.parseBitand();
    while (this.at('^')) {
      this.next();
      const right = this.parseBitand();
      left = { type: 'BinOp', op: '^', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseBitand() {
    let left = this.parseShift();
    while (this.at('&')) {
      this.next();
      const right = this.parseShift();
      left = { type: 'BinOp', op: '&', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseShift() {
    let left = this.parseArith();
    while (this.at('<<') || this.at('>>')) {
      const op = this.next().value;
      const right = this.parseArith();
      left = { type: 'BinOp', op, left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseArith() {
    let left = this.parseTerm();
    while (this.at('+') || this.at('-')) {
      const op = this.next().value;
      const right = this.parseTerm();
      left = { type: 'BinOp', op, left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseTerm() {
    let left = this.parseFactor();
    while (this.at('*') || this.at('/') || this.at('//') || this.at('%')) {
      const op = this.next().value;
      const right = this.parseFactor();
      left = { type: 'BinOp', op, left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseFactor() {
    const token = this.peek();
    if (token.type === 'punct' && (token.value === '+' || token.value === '-' || token.value === '~')) {
      const op = this.next();
      const operand = this.parseFactor();
      return { type: 'UnaryOp', op: op.value, operand, line: op.line, column: op.column };
    }
    return this.parsePower();
  }

  parsePower() {
    const base = this.parsePostfix();
    if (!this.at('**')) return base;
    this.next();
    const exponent = this.parseFactor();
    return { type: 'BinOp', op: '**', left: base, right: exponent, line: base.line, column: base.column };
  }

  parsePostfix() {
    let expr = this.parsePrimary();
    for (;;) {
      if (this.at('.')) {
        this.next();
        const prop = this.parseName('an attribute name');
        expr = {
          type: 'Attribute', value: expr, attr: prop.name,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (this.at('[')) {
        this.next();
        const slice = this.parseSubscript();
        this.expect(']', "']' after a subscript");
        expr = {
          type: 'Subscript', value: expr, slice,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (this.at('(')) {
        const call = this.parseCallArgs(expr);
        expr = call;
        continue;
      }
      break;
    }
    return expr;
  }

  // Parse `[a:b:c]`, `[a]`, `[a, b]`, `[:]` inside a
  // subscript. Returns the slice expression, a Slice
  // node, or a Tuple of them.
  parseSubscript() {
    const start = this.peek();
    if (this.at(':')) {
      return this.parseSliceRest(null, start);
    }
    const first = this.parseExpression();
    if (this.at(':')) return this.parseSliceRest(first, start);
    if (this.at(',')) {
      const elements = [first];
      while (this.match(',')) {
        if (this.at(']')) break;
        if (this.at(':')) {
          elements.push(this.parseSliceRest(null, this.peek()));
        } else {
          const element = this.parseExpression();
          if (this.at(':')) elements.push(this.parseSliceRest(element, element));
          else elements.push(element);
        }
      }
      return { type: 'Tuple', elts: elements, line: start.line, column: start.column };
    }
    return first;
  }

  parseSliceRest(lower, start) {
    this.expect(':', "':' in a slice");
    let upper = null;
    let step = null;
    if (!this.at(':') && !this.at(']') && !this.at(',')) upper = this.parseExpression();
    if (this.at(':')) {
      this.next();
      if (!this.at(']') && !this.at(',')) step = this.parseExpression();
    }
    return {
      type: 'Slice', lower, upper, step,
      line: start.line, column: start.column,
    };
  }

  // Parse call arguments after the callee; the current
  // token is `(`. Returns a Call node.
  parseCallArgs(callee) {
    const start = callee;
    this.expect('(', "'(' before call arguments");
    const args = [];
    const keywords = [];
    while (!this.at(')') && !this.atEof()) {
      if (this.at('*')) {
        this.next();
        args.push({ type: 'Starred', value: this.parseExpression(), line: start.line, column: start.column });
      } else if (this.at('**')) {
        this.next();
        keywords.push({ arg: null, value: this.parseExpression() });
      } else if (this.peek().type === 'name' && this.peek(1).value === '=') {
        const name = this.next();
        this.next(); // '='
        keywords.push({ arg: name.value, value: this.parseExpression() });
      } else {
        const arg = this.parseExpression();
        if (this.at('for')) {
          this.error('generator expressions are not supported by the subset parser', this.peek());
        }
        args.push(arg);
      }
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after call arguments");
    return {
      type: 'Call', func: callee, args, keywords,
      line: callee.line, column: callee.column,
    };
  }

  parsePrimary() {
    const token = this.peek();
    if (token.type === 'number') {
      this.next();
      return { type: 'Constant', value: token.value, kind: 'number', line: token.line, column: token.column };
    }
    if (token.type === 'string') {
      this.next();
      let node = token.kind === 'fstring'
        ? this.parseFString(token)
        : { type: 'Constant', value: token.value, kind: 'string', line: token.line, column: token.column };
      // Implicit adjacent-string concatenation (`"a"
      // "b"` is one string in Python).
      while (this.peek().type === 'string') {
        const next = this.next();
        const nextNode = next.kind === 'fstring'
          ? this.parseFString(next)
          : { type: 'Constant', value: next.value, kind: 'string', line: next.line, column: next.column };
        node = mergeStringNodes(node, nextNode);
      }
      return node;
    }
    if (token.type === 'name') {
      if (token.value === 'True' || token.value === 'False') {
        this.next();
        return { type: 'Constant', value: token.value, kind: 'boolean', line: token.line, column: token.column };
      }
      if (token.value === 'None') {
        this.next();
        return { type: 'Constant', value: null, kind: 'none', line: token.line, column: token.column };
      }
      if (token.value === 'lambda') {
        this.error('lambda expressions are not supported by the subset parser', token);
      }
      if (token.value === 'await' || token.value === 'yield') {
        this.error('async / await and yield are not supported by the subset parser', token);
      }
      if (RESERVED.has(token.value)) {
        this.error(`unexpected keyword ${JSON.stringify(token.value)}`, token);
      }
      this.next();
      return { type: 'Name', id: token.value, line: token.line, column: token.column };
    }
    if (token.type === 'punct' && token.value === '(') {
      const start = this.next();
      if (this.at(')')) {
        this.next();
        return { type: 'Tuple', elts: [], line: start.line, column: start.column };
      }
      const first = this.parseExpression();
      if (this.at(',')) {
        const elements = [first];
        while (this.match(',')) {
          if (this.at(')')) break;
          elements.push(this.parseExpression());
        }
        this.expect(')', "')' after a tuple");
        return { type: 'Tuple', elts: elements, line: start.line, column: start.column };
      }
      this.expect(')', "')' after a parenthesized expression");
      return first;
    }
    if (token.type === 'punct' && token.value === '[') {
      const start = this.next();
      const elts = [];
      while (!this.at(']') && !this.atEof()) {
        if (this.at('*')) {
          this.next();
          elts.push({ type: 'Starred', value: this.parseExpression(), line: start.line, column: start.column });
        } else {
          elts.push(this.parseExpression());
        }
        if (this.at('for')) {
          this.error('comprehensions are not supported by the subset parser', this.peek());
        }
        if (!this.match(',')) break;
      }
      this.expect(']', "']' after a list display");
      return { type: 'List', elts, line: start.line, column: start.column };
    }
    if (token.type === 'punct' && token.value === '{') {
      const start = this.next();
      if (this.at('}')) {
        this.next();
        return { type: 'Dict', keys: [], values: [], line: start.line, column: start.column };
      }
      const first = this.parseExpression();
      if (this.at(':')) {
        // Dict display.
        const keys = [];
        const values = [];
        this.next();
        const firstValue = this.parseExpression();
        keys.push(first);
        values.push(firstValue);
        if (this.at('for')) {
          this.error('comprehensions are not supported by the subset parser', this.peek());
        }
        while (this.match(',')) {
          if (this.at('}')) break;
          if (this.at('*')) {
            this.next();
            keys.push(null);
            values.push(this.parseExpression());
          } else {
            const key = this.parseExpression();
            this.expect(':', "':' in a dict display");
            keys.push(key);
            values.push(this.parseExpression());
          }
        }
        this.expect('}', "'}' after a dict display");
        return { type: 'Dict', keys, values, line: start.line, column: start.column };
      }
      // Set display.
      const elts = [first];
      if (this.at('for')) {
        this.error('comprehensions are not supported by the subset parser', this.peek());
      }
      while (this.match(',')) {
        if (this.at('}')) break;
        elts.push(this.parseExpression());
      }
      this.expect('}', "'}' after a set display");
      return { type: 'Set', elts, line: start.line, column: start.column };
    }
    this.error(`unexpected token ${JSON.stringify(token.value) || token.type} in expression`, token);
    return null;
  }

  // Split an f-string token's raw contents into literal
  // and expression parts. An expression part is parsed
  // with a fresh tokenizer over the fragment, re-based to
  // the f-string token's position. `{{` / `}}` are literal
  // braces; a trailing `=`, `!r` / `!s` / `!a` conversion,
  // and a `:format-spec` are stripped from the expression
  // source before parsing.
  parseFString(token) {
    const raw = token.value;
    const parts = [];
    let i = 0;
    let literal = '';
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === '{' && raw[i + 1] === '{') { literal += '{'; i += 2; continue; }
      if (ch === '}' && raw[i + 1] === '}') { literal += '}'; i += 2; continue; }
      if (ch === '{') {
        let depth = 1;
        let j = i + 1;
        let quote = null;
        let triple = false;
        while (j < raw.length && depth > 0) {
          const c = raw[j];
          if (quote) {
            if (c === '\\') { j += 2; continue; }
            if (triple) {
              if (raw.startsWith(quote.repeat(3), j)) { j += 3; quote = null; }
              else j += 1;
            } else if (c === quote) { quote = null; j += 1; }
            else j += 1;
            continue;
          }
          if (c === '"' || c === "'") {
            if (raw.startsWith(c.repeat(3), j)) { quote = c; triple = true; j += 3; }
            else { quote = c; triple = false; j += 1; }
            continue;
          }
          if (c === '{') depth += 1;
          else if (c === '}') depth -= 1;
          j += 1;
        }
        if (depth !== 0) {
          throw new PyParseError('unmatched "{" in f-string', token.line, token.column);
        }
        if (literal !== '') {
          parts.push({ type: 'literal', value: literal });
          literal = '';
        }
        let exprSource = raw.slice(i + 1, j - 1);
        exprSource = stripFStringFormatSpec(exprSource);
        exprSource = stripFStringConversion(exprSource);
        if (exprSource.endsWith('=')) exprSource = exprSource.slice(0, -1);
        exprSource = exprSource.trim();
        if (exprSource === '') {
          throw new PyParseError('empty expression in f-string', token.line, token.column);
        }
        const fragment = new Parser(tokenize(exprSource, { baseLine: token.line, baseColumn: token.column }));
        const node = fragment.parseExpression();
        fragment.skipNewlines();
        if (!fragment.atEof()) {
          throw new PyParseError('unexpected trailing token in f-string expression', token.line, token.column);
        }
        parts.push({ type: 'expr', node });
        i = j;
        continue;
      }
      if (ch === '}') {
        throw new PyParseError('single "}" in f-string', token.line, token.column);
      }
      literal += ch;
      i += 1;
    }
    if (literal !== '') parts.push({ type: 'literal', value: literal });
    return {
      type: 'JoinedStr', values: parts,
      line: token.line, column: token.column,
    };
  }
}

// Is this node a valid assignment / deletion target?
// Names, attributes, subscripts, tuples / lists of
// targets, and starred targets only — a call or a
// binary expression is not a target.
function isValidTarget(node) {
  if (!node || typeof node !== 'object') return false;
  switch (node.type) {
    case 'Name':
    case 'Attribute':
    case 'Subscript':
      return true;
    case 'Tuple':
    case 'List':
      return node.elts.every(isValidTarget);
    case 'Starred':
      return isValidTarget(node.value);
    default:
      return false;
  }
}

// Merge two adjacent string literal nodes (implicit
// concatenation): two plain strings join their values;
// anything involving an f-string becomes a JoinedStr
// whose adjacent literal parts are joined.
function mergeStringNodes(a, b) {
  if (a.type === 'Constant' && b.type === 'Constant') {
    return {
      type: 'Constant', value: a.value + b.value, kind: 'string',
      line: a.line, column: a.column,
    };
  }
  const aParts = a.type === 'JoinedStr' ? a.values : [{ type: 'literal', value: a.value }];
  const bParts = b.type === 'JoinedStr' ? b.values : [{ type: 'literal', value: b.value }];
  const parts = [...aParts];
  for (const part of bParts) {
    const last = parts[parts.length - 1];
    if (last && last.type === 'literal' && part.type === 'literal') last.value += part.value;
    else parts.push(part);
  }
  return { type: 'JoinedStr', values: parts, line: a.line, column: a.column };
}

// Split an f-string replacement field on the first `:`
// at bracket depth 0 outside strings (the format spec
// follows it); the expression is the part before it.
function stripFStringFormatSpec(source) {
  let depth = 0;
  let quote = null;
  let triple = false;
  for (let j = 0; j < source.length; j += 1) {
    const c = source[j];
    if (quote) {
      if (c === '\\') { j += 1; continue; }
      if (triple) {
        if (source.startsWith(quote.repeat(3), j)) { j += 2; quote = null; }
      } else if (c === quote) { quote = null; }
      continue;
    }
    if (c === '"' || c === "'") {
      if (source.startsWith(c.repeat(3), j)) { quote = c; triple = true; j += 2; }
      else { quote = c; triple = false; }
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ':' && depth === 0) return source.slice(0, j);
  }
  return source;
}

// Strip a trailing `!r` / `!s` / `!a` conversion from an
// f-string replacement field.
function stripFStringConversion(source) {
  const trimmed = source.trimEnd();
  if (/![rsa]$/.test(trimmed)) return trimmed.slice(0, -2);
  return trimmed;
}

function parsePython(source) {
  if (typeof source !== 'string') {
    throw new PyParseError('source must be a string', 1, 1);
  }
  const parser = new Parser(tokenize(source));
  const program = parser.parseProgram();
  if (!parser.atEof()) {
    const token = parser.peek();
    throw new PyParseError(
      `unexpected trailing token ${JSON.stringify(token.value) || token.type}`,
      token.line, token.column,
    );
  }
  return program;
}

module.exports = parsePython;
module.exports.parsePython = parsePython;
module.exports.tokenize = tokenize;
module.exports.PyParseError = PyParseError;
