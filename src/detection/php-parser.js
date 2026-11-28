// Hand-written PHP subset parser (Phase 5, round 116):
// tokenizer + recursive-descent parser producing an AST with
// line/column positions. Stdlib-only, synchronous, deterministic,
// and it NEVER executes the code it parses.
//
// Why hand-written: the fourth language needs structure
// (function definitions, include / require constructs,
// superglobal taint flow through assignments and calls)
// that a regex cannot see, and the skill installs and
// verifies offline, so an npm parser is out of scope this
// round. The model is `src/detection/py-parser.js`
// (round 115): the same tokenizer + recursive-descent
// shape, the same error discipline, the same test posture
// (valid code parses, unsupported syntax fails loudly).
// PHP's differences from Python are the `<?php` / `?>`
// tags (HTML between segments is skipped), `$variables`,
// `->` / `::` member access, `;`-terminated statements,
// and `include` / `require` as language constructs rather
// than calls.
//
// The grammar is a SUBSET (see docs/php-parser-v1.md for
// the full list): PHP tags (`<?php`, `<?=`, `<?`),
// `namespace` / `use` / `declare` declarations, function
// definitions, statements (assignment including `list()`
// and short-list targets, chained, augmented, `??=`,
// `if` / `elseif` / `else`, `foreach` / `for` / `while` /
// `do` / `while`, `switch`, `try` / `catch` / `finally`,
// `return` / `break` / `continue` / `throw` / `echo`,
// `global` / `static` / `unset`, braced AND alternative
// (`:` / `endif` / ...) suites), and expressions
// (literals, interpolated double-quoted and backtick
// strings, variables, names / qualified names, attribute
// / static / subscript access, calls with positional /
// named / spread arguments, arrays, ternary incl. short
// form, null coalescing, casts, `new`, `clone`,
// `instanceof`, include / require constructs).
// Anything outside the subset fails with a PhpParseError
// carrying line and column — the caller (the detector)
// counts that record in `skipped`, it NEVER falls back
// to scanning text with a regex.
//
// Safety properties:
// - Comments (`//`, `#`, `/* */`) are stripped by the
//   tokenizer and string contents are single tokens, so
//   sink text inside a comment or a string never becomes
//   a call node.
// - Positions are 1-based line/column, taken from the
//   first token of each node.
// - Class / interface / trait / enum definitions,
//   closures, `fn` arrow functions, `match` expressions,
//   heredoc / nowdoc, `yield`, `goto`, variable variables
//   (`$$x`), `${expr}`, and dynamic member access
//   (`->$x`, `->{...}`) are NOT in the subset: code using
//   them fails the parse loudly instead of being scanned
//   approximately (a partial or wrong answer presented
//   as a parse is worse than no answer).
'use strict';

class PhpParseError extends Error {
  constructor(message, line, column) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = 'PhpParseError';
    this.line = line;
    this.column = column;
  }
}

// Keywords (matched case-insensitively by the parser —
// PHP keywords are case-insensitive; the tokenizer keeps
// the original case). `True`, `False`, `Null` are
// literals, not names.
const RESERVED = new Set([
  'abstract', 'and', 'array', 'as', 'break', 'callable', 'case',
  'catch', 'class', 'clone', 'const', 'continue', 'declare',
  'default', 'die', 'do', 'echo', 'else', 'elseif', 'empty',
  'enddeclare', 'endfor', 'endforeach', 'endif', 'endswitch',
  'endwhile', 'enum', 'exit', 'extends', 'final', 'finally',
  'fn', 'for', 'foreach', 'function', 'global', 'goto', 'if',
  'implements', 'include', 'include_once', 'instanceof',
  'insteadof', 'interface', 'isset', 'list', 'match',
  'namespace', 'new', 'or', 'print', 'private', 'protected',
  'public', 'readonly', 'require', 'require_once', 'return',
  'static', 'switch', 'throw', 'trait', 'try', 'unset', 'use',
  'var', 'while', 'xor', 'yield', 'yield from', 'true',
  'false', 'null',
]);

// Structural keywords that can never start a simple
// statement: they belong to the enclosing construct and
// must terminate a `;`-separated run of simple
// statements (see parseSimpleStatements).
const SIMPLE_STATEMENT_TERMINATORS = new Set([
  'elseif', 'else', 'endif', 'endforeach', 'endfor',
  'endwhile', 'endswitch', 'case', 'default', 'catch',
  'finally',
]);

// Keywords that start a compound or declaration
// statement — they can never start a simple statement,
// so they must terminate a `;`-separated run of simple
// statements (see parseSimpleStatements). The
// simple-statement keywords (return / break / continue /
// throw / echo / global / static) and the expression
// keywords (print / exit / die / isset / empty / unset /
// include / require / list / new / clone / array) are
// NOT in this set — parseSimpleStatement handles them.
const COMPOUND_STATEMENT_KEYWORDS = new Set([
  'if', 'foreach', 'for', 'while', 'do', 'switch', 'try',
  'function', 'declare', 'namespace', 'use', 'const',
  'class', 'interface', 'trait', 'enum', 'fn', 'match',
  'goto', 'enddeclare',
]);

// Punctuation, longest first — the tokenizer tries them in
// this order at each position.
const PUNCTUATORS = [
  '...', '**=', '<<=', '>>=', '??=', '===', '!==', '==', '!=',
  '<=>', '<=', '>=', '**', '<<', '>>', '+=', '-=', '*=', '/=',
  '%=', '.=', '&=', '|=', '^=', '??', '?->', '->', '::', '=>',
  '++', '--', '&&', '||', '+', '-', '*', '/', '%', '.', '<',
  '>', '=', '&', '|', '^', '~', '!', '@', '?', ':', ';', ',',
  '(', ')', '[', ']', '{', '}', '$', '\\', '#',
];

function isIdentStart(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_'
    || (ch && ch.charCodeAt(0) > 127);
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

// Tokenize source into { type, value, line, column } tokens.
// type: 'name' | 'variable' | 'number' | 'string' | 'punct' |
// 'open' | 'close' | 'eof'. A string token's value is the
// raw contents between the quotes (escapes NOT decoded —
// the analysis never needs a decoded literal, only its
// boundaries and, for the `php://input` check, its raw
// text); `kind` is 'single', 'double', or 'backtick'.
// An 'open' token's value is 'php' or 'echo' (`<?=`);
// a 'close' token's value is '?>'. HTML outside PHP tags
// is skipped entirely. `options.fragment` tokenizes a
// bare PHP expression (no `<?php` tag), for string
// interpolation fragments.
function tokenize(source, options) {
  if (typeof source !== 'string') {
    throw new PhpParseError('source must be a string', 1, 1);
  }
  const tokens = [];
  let i = 0;
  let line = 1;
  let column = 1;
  let inPhp = !!(options && options.fragment);

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

  // Is there a PHP open tag at `pos`? Returns 'php',
  // 'echo', or null. `<?xml` is NOT an open tag.
  function openTagAt(pos) {
    if (!source.startsWith('<?', pos)) return null;
    if (source.startsWith('<?xml', pos)
      && (source[pos + 5] === ' ' || source[pos + 5] === '\t'
        || source[pos + 5] === '\n' || source[pos + 5] === '\r')) {
      return null;
    }
    if (source.startsWith('<?php', pos)) {
      const after = source[pos + 5];
      if (after === undefined || after === ' ' || after === '\t'
        || after === '\n' || after === '\r' || after === '?') {
        return 'php';
      }
      return null;
    }
    if (source.startsWith('<?=', pos)) return 'echo';
    // Any other `<?` is a short open tag (when
    // short_open_tag is on) — including `<? ` with a
    // space, `<?\n`, and `<?$x`. `<?xml` (with a space
    // after) was excluded above; `<?xmlfoo` is a short
    // tag in real PHP too.
    return 'php';
  }

  // Scan a quoted string starting at the quote at `start`
  // (single, double, or backtick); returns { value, raw,
  // kind, end } where `end` is the index just past the
  // closing quote. Throws PhpParseError on an unterminated
  // string. A backslash always skips the next character
  // for termination purposes. For double-quoted and
  // backtick strings, an interpolation (`{$expr}` or
  // `${expr}`) is skipped to its matching `}` — quotes
  // inside the expression do NOT terminate the outer
  // string (real PHP lexing: `"{$_GET["p"]}"` is one
  // string token, and the parser splits it afterwards).
  function scanString(start, quote, kind) {
    let k = start + 1;
    while (k < source.length) {
      if (source[k] === '\\') { k += 2; continue; }
      if (source[k] === quote) {
        return {
          value: source.slice(start + 1, k),
          raw: source.slice(start, k + 1),
          kind,
          end: k + 1,
        };
      }
      if (source[k] === '\n' && kind !== 'double' && kind !== 'backtick') break;
      if ((kind === 'double' || kind === 'backtick') && source[k] === '{'
        && (source[k + 1] === '$' || source[k - 1] === '$')) {
        k = skipInterpolationBraces(k);
        continue;
      }
      k += 1;
    }
    throw new PhpParseError('unterminated string literal', line, column);
  }

  // Skip from the `{` at `k` to just past its matching
  // `}`, counting nested braces and skipping nested
  // quoted strings (so a `}` inside `"..."` does not
  // close the interpolation). Throws on an unmatched
  // `{`.
  function skipInterpolationBraces(k) {
    let depth = 0;
    while (k < source.length) {
      const ch = source[k];
      if (ch === '\\') { k += 2; continue; }
      if (ch === "'" || ch === '"' || ch === '`') {
        const nested = scanString(k, ch, ch === "'" ? 'single' : (ch === '"' ? 'double' : 'backtick'));
        k = nested.end;
        continue;
      }
      if (ch === '{') depth += 1;
      else if (ch === '}') {
        depth -= 1;
        if (depth === 0) return k + 1;
      }
      k += 1;
    }
    throw new PhpParseError('unmatched "{" in string interpolation', line, column);
  }

  while (i < source.length) {
    if (!inPhp) {
      const tag = openTagAt(i);
      if (tag) {
        const start = position();
        const len = tag === 'echo' ? 3 : (source.startsWith('<?php', i) ? 5 : 2);
        advance(len);
        tokens.push({ type: 'open', value: tag, ...start });
        inPhp = true;
        continue;
      }
      advance();
      continue;
    }

    const ch = source[i];

    // The closing tag ends the PHP segment (and, as in
    // real PHP, also ends a comment — handled inside the
    // comment scanners below).
    if (source.startsWith('?>', i)) {
      const start = position();
      advance(2);
      tokens.push({ type: 'close', value: '?>', ...start });
      inPhp = false;
      // The newline immediately after `?>` belongs to
      // the close tag in PHP; consume it silently.
      if (source[i] === '\r' && source[i + 1] === '\n') advance(2);
      else if (source[i] === '\n' || source[i] === '\r') advance();
      continue;
    }

    // Mid-line whitespace.
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\f' || ch === '\v' || ch === '\n') {
      advance();
      continue;
    }

    // Line comments (`//` and `#`, but `#[` opens an
    // attribute group, not a comment). A `?>` inside a
    // comment closes the PHP segment, as in real PHP.
    if (source.startsWith('//', i)) {
      while (i < source.length && source[i] !== '\n' && !source.startsWith('?>', i)) advance();
      continue;
    }
    if (ch === '#' && source[i + 1] !== '[') {
      while (i < source.length && source[i] !== '\n' && !source.startsWith('?>', i)) advance();
      continue;
    }

    // Block comments (`/* */`); a `?>` inside closes
    // the PHP segment, as in real PHP.
    if (source.startsWith('/*', i)) {
      advance(2);
      let closed = false;
      while (i < source.length) {
        if (source.startsWith('*/', i)) { advance(2); closed = true; break; }
        if (source.startsWith('?>', i)) break;
        advance();
      }
      if (!closed && i >= source.length) {
        throw new PhpParseError('unterminated comment', line, column);
      }
      continue;
    }

    // Heredoc / nowdoc: not in the subset.
    if (source.startsWith('<<<', i)) {
      throw new PhpParseError('heredoc / nowdoc is not supported by the subset parser', line, column);
    }

    const start = position();

    // Variables: `$name`. `$$` (variable variables) and
    // `${...}` are not in the subset.
    if (ch === '$') {
      const next = source[i + 1];
      if (next === '$') {
        throw new PhpParseError('variable variables ($$) are not supported by the subset parser', start.line, start.column);
      }
      if (next === '{') {
        throw new PhpParseError('${...} variable expressions are not supported by the subset parser', start.line, start.column);
      }
      if (next !== undefined && isIdentStart(next)) {
        let j = i + 1;
        while (j < source.length && isIdentPart(source[j])) j += 1;
        const value = source.slice(i + 1, j);
        advance(j - i);
        tokens.push({ type: 'variable', value, ...start });
        continue;
      }
      // A lone `$` (e.g. end of input) — let the
      // punctuator table report it as unexpected.
    }

    // Strings (single, double, backtick).
    if (ch === "'") {
      const scanned = scanString(i, "'", 'single');
      advance(scanned.end - i);
      tokens.push({ type: 'string', value: scanned.value, kind: scanned.kind, ...start });
      continue;
    }
    if (ch === '"') {
      const scanned = scanString(i, '"', 'double');
      advance(scanned.end - i);
      tokens.push({ type: 'string', value: scanned.value, kind: scanned.kind, ...start });
      continue;
    }
    if (ch === '`') {
      const scanned = scanString(i, '`', 'backtick');
      advance(scanned.end - i);
      tokens.push({ type: 'string', value: scanned.value, kind: scanned.kind, ...start });
      continue;
    }

    // Names (identifiers / keywords).
    if (isIdentStart(ch)) {
      let j = i;
      while (j < source.length && isIdentPart(source[j])) j += 1;
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'name', value, ...start });
      continue;
    }

    // Numbers: hex / octal / binary, decimal integers
    // with `_` separators, fractions, exponents.
    if (isDigit(ch) || (ch === '.' && isDigit(source[i + 1] || ''))) {
      let j = i;
      if (source[j] === '0' && (source[j + 1] === 'x' || source[j + 1] === 'X')) {
        j += 2;
        while (j < source.length && (isHexDigit(source[j]) || source[j] === '_')) j += 1;
      } else if (source[j] === '0' && (source[j + 1] === 'b' || source[j + 1] === 'B')) {
        j += 2;
        while (j < source.length && (isBinDigit(source[j]) || source[j] === '_')) j += 1;
      } else if (source[j] === '0' && (source[j + 1] === 'o' || source[j + 1] === 'O')) {
        j += 2;
        while (j < source.length && (isOctDigit(source[j]) || source[j] === '_')) j += 1;
      } else {
        while (j < source.length && (isDigit(source[j]) || source[j] === '_')) j += 1;
        if (source[j] === '.' && source[j + 1] !== '.') {
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
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'number', value, ...start });
      continue;
    }

    // Punctuators (longest first).
    let matched = null;
    for (const p of PUNCTUATORS) {
      if (source.startsWith(p, i)) { matched = p; break; }
    }
    if (matched) {
      advance(matched.length);
      tokens.push({ type: 'punct', value: matched, ...start });
      continue;
    }

    throw new PhpParseError(`unexpected character ${JSON.stringify(ch)}`, start.line, start.column);
  }

  const eofPos = position();
  tokens.push({ type: 'eof', value: '', line: eofPos.line, column: eofPos.column });
  return tokens;
}

// --- Parser --------------------------------------------------------------

const AUGMENTED_OPERATORS = new Set([
  '+=', '-=', '*=', '/=', '%=', '.=', '**=', '<<=', '>>=',
  '&=', '|=', '^=', '??=',
]);

const COMPARISON_OPERATORS = new Set([
  '==', '!=', '===', '!==', '<', '<=', '>', '>=', '<=>',
]);

// Cast type names: `(int) $x`, `(string) $x`, ...
const CAST_TYPES = new Set([
  'int', 'integer', 'float', 'double', 'real', 'string',
  'bool', 'boolean', 'array', 'object', 'unset', 'binary',
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

  // Case-insensitive keyword test (PHP keywords are
  // case-insensitive; the tokenizer keeps the original
  // case, so compare lowercased).
  atKw(value) {
    const token = this.peek();
    return token.type === 'name' && token.value.toLowerCase() === value;
  }

  atType(type) {
    return this.peek().type === type;
  }

  atEof() {
    return this.peek().type === 'eof';
  }

  atCloseTag() {
    return this.peek().type === 'close';
  }

  match(value) {
    if (this.at(value)) { this.next(); return true; }
    return false;
  }

  matchKw(value) {
    if (this.atKw(value)) { this.next(); return true; }
    return false;
  }

  expect(value, what) {
    if (!this.at(value)) {
      const token = this.peek();
      throw new PhpParseError(
        `expected ${what || JSON.stringify(value)} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  expectType(type, what) {
    if (!this.atType(type)) {
      const token = this.peek();
      throw new PhpParseError(
        `expected ${what || type} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  error(message, token) {
    const at = token || this.peek();
    throw new PhpParseError(message, at.line, at.column);
  }

  // Skip `#[...]` attribute groups (balanced brackets).
  skipAttributes() {
    while (this.at('#') && this.peek(1).value === '[') {
      this.next(); // '#'
      this.next(); // '['
      let depth = 1;
      while (depth > 0 && !this.atEof()) {
        if (this.at('[')) depth += 1;
        else if (this.at(']')) depth -= 1;
        this.next();
      }
      if (depth !== 0) this.error('unterminated attribute group', this.peek());
    }
  }

  // Skip PHP open / close tags between segments.
  skipTags() {
    while (this.atType('open') || this.atType('close')) this.next();
  }

  // Consume a `<?= expr ?>` short-echo segment, pushing
  // an Echo node into `body`. Returns true when one was
  // consumed. Called before skipTags(), which would
  // otherwise swallow the open tag.
  handleShortEcho(body) {
    if (this.atType('open') && this.peek().value === 'echo') {
      const open = this.next();
      const value = this.parseExpression();
      body.push({ type: 'Echo', values: [value], line: open.line, column: open.column });
      if (this.at(';')) this.next();
      return true;
    }
    return false;
  }

  parseProgram() {
    const start = this.peek();
    const body = [];
    while (!this.atEof()) {
      if (this.handleShortEcho(body)) continue;
      this.skipTags();
      this.skipAttributes();
      if (this.atEof()) break;
      if (this.atType('open')) { this.next(); continue; }
      body.push(...this.parseStatement());
    }
    return { type: 'Program', body, line: start.line, column: start.column };
  }

  // Statements until `}` or EOF (inside a braced block),
  // or until one of the alternative-syntax terminators
  // (inside a `:` suite). Open / close tags are skipped
  // between statements; a close tag never ends a block.
  // `endKws` is null, a keyword string, or an array of
  // keyword strings.
  parseStatementsUntilBraceOr(endKws) {
    const ends = endKws === null || endKws === undefined
      ? null
      : (Array.isArray(endKws) ? endKws : [endKws]);
    const atEnd = () => ends !== null && ends.some((kw) => this.atKw(kw));
    const body = [];
    while (!this.atEof() && !this.at('}')) {
      if (atEnd()) break;
      if (this.handleShortEcho(body)) continue;
      this.skipTags();
      this.skipAttributes();
      if (this.atEof() || this.at('}')) break;
      if (atEnd()) break;
      if (this.atType('open')) { this.next(); continue; }
      body.push(...this.parseStatement());
    }
    return body;
  }

  // A suite after a control header: either a braced
  // block, or the alternative syntax (`:` statements
  // until the matching end keyword).
  parseSuite(endKw) {
    if (this.at('{')) {
      this.next();
      const body = this.parseStatementsUntilBraceOr(null);
      this.expect('}', "'}' after the block");
      return body;
    }
    if (this.at(':')) {
      this.next();
      const body = this.parseStatementsUntilBraceOr(endKw);
      if (endKw) {
        if (!this.atKw(endKw)) this.error(`expected ${endKw}`, this.peek());
        this.next();
      }
      if (this.at(';')) this.next();
      return body;
    }
    this.error("expected '{' or ':' after the control header", this.peek());
    return [];
  }


  // One statement; returns an ARRAY (a `;`-separated
  // line yields several nodes; an empty statement yields
  // none).
  parseStatement() {
    this.skipAttributes();
    const token = this.peek();
    if (token.type === 'punct' && token.value === ';') {
      this.next();
      return [];
    }
    if (token.type === 'name') {
      const kw = token.value.toLowerCase();
      switch (kw) {
        case 'function': return [this.parseFunctionDef()];
        case 'class':
        case 'interface':
        case 'trait':
        case 'enum':
          this.error(`${kw} definitions are not supported by the subset parser`, token);
          break;
        case 'fn':
          this.error('arrow functions (fn) are not supported by the subset parser', token);
          break;
        case 'match':
          this.error('match expressions are not supported by the subset parser', token);
          break;
        case 'goto':
          this.error('goto is not supported by the subset parser', token);
          break;
        case 'if': return [this.parseIf()];
        case 'foreach': return [this.parseForeach()];
        case 'for': return [this.parseFor()];
        case 'while': return [this.parseWhile()];
        case 'do': return [this.parseDoWhile()];
        case 'switch': return [this.parseSwitch()];
        case 'try': return [this.parseTry()];
        case 'declare': return [this.parseDeclare()];
        case 'namespace': return [this.parseNamespace()];
        case 'use': return [this.parseUse()];
        case 'const': return [this.parseConst()];
        case 'global':
          return [this.parseGlobalOrStatic()];
        case 'static':
          // `static::foo()` is a static call, not a
          // declaration — fall through to the expression
          // statement below.
          if (this.peek(1).value === '::') break;
          return [this.parseGlobalOrStatic()];
        default:
          break;
      }
    }
    return this.parseSimpleStatements();
  }

  // One or more simple statements separated by `;`,
  // terminated by `;`, `?>`, `}` or EOF.
  parseSimpleStatements() {
    const stmts = [];
    for (;;) {
      stmts.push(this.parseSimpleStatement());
      if (this.match(';')) {
        if (this.atCloseTag() || this.at('}') || this.atEof()) break;
        if (this.atType('open')) break;
        // A structural keyword can never start a simple
        // statement — it belongs to the enclosing
        // construct (alternative-syntax `else` /
        // `elseif` / `endif` / `endforeach` / `endfor` /
        // `endwhile` / `endswitch`, switch `case` /
        // `default`, `catch` / `finally`), or it starts
        // a compound / declaration statement (`if`,
        // `foreach`, `function`, `use`, ...) that only
        // parseStatement handles. Stop here so the caller
        // can handle it; without this, `;` would swallow
        // the keyword into the next simple statement and
        // the parse would fail (`$x = 1; if (...) {...}`
        // is the commonest shape in real code).
        if (this.peek().type === 'name'
          && (SIMPLE_STATEMENT_TERMINATORS.has(this.peek().value.toLowerCase())
            || COMPOUND_STATEMENT_KEYWORDS.has(this.peek().value.toLowerCase()))) {
          break;
        }
        continue;
      }
      break;
    }
    if (this.at(';')) this.next();
    else if (this.atCloseTag()) this.next();
    else if (this.at('}') || this.atEof() || this.atType('open')) {
      // Fine — the caller closes the block / segment.
    } else if (this.peek().type === 'name'
      && (SIMPLE_STATEMENT_TERMINATORS.has(this.peek().value.toLowerCase())
        || COMPOUND_STATEMENT_KEYWORDS.has(this.peek().value.toLowerCase()))) {
      // Fine — a structural or compound keyword the
      // caller handles (see the break above).
    } else {
      this.error('expected ";" after the statement', this.peek());
    }
    return stmts;
  }

  parseSimpleStatement() {
    const token = this.peek();
    if (token.type === 'name') {
      const kw = token.value.toLowerCase();
      switch (kw) {
        case 'return': {
          const start = this.next();
          let value = null;
          if (!this.at(';') && !this.atCloseTag() && !this.at('}') && !this.atEof()) {
            value = this.parseExpression();
          }
          return { type: 'Return', value, line: start.line, column: start.column };
        }
        case 'break': {
          const start = this.next();
          let value = null;
          if (!this.at(';') && !this.atCloseTag() && !this.at('}') && !this.atEof()) {
            value = this.parseExpression();
          }
          return { type: 'Break', value, line: start.line, column: start.column };
        }
        case 'continue': {
          const start = this.next();
          let value = null;
          if (!this.at(';') && !this.atCloseTag() && !this.at('}') && !this.atEof()) {
            value = this.parseExpression();
          }
          return { type: 'Continue', value, line: start.line, column: start.column };
        }
        case 'throw': {
          const start = this.next();
          const exc = this.parseExpression();
          return { type: 'Throw', exc, line: start.line, column: start.column };
        }
        case 'echo': {
          const start = this.next();
          const values = [this.parseExpression()];
          while (this.match(',')) values.push(this.parseExpression());
          return { type: 'Echo', values, line: start.line, column: start.column };
        }
        case 'global':
          return this.parseGlobalOrStatic();
        case 'static':
          // `static $x = 1;` is a declaration; `static::`
          // is an expression start — fall through to the
          // expression below in that case.
          if (this.peek(1).value !== '::') return this.parseGlobalOrStatic();
          break;
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
    const value = this.parseExpression();
    return { type: 'Expr', value, line: value.line, column: value.column };
  }

  // `const FOO = 1, BAR = 2;` — a top-level constant
  // declaration, no taint effect (the analyzer never
  // treats a defined constant as a source).
  parseConst() {
    const start = this.next(); // 'const'
    const names = [];
    for (;;) {
      const nameToken = this.expectType('name', 'a constant name');
      let value = null;
      if (this.at('=')) {
        this.next();
        value = this.parseExpression();
      }
      names.push({ name: nameToken.value, value });
      if (!this.match(',')) break;
    }
    return { type: 'Const', names, line: start.line, column: start.column };
  }

  parseGlobalOrStatic() {
    const start = this.next(); // 'global' or 'static'
    const isGlobal = start.value.toLowerCase() === 'global';
    const names = [];
    for (;;) {
      const varToken = this.expectType('variable', 'a variable name');
      let value = null;
      if (!isGlobal && this.at('=')) {
        this.next();
        value = this.parseExpression();
      }
      names.push({ name: varToken.value, value });
      if (!this.match(',')) break;
    }
    return {
      type: isGlobal ? 'Global' : 'Static',
      names, line: start.line, column: start.column,
    };
  }

  parseDeclare() {
    const start = this.next(); // 'declare'
    this.expect('(', "'(' after declare");
    let depth = 1;
    while (depth > 0 && !this.atEof()) {
      if (this.at('(')) depth += 1;
      else if (this.at(')')) depth -= 1;
      this.next();
    }
    if (depth !== 0) this.error('unterminated declare()', this.peek());
    let body = null;
    if (this.at('{')) {
      this.next();
      body = this.parseStatementsUntilBraceOr(null);
      this.expect('}', "'}' after the declare block");
    } else if (this.at(':')) {
      // Alternative syntax: `declare (...): ...
      // enddeclare;`
      this.next();
      body = this.parseStatementsUntilBraceOr(['enddeclare']);
      if (!this.atKw('enddeclare')) this.error('expected enddeclare', this.peek());
      this.next();
      if (this.at(';')) this.next();
    }
    return { type: 'Declare', body, line: start.line, column: start.column };
  }

  parseNamespace() {
    const start = this.next(); // 'namespace'
    let name = null;
    if (this.peek().type === 'name') name = this.parseQualifiedName();
    if (this.at('{')) {
      this.next();
      const body = this.parseStatementsUntilBraceOr(null);
      this.expect('}', "'}' after the namespace block");
      return { type: 'Namespace', name, body, line: start.line, column: start.column };
    }
    return { type: 'Namespace', name, body: null, line: start.line, column: start.column };
  }

  // `use Foo\Bar;`, `use function foo\bar as baz;`,
  // `use const FOO\BAR;`, `use Foo\{A, B as C};`.
  parseUse() {
    const start = this.next(); // 'use'
    let kind = 'class';
    if (this.atKw('function')) { this.next(); kind = 'function'; }
    else if (this.atKw('const')) { this.next(); kind = 'const'; }
    const names = [];
    const parseOneUse = () => {
      const name = this.parseQualifiedName();
      let alias = null;
      if (this.atKw('as')) {
        this.next();
        alias = this.expectType('name', 'an import alias').value;
      }
      names.push({ name, alias });
    };
    // A grouped use looks like `use Foo\{A, B};`: the
    // qualified-name parser stops before `\` when the
    // next token is not a name, so a grouped use's `{`
    // is preceded by an unconsumed `\` — consume it
    // here and detect the group below.
    const first = this.parseQualifiedName();
    if (this.at('\\') && this.peek(1).value === '{') this.next();
    if (this.at('{')) {
      this.next();
      for (;;) {
        const sub = this.parseQualifiedName();
        let alias = null;
        if (this.atKw('as')) {
          this.next();
          alias = this.expectType('name', 'an import alias').value;
        }
        names.push({ name: `${first}\\${sub}`, alias });
        if (!this.match(',')) break;
      }
      this.expect('}', "'}' after the grouped use list");
    } else {
      let alias = null;
      if (this.atKw('as')) {
        this.next();
        alias = this.expectType('name', 'an import alias').value;
      }
      names.push({ name: first, alias });
      while (this.match(',')) parseOneUse();
    }
    return { type: 'UseDecl', kind, names, line: start.line, column: start.column };
  }

  // A qualified name: [`\`] name (`\` name)* — the
  // leading backslash marks a fully-qualified name.
  // A `\` is only consumed when a name follows it, so
  // a grouped `use` (`use Foo\{A, B}`) stops at the
  // `\` before `{` instead of erroring on it.
  parseQualifiedName() {
    const start = this.peek();
    let name = '';
    if (this.at('\\')) { this.next(); name = '\\'; }
    const first = this.expectType('name', 'a name');
    name += first.value;
    while (this.at('\\') && this.peek(1).type === 'name') {
      this.next();
      name += `\\${this.expectType('name', 'a name').value}`;
    }
    return name;
  }

  parseFunctionDef() {
    const start = this.next(); // 'function'
    if (this.at('&')) this.next(); // return by reference
    if (this.at('(')) {
      this.error('closures are not supported by the subset parser', start);
    }
    const nameToken = this.expectType('name', 'a function name');
    const params = this.parseParams();
    // Optional return type: `: Type`, `?Type`, unions.
    if (this.at(':')) {
      this.next();
      this.parseType();
    }
    this.skipAttributes();
    const body = this.parseSuite(null);
    return {
      type: 'FunctionDef', name: nameToken.value, params, body,
      line: start.line, column: start.column,
    };
  }

  // A type: [`?`] qualified-name (`|` / `&`
  // qualified-name)* — parsed and discarded.
  parseType() {
    if (this.at('?')) this.next();
    if (this.at('\\') || this.peek().type === 'name') this.parseQualifiedName();
    else this.error('expected a type name', this.peek());
    while (this.at('|') || this.at('&')) {
      this.next();
      if (this.at('?')) this.next();
      this.parseQualifiedName();
    }
  }

  // A parameter list: `(` [param (`,` param)*] `)` where
  // a parameter is [visibility] [type] [`&`] [`...`]
  // `$name` [`=` default]. Returns [{ name, kind }] with
  // kind 'pos' | 'var_arg' | 'var_kw' (PHP has no
  // `**kwargs`; a `**` in a parameter list is an error).
  parseParams() {
    this.expect('(', "'(' before parameters");
    const params = [];
    while (!this.at(')') && !this.atEof()) {
      // Promoted-property visibility / readonly modifiers
      // (constructor only, accepted and ignored).
      while (this.atKw('public') || this.atKw('private')
        || this.atKw('protected') || this.atKw('readonly')) {
        this.next();
      }
      let kind = 'pos';
      if (this.at('...')) {
        this.next();
        kind = 'var_arg';
      }
      // An optional type before the variable.
      if (this.peek().type === 'variable') {
        // No type.
      } else if (this.at('?') || this.at('\\') || this.peek().type === 'name') {
        this.parseType();
        if (this.at('...')) { this.next(); kind = 'var_arg'; }
      }
      if (this.at('&')) this.next();
      const varToken = this.expectType('variable', 'a parameter name');
      if (this.at('=')) {
        this.next();
        this.parseExpression(); // default value
      }
      params.push({ name: varToken.value, kind });
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after parameters");
    return params;
  }

  parseIf() {
    const start = this.next(); // 'if'
    this.expect('(', "'(' after if");
    const test = this.parseExpression();
    this.expect(')', "')' after the if test");
    let body;
    let orelse = [];
    if (this.at(':')) {
      // Alternative syntax: `if (...): ... elseif ...:
      // ... else: ... endif;`
      this.next();
      body = this.parseStatementsUntilBraceOr(['elseif', 'else', 'endif']);
      const chain = [];
      while (this.atKw('elseif')) {
        this.next();
        this.expect('(', "'(' after elseif");
        const elifTest = this.parseExpression();
        this.expect(')', "')' after the elseif test");
        this.expect(':', "':' after elseif");
        const elifBody = this.parseStatementsUntilBraceOr(['elseif', 'else', 'endif']);
        chain.push({
          type: 'If', test: elifTest, body: elifBody, orelse: [],
          line: start.line, column: start.column,
        });
      }
      let elseBody = [];
      if (this.atKw('else')) {
        this.next();
        this.expect(':', "':' after else");
        elseBody = this.parseStatementsUntilBraceOr(['endif']);
      }
      if (!this.atKw('endif')) this.error('expected endif', this.peek());
      this.next();
      if (this.at(';')) this.next();
      // Nest the elseif chain: each elseif's orelse
      // holds the next one; the last holds the else body.
      for (let i = 0; i < chain.length - 1; i += 1) {
        chain[i].orelse = [chain[i + 1]];
      }
      if (chain.length > 0) {
        chain[chain.length - 1].orelse = elseBody;
        orelse = [chain[0]];
      } else {
        orelse = elseBody;
      }
    } else {
      body = this.parseSuite(null);
      if (this.atKw('elseif')) {
        orelse = [this.parseIf()];
      } else if (this.atKw('else')) {
        this.next();
        orelse = this.parseSuite(null);
      }
    }
    return { type: 'If', test, body, orelse, line: start.line, column: start.column };
  }

  parseForeach() {
    const start = this.next(); // 'foreach'
    this.expect('(', "'(' after foreach");
    const iter = this.parseExpression();
    this.expectKw('as', "'as' in a foreach statement");
    const first = this.parseTarget();
    let target = first;
    if (this.at('=>')) {
      this.next();
      const value = this.parseTarget();
      target = { type: 'Pair', key: first, value, line: first.line, column: first.column };
    }
    this.expect(')', "')' after the foreach header");
    const body = this.parseSuite('endforeach');
    return { type: 'Foreach', target, iter, body, line: start.line, column: start.column };
  }

  parseFor() {
    const start = this.next(); // 'for'
    this.expect('(', "'(' after for");
    let init = null;
    if (!this.at(';')) init = this.parseExpressionList();
    this.expect(';', "';' in a for header");
    let test = null;
    if (!this.at(';')) test = this.parseExpressionList();
    this.expect(';', "';' in a for header");
    let update = null;
    if (!this.at(')')) update = this.parseExpressionList();
    this.expect(')', "')' after the for header");
    const body = this.parseSuite('endfor');
    return { type: 'For', init, test, update, body, line: start.line, column: start.column };
  }

  parseWhile() {
    const start = this.next(); // 'while'
    this.expect('(', "'(' after while");
    const test = this.parseExpression();
    this.expect(')', "')' after the while test");
    const body = this.parseSuite('endwhile');
    return { type: 'While', test, body, line: start.line, column: start.column };
  }

  parseDoWhile() {
    const start = this.next(); // 'do'
    const body = this.parseSuite(null);
    if (!this.atKw('while')) this.error('expected while after a do block', this.peek());
    this.next();
    this.expect('(', "'(' after while");
    const test = this.parseExpression();
    this.expect(')', "')' after the while test");
    return { type: 'DoWhile', test, body, line: start.line, column: start.column };
  }

  parseSwitch() {
    const start = this.next(); // 'switch'
    this.expect('(', "'(' after switch");
    const test = this.parseExpression();
    this.expect(')', "')' after the switch test");
    const alternative = this.at(':');
    if (alternative) this.next();
    else this.expect('{', "'{' after the switch test");
    const cases = [];
    for (;;) {
      this.skipTags();
      this.skipAttributes();
      if (this.atEof()) this.error('unterminated switch', this.peek());
      if (alternative && this.atKw('endswitch')) break;
      if (!alternative && this.at('}')) break;
      let caseTest = null;
      if (this.atKw('case')) {
        this.next();
        caseTest = this.parseExpression();
      } else if (this.atKw('default')) {
        this.next();
      } else {
        this.error('expected case or default in a switch', this.peek());
      }
      this.expect(':', "':' after a case label");
      const body = [];
      for (;;) {
        if (this.handleShortEcho(body)) continue;
        this.skipTags();
        this.skipAttributes();
        if (this.atEof()) break;
        if (this.atKw('case') || this.atKw('default')) break;
        if (alternative && this.atKw('endswitch')) break;
        if (!alternative && this.at('}')) break;
        if (this.atType('open')) { this.next(); continue; }
        body.push(...this.parseStatement());
      }
      cases.push({ test: caseTest, body, line: start.line, column: start.column });
    }
    if (alternative) {
      if (!this.atKw('endswitch')) this.error('expected endswitch', this.peek());
      this.next();
      if (this.at(';')) this.next();
    } else {
      this.expect('}', "'}' after the switch");
    }
    return { type: 'Switch', test, cases, line: start.line, column: start.column };
  }

  parseTry() {
    const start = this.next(); // 'try'
    const body = this.parseSuite(null);
    const handlers = [];
    let finalbody = [];
    while (this.atKw('catch')) {
      const handlerStart = this.next();
      let types = [];
      let name = null;
      if (this.at('(')) {
        this.next();
        if (!this.at(')')) {
          types.push(this.parseQualifiedName());
          while (this.at('|')) {
            this.next();
            types.push(this.parseQualifiedName());
          }
          if (this.peek().type === 'variable') name = this.next().value;
        }
        this.expect(')', "')' after the catch clause");
      }
      const handlerBody = this.parseSuite(null);
      handlers.push({
        types, name, body: handlerBody,
        line: handlerStart.line, column: handlerStart.column,
      });
    }
    if (this.atKw('finally')) {
      this.next();
      finalbody = this.parseSuite(null);
    }
    if (handlers.length === 0 && finalbody.length === 0) {
      this.error('try must have at least one catch or a finally clause', start);
    }
    return {
      type: 'Try', body, handlers, finalbody,
      line: start.line, column: start.column,
    };
  }

  expectKw(value, what) {
    if (!this.atKw(value)) {
      const token = this.peek();
      throw new PhpParseError(
        `expected ${what || JSON.stringify(value)} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  // An assignment target: a variable, an attribute /
  // subscript chain, a `list(...)` / `[...]` list of
  // targets. Parsed WITHOUT comparison operators.
  parseTarget() {
    const start = this.peek();
    if (this.atKw('list')) {
      this.next();
      this.expect('(', "'(' after list");
      const elts = [];
      while (!this.at(')') && !this.atEof()) {
        if (this.at(',')) { this.next(); elts.push(null); continue; }
        elts.push(this.parseTarget());
        if (!this.match(',')) break;
      }
      this.expect(')', "')' after a list target");
      return { type: 'List', elts, line: start.line, column: start.column };
    }
    if (this.at('[')) {
      this.next();
      const elts = [];
      while (!this.at(']') && !this.atEof()) {
        if (this.at(',')) { this.next(); elts.push(null); continue; }
        elts.push(this.parseTarget());
        if (!this.match(',')) break;
      }
      this.expect(']', "']' after a list target");
      return { type: 'List', elts, line: start.line, column: start.column };
    }
    const node = this.parsePostfix();
    if (node.type !== 'Variable' && node.type !== 'Attribute'
      && node.type !== 'Subscript' && node.type !== 'List') {
      this.error('invalid assignment target', node);
    }
    return node;
  }

  // An expression list: `expr (, expr)*`.
  parseExpressionList() {
    const first = this.parseExpression();
    const elements = [first];
    while (this.at(',')) {
      this.next();
      elements.push(this.parseExpression());
    }
    if (elements.length === 1) return first;
    return { type: 'Tuple', elts: elements, line: first.line, column: first.column };
  }

  // --- Expressions (precedence climbing) -------------------------------
  //
  // Lowest to highest: word-or / word-xor / word-and /
  // assignment / conditional (?:) / coalesce (??) /
  // || / && / comparison / | / ^ / & / shift / concat /
  // + - / * / % / factor (unary, casts) / ** / postfix /
  // primary. `include` binds looser than `?:` and `=`
  // (its operand is parsed at the coalesce level), and
  // `and` / `xor` / `or` bind looser than `=`, as in PHP.

  parseExpression() {
    return this.parseWordOr();
  }

  parseWordOr() {
    let left = this.parseWordXor();
    while (this.atKw('or')) {
      this.next();
      const right = this.parseWordXor();
      left = { type: 'BoolOp', op: 'or', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  parseWordXor() {
    let left = this.parseWordAnd();
    while (this.atKw('xor')) {
      this.next();
      const right = this.parseWordAnd();
      left = { type: 'BoolOp', op: 'xor', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  parseWordAnd() {
    let left = this.parseAssignment();
    while (this.atKw('and')) {
      this.next();
      const right = this.parseAssignment();
      left = { type: 'BoolOp', op: 'and', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  // Assignment (right-associative): `a = b`, `a = b = c`,
  // `a += b`, `a ??= b`. The left-hand side is parsed as
  // a general expression first, then validated as a
  // target when an assignment operator follows.
  parseAssignment() {
    const first = this.parseConditional();
    if (this.at('=')) {
      if (!isValidTarget(first)) this.error('invalid assignment target', first);
      this.next();
      const value = this.parseAssignment();
      return { type: 'Assign', targets: [first], value, line: first.line, column: first.column };
    }
    if (this.peek().type === 'punct' && AUGMENTED_OPERATORS.has(this.peek().value)) {
      if (!isValidTarget(first)) this.error('invalid assignment target', first);
      const op = this.next().value;
      const value = this.parseAssignment();
      return { type: 'AugAssign', target: first, op, value, line: first.line, column: first.column };
    }
    return first;
  }

  parseConditional() {
    const test = this.parseCoalesce();
    if (!this.at('?')) return test;
    this.next();
    let body = null;
    if (!this.at(':')) body = this.parseExpression();
    this.expect(':', "':' in a ternary expression");
    const orelse = this.parseConditional();
    return {
      type: 'Conditional', test, body, orelse,
      line: test.line, column: test.column,
    };
  }

  parseCoalesce() {
    let left = this.parseBoolOr();
    while (this.at('??')) {
      this.next();
      const right = this.parseBoolOr();
      left = { type: 'BinOp', op: '??', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseBoolOr() {
    let left = this.parseBoolAnd();
    while (this.at('||')) {
      this.next();
      const right = this.parseBoolAnd();
      left = { type: 'BoolOp', op: '||', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  parseBoolAnd() {
    let left = this.parseComparison();
    while (this.at('&&')) {
      this.next();
      const right = this.parseComparison();
      left = { type: 'BoolOp', op: '&&', values: [left, right], line: left.line, column: left.column };
    }
    return left;
  }

  parseComparison() {
    const left = this.parseBitOr();
    const ops = [];
    const comparators = [];
    for (;;) {
      let op = null;
      if (this.peek().type === 'punct' && COMPARISON_OPERATORS.has(this.peek().value)) {
        op = this.next().value;
      } else if (this.atKw('instanceof')) {
        this.next();
        op = 'instanceof';
      } else {
        break;
      }
      ops.push(op);
      comparators.push(this.parseBitOr());
    }
    if (ops.length === 0) return left;
    return {
      type: 'Compare', left, ops, comparators,
      line: left.line, column: left.column,
    };
  }

  parseBitOr() {
    let left = this.parseBitXor();
    while (this.at('|')) {
      this.next();
      const right = this.parseBitXor();
      left = { type: 'BinOp', op: '|', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseBitXor() {
    let left = this.parseBitAnd();
    while (this.at('^')) {
      this.next();
      const right = this.parseBitAnd();
      left = { type: 'BinOp', op: '^', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseBitAnd() {
    let left = this.parseShift();
    while (this.at('&')) {
      this.next();
      const right = this.parseShift();
      left = { type: 'BinOp', op: '&', left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseShift() {
    let left = this.parseConcat();
    while (this.at('<<') || this.at('>>')) {
      const op = this.next().value;
      const right = this.parseConcat();
      left = { type: 'BinOp', op, left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseConcat() {
    let left = this.parseArith();
    while (this.at('.')) {
      this.next();
      const right = this.parseArith();
      left = { type: 'BinOp', op: '.', left, right, line: left.line, column: left.column };
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
    while (this.at('*') || this.at('/') || this.at('%')) {
      const op = this.next().value;
      const right = this.parseFactor();
      left = { type: 'BinOp', op, left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseFactor() {
    const token = this.peek();
    if (token.type === 'punct' && (token.value === '+' || token.value === '-' || token.value === '~'
      || token.value === '!' || token.value === '@')) {
      const op = this.next();
      const operand = this.parseFactor();
      return { type: 'UnaryOp', op: op.value, operand, line: op.line, column: op.column };
    }
    if (token.type === 'punct' && (token.value === '++' || token.value === '--')) {
      const op = this.next();
      const operand = this.parseFactor();
      return { type: 'PrefixIncDec', op: op.value, value: operand, line: op.line, column: op.column };
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
      if (this.at('->') || this.at('?->')) {
        // `?->` is the nullsafe member-access operator
        // (PHP 8) — same shape as `->`, flagged so the
        // analyzer can tell them apart if it ever needs
        // to (it currently treats both identically).
        const nullsafe = this.at('?->');
        this.next();
        if (this.peek().type === 'variable' || this.at('{')) {
          this.error('dynamic member access (->$x, ->{...}) is not supported by the subset parser', this.peek());
        }
        const prop = this.expectType('name', 'a property or method name');
        expr = {
          type: 'Attribute', value: expr, attr: prop.value, isStatic: false, nullsafe,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (this.at('::')) {
        this.next();
        let attr;
        let isStaticProp = false;
        if (this.peek().type === 'variable') {
          attr = this.next().value;
          isStaticProp = true;
        } else if (this.peek().type === 'name') {
          attr = this.next().value;
        } else if (this.at('{')) {
          this.error('dynamic static access (::{...}) is not supported by the subset parser', this.peek());
        } else {
          this.error('expected a member name after ::', this.peek());
        }
        expr = {
          type: 'Attribute', value: expr, attr, isStatic: true, isStaticProp,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (this.at('[')) {
        this.next();
        let index = null;
        if (!this.at(']')) index = this.parseExpression();
        this.expect(']', "']' after a subscript");
        expr = {
          type: 'Subscript', value: expr, slice: index,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (this.at('(')) {
        expr = this.parseCallArgs(expr);
        continue;
      }
      if (this.at('++') || this.at('--')) {
        const op = this.next();
        expr = {
          type: 'PostfixIncDec', op: op.value, value: expr,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      break;
    }
    return expr;
  }

  // Parse call arguments after the callee; the current
  // token is `(`. Returns a Call node. Arguments are
  // positional, named (`name: value`, PHP 8), or spread
  // (`...$args`).
  parseCallArgs(callee) {
    this.expect('(', "'(' before call arguments");
    const args = [];
    const keywords = [];
    while (!this.at(')') && !this.atEof()) {
      if (this.at('...')) {
        this.next();
        args.push({ type: 'Spread', value: this.parseExpression(), line: callee.line, column: callee.column });
      } else if (this.peek().type === 'name' && this.peek(1).value === ':') {
        // Named argument (`name: value`). Any bare name
        // followed by `:` is a named argument in this
        // position — a ternary never starts an argument
        // with a bare name, and `=>` keys are parsed
        // inside array displays, not here. Reserved
        // words are accepted as names too (a lenient
        // deviation — PHP rejects some — that cannot
        // change a taint verdict).
        const name = this.next();
        this.next(); // ':'
        keywords.push({ arg: name.value, value: this.parseExpression() });
      } else {
        args.push(this.parseExpression());
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
      if (token.kind === 'single') {
        return { type: 'Constant', value: token.value, kind: 'string', line: token.line, column: token.column };
      }
      return this.parseInterpolatedString(token);
    }
    if (token.type === 'variable') {
      this.next();
      return { type: 'Variable', name: token.value, line: token.line, column: token.column };
    }
    if (token.type === 'name') {
      const kw = token.value.toLowerCase();
      if (kw === 'true' || kw === 'false') {
        this.next();
        return { type: 'Constant', value: kw, kind: 'boolean', line: token.line, column: token.column };
      }
      if (kw === 'null') {
        this.next();
        return { type: 'Constant', value: null, kind: 'null', line: token.line, column: token.column };
      }
      if (kw === 'include' || kw === 'require' || kw === 'include_once' || kw === 'require_once') {
        const start = this.next();
        const value = this.parseCoalesce();
        return {
          type: 'Include', kind: kw, value,
          line: start.line, column: start.column,
        };
      }
      if (kw === 'print') {
        const start = this.next();
        const value = this.parseCoalesce();
        return { type: 'Print', value, line: start.line, column: start.column };
      }
      if (kw === 'exit' || kw === 'die') {
        const start = this.next();
        let value = null;
        if (this.at('(')) {
          this.next();
          if (!this.at(')')) value = this.parseExpression();
          this.expect(')', "')' after exit()");
        } else if (!this.at(';') && !this.atCloseTag() && !this.at('}') && !this.at(')')
          && !this.at(',') && !this.at('?') && !this.at(':') && !this.atEof()) {
          value = this.parseCoalesce();
        }
        return { type: 'Exit', value, line: start.line, column: start.column };
      }
      if (kw === 'array' && this.peek(1).value === '(') {
        return this.parseArrayDisplay();
      }
      if (kw === 'list' && this.peek(1).value === '(') {
        const start = this.next();
        this.next(); // '('
        const elts = [];
        while (!this.at(')') && !this.atEof()) {
          if (this.at(',')) { this.next(); elts.push(null); continue; }
          elts.push(this.parseTarget());
          if (!this.match(',')) break;
        }
        this.expect(')', "')' after list()");
        return { type: 'List', elts, line: start.line, column: start.column };
      }
      if (kw === 'isset' || kw === 'empty' || kw === 'unset') {
        const start = this.next();
        this.expect('(', `'(' after ${kw}`);
        const args = [];
        while (!this.at(')') && !this.atEof()) {
          args.push(this.parseExpression());
          if (!this.match(',')) break;
        }
        this.expect(')', `')' after ${kw}()`);
        return {
          type: 'Call',
          func: { type: 'Name', id: kw, line: start.line, column: start.column },
          args, keywords: [], line: start.line, column: start.column,
        };
      }
      if (kw === 'new') {
        const start = this.next();
        let cls;
        if (this.peek().type === 'variable') {
          const varToken = this.next();
          cls = { type: 'Variable', name: varToken.value, line: varToken.line, column: varToken.column };
        } else {
          cls = { type: 'Name', id: this.parseQualifiedName(), line: start.line, column: start.column };
        }
        let args = [];
        let keywords = [];
        if (this.at('(')) {
          const call = this.parseCallArgs(cls);
          args = call.args;
          keywords = call.keywords;
        }
        return { type: 'New', class: cls, args, keywords, line: start.line, column: start.column };
      }
      if (kw === 'clone') {
        const start = this.next();
        const value = this.parseFactor();
        return { type: 'Clone', value, line: start.line, column: start.column };
      }
      if (kw === 'fn') {
        this.error('arrow functions (fn) are not supported by the subset parser', token);
      }
      if (kw === 'function') {
        this.error('closures are not supported by the subset parser', token);
      }
      if (kw === '__halt_compiler') {
        this.error('__halt_compiler is not supported by the subset parser', token);
      }
      if (kw === 'yield') {
        this.error('yield is not supported by the subset parser', token);
      }
      if (kw === 'match') {
        this.error('match expressions are not supported by the subset parser', token);
      }
      if (kw === 'class' || kw === 'interface' || kw === 'trait' || kw === 'enum') {
        this.error(`${kw} definitions are not supported by the subset parser`, token);
      }
      // `static::` / `self::` / `parent::` are class-name
      // positions, not the `static` declaration keyword
      // — accept them as names. A bare `static` /
      // `self` / `parent` anywhere else is still an
      // error (it is not a valid PHP expression).
      if (RESERVED.has(kw)
        && !((kw === 'static' || kw === 'self' || kw === 'parent')
          && this.peek(1).value === '::')) {
        this.error(`unexpected keyword ${JSON.stringify(token.value)}`, token);
      }
      this.next();
      // A qualified name (`Foo\Bar`, `\Foo\Bar`). The
      // `\` is only consumed when a name follows it — a
      // `\` before `{` belongs to a grouped `use`
      // (`use Foo\{A, B}`), not to the name.
      let id = token.value;
      while (this.at('\\') && this.peek(1).type === 'name') {
        this.next();
        id += `\\${this.expectType('name', 'a name').value}`;
      }
      return { type: 'Name', id, line: token.line, column: token.column };
    }
    if (token.type === 'punct' && token.value === '\\') {
      // A leading backslash: a fully-qualified name.
      this.next();
      const name = this.parseQualifiedName();
      // The leading backslash is part of the id — it is
      // what distinguishes `\unserialize` (a sink) from
      // `Foo\unserialize` (not a sink).
      return { type: 'QualifiedName', id: `\\${name}`, line: token.line, column: token.column };
    }
    if (token.type === 'punct' && token.value === '(') {
      // A cast (`(int) $x`) or a parenthesized expression.
      const start = this.next();
      if (this.peek().type === 'name'
        && CAST_TYPES.has(this.peek().value.toLowerCase())
        && this.peek(1).value === ')') {
        const castType = this.next().value.toLowerCase();
        this.next(); // ')'
        const value = this.parseFactor();
        return { type: 'Cast', castType, value, line: start.line, column: start.column };
      }
      if (this.peek().type === 'name'
        && (this.peek().value.toLowerCase() === 'function'
          || this.peek().value.toLowerCase() === 'fn')) {
        this.error('closures are not supported by the subset parser', this.peek());
      }
      const expr = this.parseExpression();
      this.expect(')', "')' after a parenthesized expression");
      return expr;
    }
    if (token.type === 'punct' && token.value === '[') {
      return this.parseArrayDisplay();
    }
    this.error(`unexpected token ${JSON.stringify(token.value) || token.type} in expression`, token);
    return null;
  }

  // An array display: `[...]` or `array(...)`. Elements
  // are `value` or `key => value`, with optional spread.
  parseArrayDisplay() {
    const start = this.peek();
    const isArrayKeyword = this.atKw('array');
    if (isArrayKeyword) {
      this.next();
      this.expect('(', "'(' after array");
    } else {
      this.next(); // '['
    }
    const elements = [];
    while ((!isArrayKeyword && !this.at(']')) || (isArrayKeyword && !this.at(')'))) {
      if (this.atEof()) break;
      if (this.at('...')) {
        this.next();
        elements.push({
          key: null, value: this.parseExpression(), spread: true,
          line: start.line, column: start.column,
        });
      } else {
        const first = this.parseExpression();
        if (this.at('=>')) {
          this.next();
          const value = this.parseExpression();
          elements.push({ key: first, value, spread: false, line: first.line, column: first.column });
        } else {
          elements.push({ key: null, value: first, spread: false, line: first.line, column: first.column });
        }
      }
      if (!this.match(',')) break;
      if ((!isArrayKeyword && this.at(']')) || (isArrayKeyword && this.at(')'))) break;
    }
    if (isArrayKeyword) this.expect(')', "')' after array()");
    else this.expect(']', "']' after an array display");
    return { type: 'Array', elements, line: start.line, column: start.column };
  }

  // Split a double-quoted / backtick string token's raw
  // contents into literal and expression parts. `$name`
  // (with optional `[...]` / `->prop` chains), `${name}`,
  // and `{$expr}` interpolate; `{{` / `}}` do not exist
  // in PHP — a lone `$` not followed by a name or `{`
  // is a literal `$`, and `\$` is an escaped dollar.
  // Expression fragments are parsed with a fresh
  // tokenizer over the fragment (like the Python
  // parser's f-strings); their positions are approximate
  // (the string token's line) — findings never carry a
  // source line, so this affects nothing the operator
  // sees.
  parseInterpolatedString(token) {
    const raw = token.value;
    const parts = [];
    let i = 0;
    let literal = '';
    const pushLiteral = () => {
      if (literal !== '') {
        parts.push({ type: 'literal', value: literal });
        literal = '';
      }
    };
    const parseFragment = (fragment) => {
      const fragmentTokens = tokenize(fragment, { fragment: true });
      const fragmentParser = new Parser(fragmentTokens);
      const node = fragmentParser.parseExpression();
      fragmentParser.skipTags();
      if (!fragmentParser.atEof()) {
        throw new PhpParseError('unexpected trailing token in string interpolation', token.line, token.column);
      }
      return node;
    };
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === '\\' && i + 1 < raw.length) {
        literal += raw.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (ch === '$') {
        const next = raw[i + 1];
        if (next === '{') {
          // `${name}` — a simple variable.
          let j = i + 2;
          if (j >= raw.length || !isIdentStart(raw[j])) {
            literal += '$';
            i += 1;
            continue;
          }
          while (j < raw.length && isIdentPart(raw[j])) j += 1;
          if (raw[j] !== '}') {
            throw new PhpParseError('unterminated ${...} in string interpolation', token.line, token.column);
          }
          pushLiteral();
          parts.push({ type: 'expr', node: parseFragment('$' + raw.slice(i + 2, j)) });
          i = j + 1;
          continue;
        }
        if (next !== undefined && isIdentStart(next)) {
          // `$name` with optional `[...]` / `->prop`
          // chains immediately following.
          let j = i + 1;
          while (j < raw.length && isIdentPart(raw[j])) j += 1;
          for (;;) {
            if (raw[j] === '[') {
              let depth = 1;
              let k = j + 1;
              let quote = null;
              while (k < raw.length && depth > 0) {
                const c = raw[k];
                if (quote) {
                  if (c === '\\') { k += 2; continue; }
                  if (c === quote) quote = null;
                  k += 1;
                  continue;
                }
                if (c === '"' || c === "'") { quote = c; k += 1; continue; }
                if (c === '[') depth += 1;
                else if (c === ']') depth -= 1;
                k += 1;
              }
              if (depth !== 0) break;
              j = k;
              continue;
            }
            if (raw.startsWith('->', j)) {
              let k = j + 2;
              if (k < raw.length && isIdentStart(raw[k])) {
                while (k < raw.length && isIdentPart(raw[k])) k += 1;
                j = k;
                continue;
              }
              break;
            }
            break;
          }
          pushLiteral();
          parts.push({ type: 'expr', node: parseFragment(raw.slice(i, j)) });
          i = j;
          continue;
        }
        // A lone `$` (followed by neither a name nor
        // `{`) is literal, as in PHP.
        literal += '$';
        i += 1;
        continue;
      }
      if (ch === '{' && raw[i + 1] === '$') {
        // `{$expr}` — a braced expression.
        let depth = 1;
        let j = i + 2;
        let quote = null;
        while (j < raw.length && depth > 0) {
          const c = raw[j];
          if (quote) {
            if (c === '\\') { j += 2; continue; }
            if (c === quote) quote = null;
            j += 1;
            continue;
          }
          if (c === '"' || c === "'") { quote = c; j += 1; continue; }
          if (c === '{') depth += 1;
          else if (c === '}') depth -= 1;
          j += 1;
        }
        if (depth !== 0) {
          throw new PhpParseError('unmatched "{" in string interpolation', token.line, token.column);
        }
        pushLiteral();
        // The fragment starts at the `$` (i + 1 skips
        // only the `{`); dropping it would turn
        // `{$_GET["p"]}` into a bare Name `_GET`, which
        // the analyzer would not recognize as the
        // superglobal.
        parts.push({ type: 'expr', node: parseFragment(raw.slice(i + 1, j - 1)) });
        i = j;
        continue;
      }
      literal += ch;
      i += 1;
    }
    pushLiteral();
    if (parts.length === 0) {
      return { type: 'Constant', value: raw, kind: 'string', line: token.line, column: token.column };
    }
    if (parts.length === 1 && parts[0].type === 'literal') {
      return { type: 'Constant', value: parts[0].value, kind: 'string', line: token.line, column: token.column };
    }
    return {
      type: 'JoinedStr', values: parts,
      line: token.line, column: token.column,
    };
  }
}

// Is this node a valid assignment target? Variables,
// attribute / subscript chains, and lists of targets
// only — a call or a binary expression is not a target.
function isValidTarget(node) {
  if (!node || typeof node !== 'object') return false;
  switch (node.type) {
    case 'Variable':
    case 'Attribute':
    case 'Subscript':
      return true;
    case 'List':
      return node.elts.every((elt) => elt === null || isValidTarget(elt));
    case 'Array':
      // A short list target: `[$a, $b] = $arr` — every
      // element must be a valid target, with no key and
      // no spread.
      return node.elements.every(
        (el) => el && !el.spread && el.key === null && isValidTarget(el.value),
      );
    default:
      return false;
  }
}

function parsePhp(source, options) {
  if (typeof source !== 'string') {
    throw new PhpParseError('source must be a string', 1, 1);
  }
  const parser = new Parser(tokenize(source, options));
  const program = parser.parseProgram();
  if (!parser.atEof()) {
    const token = parser.peek();
    throw new PhpParseError(
      `unexpected trailing token ${JSON.stringify(token.value) || token.type}`,
      token.line, token.column,
    );
  }
  return program;
}

module.exports = parsePhp;
module.exports.parsePhp = parsePhp;
module.exports.tokenize = tokenize;
module.exports.PhpParseError = PhpParseError;
