// Hand-written JavaScript subset parser (Phase 5, round 95):
// tokenizer + recursive-descent parser producing an AST with
// line/column positions. Stdlib-only, synchronous, deterministic,
// and it NEVER executes the code it parses.
//
// Why hand-written: the taint detector needs structure (call
// expressions, bindings, flow) that a regex cannot see, and the
// skill installs and verifies offline, so an npm parser (Acorn
// was evaluated — MIT, ~100 KB, the parser behind ESLint —
// and NOT adopted this round: it would need a vendoring story
// that does not exist yet, and the prototype's single detector
// class does not need a full grammar) is out of scope. Acorn
// remains the documented upgrade path in
// docs/parser-taint-scope-v1.md if the grammar outgrows this
// subset or a second language is added.
//
// The grammar is a SUBSET (see docs/parser-taint-scope-v1.md
// §2.2 for the full list): programs, blocks, functions
// (declarations, expressions, arrows, methods), classes
// (methods + fields), variables (including destructuring),
// control flow (if/while/for/try/switch/throw), assignments,
// calls, members (including optional chaining), new, await,
// yield, literals (including templates with interpolations
// and regex literals), objects, arrays, spread, import
// declarations (bindings tracked since round 106; exotic
// import forms fall back to the structural skip) and export
// (skipped structurally). Anything outside the subset fails
// with a JSParseError carrying line and column — the caller
// (the detector) counts that record in `skipped`, it NEVER
// falls back to scanning text with a regex.
//
// Safety properties:
// - Comments are stripped by the tokenizer and string contents
//   are single tokens, so sink text inside a comment or a
//   string never becomes a call node.
// - A template literal's interpolations are parsed as real
//   expressions (sub-tokenized with positions shifted to the
//   interpolation's location), so taint flows through them.
// - Positions are 1-based line/column, taken from the first
//   token of each node.
'use strict';

class JSParseError extends Error {
  constructor(message, line, column) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = 'JSParseError';
    this.line = line;
    this.column = column;
  }
}

const KEYWORDS = new Set([
  'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
  'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends',
  'false', 'finally', 'for', 'function', 'if', 'import', 'in',
  'instanceof', 'let', 'new', 'null', 'of', 'return', 'static',
  'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof',
  'var', 'void', 'while', 'with', 'yield', 'async', 'get', 'set',
  'from', 'as',
]);

// Punctuation, longest first — the tokenizer tries them in this
// order at each position.
const PUNCTUATORS = [
  '...', '===', '!==', '>>>', '**=', '<<=', '>>=', '&&=', '||=',
  '??=', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '=>',
  '++', '--', '+=', '-=', '*=', '/=', '%=', '**', '<<', '>>',
  '&', '|', '^', '~', '!', '+', '-', '*', '/', '%', '<', '>',
  '=', '?', ':', ';', ',', '.', '(', ')', '[', ']', '{', '}',
];

function isIdentStart(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_' || ch === '$';
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

function decodeString(raw, line, column) {
  // raw includes the surrounding quotes. Decode the common
  // escapes; anything exotic is kept verbatim (the value only
  // matters for computed member keys like yaml['load']).
  const quote = raw[0];
  let out = '';
  for (let i = 1; i < raw.length - 1; i += 1) {
    const ch = raw[i];
    if (ch !== '\\') { out += ch; continue; }
    const next = raw[i + 1];
    if (next === undefined) break;
    i += 1;
    switch (next) {
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'v': out += '\v'; break;
      case '0': out += '\0'; break;
      case 'x': {
        const hex = raw.slice(i + 1, i + 3);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) { out += String.fromCharCode(parseInt(hex, 16)); i += 2; }
        else out += `\\x${hex}`;
        break;
      }
      case 'u': {
        if (raw[i + 1] === '{') {
          const end = raw.indexOf('}', i + 2);
          const hex = end === -1 ? '' : raw.slice(i + 2, end);
          if (/^[0-9a-fA-F]+$/.test(hex)) { out += String.fromCodePoint(parseInt(hex, 16)); i = end; }
          else out += '\\u';
        } else {
          const hex = raw.slice(i + 1, i + 5);
          if (/^[0-9a-fA-F]{4}$/.test(hex)) { out += String.fromCharCode(parseInt(hex, 16)); i += 4; }
          else out += '\\u';
        }
        break;
      }
      default: out += next; break;
    }
  }
  return { value: out, quote };
}

// Tokenize source into { type, value, line, column } tokens.
// type: 'name' | 'number' | 'string' | 'template' | 'regex' |
// 'punct' | 'eof'. A template token's value is an array of
// parts: { type: 'raw', value } or { type: 'expr', source,
// line, column } (source is the interpolation's source text).
function tokenize(source) {
  const tokens = [];
  let i = 0;
  let line = 1;
  let column = 1;

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

  // The token before the current position, for the regex-vs-
  // division heuristic: a `/` starts a regex when the previous
  // significant token cannot end an expression.
  function regexAllowed() {
    const prev = tokens[tokens.length - 1];
    if (!prev) return true;
    if (prev.type === 'name' || prev.type === 'number' || prev.type === 'string'
      || prev.type === 'template' || prev.type === 'regex') return false;
    if (prev.type === 'punct') {
      return !(prev.value === ')' || prev.value === ']' || prev.value === '}'
        || prev.value === '++' || prev.value === '--');
    }
    return true;
  }

  while (i < source.length) {
    const ch = source[i];

    // Whitespace.
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === '\f' || ch === '\v') {
      advance();
      continue;
    }

    // Comments (stripped; newlines inside still count).
    if (ch === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') advance();
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const start = position();
      advance(2);
      let closed = false;
      while (i < source.length) {
        if (source[i] === '*' && source[i + 1] === '/') { advance(2); closed = true; break; }
        advance();
      }
      if (!closed) throw new JSParseError('unterminated block comment', start.line, start.column);
      continue;
    }

    const start = position();

    // Private names (#field) — one name token.
    if (ch === '#' && isIdentStart(source[i + 1] || '')) {
      let j = i + 1;
      while (j < source.length && isIdentPart(source[j])) j += 1;
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'name', value, ...start });
      continue;
    }

    // Identifiers / keywords.
    if (isIdentStart(ch)) {
      let j = i;
      while (j < source.length && isIdentPart(source[j])) j += 1;
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'name', value, ...start });
      continue;
    }

    // Numbers.
    if (isDigit(ch) || (ch === '.' && isDigit(source[i + 1] || ''))) {
      let j = i;
      if (source[j] === '0' && (source[j + 1] === 'x' || source[j + 1] === 'X')) {
        j += 2;
        while (j < source.length && (isHexDigit(source[j]) || source[j] === '_')) j += 1;
      } else if (source[j] === '0' && (source[j + 1] === 'b' || source[j + 1] === 'B')) {
        j += 2;
        while (j < source.length && (source[j] === '0' || source[j] === '1' || source[j] === '_')) j += 1;
      } else if (source[j] === '0' && (source[j + 1] === 'o' || source[j + 1] === 'O')) {
        j += 2;
        while (j < source.length && ((source[j] >= '0' && source[j] <= '7') || source[j] === '_')) j += 1;
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
      if (source[j] === 'n') j += 1;
      const value = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'number', value, ...start });
      continue;
    }

    // Strings.
    if (ch === '"' || ch === "'") {
      const quote = ch;
      let j = i + 1;
      let closed = false;
      while (j < source.length) {
        if (source[j] === '\\') { j += 2; continue; }
        if (source[j] === quote) { closed = true; j += 1; break; }
        if (source[j] === '\n') break;
        j += 1;
      }
      if (!closed) throw new JSParseError('unterminated string literal', start.line, start.column);
      const raw = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'string', value: decodeString(raw, start.line, start.column).value, raw, ...start });
      continue;
    }

    // Template literals: one token, interpolations kept as
    // source text with positions for the parser to sub-parse.
    if (ch === '`') {
      advance();
      const parts = [];
      let raw = '';
      let closed = false;
      while (i < source.length) {
        const c = source[i];
        if (c === '\\') {
          raw += source.slice(i, i + 2);
          advance(2);
          continue;
        }
        if (c === '`') { advance(); closed = true; break; }
        if (c === '$' && source[i + 1] === '{') {
          const exprStart = position();
          advance(2);
          // Scan the interpolation with brace depth, honouring
          // strings, templates (nested, one level of backticks
          // handled by depth on '`' toggling is too fragile —
          // nested templates are rare; a nested backtick inside
          // the interpolation ends the scan as a parse error
          // rather than a wrong parse) and comments.
          let depth = 1;
          let expr = '';
          let ok = false;
          while (i < source.length) {
            const d = source[i];
            if (d === "'" || d === '"') {
              const q = d;
              expr += d;
              advance();
              while (i < source.length && source[i] !== q) {
                if (source[i] === '\\') { expr += source.slice(i, i + 2); advance(2); continue; }
                if (source[i] === '\n') break;
                expr += source[i];
                advance();
              }
              if (i < source.length && source[i] === q) { expr += q; advance(); }
              continue;
            }
            if (d === '/' && source[i + 1] === '/') {
              while (i < source.length && source[i] !== '\n') { expr += source[i]; advance(); }
              continue;
            }
            if (d === '/' && source[i + 1] === '*') {
              expr += '/*';
              advance(2);
              while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
                expr += source[i];
                advance();
              }
              if (i < source.length) { expr += '*/'; advance(2); }
              continue;
            }
            if (d === '`') break; // nested template: give up cleanly
            if (d === '{') depth += 1;
            if (d === '}') {
              depth -= 1;
              if (depth === 0) { advance(); ok = true; break; }
            }
            expr += d;
            advance();
          }
          if (!ok) throw new JSParseError('unterminated template interpolation', exprStart.line, exprStart.column);
          parts.push({ type: 'raw', value: raw });
          raw = '';
          parts.push({ type: 'expr', source: expr, line: exprStart.line, column: exprStart.column });
          continue;
        }
        raw += c;
        advance();
      }
      if (!closed) throw new JSParseError('unterminated template literal', start.line, start.column);
      parts.push({ type: 'raw', value: raw });
      tokens.push({ type: 'template', value: parts, ...start });
      continue;
    }

    // Regex literal vs division (heuristic on previous token).
    if (ch === '/' && regexAllowed()) {
      let j = i + 1;
      let inClass = false;
      let ok = false;
      while (j < source.length) {
        const d = source[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '\n') break;
        if (d === '[') inClass = true;
        if (d === ']') inClass = false;
        if (d === '/' && !inClass) { ok = true; break; }
        j += 1;
      }
      if (ok) {
        let k = j + 1;
        while (k < source.length && source[k] >= 'a' && source[k] <= 'z') k += 1;
        const value = source.slice(i, k);
        advance(k - i);
        tokens.push({ type: 'regex', value, ...start });
        continue;
      }
      // Not a valid regex: fall through to punctuator `/`.
    }

    // Punctuators (longest first).
    let matched = null;
    for (const p of PUNCTUATORS) {
      if (source.startsWith(p, i)) {
        // `?.` only when the next char is not a digit
        // (`a?.5:3` is `?` + `.5`, the ternary).
        if (p === '?.' && isDigit(source[i + 2] || '')) continue;
        matched = p;
        break;
      }
    }
    if (matched) {
      advance(matched.length);
      tokens.push({ type: 'punct', value: matched, ...start });
      continue;
    }

    throw new JSParseError(`unexpected character ${JSON.stringify(ch)}`, start.line, start.column);
  }

  tokens.push({ type: 'eof', value: '', line, column });
  return tokens;
}

// Shift every position in a node (and its children) by a line
// offset and, for nodes on the sub-parse's first line, a column
// offset. Used for template interpolations, which are
// sub-parsed from their source text.
function shiftPositions(node, lineOffset, columnOffset) {
  if (!node || typeof node !== 'object') return;
  if (typeof node.line === 'number' && typeof node.column === 'number') {
    if (node.line === 1) node.column += columnOffset;
    node.line += lineOffset;
  }
  for (const key of Object.keys(node)) {
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) shiftPositions(item, lineOffset, columnOffset);
    } else if (value && typeof value === 'object' && value.type) {
      shiftPositions(value, lineOffset, columnOffset);
    }
  }
}

const BINARY_PRECEDENCE = {
  '||': 1, '&&': 2, '??': 2,
  '|': 3, '^': 4, '&': 5,
  '==': 6, '!=': 6, '===': 6, '!==': 6,
  '<': 7, '>': 7, '<=': 7, '>=': 7, 'in': 7, 'instanceof': 7,
  '<<': 8, '>>': 8, '>>>': 8,
  '+': 9, '-': 9,
  '*': 10, '/': 10, '%': 10,
  '**': 11,
};

const ASSIGNMENT_OPERATORS = new Set([
  '=', '+=', '-=', '*=', '/=', '%=', '**=', '<<=', '>>=',
  '>>>=', '&=', '|=', '^=', '&&=', '||=', '??=',
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
      throw new JSParseError(
        `expected ${what || JSON.stringify(value)} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  error(message, token) {
    const at = token || this.peek();
    throw new JSParseError(message, at.line, at.column);
  }

  // Skip a `;` when present; ASI for the common cases is
  // handled by the statement loop (a following token that
  // cannot continue the previous statement simply starts
  // the next one).
  semicolon() {
    if (this.at(';')) this.next();
  }

  parseProgram() {
    const start = this.peek();
    const body = [];
    while (!this.atEof()) body.push(this.parseStatement());
    return { type: 'Program', body, line: start.line, column: start.column };
  }

  parseStatement() {
    const token = this.peek();
    if (token.type === 'punct' && token.value === ';') {
      this.next();
      return { type: 'EmptyStatement', line: token.line, column: token.column };
    }
    if (token.type === 'punct' && token.value === '{') return this.parseBlock();
    if (token.type === 'name') {
      switch (token.value) {
        case 'const':
        case 'let':
        case 'var':
          return this.parseVariableDeclaration();
        case 'function':
          return this.parseFunction(true);
        case 'async': {
          if (this.peek(1).value === 'function') return this.parseFunction(true);
          break;
        }
        case 'class':
          return this.parseClass(true);
        case 'return': {
          const start = this.next();
          let argument = null;
          // `return` followed by a newline has no argument (ASI).
          if (!this.atEof() && !this.at(';') && !this.at('}') && this.peek().line === start.line) {
            argument = this.parseExpression();
          }
          this.semicolon();
          return { type: 'ReturnStatement', argument, line: start.line, column: start.column };
        }
        case 'if': {
          const start = this.next();
          this.expect('(', "'(' after if");
          const test = this.parseExpression();
          this.expect(')', "')' after if test");
          const consequent = this.parseStatement();
          let alternate = null;
          if (this.at('else')) { this.next(); alternate = this.parseStatement(); }
          return { type: 'IfStatement', test, consequent, alternate, line: start.line, column: start.column };
        }
        case 'while': {
          const start = this.next();
          this.expect('(', "'(' after while");
          const test = this.parseExpression();
          this.expect(')', "')' after while test");
          const body = this.parseStatement();
          return { type: 'WhileStatement', test, body, line: start.line, column: start.column };
        }
        case 'do': {
          const start = this.next();
          const body = this.parseStatement();
          this.expect('while', "'while' after do body");
          this.expect('(', "'(' after while");
          const test = this.parseExpression();
          this.expect(')', "')' after do-while test");
          this.semicolon();
          return { type: 'DoWhileStatement', test, body, line: start.line, column: start.column };
        }
        case 'for': {
          return this.parseFor();
        }
        case 'try': {
          const start = this.next();
          const block = this.parseBlock();
          let handler = null;
          let finalizer = null;
          if (this.at('catch')) {
            const catchStart = this.next();
            let param = null;
            if (this.at('(')) {
              this.next();
              if (!this.at(')')) param = this.parsePattern();
              this.expect(')', "')' after catch parameter");
            }
            const body = this.parseBlock();
            handler = { type: 'CatchClause', param, body, line: catchStart.line, column: catchStart.column };
          }
          if (this.at('finally')) {
            this.next();
            finalizer = this.parseBlock();
          }
          if (!handler && !finalizer) this.error('try without catch or finally', start);
          return { type: 'TryStatement', block, handler, finalizer, line: start.line, column: start.column };
        }
        case 'throw': {
          const start = this.next();
          if (this.peek().line !== start.line) this.error('throw must be followed by an expression on the same line', start);
          const argument = this.parseExpression();
          this.semicolon();
          return { type: 'ThrowStatement', argument, line: start.line, column: start.column };
        }
        case 'switch': {
          const start = this.next();
          this.expect('(', "'(' after switch");
          const discriminant = this.parseExpression();
          this.expect(')', "')' after switch discriminant");
          this.expect('{', "'{' after switch");
          const cases = [];
          while (!this.at('}') && !this.atEof()) {
            let test = null;
            let caseStart;
            if (this.at('case')) {
              caseStart = this.next();
              test = this.parseExpression();
              this.expect(':', "':' after case");
            } else if (this.at('default')) {
              caseStart = this.next();
              this.expect(':', "':' after default");
            } else {
              this.error("expected 'case' or 'default' in switch", this.peek());
            }
            const consequent = [];
            while (!this.at('case') && !this.at('default') && !this.at('}') && !this.atEof()) {
              consequent.push(this.parseStatement());
            }
            cases.push({ type: 'SwitchCase', test, consequent, line: caseStart.line, column: caseStart.column });
          }
          this.expect('}', "'}' after switch");
          return { type: 'SwitchStatement', discriminant, cases, line: start.line, column: start.column };
        }
        case 'break': {
          const start = this.next();
          let label = null;
          if (!this.atEof() && !this.at(';') && !this.at('}') && this.peek().line === start.line && this.peek().type === 'name') {
            label = this.next().value;
          }
          this.semicolon();
          return { type: 'BreakStatement', label, line: start.line, column: start.column };
        }
        case 'continue': {
          const start = this.next();
          let label = null;
          if (!this.atEof() && !this.at(';') && !this.at('}') && this.peek().line === start.line && this.peek().type === 'name') {
            label = this.next().value;
          }
          this.semicolon();
          return { type: 'ContinueStatement', label, line: start.line, column: start.column };
        }
        case 'import': {
          const start = this.next();
          // Dynamic import `import(...)` is an expression, not a
          // declaration: skip it structurally as before.
          if (this.at('(')) return this.skipImportStatement(start);
          // Parse the declaration; anything outside the
          // supported forms falls back to the old structural
          // skip, so a record with an exotic import still
          // scans instead of failing the parse.
          const saved = this.pos;
          try {
            return this.parseImportDeclaration(start);
          } catch (error) {
            if (!(error instanceof JSParseError)) throw error;
            this.pos = saved;
            return this.skipImportStatement(start);
          }
        }
        case 'export': {
          const start = this.next();
          if (this.at('*')) {
            this.next();
            if (this.at('as')) { this.next(); this.next(); }
            if (this.at('from')) { this.next(); this.parseExpression(); }
            this.semicolon();
            return { type: 'ExportAllDeclaration', line: start.line, column: start.column };
          }
          if (this.at('{')) {
            // export { a, b } [from '...'];
            let depth = 0;
            while (!this.atEof()) {
              const t = this.peek();
              if (t.value === '{') depth += 1;
              else if (t.value === '}') { depth -= 1; this.next(); if (depth === 0) break; continue; }
              this.next();
            }
            if (this.at('from')) { this.next(); this.parseExpression(); }
            this.semicolon();
            return { type: 'ExportNamedDeclaration', declaration: null, line: start.line, column: start.column };
          }
          if (this.at('default')) {
            this.next();
            if (this.at('function') || (this.at('async') && this.peek(1).value === 'function')) {
              const declaration = this.parseFunction(false);
              return { type: 'ExportDefaultDeclaration', declaration, line: start.line, column: start.column };
            }
            if (this.at('class')) {
              const declaration = this.parseClass(false);
              return { type: 'ExportDefaultDeclaration', declaration, line: start.line, column: start.column };
            }
            const declaration = this.parseExpression();
            this.semicolon();
            return { type: 'ExportDefaultDeclaration', declaration, line: start.line, column: start.column };
          }
          const declaration = this.parseStatement();
          return { type: 'ExportNamedDeclaration', declaration, line: start.line, column: start.column };
        }
        case 'with': {
          const start = this.next();
          this.expect('(', "'(' after with");
          const object = this.parseExpression();
          this.expect(')', "')' after with object");
          const body = this.parseStatement();
          return { type: 'WithStatement', object, body, line: start.line, column: start.column };
        }
        default:
          break;
      }
    }
    // Label: `name: statement`.
    if (token.type === 'name' && this.peek(1).value === ':') {
      this.next();
      this.next();
      return this.parseStatement();
    }
    const expr = this.parseExpression();
    this.semicolon();
    return { type: 'ExpressionStatement', expression: expr, line: expr.line, column: expr.column };
  }

  // Skip an import statement to `;` at depth 0 without
  // tracking bindings — the pre-round-106 behavior, kept as
  // the fallback for dynamic import and for declaration
  // forms outside the supported set.
  skipImportStatement(start) {
    let depth = 0;
    while (!this.atEof()) {
      const t = this.peek();
      if (t.value === '{' || t.value === '(' || t.value === '[') depth += 1;
      else if (t.value === '}' || t.value === ')' || t.value === ']') depth -= 1;
      else if (t.value === ';' && depth === 0) { this.next(); break; }
      else if (t.type === 'name' && depth === 0 && (t.value === 'import' || t.value === 'export')) break;
      this.next();
      if (depth < 0) break;
    }
    return { type: 'ImportDeclaration', specifiers: [], source: null, line: start.line, column: start.column };
  }

  // An imported name: any `name` token (keywords included —
  // a module may export `get`, `default`, or `from`).
  parseImportName() {
    const token = this.peek();
    if (token.type !== 'name') this.error('expected an imported name in import', token);
    this.next();
    return { type: 'Identifier', name: token.value, line: token.line, column: token.column };
  }

  // A local binding name: a `name` token that is NOT a
  // subset keyword (`get`, `from`, `as`, ... cannot bind —
  // the declaration falls back to the structural skip).
  parseImportLocalName() {
    const token = this.peek();
    if (token.type !== 'name' || KEYWORDS.has(token.value)) {
      this.error('expected a binding name in import', token);
    }
    this.next();
    return { type: 'Identifier', name: token.value, line: token.line, column: token.column };
  }

  // The `{ a, b as c }` specifier list after the opening
  // `{` was consumed.
  parseImportNamedSpecifiers() {
    const specifiers = [];
    while (!this.at('}') && !this.atEof()) {
      const imported = this.parseImportName();
      let local = imported;
      if (this.at('as')) {
        this.next();
        local = this.parseImportLocalName();
      }
      specifiers.push({ type: 'ImportSpecifier', imported, local, line: imported.line, column: imported.column });
      if (!this.match(',')) break;
    }
    this.expect('}', "'}' after import specifiers");
    return specifiers;
  }

  // Parse an import declaration after the `import` keyword
  // was consumed. Supported forms (all with a string-literal
  // module specifier):
  //   import 'mod';
  //   import Default from 'mod';
  //   import * as ns from 'mod';
  //   import { a, b as c } from 'mod';
  //   import Default, { a } from 'mod';
  //   import Default, * as ns from 'mod';
  // Anything else throws JSParseError and the caller falls
  // back to the structural skip.
  parseImportDeclaration(start) {
    let specifiers = [];
    if (this.peek().type === 'string') {
      const source = this.next();
      this.semicolon();
      return {
        type: 'ImportDeclaration', specifiers, source: { type: 'Literal', value: source.value, line: source.line, column: source.column },
        line: start.line, column: start.column,
      };
    }
    if (this.at('*')) {
      this.next();
      this.expect('as', "'as' after * in import");
      const local = this.parseImportLocalName();
      specifiers.push({ type: 'ImportNamespaceSpecifier', local, line: local.line, column: local.column });
    } else if (this.at('{')) {
      this.next();
      specifiers = this.parseImportNamedSpecifiers();
    } else if (this.peek().type === 'name' && !KEYWORDS.has(this.peek().value)) {
      const local = this.next();
      specifiers.push({
        type: 'ImportDefaultSpecifier',
        local: { type: 'Identifier', name: local.value, line: local.line, column: local.column },
        line: local.line, column: local.column,
      });
      if (this.at(',')) {
        this.next();
        if (this.at('*')) {
          this.next();
          this.expect('as', "'as' after * in import");
          const ns = this.parseImportLocalName();
          specifiers.push({ type: 'ImportNamespaceSpecifier', local: ns, line: ns.line, column: ns.column });
        } else if (this.at('{')) {
          this.next();
          specifiers = specifiers.concat(this.parseImportNamedSpecifiers());
        } else {
          this.error("expected '{' or '*' after ',' in import", this.peek());
        }
      }
    } else {
      this.error('unsupported import form', this.peek());
    }
    this.expect('from', "'from' after import specifiers");
    if (this.peek().type !== 'string') this.error('expected a string module specifier after from', this.peek());
    const source = this.next();
    this.semicolon();
    return {
      type: 'ImportDeclaration', specifiers,
      source: { type: 'Literal', value: source.value, line: source.line, column: source.column },
      line: start.line, column: start.column,
    };
  }

  parseBlock() {
    const start = this.expect('{', "'{'");
    const body = [];
    while (!this.at('}') && !this.atEof()) body.push(this.parseStatement());
    this.expect('}', "'}'");
    return { type: 'BlockStatement', body, line: start.line, column: start.column };
  }

  parseFor() {
    const start = this.next(); // 'for'
    let awaited = false;
    if (this.at('await')) { this.next(); awaited = true; }
    this.expect('(', "'(' after for");
    let init = null;
    if (!this.at(';')) {
      if (this.at('const') || this.at('let') || this.at('var')) {
        init = this.parseVariableDeclaration(true);
      } else {
        init = this.parseExpression();
      }
    }
    if (this.at('of') || this.at('in')) {
      const kind = this.next().value;
      const right = this.parseExpression();
      this.expect(')', "')' after for head");
      const body = this.parseStatement();
      return {
        type: kind === 'of' ? 'ForOfStatement' : 'ForInStatement',
        left: init, right, body, await: awaited,
        line: start.line, column: start.column,
      };
    }
    this.expect(';', "';' after for init");
    let test = null;
    if (!this.at(';')) test = this.parseExpression();
    this.expect(';', "';' after for test");
    let update = null;
    if (!this.at(')')) update = this.parseExpression();
    this.expect(')', "')' after for update");
    const body = this.parseStatement();
    return { type: 'ForStatement', init, test, update, body, line: start.line, column: start.column };
  }

  parseVariableDeclaration(noSemicolon = false) {
    const start = this.next(); // const / let / var
    const kind = start.value;
    const declarations = [];
    for (;;) {
      const id = this.parsePattern();
      let init = null;
      if (this.at('=')) { this.next(); init = this.parseAssignment(); }
      declarations.push({ type: 'VariableDeclarator', id, init, line: id.line, column: id.column });
      if (!this.match(',')) break;
    }
    if (!noSemicolon) this.semicolon();
    return { type: 'VariableDeclaration', kind, declarations, line: start.line, column: start.column };
  }

  // Parse a binding pattern: identifier, object/array
  // destructuring, rest element, or a default
  // (`pattern = expression`).
  parsePattern() {
    const token = this.peek();
    if (token.type === 'punct' && token.value === '{') {
      const start = this.next();
      const properties = [];
      while (!this.at('}') && !this.atEof()) {
        if (this.at('...')) {
          const restStart = this.next();
          const argument = this.parsePattern();
          properties.push({ type: 'RestElement', argument, line: restStart.line, column: restStart.column });
        } else {
          let key;
          let computed = false;
          if (this.at('[')) {
            this.next();
            key = this.parseExpression();
            this.expect(']', "']' after computed key");
            computed = true;
          } else if (this.peek().type === 'string' || this.peek().type === 'number') {
            const lit = this.next();
            key = { type: 'Literal', value: lit.value, line: lit.line, column: lit.column };
          } else if (this.peek().type === 'name') {
            const name = this.next();
            key = { type: 'Identifier', name: name.value, line: name.line, column: name.column };
          } else {
            this.error('expected a property name in object pattern', this.peek());
          }
          let value;
          if (this.at(':')) {
            this.next();
            value = this.parsePattern();
          } else {
            value = key;
          }
          if (this.at('=')) {
            const eq = this.next();
            const right = this.parseAssignment();
            value = { type: 'AssignmentPattern', left: value, right, line: eq.line, column: eq.column };
          }
          properties.push({ type: 'Property', key, value, shorthand: value === key, computed, line: key.line, column: key.column });
        }
        if (!this.match(',')) break;
      }
      this.expect('}', "'}' after object pattern");
      return { type: 'ObjectPattern', properties, line: start.line, column: start.column };
    }
    if (token.type === 'punct' && token.value === '[') {
      const start = this.next();
      const elements = [];
      while (!this.at(']') && !this.atEof()) {
        if (this.at(',')) { this.next(); elements.push(null); continue; }
        if (this.at('...')) {
          const restStart = this.next();
          const argument = this.parsePattern();
          elements.push({ type: 'RestElement', argument, line: restStart.line, column: restStart.column });
        } else {
          elements.push(this.parsePattern());
        }
        if (!this.match(',')) break;
      }
      this.expect(']', "']' after array pattern");
      return { type: 'ArrayPattern', elements, line: start.line, column: start.column };
    }
    if (token.type === 'name' && !KEYWORDS.has(token.value)) {
      const name = this.next();
      return { type: 'Identifier', name: name.value, line: name.line, column: name.column };
    }
    this.error('expected a binding pattern', token);
    return null;
  }

  collectPatternNames(pattern, out = []) {
    if (!pattern) return out;
    switch (pattern.type) {
      case 'Identifier':
        out.push(pattern.name);
        break;
      case 'ObjectPattern':
        for (const prop of pattern.properties) {
          if (prop.type === 'RestElement') this.collectPatternNames(prop.argument, out);
          else this.collectPatternNames(prop.value, out);
        }
        break;
      case 'ArrayPattern':
        for (const el of pattern.elements) {
          if (!el) continue;
          if (el.type === 'RestElement') this.collectPatternNames(el.argument, out);
          else this.collectPatternNames(el, out);
        }
        break;
      case 'AssignmentPattern':
        this.collectPatternNames(pattern.left, out);
        break;
      default:
        break;
    }
    return out;
  }

  parseFunction(isDeclaration) {
    const start = this.peek();
    let async = false;
    if (this.at('async')) { this.next(); async = true; }
    this.expect('function', "'function'");
    let generator = false;
    if (this.at('*')) { this.next(); generator = true; }
    let id = null;
    if (this.peek().type === 'name' && !KEYWORDS.has(this.peek().value)) {
      const name = this.next();
      id = { type: 'Identifier', name: name.value, line: name.line, column: name.column };
    }
    if (isDeclaration && !id) this.error('function declaration requires a name', this.peek());
    const params = this.parseParams();
    const body = this.parseBlock();
    return {
      type: isDeclaration ? 'FunctionDeclaration' : 'FunctionExpression',
      id, params, body, async, generator,
      line: start.line, column: start.column,
    };
  }

  parseParams() {
    this.expect('(', "'(' before parameters");
    const params = [];
    while (!this.at(')') && !this.atEof()) {
      if (this.at('...')) {
        const restStart = this.next();
        const argument = this.parsePattern();
        params.push({ type: 'RestElement', argument, line: restStart.line, column: restStart.column });
      } else {
        let param = this.parsePattern();
        if (this.at('=')) {
          const eq = this.next();
          const right = this.parseAssignment();
          param = { type: 'AssignmentPattern', left: param, right, line: eq.line, column: eq.column };
        }
        params.push(param);
      }
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after parameters");
    return params;
  }

  parseClass(isDeclaration) {
    const start = this.next(); // 'class'
    let id = null;
    if (this.peek().type === 'name' && !KEYWORDS.has(this.peek().value)) {
      const name = this.next();
      id = { type: 'Identifier', name: name.value, line: name.line, column: name.column };
    }
    if (isDeclaration && !id) this.error('class declaration requires a name', this.peek());
    let superClass = null;
    if (this.at('extends')) {
      this.next();
      superClass = this.parsePostfix();
    }
    this.expect('{', "'{' after class header");
    const body = [];
    while (!this.at('}') && !this.atEof()) {
      if (this.at(';')) { this.next(); continue; }
      const memberStart = this.peek();
      let isStatic = false;
      let kind = 'method';
      let async = false;
      let generator = false;
      // Modifiers: static / async / get / set / * (in order).
      for (;;) {
        if (this.at('static') && !this.atNextIsParen()) { this.next(); isStatic = true; continue; }
        if (this.at('async') && !this.atNextIsParen()) { this.next(); async = true; continue; }
        if ((this.at('get') || this.at('set')) && !this.atNextIsParen()) {
          kind = this.next().value;
          continue;
        }
        if (this.at('*')) { this.next(); generator = true; continue; }
        break;
      }
      let key;
      if (this.at('[')) {
        this.next();
        key = this.parseExpression();
        this.expect(']', "']' after computed class key");
      } else if (this.peek().type === 'string' || this.peek().type === 'number') {
        const lit = this.next();
        key = { type: 'Literal', value: lit.value, line: lit.line, column: lit.column };
      } else if (this.peek().type === 'name') {
        const name = this.next();
        key = { type: 'Identifier', name: name.value, line: name.line, column: name.column };
      } else {
        this.error('expected a class member name', this.peek());
      }
      if (this.at('(')) {
        const params = this.parseParams();
        const value = this.parseBlock();
        body.push({
          type: 'MethodDefinition', key, kind, static: isStatic, async, generator,
          value: { type: 'FunctionExpression', id: null, params, body: value, async, generator, line: memberStart.line, column: memberStart.column },
          line: memberStart.line, column: memberStart.column,
        });
      } else if (this.at('=')) {
        this.next();
        const init = this.parseAssignment();
        this.semicolon();
        body.push({ type: 'ClassField', key, init, static: isStatic, line: memberStart.line, column: memberStart.column });
      } else {
        this.semicolon();
        body.push({ type: 'ClassField', key, init: null, static: isStatic, line: memberStart.line, column: memberStart.column });
      }
    }
    this.expect('}', "'}' after class body");
    return {
      type: isDeclaration ? 'ClassDeclaration' : 'ClassExpression',
      id, superClass, body, line: start.line, column: start.column,
    };
  }

  // In a class body, `static (` means a static block, and
  // `async (` / `get (` / `set (` mean a method literally
  // named static/async/get/set. True only when the modifier
  // is followed by `(`.
  atNextIsParen() {
    return this.peek(1).value === '(';
  }

  parseExpression() {
    return this.parseAssignment();
  }

  // Try to parse an arrow function at the current position.
  // Returns the node, or null (position restored) when this
  // is not an arrow. Handles `x =>`, `(a, b) =>`,
  // `async x =>`, `async (a) =>`.
  tryParseArrow() {
    const saved = this.pos;
    const start = this.peek();
    let async = false;
    if (this.at('async')) {
      const next = this.peek(1);
      if (!((next.type === 'name' && !KEYWORDS.has(next.value)) || next.value === '(')) {
        return null;
      }
      this.next();
      async = true;
    }
    let params = null;
    if (this.peek().type === 'name' && !KEYWORDS.has(this.peek().value) && this.peek(1).value === '=>') {
      const name = this.next();
      params = [{ type: 'Identifier', name: name.value, line: name.line, column: name.column }];
    } else if (this.at('(')) {
      try {
        params = this.parseParams();
      } catch {
        this.pos = saved;
        return null;
      }
    } else {
      this.pos = saved;
      return null;
    }
    if (!this.at('=>')) {
      this.pos = saved;
      return null;
    }
    this.next();
    let body;
    let expression;
    if (this.at('{')) {
      body = this.parseBlock();
      expression = false;
    } else {
      body = this.parseAssignment();
      expression = true;
    }
    return {
      type: 'ArrowFunctionExpression', params, body, expression, async,
      line: start.line, column: start.column,
    };
  }

  parseAssignment() {
    const arrow = this.tryParseArrow();
    if (arrow) return arrow;
    const left = this.parseConditional();
    if (this.peek().type === 'punct' && ASSIGNMENT_OPERATORS.has(this.peek().value)) {
      const op = this.next();
      const right = this.parseAssignment();
      return {
        type: 'AssignmentExpression', operator: op.value, left, right,
        line: left.line, column: left.column,
      };
    }
    return left;
  }

  parseConditional() {
    const test = this.parseBinary(0);
    if (!this.at('?')) return test;
    const q = this.next();
    const consequent = this.parseAssignment();
    this.expect(':', "':' in conditional");
    const alternate = this.parseAssignment();
    return {
      type: 'ConditionalExpression', test, consequent, alternate,
      line: test.line, column: test.column,
    };
  }

  parseBinary(minPrecedence) {
    let left = this.parseUnary();
    for (;;) {
      const token = this.peek();
      let op = null;
      if (token.type === 'punct') op = token.value;
      else if (token.type === 'name' && (token.value === 'in' || token.value === 'instanceof')) op = token.value;
      if (!op || !(op in BINARY_PRECEDENCE)) break;
      const precedence = BINARY_PRECEDENCE[op];
      if (precedence < minPrecedence) break;
      this.next();
      // `**` is right-associative; everything else left.
      const right = this.parseBinary(op === '**' ? precedence : precedence + 1);
      const type = (op === '&&' || op === '||' || op === '??') ? 'LogicalExpression' : 'BinaryExpression';
      left = { type, operator: op, left, right, line: left.line, column: left.column };
    }
    return left;
  }

  parseUnary() {
    const token = this.peek();
    if (token.type === 'punct' && (token.value === '!' || token.value === '~'
      || token.value === '+' || token.value === '-' || token.value === '++' || token.value === '--')) {
      const op = this.next();
      const argument = this.parseUnary();
      if (op.value === '++' || op.value === '--') {
        return { type: 'UpdateExpression', operator: op.value, argument, prefix: true, line: op.line, column: op.column };
      }
      return { type: 'UnaryExpression', operator: op.value, argument, line: op.line, column: op.column };
    }
    if (token.type === 'name' && (token.value === 'typeof' || token.value === 'void' || token.value === 'delete')) {
      const op = this.next();
      const argument = this.parseUnary();
      return { type: 'UnaryExpression', operator: op.value, argument, line: op.line, column: op.column };
    }
    if (token.type === 'name' && token.value === 'await') {
      const op = this.next();
      const argument = this.parseUnary();
      return { type: 'AwaitExpression', argument, line: op.line, column: op.column };
    }
    if (token.type === 'name' && token.value === 'yield') {
      const op = this.next();
      let argument = null;
      if (!this.atEof() && !this.at(';') && !this.at('}') && !this.at(')') && !this.at(']') && !this.at(',')) {
        let delegate = false;
        if (this.at('*')) { this.next(); delegate = true; }
        argument = this.parseAssignment();
        return { type: 'YieldExpression', argument, delegate, line: op.line, column: op.column };
      }
      return { type: 'YieldExpression', argument, delegate: false, line: op.line, column: op.column };
    }
    return this.parsePostfix();
  }

  parsePostfix() {
    let expr = this.parsePrimary();
    for (;;) {
      const token = this.peek();
      if (token.type === 'punct' && (token.value === '++' || token.value === '--')) {
        // Postfix update only when on the same line (ASI).
        if (token.line !== expr.line && expr.type !== 'MemberExpression') break;
        const op = this.next();
        expr = { type: 'UpdateExpression', operator: op.value, argument: expr, prefix: false, line: op.line, column: op.column };
        continue;
      }
      if (token.type === 'punct' && token.value === '.') {
        this.next();
        const prop = this.peek();
        if (prop.type !== 'name') this.error('expected a property name after .', prop);
        this.next();
        expr = {
          type: 'MemberExpression', object: expr,
          property: { type: 'Identifier', name: prop.value, line: prop.line, column: prop.column },
          computed: false, optional: false,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'punct' && token.value === '?.') {
        this.next();
        if (this.at('(')) {
          const args = this.parseArguments();
          expr = {
            type: 'CallExpression', callee: expr, arguments: args, optional: true,
            line: expr.line, column: expr.column,
          };
          continue;
        }
        if (this.at('[')) {
          this.next();
          const property = this.parseExpression();
          this.expect(']', "']' after computed member");
          expr = {
            type: 'MemberExpression', object: expr, property,
            computed: true, optional: true,
            line: expr.line, column: expr.column,
          };
          continue;
        }
        const prop = this.peek();
        if (prop.type !== 'name') this.error('expected a property name after ?.', prop);
        this.next();
        expr = {
          type: 'MemberExpression', object: expr,
          property: { type: 'Identifier', name: prop.value, line: prop.line, column: prop.column },
          computed: false, optional: true,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'punct' && token.value === '[') {
        this.next();
        const property = this.parseExpression();
        this.expect(']', "']' after computed member");
        expr = {
          type: 'MemberExpression', object: expr, property,
          computed: true, optional: false,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'punct' && token.value === '(') {
        const args = this.parseArguments();
        expr = {
          type: 'CallExpression', callee: expr, arguments: args, optional: false,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'template') {
        // Tagged template: treat as a call with the template
        // as its single argument (taint flows through it).
        const tpl = this.next();
        const template = this.parseTemplateLiteral(tpl);
        expr = {
          type: 'CallExpression', callee: expr, arguments: [template], optional: false, taggedTemplate: true,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      break;
    }
    return expr;
  }

  parseArguments() {
    this.expect('(', "'(' before arguments");
    const args = [];
    while (!this.at(')') && !this.atEof()) {
      if (this.at('...')) {
        const start = this.next();
        const argument = this.parseAssignment();
        args.push({ type: 'SpreadElement', argument, line: start.line, column: start.column });
      } else {
        args.push(this.parseAssignment());
      }
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after arguments");
    return args;
  }

  parseTemplateLiteral(token) {
    const expressions = [];
    const quasis = [];
    for (const part of token.value) {
      if (part.type === 'raw') {
        quasis.push({ type: 'TemplateElement', value: part.value, line: token.line, column: token.column });
      } else {
        const subTokens = tokenize(part.source);
        const subParser = new Parser(subTokens);
        const expr = subParser.parseExpression();
        if (!subParser.atEof()) {
          const bad = subParser.peek();
          throw new JSParseError(
            `unexpected token ${JSON.stringify(bad.value) || bad.type} in template interpolation`,
            bad.line, bad.column,
          );
        }
        // Shift the sub-parse positions to the interpolation.
        // The interpolation starts after `${` (column + 2 on
        // its first line); later lines keep their column.
        shiftPositions(expr, part.line - 1, part.column + 1);
        expressions.push(expr);
      }
    }
    return { type: 'TemplateLiteral', quasis, expressions, line: token.line, column: token.column };
  }

  parsePrimary() {
    const token = this.peek();
    if (token.type === 'number') {
      this.next();
      return { type: 'Literal', value: Number(token.value), raw: token.value, line: token.line, column: token.column };
    }
    if (token.type === 'string') {
      this.next();
      return { type: 'Literal', value: token.value, raw: token.raw, line: token.line, column: token.column };
    }
    if (token.type === 'regex') {
      this.next();
      return { type: 'Literal', value: token.value, regex: true, line: token.line, column: token.column };
    }
    if (token.type === 'template') {
      this.next();
      return this.parseTemplateLiteral(token);
    }
    if (token.type === 'punct' && token.value === '(') {
      this.next();
      if (this.at(')')) {
        this.next();
        return { type: 'SequenceExpression', expressions: [], line: token.line, column: token.column };
      }
      const expr = this.parseExpression();
      if (this.at(',')) {
        const expressions = [expr];
        while (this.match(',')) {
          if (this.at(')')) break;
          expressions.push(this.parseAssignment());
        }
        this.expect(')', "')' after sequence");
        return { type: 'SequenceExpression', expressions, line: token.line, column: token.column };
      }
      this.expect(')', "')' after expression");
      return expr;
    }
    if (token.type === 'punct' && token.value === '[') {
      const start = this.next();
      const elements = [];
      while (!this.at(']') && !this.atEof()) {
        if (this.at(',')) { this.next(); elements.push(null); continue; }
        if (this.at('...')) {
          const spreadStart = this.next();
          const argument = this.parseAssignment();
          elements.push({ type: 'SpreadElement', argument, line: spreadStart.line, column: spreadStart.column });
        } else {
          elements.push(this.parseAssignment());
        }
        if (!this.match(',')) break;
      }
      this.expect(']', "']' after array literal");
      return { type: 'ArrayExpression', elements, line: start.line, column: start.column };
    }
    if (token.type === 'punct' && token.value === '{') {
      const start = this.next();
      const properties = [];
      while (!this.at('}') && !this.atEof()) {
        if (this.at('...')) {
          const spreadStart = this.next();
          const argument = this.parseAssignment();
          properties.push({ type: 'SpreadElement', argument, line: spreadStart.line, column: spreadStart.column });
        } else {
          let key;
          let computed = false;
          if (this.at('[')) {
            this.next();
            key = this.parseExpression();
            this.expect(']', "']' after computed key");
            computed = true;
          } else if (this.peek().type === 'string' || this.peek().type === 'number') {
            const lit = this.next();
            key = { type: 'Literal', value: lit.value, line: lit.line, column: lit.column };
          } else if (this.peek().type === 'name') {
            const name = this.next();
            key = { type: 'Identifier', name: name.value, line: name.line, column: name.column };
          } else {
            this.error('expected a property name in object literal', this.peek());
          }
          let value;
          if (this.at(':')) {
            this.next();
            value = this.parseAssignment();
          } else if (this.at('(')) {
            // Shorthand method: { load(x) { ... } }.
            const params = this.parseParams();
            const body = this.parseBlock();
            value = {
              type: 'FunctionExpression', id: null, params, body,
              async: false, generator: false,
              line: key.line, column: key.column,
            };
          } else {
            value = key;
          }
          properties.push({
            type: 'Property', key, value,
            shorthand: value === key, computed,
            line: key.line, column: key.column,
          });
        }
        if (!this.match(',')) break;
      }
      this.expect('}', "'}' after object literal");
      return { type: 'ObjectExpression', properties, line: start.line, column: start.column };
    }
    if (token.type === 'name') {
      switch (token.value) {
        case 'true':
          this.next();
          return { type: 'Literal', value: true, line: token.line, column: token.column };
        case 'false':
          this.next();
          return { type: 'Literal', value: false, line: token.line, column: token.column };
        case 'null':
          this.next();
          return { type: 'Literal', value: null, line: token.line, column: token.column };
        case 'undefined':
        case 'this':
        case 'super':
          this.next();
          return { type: 'Identifier', name: token.value, line: token.line, column: token.column };
        case 'function':
          return this.parseFunction(false);
        case 'async': {
          if (this.peek(1).value === 'function') return this.parseFunction(false);
          const name = this.next();
          return { type: 'Identifier', name: name.value, line: name.line, column: name.column };
        }
        case 'class':
          return this.parseClass(false);
        case 'new': {
          const start = this.next();
          const callee = this.parsePostfix();
          let args = [];
          if (this.at('(')) args = this.parseArguments();
          return { type: 'NewExpression', callee, arguments: args, line: start.line, column: start.column };
        }
        default:
          if (KEYWORDS.has(token.value)) this.error(`unexpected keyword ${token.value}`, token);
          this.next();
          return { type: 'Identifier', name: token.value, line: token.line, column: token.column };
      }
    }
    this.error(`unexpected token ${JSON.stringify(token.value) || token.type}`, token);
    return null;
  }
}

// Parse JavaScript source into a Program AST. Throws
// JSParseError (with line/column) on anything outside the
// subset grammar.
function parseJavaScript(source) {
  if (typeof source !== 'string') {
    throw new JSParseError('source must be a string', 1, 1);
  }
  const tokens = tokenize(source);
  const parser = new Parser(tokens);
  const program = parser.parseProgram();
  return program;
}

module.exports = parseJavaScript;
module.exports.parseJavaScript = parseJavaScript;
module.exports.tokenize = tokenize;
module.exports.JSParseError = JSParseError;
module.exports.shiftPositions = shiftPositions;
