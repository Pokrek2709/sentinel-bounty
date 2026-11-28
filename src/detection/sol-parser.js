// Hand-written Solidity subset parser (Phase 5, round 108):
// tokenizer + recursive-descent parser producing an AST with
// line/column positions. Stdlib-only, synchronous, deterministic,
// and it NEVER executes the code it parses.
//
// Why hand-written: the second language needs structure
// (contracts, state variables, functions, external calls,
// state writes in order) that a regex cannot see, and the
// skill installs and verifies offline, so an npm parser
// (@solidity-parser/parser was evaluated — MIT, the
// community-standard Solidity grammar — and NOT adopted
// this round: it would need a vendoring story that does
// not exist yet, and the prototype's first Solidity class
// does not need a full grammar) is out of scope.
// @solidity-parser/parser remains the documented upgrade
// path in docs/solidity-parser-v1.md if the detector set
// grows beyond what the subset grammar covers. That is a
// future decision (round 119's Acorn-vendoring decision
// covers the same question for JavaScript), not a blocker
// for this round.
//
// The grammar is a SUBSET (see docs/solidity-parser-v1.md
// for the full list): programs (pragma / import / using /
// contract / library / interface / free functions / struct /
// enum / event / error / user-defined value types),
// contracts with inheritance lists, state variables,
// functions (including constructor / receive / fallback),
// modifiers, and statements (blocks, variable declarations
// including tuple declarations, assignments, if / for /
// while / do-while, return / break / continue, emit,
// unchecked blocks, delete). Anything outside the subset
// fails with a SolParseError carrying line and column —
// the caller (the detector) counts that record in
// `skipped`, it NEVER falls back to scanning text with a
// regex.
//
// Safety properties:
// - Comments (including NatSpec /// and /** */) are stripped
//   by the tokenizer and string contents are single tokens,
//   so sink text inside a comment or a string never becomes
//   a call node.
// - Positions are 1-based line/column, taken from the first
//   token of each node.
// - Inline assembly and try/catch are NOT in the subset:
//   a contract using them fails the parse loudly instead of
//   being scanned approximately (a partial or wrong answer
//   presented as a parse is worse than no answer).
'use strict';

class SolParseError extends Error {
  constructor(message, line, column) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = 'SolParseError';
    this.line = line;
    this.column = column;
  }
}

// Reserved words that can never be a binding name. Type
// keywords (uint256, address, ...) are NOT in this set:
// they are ordinary name tokens the type parser consumes.
const RESERVED = new Set([
  'abstract', 'after', 'alias', 'apply', 'auto', 'case', 'catch',
  'contract', 'copyof', 'default', 'define', 'do', 'else', 'emit',
  'enum', 'error', 'event', 'external', 'false', 'final', 'for',
  'function', 'if', 'implements', 'import', 'in', 'inline',
  'interface', 'internal', 'is', 'let', 'library', 'macro',
  'mapping', 'match', 'memory', 'modifier', 'mutable', 'new',
  'null', 'of', 'override', 'payable', 'pragma', 'private',
  'public', 'pure', 'reference', 'relocatable', 'return',
  'returns', 'sealed', 'sizeof', 'static', 'storage', 'struct',
  'supports', 'switch', 'true', 'try', 'type', 'typedef',
  'typeof', 'unchecked', 'using', 'var', 'view', 'virtual',
  'while', 'assembly', 'break', 'continue', 'constructor',
  'delete', 'fallback', 'receive', 'revert', 'throw', 'calldata',
  'constant', 'immutable', 'transient', 'override',
]);

// Storage-location / visibility / mutability keywords that
// may appear between a type and a variable name (or after a
// function parameter list). They are name tokens; the
// parsers that need them check by value.
const TYPE_QUALIFIERS = new Set([
  'memory', 'calldata', 'storage', 'public', 'private',
  'internal', 'external', 'constant', 'immutable', 'transient',
  'payable', 'pure', 'view', 'virtual',
]);

// Number-literal units (`1 ether`, `30 days`). Consumed by
// the expression parser after a numeric literal.
const NUMBER_UNITS = new Set([
  'wei', 'gwei', 'ether', 'seconds', 'minutes', 'hours', 'days',
  'weeks', 'years',
]);

// Punctuation, longest first — the tokenizer tries them in
// this order at each position.
const PUNCTUATORS = [
  '...', '<<=', '>>=', '**=', '==', '!=', '<=', '>=', '&&',
  '||', '=>', '<<', '>>', '**', '+=', '-=', '*=', '/=', '%=',
  '&=', '|=', '^=', '++', '--', '&', '|', '^', '~', '!', '+',
  '-', '*', '/', '%', '<', '>', '=', '?', ':', ';', ',', '.',
  '(', ')', '[', ']', '{', '}',
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

// Tokenize source into { type, value, line, column } tokens.
// type: 'name' | 'number' | 'string' | 'punct' | 'eof'.
// A string token's value is the decoded contents.
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

  while (i < source.length) {
    const ch = source[i];

    // Whitespace.
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === '\f' || ch === '\v') {
      advance();
      continue;
    }

    // Comments (line, block, and NatSpec /// and /** */ —
    // all stripped; newlines inside still count).
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
      if (!closed) throw new SolParseError('unterminated block comment', start.line, start.column);
      continue;
    }

    const start = position();

    // Identifiers, including the `unicode` / `hex` string
    // prefixes (a prefix immediately followed by a quote
    // opens a string literal instead).
    if (isIdentStart(ch)) {
      let j = i;
      while (j < source.length && isIdentPart(source[j])) j += 1;
      const value = source.slice(i, j);
      if ((value === 'unicode' || value === 'hex')
        && (source[j] === '"' || source[j] === "'")) {
        const quote = source[j];
        let k = j + 1;
        let closed = false;
        while (k < source.length) {
          if (source[k] === '\\') { k += 2; continue; }
          if (source[k] === quote) { closed = true; k += 1; break; }
          if (source[k] === '\n') break;
          k += 1;
        }
        if (!closed) throw new SolParseError('unterminated string literal', start.line, start.column);
        const raw = source.slice(j, k);
        advance(k - i);
        tokens.push({ type: 'string', value: raw.slice(1, -1), raw, ...start });
        continue;
      }
      advance(j - i);
      tokens.push({ type: 'name', value, ...start });
      continue;
    }

    // Numbers: hex, decimal with `_` separators, fractions,
    // exponents (`1e18`). A following unit identifier is a
    // separate token for the expression parser to consume.
    if (isDigit(ch) || (ch === '.' && isDigit(source[i + 1] || ''))) {
      let j = i;
      if (source[j] === '0' && (source[j + 1] === 'x' || source[j + 1] === 'X')) {
        j += 2;
        while (j < source.length && (isHexDigit(source[j]) || source[j] === '_')) j += 1;
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
      if (!closed) throw new SolParseError('unterminated string literal', start.line, start.column);
      const raw = source.slice(i, j);
      advance(j - i);
      tokens.push({ type: 'string', value: raw.slice(1, -1), raw, ...start });
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

    throw new SolParseError(`unexpected character ${JSON.stringify(ch)}`, start.line, start.column);
  }

  tokens.push({ type: 'eof', value: '', line, column });
  return tokens;
}

const BINARY_PRECEDENCE = {
  '||': 1, '&&': 2,
  '|': 3, '^': 4, '&': 5,
  '==': 6, '!=': 6,
  '<': 7, '>': 7, '<=': 7, '>=': 7,
  '<<': 8, '>>': 8,
  '+': 9, '-': 9,
  '*': 10, '/': 10, '%': 10,
  '**': 11,
};

const ASSIGNMENT_OPERATORS = new Set([
  '=', '+=', '-=', '*=', '/=', '%=', '**=', '<<=', '>>=',
  '&=', '|=', '^=',
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
      throw new SolParseError(
        `expected ${what || JSON.stringify(value)} but found ${JSON.stringify(token.value) || token.type}`,
        token.line, token.column,
      );
    }
    return this.next();
  }

  error(message, token) {
    const at = token || this.peek();
    throw new SolParseError(message, at.line, at.column);
  }

  // Skip a `;` when present.
  semicolon() {
    if (this.at(';')) this.next();
  }

  // Skip tokens to the next `;` at depth 0 (used for
  // pragma / import / using / event / error / type
  // declarations, which carry no analyzable code).
  skipToSemicolon() {
    let depth = 0;
    while (!this.atEof()) {
      const token = this.peek();
      if (token.value === '{' || token.value === '(' || token.value === '[') depth += 1;
      else if (token.value === '}' || token.value === ')' || token.value === ']') {
        if (depth === 0) break;
        depth -= 1;
      } else if (token.value === ';' && depth === 0) {
        this.next();
        return;
      }
      this.next();
    }
  }

  // Skip a balanced `{ ... }` block (used for struct /
  // enum bodies, which carry no analyzable code). The
  // opening `{` must be the current token.
  skipBracedBlock() {
    this.expect('{', "'{'");
    let depth = 1;
    while (!this.atEof() && depth > 0) {
      const token = this.next();
      if (token.value === '{') depth += 1;
      else if (token.value === '}') depth -= 1;
    }
    if (depth !== 0) this.error('unterminated block', this.peek());
  }

  parseProgram() {
    const start = this.peek();
    const body = [];
    while (!this.atEof()) body.push(this.parseTopLevel());
    return { type: 'Program', body, line: start.line, column: start.column };
  }

  parseTopLevel() {
    const token = this.peek();
    if (token.type === 'name') {
      switch (token.value) {
        case 'pragma': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'PragmaDirective', line: start.line, column: start.column };
        }
        case 'import': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'ImportDirective', line: start.line, column: start.column };
        }
        case 'using': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'UsingDirective', line: start.line, column: start.column };
        }
        case 'contract':
        case 'library':
        case 'interface':
          return this.parseContract();
        case 'function':
          return this.parseFunction('function');
        case 'struct': {
          const start = this.next();
          this.parseName('struct name');
          this.skipBracedBlock();
          return { type: 'StructDefinition', line: start.line, column: start.column };
        }
        case 'enum': {
          const start = this.next();
          this.parseName('enum name');
          this.skipBracedBlock();
          return { type: 'EnumDefinition', line: start.line, column: start.column };
        }
        case 'event': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'EventDefinition', line: start.line, column: start.column };
        }
        case 'error': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'ErrorDefinition', line: start.line, column: start.column };
        }
        case 'type': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'UserDefinedValueTypeDefinition', line: start.line, column: start.column };
        }
        default:
          break;
      }
    }
    this.error(`unsupported top-level item ${JSON.stringify(token.value) || token.type}`, token);
    return null;
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

  parseContract() {
    const start = this.next(); // contract | library | interface
    const kind = start.value;
    const name = this.parseName('contract name');
    const bases = [];
    if (this.at('is')) {
      this.next();
      for (;;) {
        const base = this.parseName('base contract name');
        bases.push(base.name);
        // A base may carry constructor arguments:
        // `is ERC20("name", "symbol")` — skipped.
        if (this.at('(')) this.skipParens();
        if (!this.match(',')) break;
      }
    }
    this.expect('{', "'{' after contract header");
    const stateVars = [];
    const functions = [];
    while (!this.at('}') && !this.atEof()) {
      const part = this.parseContractPart(stateVars, functions);
      if (part && part.type === 'StateVariableDeclaration') stateVars.push(part);
      else if (part && part.type === 'FunctionDefinition') functions.push(part);
    }
    this.expect('}', "'}' after contract body");
    return {
      type: 'ContractDefinition', name: name.name, kind, bases,
      stateVars, functions, line: start.line, column: start.column,
    };
  }

  // Skip a parenthesized group (the current token must be
  // `(`); used for base-constructor arguments and modifier
  // arguments, whose contents carry no analyzable code
  // beyond nested calls — which are analyzed where they
  // appear in function bodies, not in headers.
  skipParens() {
    this.expect('(', "'('");
    let depth = 1;
    while (!this.atEof() && depth > 0) {
      const token = this.next();
      if (token.value === '(') depth += 1;
      else if (token.value === ')') depth -= 1;
    }
    if (depth !== 0) this.error('unterminated parenthesized group', this.peek());
  }

  parseContractPart(stateVars, functions) {
    const token = this.peek();
    if (token.type === 'name') {
      switch (token.value) {
        case 'function':
          return this.parseFunction('function');
        case 'constructor':
          return this.parseFunction('constructor');
        case 'receive':
          return this.parseFunction('receive');
        case 'fallback':
          return this.parseFunction('fallback');
        case 'modifier':
          return this.parseModifier();
        case 'struct': {
          const start = this.next();
          this.parseName('struct name');
          this.skipBracedBlock();
          return { type: 'StructDefinition', line: start.line, column: start.column };
        }
        case 'enum': {
          const start = this.next();
          this.parseName('enum name');
          this.skipBracedBlock();
          return { type: 'EnumDefinition', line: start.line, column: start.column };
        }
        case 'event': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'EventDefinition', line: start.line, column: start.column };
        }
        case 'error': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'ErrorDefinition', line: start.line, column: start.column };
        }
        case 'using': {
          const start = this.next();
          this.skipToSemicolon();
          return { type: 'UsingDirective', line: start.line, column: start.column };
        }
        default:
          break;
      }
    }
    // Otherwise: a state variable declaration.
    return this.parseStateVariable();
  }

  // A state variable: `Type [qualifiers...] name [= expr];`
  // Qualifiers (visibility, mutability, location) are
  // skipped — only the name matters for the analysis.
  parseStateVariable() {
    const start = this.peek();
    const type = this.parseType();
    while (this.peek().type === 'name' && TYPE_QUALIFIERS.has(this.peek().value)) this.next();
    const name = this.parseName('state variable name');
    let initialValue = null;
    if (this.at('=')) {
      this.next();
      initialValue = this.parseExpression();
    }
    this.expect(';', "';' after state variable declaration");
    return {
      type: 'StateVariableDeclaration', name: name.name, typeText: type.text,
      initialValue, line: start.line, column: start.column,
    };
  }

  // Parse a type and return { text }. The text is only
  // descriptive — the analysis needs variable names, not
  // type structure. Supported: elementary and user-defined
  // names, `address payable`, `mapping(K => V)`, arrays
  // (`T[]`, `T[n]`), and `function` types (parsed loosely).
  parseType() {
    const start = this.peek();
    let text;
    if (this.at('mapping')) {
      this.next();
      this.expect('(', "'(' after mapping");
      const key = this.parseType();
      this.expect('=>', "'=>' in mapping");
      const value = this.parseType();
      this.expect(')', "')' after mapping");
      text = `mapping(${key.text} => ${value.text})`;
    } else if (this.at('function')) {
      this.next();
      this.parseParams();
      text = 'function';
      // Optional `returns (...)` on a function type.
      if (this.at('returns')) {
        this.next();
        this.parseParams();
      }
    } else {
      // A reserved word can never be a type name: without
      // this guard `delete x;` would parse as a variable
      // declaration of type `delete` named `x`. Throwing
      // here makes tryParseVarDecl fall back to expression
      // parsing, where `delete` is handled as a unary
      // operator; in a genuine type position (state
      // variable, parameter) the error is real.
      if (this.peek().type === 'name' && RESERVED.has(this.peek().value)) {
        this.error(`expected a type but found keyword ${JSON.stringify(this.peek().value)}`, this.peek());
      }
      if (this.peek().type !== 'name') this.error('expected a type', this.peek());
      const base = this.next();
      text = base.value;
      if (text === 'address' && this.at('payable')) {
        this.next();
        text = 'address payable';
      }
    }
    // Array suffixes: `T[]`, `T[3]`.
    while (this.at('[')) {
      this.next();
      if (!this.at(']')) this.parseExpression();
      this.expect(']', "']' after array length");
      text += '[]';
    }
    return { text, line: start.line, column: start.column };
  }

  // A modifier definition: `modifier name(params) { body }`
  // (the `_;` placeholder parses as an identifier
  // expression statement). The body is analyzed like any
  // function body for locals, but modifiers are never
  // analyzed for reentrancy themselves.
  parseModifier() {
    const start = this.next(); // 'modifier'
    const name = this.parseName('modifier name');
    const params = this.parseParams();
    if (this.at(';')) {
      this.next();
      return {
        type: 'ModifierDefinition', name: name.name, params, body: null,
        line: start.line, column: start.column,
      };
    }
    const body = this.parseBlock();
    return {
      type: 'ModifierDefinition', name: name.name, params, body,
      line: start.line, column: start.column,
    };
  }

  // A function (or constructor / receive / fallback).
  // `kind` is 'function' | 'constructor' | 'receive' |
  // 'fallback'. Header tokens after the parameter list —
  // visibility, mutability, virtual / override, modifiers
  // (name, optionally with arguments), `returns (...)` —
  // are consumed in any order; modifier names are recorded
  // (the `nonReentrant` guard check reads them).
  parseFunction(kind) {
    const start = this.peek();
    if (kind === 'function') this.next(); // 'function'
    else this.next(); // 'constructor' | 'receive' | 'fallback'
    let name = null;
    if (kind === 'function') {
      name = this.parseName('function name');
    } else if (kind === 'constructor') {
      name = { type: 'Identifier', name: 'constructor', line: start.line, column: start.column };
    } else {
      name = { type: 'Identifier', name: kind, line: start.line, column: start.column };
    }
    const params = this.parseParams();
    const modifiers = [];
    // Header tokens until `{` (body) or `;` (no body).
    for (;;) {
      if (this.at('{') || this.at(';') || this.atEof()) break;
      if (this.at('returns')) {
        this.next();
        this.parseParams();
        continue;
      }
      if (this.at('override')) {
        this.next();
        if (this.at('(')) this.skipParens();
        continue;
      }
      if (this.peek().type === 'name'
        && (TYPE_QUALIFIERS.has(this.peek().value) || this.peek().value === 'override')) {
        this.next();
        continue;
      }
      if (this.peek().type === 'name' && !RESERVED.has(this.peek().value)) {
        const modifier = this.next();
        modifiers.push(modifier.value);
        if (this.at('(')) this.skipParens();
        continue;
      }
      this.error(`unexpected token ${JSON.stringify(this.peek().value)} in function header`, this.peek());
    }
    let body = null;
    if (this.at('{')) {
      body = this.parseBlock();
    } else {
      this.expect(';', "'{' or ';' after function header");
    }
    return {
      type: 'FunctionDefinition', name: name.name, kind, params,
      modifiers, body, line: start.line, column: start.column,
    };
  }

  // A parameter list: `(` [param (`,` param)*] `)` where a
  // parameter is `Type [location] [name]`. Unnamed parameters
  // (interface functions) carry name null.
  parseParams() {
    this.expect('(', "'(' before parameters");
    const params = [];
    while (!this.at(')') && !this.atEof()) {
      const type = this.parseType();
      if (this.peek().type === 'name'
        && (this.peek().value === 'memory' || this.peek().value === 'calldata'
          || this.peek().value === 'storage')) {
        this.next();
      }
      let name = null;
      if (this.peek().type === 'name' && !RESERVED.has(this.peek().value)) {
        name = this.next().value;
      }
      params.push({ name, type: type.text });
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after parameters");
    return params;
  }

  parseBlock() {
    const start = this.expect('{', "'{'");
    const body = [];
    while (!this.at('}') && !this.atEof()) body.push(this.parseStatement());
    this.expect('}', "'}'");
    return { type: 'BlockStatement', body, line: start.line, column: start.column };
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
        case 'unchecked': {
          if (this.peek(1).value === '{') {
            const start = this.next();
            const body = this.parseBlock();
            return { type: 'UncheckedBlock', body, line: start.line, column: start.column };
          }
          break;
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
        case 'for': {
          const start = this.next();
          this.expect('(', "'(' after for");
          let init = null;
          if (!this.at(';')) {
            // A for-init declaration does NOT consume its
            // `;` — the `;` is the separator between init
            // and test, consumed below.
            const decl = this.tryParseVarDecl(false);
            init = decl || this.parseExpression();
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
        case 'return': {
          const start = this.next();
          let argument = null;
          if (!this.atEof() && !this.at(';') && !this.at('}')) argument = this.parseExpression();
          this.semicolon();
          return { type: 'ReturnStatement', argument, line: start.line, column: start.column };
        }
        case 'break': {
          const start = this.next();
          this.semicolon();
          return { type: 'BreakStatement', line: start.line, column: start.column };
        }
        case 'continue': {
          const start = this.next();
          this.semicolon();
          return { type: 'ContinueStatement', line: start.line, column: start.column };
        }
        case 'emit': {
          const start = this.next();
          const call = this.parseCallLike();
          this.semicolon();
          return { type: 'EmitStatement', call, line: start.line, column: start.column };
        }
        case 'assembly':
          this.error('inline assembly is not supported by the subset parser', token);
          break;
        case 'try':
          this.error('try/catch is not supported by the subset parser', token);
          break;
        default:
          break;
      }
    }
    // Tuple declaration: `(Type name, Type name) = expr;`
    if (token.type === 'punct' && token.value === '(') {
      const tupleDecl = this.tryParseTupleDecl();
      if (tupleDecl) return tupleDecl;
    }
    // Variable declaration: `Type [qualifiers] name [= expr]
    // [, name [= expr]];` — attempted first, with position
    // restore, because a statement starting with a type name
    // is otherwise an expression statement.
    const decl = this.tryParseVarDecl();
    if (decl) return decl;
    const expr = this.parseExpression();
    this.semicolon();
    return { type: 'ExpressionStatement', expression: expr, line: expr.line, column: expr.column };
  }

  // Try to parse `(Type name, Type name) = expr;` at the
  // current position. Returns the node, or null (position
  // restored) when this is not a tuple declaration.
  tryParseTupleDecl() {
    const saved = this.pos;
    try {
      const start = this.next(); // '('
      const declarations = [];
      while (!this.at(')') && !this.atEof()) {
        // An empty element (`, ,` or a leading `,`): the
        // slot is skipped in the destructuring.
        if (this.at(',')) {
          declarations.push({ name: null, initialValue: null });
          this.next();
          continue;
        }
        this.parseType();
        while (this.peek().type === 'name' && TYPE_QUALIFIERS.has(this.peek().value)) this.next();
        if (this.peek().type !== 'name' || RESERVED.has(this.peek().value)) {
          this.pos = saved;
          return null;
        }
        const name = this.next();
        declarations.push({ name: name.value, initialValue: null });
        if (!this.match(',')) break;
      }
      this.expect(')', "')' after tuple declaration");
      if (!this.at('=')) {
        this.pos = saved;
        return null;
      }
      this.next();
      const initialValue = this.parseExpression();
      this.expect(';', "';' after tuple declaration");
      return {
        type: 'VariableDeclarationStatement', declarations, initialValue,
        line: start.line, column: start.column,
      };
    } catch (error) {
      if (!(error instanceof SolParseError)) throw error;
      this.pos = saved;
      return null;
    }
  }

  // Try to parse a variable declaration at the current
  // position. Returns the node, or null (position restored)
  // when this is not a declaration (an expression statement
  // starting with a type-like name, e.g. `uint(x);` or
  // `balances[x] = 0;`). When `consumeSemicolon` is false
  // (a for-init declaration) the trailing `;` is left for
  // the caller — it is the separator, not the statement's
  // terminator.
  tryParseVarDecl(consumeSemicolon = true) {
    const saved = this.pos;
    try {
      const start = this.peek();
      this.parseType();
      while (this.peek().type === 'name' && TYPE_QUALIFIERS.has(this.peek().value)) this.next();
      if (this.peek().type !== 'name' || RESERVED.has(this.peek().value)) {
        this.pos = saved;
        return null;
      }
      const declarations = [];
      for (;;) {
        const name = this.next();
        let initialValue = null;
        if (this.at('=')) {
          this.next();
          initialValue = this.parseExpression();
        }
        declarations.push({ name: name.value, initialValue });
        if (!this.match(',')) break;
        // A further declarator is a bare name (`uint a = 1,
        // b = 2;`) — no repeated type.
        if (this.peek().type !== 'name' || RESERVED.has(this.peek().value)) {
          this.pos = saved;
          return null;
        }
      }
      if (consumeSemicolon) this.expect(';', "';' after variable declaration");
      return {
        type: 'VariableDeclarationStatement', declarations,
        initialValue: null, line: start.line, column: start.column,
      };
    } catch (error) {
      if (!(error instanceof SolParseError)) throw error;
      this.pos = saved;
      return null;
    }
  }

  // Parse a call-like expression (`name(args)` or
  // `a.b.c(args)`, with optional `{...}` call options)
  // starting at the current position. Used for `emit`.
  parseCallLike() {
    const expr = this.parsePostfix();
    if (expr.type !== 'CallExpression') {
      this.error('expected a call expression', this.peek());
    }
    return expr;
  }

  parseExpression() {
    return this.parseAssignment();
  }

  parseAssignment() {
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
    this.next();
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
      if (token.type !== 'punct') break;
      const op = token.value;
      if (!(op in BINARY_PRECEDENCE)) break;
      const precedence = BINARY_PRECEDENCE[op];
      if (precedence < minPrecedence) break;
      this.next();
      const right = this.parseBinary(op === '**' ? precedence : precedence + 1);
      left = { type: 'BinaryExpression', operator: op, left, right, line: left.line, column: left.column };
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
    if (token.type === 'name' && token.value === 'delete') {
      const op = this.next();
      const argument = this.parseUnary();
      return { type: 'UnaryExpression', operator: 'delete', argument, line: op.line, column: op.column };
    }
    return this.parsePostfix();
  }

  parsePostfix() {
    let expr = this.parsePrimary();
    for (;;) {
      const token = this.peek();
      if (token.type === 'punct' && (token.value === '++' || token.value === '--')) {
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
          computed: false, line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'punct' && token.value === '[') {
        this.next();
        const property = this.parseExpression();
        this.expect(']', "']' after computed member");
        expr = {
          type: 'MemberExpression', object: expr, property,
          computed: true, line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'punct' && token.value === '{') {
        // Call options: `callee{value: 1 ether}(args)`.
        // Solidity has no object literals, so `{` after a
        // callee in expression position is unambiguous.
        const options = this.parseCallOptions();
        this.expect('(', "'(' after call options");
        const args = this.parseArgumentsRest();
        expr = {
          type: 'CallExpression', callee: expr, arguments: args, options,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      if (token.type === 'punct' && token.value === '(') {
        const args = this.parseArguments();
        expr = {
          type: 'CallExpression', callee: expr, arguments: args, options: null,
          line: expr.line, column: expr.column,
        };
        continue;
      }
      break;
    }
    return expr;
  }

  // Parse `{ key: value, ... }` call options (the current
  // token must be `{`). Keys are identifiers; values are
  // expressions.
  parseCallOptions() {
    this.expect('{', "'{' before call options");
    const options = [];
    while (!this.at('}') && !this.atEof()) {
      if (this.peek().type !== 'name') this.error('expected an option name in call options', this.peek());
      const key = this.next();
      this.expect(':', "':' in call options");
      const value = this.parseExpression();
      options.push({ key: key.value, value, line: key.line, column: key.column });
      if (!this.match(',')) break;
    }
    this.expect('}', "'}' after call options");
    return options;
  }

  parseArguments() {
    this.expect('(', "'(' before arguments");
    return this.parseArgumentsRest();
  }

  // Arguments after the opening `(` was consumed.
  parseArgumentsRest() {
    const args = [];
    while (!this.at(')') && !this.atEof()) {
      if (this.at('{')) {
        // A struct-constructor-style named argument
        // (`Foo({a: 1})`) is not supported: fail loudly
        // instead of mis-parsing it as a call option.
        this.error('struct-constructor arguments are not supported by the subset parser', this.peek());
      }
      args.push(this.parseAssignment());
      if (!this.match(',')) break;
    }
    this.expect(')', "')' after arguments");
    return args;
  }

  parsePrimary() {
    const token = this.peek();
    if (token.type === 'number') {
      this.next();
      let unit = null;
      if (this.peek().type === 'name' && NUMBER_UNITS.has(this.peek().value)) {
        unit = this.next().value;
      }
      return { type: 'Literal', value: token.value, kind: 'number', unit, line: token.line, column: token.column };
    }
    if (token.type === 'string') {
      this.next();
      return { type: 'Literal', value: token.value, kind: 'string', line: token.line, column: token.column };
    }
    if (token.type === 'name') {
      if (token.value === 'true' || token.value === 'false') {
        this.next();
        return { type: 'Literal', value: token.value, kind: 'boolean', line: token.line, column: token.column };
      }
      if (token.value === 'new') {
        const start = this.next();
        const type = this.parseType();
        let options = null;
        if (this.at('{')) options = this.parseCallOptions();
        const args = this.parseArguments();
        return {
          type: 'NewExpression', callee: type.text, arguments: args, options,
          line: start.line, column: start.column,
        };
      }
      // `payable(...)` and `type(...)` are type conversions
      // / meta-type expressions, so they are usable as
      // primaries even though both words are keywords.
      // Every other reserved word is an error here.
      if (RESERVED.has(token.value) && token.value !== 'payable' && token.value !== 'type') {
        this.error(`unexpected keyword ${JSON.stringify(token.value)}`, token);
      }
      this.next();
      return { type: 'Identifier', name: token.value, line: token.line, column: token.column };
    }
    if (token.type === 'punct' && token.value === '(') {
      const start = this.next();
      // A parenthesized expression, or a tuple when a
      // comma follows the first element.
      const first = this.parseExpression();
      if (this.at(',')) {
        const elements = [first];
        while (this.match(',')) {
          if (this.at(')')) { elements.push(null); break; }
          elements.push(this.parseExpression());
        }
        this.expect(')', "')' after tuple");
        return { type: 'TupleExpression', elements, line: start.line, column: start.column };
      }
      this.expect(')', "')' after parenthesized expression");
      return first;
    }
    this.error(`unexpected token ${JSON.stringify(token.value) || token.type} in expression`, token);
    return null;
  }
}

function parseSolidity(source) {
  if (typeof source !== 'string') {
    throw new SolParseError('source must be a string', 1, 1);
  }
  const parser = new Parser(tokenize(source));
  const program = parser.parseProgram();
  if (!parser.atEof()) {
    const token = parser.peek();
    throw new SolParseError(
      `unexpected trailing token ${JSON.stringify(token.value) || token.type}`,
      token.line, token.column,
    );
  }
  return program;
}

module.exports = parseSolidity;
module.exports.parseSolidity = parseSolidity;
module.exports.tokenize = tokenize;
module.exports.SolParseError = SolParseError;
