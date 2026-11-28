// Tests for the Solidity subset parser
// (src/detection/sol-parser.js, round 108).
// The parser is tested on its own: valid contracts parse
// to the expected AST shape, and unsupported syntax fails
// loudly with a SolParseError — never silently skipped.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const parseSolidity = require('../src/detection/sol-parser.js');
const { SolParseError } = require('../src/detection/sol-parser.js');

function parse(source) {
  return parseSolidity(source);
}

test('parser: empty program and pragma-only program parse', () => {
  const empty = parse('');
  assert.equal(empty.type, 'Program');
  assert.deepEqual(empty.body, []);
  const pragma = parse('pragma solidity ^0.8.20;');
  assert.equal(pragma.body.length, 1);
  assert.equal(pragma.body[0].type, 'PragmaDirective');
});

test('parser: contract with state variables, mapping, and visibility', () => {
  const ast = parse(`
    contract Vault {
      mapping(address => uint256) public balances;
      uint256 public totalSupply;
      address private owner;
      bool internal paused;
    }
  `);
  const contract = ast.body[0];
  assert.equal(contract.type, 'ContractDefinition');
  assert.equal(contract.name, 'Vault');
  assert.deepEqual(
    contract.stateVars.map((v) => v.name),
    ['balances', 'totalSupply', 'owner', 'paused'],
  );
  assert.equal(contract.stateVars[0].typeText, 'mapping(address => uint256)');
});

test('parser: inheritance list with constructor arguments', () => {
  const ast = parse(`
    contract Token is ERC20("My Token", "MTK"), Ownable {
      uint256 public x;
    }
  `);
  const contract = ast.body[0];
  assert.deepEqual(contract.bases, ['ERC20', 'Ownable']);
});

test('parser: function header with visibility, mutability, modifiers, returns', () => {
  const ast = parse(`
    contract C {
      function f(uint256 a) external payable nonReentrant returns (uint256) {
        return a;
      }
    }
  `);
  const fn = ast.body[0].functions[0];
  assert.equal(fn.name, 'f');
  assert.deepEqual(fn.params, [{ name: 'a', type: 'uint256' }]);
  assert.deepEqual(fn.modifiers, ['nonReentrant']);
});

test('parser: constructor, receive, fallback', () => {
  const ast = parse(`
    contract C {
      constructor(address _owner) { owner = _owner; }
      receive() external payable {}
      fallback() external payable {}
    }
  `);
  const kinds = ast.body[0].functions.map((f) => f.kind);
  assert.deepEqual(kinds, ['constructor', 'receive', 'fallback']);
});

test('parser: interface functions without bodies are skipped', () => {
  const ast = parse(`
    interface IERC20 {
      function transfer(address to, uint256 amount) external returns (bool);
      function balanceOf(address account) external view returns (uint256);
    }
  `);
  const functions = ast.body[0].functions;
  assert.equal(functions.length, 2);
  assert.equal(functions[0].body, null);
  assert.equal(functions[1].body, null);
});

test('parser: call with value options parses to a CallExpression with options', () => {
  const ast = parse(`
    contract C {
      function f() external {
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok);
      }
    }
  `);
  const body = ast.body[0].functions[0].body.body;
  assert.equal(body.length, 2);
  const first = body[0];
  assert.equal(first.type, 'VariableDeclarationStatement');
  assert.deepEqual(first.declarations.map((d) => d.name), ['ok']);
  const call = first.initialValue;
  assert.equal(call.type, 'CallExpression');
  assert.equal(call.options.length, 1);
  assert.equal(call.options[0].key, 'value');
  assert.equal(call.options[0].value.unit, 'ether');
});

test('parser: tuple declaration and compound assignment', () => {
  const ast = parse(`
    contract C {
      uint256 public x;
      function f() external {
        (uint256 a, uint256 b) = (1, 2);
        x += a + b;
        x++;
        delete x;
      }
    }
  `);
  const body = ast.body[0].functions[0].body.body;
  assert.equal(body[0].type, 'VariableDeclarationStatement');
  assert.deepEqual(body[0].declarations.map((d) => d.name), ['a', 'b']);
  assert.equal(body[1].expression.type, 'AssignmentExpression');
  assert.equal(body[1].expression.operator, '+=');
  assert.equal(body[2].expression.type, 'UpdateExpression');
  assert.equal(body[3].expression.type, 'UnaryExpression');
  assert.equal(body[3].expression.operator, 'delete');
});

test('parser: if / for / while / do-while / unchecked / emit', () => {
  const ast = parse(`
    contract C {
      uint256 public x;
      event Done(uint256 value);
      function f() external {
        if (x > 0) { x -= 1; } else { x += 1; }
        for (uint256 i = 0; i < 3; i++) { x += i; }
        while (x < 10) { x++; }
        do { x++; } while (x < 5);
        unchecked { x += 1; }
        emit Done(x);
      }
    }
  `);
  const body = ast.body[0].functions[0].body.body;
  assert.deepEqual(
    body.map((s) => s.type),
    ['IfStatement', 'ForStatement', 'WhileStatement', 'DoWhileStatement', 'UncheckedBlock', 'EmitStatement'],
  );
});

test('parser: comments and strings never leak tokens', () => {
  const ast = parse(`
    contract C {
      // function fake() external { msg.sender.call{value: 1}(""); }
      /* balances[msg.sender] = 0; */
      string public s = "call{value: 1} transfer send";
      function f() external {}
    }
  `);
  const contract = ast.body[0];
  assert.equal(contract.stateVars.length, 1);
  assert.equal(contract.stateVars[0].name, 's');
  assert.equal(contract.functions.length, 1);
});

test('parser: msg.sender / msg.value / block.timestamp / tx.origin parse', () => {
  const ast = parse(`
    contract C {
      function f() external payable {
        require(msg.value > 0);
        require(block.timestamp > 0);
        require(tx.origin != address(0));
      }
    }
  `);
  const body = ast.body[0].functions[0].body.body;
  assert.equal(body.length, 3);
});

test('parser: struct / enum / event / error / using / import are structural', () => {
  const ast = parse(`
    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    using SafeMath for uint256;
    contract C {
      struct Point { uint256 x; uint256 y; }
      enum State { Open, Closed }
      event Done(uint256 value);
      error NotAllowed();
    }
  `);
  assert.equal(ast.body.length, 3);
  assert.deepEqual(
    ast.body.map((node) => node.type),
    ['ImportDirective', 'UsingDirective', 'ContractDefinition'],
  );
});

test('parser: inline assembly fails loudly with SolParseError', () => {
  assert.throws(
    () => parse('contract C { function f() external { assembly { } } }'),
    (error) => error instanceof SolParseError && /assembly/.test(error.message),
  );
});

test('parser: try/catch fails loudly with SolParseError', () => {
  assert.throws(
    () => parse('contract C { function f() external { try this.g() {} catch {} } }'),
    (error) => error instanceof SolParseError && /try\/catch/.test(error.message),
  );
});

test('parser: unbalanced braces fail loudly', () => {
  assert.throws(
    () => parse('contract C { function f() external { uint256 x = 1; }'),
    (error) => error instanceof SolParseError,
  );
});

test('parser: unterminated string fails loudly', () => {
  assert.throws(
    () => parse('contract C { string public s = "abc; }'),
    (error) => error instanceof SolParseError && /unterminated string/.test(error.message),
  );
});

test('parser: a bare type name as a statement is an expression, not a declaration', () => {
  const ast = parse(`
    contract C {
      function f() external {
        uint256(1);
      }
    }
  `);
  const statement = ast.body[0].functions[0].body.body[0];
  assert.equal(statement.type, 'ExpressionStatement');
  assert.equal(statement.expression.type, 'CallExpression');
});
