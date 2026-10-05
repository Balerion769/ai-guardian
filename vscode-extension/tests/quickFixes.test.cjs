const assert = require('node:assert/strict');
const test = require('node:test');
const Module = require('node:module');

class Range {
  constructor(line, start, endLine, end) {
    this.start = { line, character: start };
    this.end = { line: endLine, character: end };
  }
}
class WorkspaceEdit {
  constructor() { this.edits = []; }
  replace(uri, range, text) { this.edits.push({ uri, range, text }); }
}
class CodeAction {
  constructor(title, kind) { this.title = title; this.kind = kind; }
}
const originalLoad = Module._load;
Module._load = function (name, ...args) {
  if (name === 'vscode') return { Range, WorkspaceEdit, CodeAction, CodeActionKind: { QuickFix: 'quickfix' } };
  return originalLoad.call(this, name, ...args);
};
const { createQuickFix } = require('../out/extension.js');
Module._load = originalLoad;

function actions(source, languageId, code) {
  const range = new Range(0, 0, 0, source.length);
  const document = {
    languageId, uri: 'file:///sample',
    lineAt: () => ({ text: source, range }),
    getText: () => source,
  };
  return createQuickFix(document, { range, code, source: 'ai-guardian' });
}

test('eval quick fix replaces only the call target', () => {
  const [action] = actions('value = eval(data)', 'python', 'Unsafe Code Execution');
  assert.equal(action.edit.edits[0].text, "__import__('ast').literal_eval");
  assert.equal(action.edit.edits[0].range.start.character, 8);
});
test('exec quick fix explicitly stops dynamic execution', () => {
  const [action] = actions('    exec(data)', 'python', 'Unsafe Code Execution');
  assert.match(action.edit.edits[0].text, /^    raise RuntimeError/);
  assert.equal(actions('if ready: exec(data)', 'python', 'Unsafe Code Execution').length, 0);
});
test('DOM quick fix replaces only the HTML property', () => {
  const [action] = actions('element.innerHTML = value;', 'typescript', 'DOM XSS');
  assert.equal(action.edit.edits[0].text, '.textContent');
});
test('password quick fix preserves TypeScript declarations and requires a value', () => {
  const [action] = actions('const password: string = "sample-value";', 'typescript', 'Secret Leak');
  assert.match(action.edit.edits[0].text, /^const password: string = process.env.PASSWORD/);
  assert.match(action.edit.edits[0].text, /throw new Error/);
});
test('AWS quick fix loads the key without retaining the literal', () => {
  const [action] = actions('key = "AKIA1234567890ABCDEF"', 'python', 'fallback:extract-aws-key');
  assert.equal(action.edit.edits[0].text, "key = __import__('os').environ['AWS_ACCESS_KEY_ID']");
});
test('secret quick fixes do not discard trailing code', () => {
  assert.equal(actions('password = "sample-value"; do_work()', 'python', 'Secret Leak').length, 0);
});
