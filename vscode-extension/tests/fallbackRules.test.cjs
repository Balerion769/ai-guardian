const assert = require('node:assert/strict');
const test = require('node:test');
const { scanFallback } = require('../out/fallbackRules.js');

const cases = [
  ['Python eval', 'python', 'eval(user_input)', '# eval(user_input)', 'Dynamic Execution'],
  ['Python exec', 'python', 'exec(user_input)', '# exec(user_input)', 'Dynamic Execution'],
  ['hardcoded password', 'python', 'password = "supersecret123"', 'password = os.environ["PASSWORD"]', 'Hardcoded Secret'],
  ['AWS access key', 'python', 'key = "AKIA1234567890ABCDEF"', 'key = os.environ["AWS_KEY"]', 'Hardcoded Secret'],
  ['DOM innerHTML', 'javascript', 'element.innerHTML = userInput;', 'element.textContent = userInput;', 'DOM XSS']
];

for (const [label, language, vulnerable, safe, category] of cases) {
  test(`${label} is flagged`, () => {
    const findings = scanFallback(vulnerable, language);
    assert.ok(findings.some((finding) => finding.category === category));
  });
  test(`${label} safe case is clear`, () => {
    assert.equal(scanFallback(safe, language).length, 0);
  });
}

test('fallback reports the exact source line', () => {
  assert.equal(scanFallback('pass\neval(value)', 'python')[0].line, 1);
});
