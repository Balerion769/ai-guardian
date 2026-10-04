/** A bounded, best-effort finding used when the local audit API cannot respond. */
export interface FallbackFinding {
  readonly line: number;
  readonly start: number;
  readonly end: number;
  readonly severity: 'HIGH' | 'MEDIUM' | 'LOW';
  readonly category: string;
  readonly description: string;
  readonly remediation: string;
  readonly fix?: 'python-literal-eval' | 'dom-text-content';
}

interface Rule {
  readonly languages: readonly string[];
  readonly expression: RegExp;
  readonly category: string;
  readonly description: string;
  readonly remediation: string;
  readonly fix?: FallbackFinding['fix'];
}

// These five local checks intentionally trade completeness for availability.
const RULES: readonly Rule[] = [
  {
    languages: ['python'], expression: /\beval\s*\(/g,
    category: 'Dynamic Execution', description: 'eval() can execute attacker-controlled Python expressions.',
    remediation: 'Parse structured data with json.loads(), or use ast.literal_eval() only for Python literals.',
    fix: 'python-literal-eval'
  },
  {
    languages: ['python'], expression: /\bexec\s*\(/g,
    category: 'Dynamic Execution', description: 'exec() can execute attacker-controlled Python statements.',
    remediation: 'Replace exec() with an explicit operation dispatch table.'
  },
  {
    languages: ['python', 'javascript', 'typescript'],
    expression: /\bpassword\s*(?::\s*string\s*)?=\s*(['"])(?!\1)(?:\\.|(?!\1).){4,}\1/gi,
    category: 'Hardcoded Secret', description: 'A password appears to be embedded in source code.',
    remediation: 'Read the password from a local secret store or environment variable and rotate the exposed value.'
  },
  {
    languages: ['python', 'javascript', 'typescript'], expression: /\bAKIA[0-9A-Z]{16}\b/g,
    category: 'Hardcoded Secret', description: 'A value has the shape of an AWS access key ID.',
    remediation: 'Remove the key, rotate it in AWS, and load credentials from a secret provider.'
  },
  {
    languages: ['javascript', 'typescript'], expression: /\.innerHTML\s*=/g,
    category: 'DOM XSS', description: 'Writing HTML from a variable can inject executable markup.',
    remediation: 'Use textContent for plain text, or sanitize trusted HTML with a maintained HTML sanitizer.',
    fix: 'dom-text-content'
  }
];

/** Scan individual code lines without running repository code or contacting a service. */
export function scanFallback(text: string, languageId: string): FallbackFinding[] {
  const findings: FallbackFinding[] = [];
  const lines = text.split(/\r?\n/);
  for (let line = 0; line < lines.length; line += 1) {
    const source = lines[line];
    const trimmed = source.trimStart();
    if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    for (const rule of RULES) {
      if (!rule.languages.includes(languageId)) continue;
      rule.expression.lastIndex = 0;
      for (const match of source.matchAll(rule.expression)) {
        const start = match.index ?? 0;
        findings.push({
          line, start, end: start + match[0].length, severity: 'HIGH',
          category: rule.category, description: rule.description,
          remediation: rule.remediation, fix: rule.fix
        });
      }
    }
  }
  return findings;
}
