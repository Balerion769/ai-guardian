import * as vscode from 'vscode';
import { FallbackFinding, scanFallback } from './fallbackRules';

type Severity = 'HIGH' | 'MEDIUM' | 'LOW';
interface ApiFinding {
  severity: Severity;
  category: string;
  description: string;
  line_reference: string;
  remediation: string;
}

const LANGUAGES = ['python', 'javascript', 'typescript'];
const MAX_CHARACTERS = 200_000;
const REQUEST_TIMEOUT_MS = 7_000;
let diagnosticCollection: vscode.DiagnosticCollection;
const inFlight = new Map<string, AbortController>();
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

/** Activate diagnostics, explicit scans, save/type hooks, and safe code actions. */
export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('ai-guardian');
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) AI Guardian';
  statusBar.command = 'aiGuardian.auditFile';
  statusBar.tooltip = 'Audit the current file with AI Guardian';
  statusBar.show();

  context.subscriptions.push(
    diagnosticCollection,
    statusBar,
    vscode.commands.registerCommand('aiGuardian.auditFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showInformationMessage('Open a Python, JavaScript, or TypeScript file to audit.');
        return;
      }
      await auditDocument(editor.document, statusBar);
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (vscode.workspace.getConfiguration('aiGuardian').get<boolean>('runOnSave', true)) {
        void auditDocument(document, statusBar);
      }
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (!vscode.workspace.getConfiguration('aiGuardian').get<boolean>('runOnType', false) || event.contentChanges.length === 0) return;
      const key = event.document.uri.toString();
      const oldTimer = debounceTimers.get(key);
      if (oldTimer) clearTimeout(oldTimer);
      debounceTimers.set(key, setTimeout(() => {
        debounceTimers.delete(key);
        void auditDocument(event.document, statusBar);
      }, 750));
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      const key = document.uri.toString();
      inFlight.get(key)?.abort();
      inFlight.delete(key);
      const timer = debounceTimers.get(key);
      if (timer) clearTimeout(timer);
      debounceTimers.delete(key);
      diagnosticCollection.delete(document.uri);
    }),
    vscode.languages.registerCodeActionsProvider(LANGUAGES.map((language) => ({ language })), {
      provideCodeActions(document, _range, context) {
        return context.diagnostics.flatMap((diagnostic) => createQuickFix(document, diagnostic));
      }
    }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    { dispose() {
      for (const controller of inFlight.values()) controller.abort();
      for (const timer of debounceTimers.values()) clearTimeout(timer);
      inFlight.clear();
      debounceTimers.clear();
    } }
  );
}

/** Release extension-owned resources through context subscriptions. */
export function deactivate(): void {
  for (const controller of inFlight.values()) controller.abort();
  inFlight.clear();
}

/** Return a bounded source window and its zero-based first line. */
function sourceWindow(document: vscode.TextDocument): { text: string; firstLine: number } | undefined {
  if (document.getText().length > MAX_CHARACTERS) return undefined;
  if (document.lineCount < 500) return { text: document.getText(), firstLine: 0 };
  const editor = vscode.window.visibleTextEditors.find((candidate) => candidate.document.uri.toString() === document.uri.toString());
  const firstVisible = editor?.visibleRanges[0]?.start.line ?? 0;
  const lastVisible = editor?.visibleRanges[0]?.end.line ?? firstVisible;
  const center = Math.floor((firstVisible + lastVisible) / 2);
  const firstLine = Math.max(0, Math.min(center - 100, document.lineCount - 200));
  const lines: string[] = [];
  for (let line = firstLine; line < Math.min(document.lineCount, firstLine + 200); line += 1) {
    lines.push(document.lineAt(line).text);
  }
  return { text: lines.join('\n'), firstLine };
}

/** Validate untrusted API JSON before turning it into editor diagnostics. */
function parseFindings(value: unknown): ApiFinding[] {
  if (typeof value !== 'object' || value === null || !('vulnerabilities' in value)) throw new Error('Invalid audit response');
  const vulnerabilities = value.vulnerabilities;
  if (!Array.isArray(vulnerabilities)) throw new Error('Invalid vulnerabilities array');
  return vulnerabilities.map((finding: unknown): ApiFinding => {
    if (typeof finding !== 'object' || finding === null) throw new Error('Invalid finding');
    const data = finding as Record<string, unknown>;
    if (!['HIGH', 'MEDIUM', 'LOW'].includes(String(data.severity)) ||
        !['category', 'description', 'line_reference', 'remediation'].every((field) => typeof data[field] === 'string')) {
      throw new Error('Invalid finding fields');
    }
    return data as unknown as ApiFinding;
  });
}

/** Audit a document; use five local checks only when the API cannot respond. */
async function auditDocument(document: vscode.TextDocument, statusBar: vscode.StatusBarItem): Promise<void> {
  if (!LANGUAGES.includes(document.languageId)) return;
  const key = document.uri.toString();
  const window = sourceWindow(document);
  if (!window) {
    diagnosticCollection.delete(document.uri);
    statusBar.text = '$(shield) AI Guardian: file too large';
    return;
  }
  const version = document.version;
  inFlight.get(key)?.abort();
  const controller = new AbortController();
  inFlight.set(key, controller);
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  statusBar.text = '$(sync~spin) AI Guardian';
  try {
    const apiUrl = vscode.workspace.getConfiguration('aiGuardian').get<string>('apiUrl', 'http://localhost:8000/api/v1/audit');
    const response = await fetch(apiUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ diff_content: window.text, language: document.languageId }),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`Audit API returned HTTP ${response.status}`);
    const findings = parseFindings(await response.json());
    if (document.version !== version || inFlight.get(key) !== controller) return;
    diagnosticCollection.set(document.uri, findings.map((finding) => apiDiagnostic(document, finding, window.firstLine)));
    statusBar.text = `$(shield) AI Guardian: ${findings.length} finding(s)`;
    statusBar.tooltip = 'AI Guardian API audit completed';
  } catch (error) {
    if (document.version !== version || inFlight.get(key) !== controller) return;
    const local = scanFallback(window.text, document.languageId);
    diagnosticCollection.set(document.uri, local.map((finding) => fallbackDiagnostic(document, finding, window.firstLine)));
    statusBar.text = `$(warning) AI Guardian: offline (${local.length})`;
    statusBar.tooltip = `API unavailable; five local checks ran. ${error instanceof Error ? error.message : 'Unknown error'}`;
  } finally {
    clearTimeout(timeout);
    if (inFlight.get(key) === controller) inFlight.delete(key);
  }
}

/** Anchor an API finding to the correct line in the original document. */
function apiDiagnostic(document: vscode.TextDocument, finding: ApiFinding, firstLine: number): vscode.Diagnostic {
  const match = /\bLine\s+(\d+)\b/i.exec(finding.line_reference);
  const relativeLine = match ? Math.max(0, Number(match[1]) - 1) : 0;
  const line = Math.min(document.lineCount - 1, firstLine + relativeLine);
  const diagnostic = new vscode.Diagnostic(document.lineAt(line).range,
    `${finding.category}: ${finding.description} | Fix: ${finding.remediation}`,
    toDiagnosticSeverity(finding.severity));
  diagnostic.source = 'ai-guardian';
  diagnostic.code = finding.category;
  return diagnostic;
}

/** Anchor a local fallback finding and mark it as a limited offline check. */
function fallbackDiagnostic(document: vscode.TextDocument, finding: FallbackFinding, firstLine: number): vscode.Diagnostic {
  const line = Math.min(document.lineCount - 1, firstLine + finding.line);
  const range = new vscode.Range(line, finding.start, line, finding.end);
  const diagnostic = new vscode.Diagnostic(range,
    `${finding.category}: ${finding.description} | Fix: ${finding.remediation} (offline check)`,
    toDiagnosticSeverity(finding.severity));
  diagnostic.source = 'ai-guardian';
  diagnostic.code = finding.fix ? `fallback:${finding.fix}` : finding.category;
  return diagnostic;
}

/** Map scanner severity to the Problems panel. */
function toDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  return severity === 'HIGH' ? vscode.DiagnosticSeverity.Error
    : severity === 'MEDIUM' ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;
}

/** Offer edits only for local patterns with a precise replacement. */
function createQuickFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction[] {
  if (diagnostic.source !== 'ai-guardian') return [];
  const code = String(diagnostic.code);
  if ((code === 'fallback:dom-text-content' || code === 'DOM XSS') && document.languageId !== 'python') {
    const original = document.getText(diagnostic.range);
    const matches = [...original.matchAll(/\.innerHTML\s*=/g)];
    if (matches.length !== 1) return [];
    const start = diagnostic.range.start.character + (matches[0].index ?? 0);
    const action = new vscode.CodeAction('Use textContent for plain text', vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.edit = new vscode.WorkspaceEdit();
    action.edit.replace(document.uri, new vscode.Range(diagnostic.range.start.line, start,
      diagnostic.range.start.line, start + '.innerHTML'.length), '.textContent');
    return [action];
  }
  if ((code === 'fallback:python-literal-eval' || code === 'Unsafe Code Execution') && document.languageId === 'python') {
    const original = document.getText(diagnostic.range);
    const matches = [...original.matchAll(/\beval\s*\(/g)];
    if (matches.length !== 1) return [];
    const start = diagnostic.range.start.character + (matches[0].index ?? 0);
    const action = new vscode.CodeAction('Parse Python literals with ast.literal_eval', vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.edit = new vscode.WorkspaceEdit();
    // The explicit import expression keeps the edit valid around shebangs,
    // module docstrings, and future imports without rewriting file structure.
    action.edit.replace(document.uri, new vscode.Range(diagnostic.range.start.line, start,
      diagnostic.range.start.line, start + 'eval'.length), "__import__('ast').literal_eval");
    return [action];
  }
  return [];
}
