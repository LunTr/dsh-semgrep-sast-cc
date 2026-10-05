import {
  SAST_SCHEMA_VERSION,
  type SastDiagnostic,
  type SastEvidence,
  type SastFinding,
  type SastRule,
  type SastScanResult,
} from '@aaub-software/dsh-sast-contract'
import type { RunSemgrepResult } from './semgrep.js'
import type { SemgrepFinding } from './types.js'

export interface SemgrepMatchedCodeEvidence extends SastEvidence {
  type: 'semgrep.matched-code'
  data: {
    text: string
  }
}

export interface SemgrepMetavariablesEvidence extends SastEvidence {
  type: 'semgrep.metavariables'
  data: Record<string, string>
}

export interface SemgrepSourceContextEvidence extends SastEvidence {
  type: 'semgrep.source-context'
  data: { path: string, startLine: number, endLine: number, text: string, truncated: boolean }
}

export type SemgrepEvidence = SemgrepMatchedCodeEvidence | SemgrepMetavariablesEvidence | SemgrepSourceContextEvidence

/** Public model-facing result produced by the Semgrep adapter. */
export type SemgrepSastScanResult = SastScanResult<SemgrepEvidence>

const SEVERITY_ORDER: Readonly<Record<SemgrepFinding['severity'], number>> = {
  error: 0,
  warning: 1,
  info: 2,
}

function compareFindings(left: SemgrepFinding, right: SemgrepFinding): number {
  return SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
    || left.path.localeCompare(right.path)
    || left.startLine - right.startLine
    || left.startColumn - right.startColumn
    || left.ruleId.localeCompare(right.ruleId)
}

export interface FindingSelection {
  focusCwes?: readonly string[]
  diversify?: boolean
}

function relevance(finding: SemgrepFinding, focus: readonly string[]): number {
  const tags = normalizeCwe(finding.metadata?.cwe) ?? []
  if (tags.some(tag => focus.includes(tag))) return 0
  const related: Record<string, readonly string[]> = {
    'CWE-20': ['CWE-400', 'CWE-770', 'CWE-1333', 'CWE-835'],
    'CWE-22': ['CWE-36', 'CWE-23', 'CWE-73'],
    'CWE-36': ['CWE-22', 'CWE-23', 'CWE-73'],
    'CWE-400': ['CWE-770', 'CWE-1333', 'CWE-835', 'CWE-789'],
    'CWE-770': ['CWE-400', 'CWE-789'],
  }
  return focus.some(cwe => tags.some(tag => related[cwe]?.includes(tag))) ? 1 : 2
}

/** Prioritize CWE evidence before truncation and spread each relevance tier over files. */
export function selectFindings(
  findings: readonly SemgrepFinding[], maxFindings: number, options: FindingSelection = {},
): SemgrepFinding[] {
  const focus = options.focusCwes ?? []
  if (focus.some(cwe => !/^CWE-[1-9][0-9]*$/.test(cwe))) {
    throw new Error('semgrep-sast: focus_cwes must contain canonical CWE identifiers')
  }
  const tier = (finding: SemgrepFinding) => focus.length === 0 ? 0 : relevance(finding, focus)
  const sorted = [...findings].sort((a, b) => tier(a) - tier(b) || compareFindings(a, b))
  if (!options.diversify) return sorted.slice(0, maxFindings)
  const output: SemgrepFinding[] = []
  for (const priority of [0, 1, 2]) {
    const files = new Map<string, SemgrepFinding[]>()
    for (const finding of sorted.filter(item => tier(item) === priority)) {
      const queue = files.get(finding.path) ?? []
      queue.push(finding)
      files.set(finding.path, queue)
    }
    while (files.size > 0 && output.length < maxFindings) {
      for (const [path, queue] of files) {
        output.push(queue.shift()!)
        if (queue.length === 0) files.delete(path)
        if (output.length === maxFindings) break
      }
    }
  }
  return output
}

function normalizeCwe(values: readonly string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.flatMap((value) => {
    const match = /\bCWE-[1-9][0-9]*\b/i.exec(value)
    return match === null ? [] : [match[0].toUpperCase()]
  })
  const uniqueValues = [...new Set(normalized)]
  return uniqueValues.length === 0 ? undefined : uniqueValues
}

function normalizeOwasp(values: readonly string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.flatMap((value) => {
    const match = /\bA[0-9]{1,2}:[0-9]{4}\b/i.exec(value)
    return match === null ? [] : [match[0].toUpperCase()]
  })
  const uniqueValues = [...new Set(normalized)]
  return uniqueValues.length === 0 ? undefined : uniqueValues
}

function normalizeReferences(values: readonly string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.filter((value) => {
    try {
      const url = new URL(value)
      return url.protocol === 'https:' || url.protocol === 'http:'
    } catch {
      return false
    }
  })
  const uniqueValues = [...new Set(normalized)]
  return uniqueValues.length === 0 ? undefined : uniqueValues
}

function createRule(finding: SemgrepFinding): SastRule {
  const cwe = normalizeCwe(finding.metadata?.cwe)
  const owasp = normalizeOwasp(finding.metadata?.owasp)
  const references = normalizeReferences(finding.metadata?.references)
  return {
    id: finding.ruleId,
    severity: finding.severity,
    ...(cwe === undefined ? {} : { cwe }),
    ...(owasp === undefined ? {} : { owasp }),
    ...(references === undefined ? {} : { references }),
  }
}

function createEvidence(finding: SemgrepFinding): SemgrepEvidence[] {
  const evidence: SemgrepEvidence[] = []
  if (finding.matchedCode !== undefined) {
    evidence.push({
      type: 'semgrep.matched-code',
      data: { text: finding.matchedCode },
    })
  }
  if (finding.metavariables !== undefined) {
    evidence.push({
      type: 'semgrep.metavariables',
      data: { ...finding.metavariables },
    })
  }
  return evidence
}

function createFindingId(finding: SemgrepFinding): string {
  return [
    'semgrep',
    encodeURIComponent(finding.ruleId),
    encodeURIComponent(finding.path),
    String(finding.startLine),
    String(finding.startColumn),
    String(finding.endLine),
    String(finding.endColumn),
  ].join(':')
}

function createFinding(finding: SemgrepFinding): SastFinding<SemgrepEvidence> {
  return {
    id: createFindingId(finding),
    scanner: 'semgrep',
    rule: createRule(finding),
    message: finding.message,
    location: {
      path: finding.path,
      startLine: finding.startLine,
      startColumn: finding.startColumn,
      endLine: finding.endLine,
      endColumn: finding.endColumn,
    },
    ...(finding.fingerprint === undefined ? {} : { fingerprint: finding.fingerprint }),
    evidence: createEvidence(finding),
  }
}

function createDiagnostic(
  diagnostic: RunSemgrepResult['diagnostics'][number],
): SastDiagnostic {
  return {
    level: diagnostic.level === 'warn' ? 'warning' : diagnostic.level,
    type: diagnostic.type,
    message: diagnostic.message?.trim() || `Semgrep diagnostic code ${diagnostic.code}`,
    code: diagnostic.code,
  }
}

/** Convert one validated Semgrep execution result into the public SSC SAST contract. */
export function createSemgrepSastResult(
  scan: RunSemgrepResult,
  configuration: string,
  maxFindings: number,
  options: FindingSelection = {},
): SemgrepSastScanResult {
  if (!Number.isInteger(maxFindings) || maxFindings < 1) {
    throw new Error('semgrep-sast: maxFindings must be a positive integer')
  }

  const selectedFindings = selectFindings(scan.findings, maxFindings, options)
    .map(createFinding)

  return {
    schemaVersion: SAST_SCHEMA_VERSION,
    status: scan.status,
    scanner: {
      name: 'semgrep',
      version: scan.version,
      configuration,
    },
    scannedPaths: [...scan.scannedPaths],
    findings: selectedFindings,
    diagnostics: scan.diagnostics.map(createDiagnostic),
    summary: {
      totalFindings: scan.findings.length,
      returnedFindings: selectedFindings.length,
      truncated: selectedFindings.length < scan.findings.length,
      durationMs: scan.durationMs,
    },
  }
}
