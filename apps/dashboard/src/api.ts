import { timelineRows as fallbackTimelineRows, verdictRows as fallbackVerdictRows } from './data';
import type { ExceptionResponse, ServiceStatus, SourceKind, TimelineRow, VerdictKind, VerdictRow, VerdictType } from './types';

const apiBaseUrl = (import.meta.env.VITE_POUNCE_DASHBOARD_API_BASE_URL ?? '/api').replace(/\/$/, '');

export interface DashboardData {
  status: ServiceStatus;
  verdicts: VerdictRow[];
  timeline: TimelineRow[];
  fromFallback: boolean;
}

export async function loadDashboardData(): Promise<DashboardData> {
  const [status, verdictsResponse] = await Promise.all([
    requestJson<ServiceStatus>('/v1/status'),
    requestJson<{ count: number; verdicts: unknown[] }>('/v1/verdicts')
  ]);

  const verdicts = verdictsResponse.verdicts.map(normalizeVerdict);
  return {
    status: normalizeStatus(status),
    verdicts,
    timeline: buildTimeline(verdicts),
    fromFallback: false
  };
}

export function fallbackDashboardData(): DashboardData {
  return {
    status: {
      service: 'pounce-sentinel-policy-api',
      status: 'degraded',
      mode: 'demo-fallback',
      integrations: {
        foundry: 'configured-by-openapi',
        github: 'action-ready',
        teams: 'bot-ready',
        azureAudit: 'demo-data'
      },
      feeds: [
        { name: 'seeded-malware-intel', status: 'demo', updatedAgo: '1 min', selectedFrom: 'seed', trustState: 'bundled_seed', activeItemCount: 5 },
        { name: 'security-advisories', status: 'demo', updatedAgo: '3 min', selectedFrom: 'seed', trustState: 'bundled_seed', activeItemCount: 5 },
        { name: 'sbom-policy', status: 'demo', updatedAgo: '2 min', selectedFrom: 'seed', trustState: 'bundled_seed', activeItemCount: 5 }
      ]
    },
    verdicts: fallbackVerdictRows,
    timeline: fallbackTimelineRows,
    fromFallback: true
  };
}

export async function requestException(auditId: string, reason: string): Promise<ExceptionResponse> {
  return requestJson<ExceptionResponse>('/v1/exceptions', {
    method: 'POST',
    body: JSON.stringify({
      auditId,
      reason,
      approver: 'dashboard-user'
    })
  });
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers ?? {})
    }
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Pounce API returned ${response.status}${text ? `: ${text.slice(0, 160)}` : ''}`);
  }

  return (await response.json()) as T;
}

function normalizeStatus(status: ServiceStatus): ServiceStatus {
  return {
    service: status.service ?? 'pounce-sentinel-policy-api',
    status: status.status ?? 'unknown',
    mode: status.mode ?? 'unknown',
    integrations: status.integrations ?? {},
    feeds: Array.isArray(status.feeds) ? status.feeds : []
  };
}

function normalizeVerdict(raw: unknown): VerdictRow {
  const value = raw as Record<string, unknown>;
  const verdict = normalizeVerdictKind(value.verdict);
  const createdAt = stringValue(value.createdAt) || new Date().toISOString();
  const packageName = stringValue(value.packageName);
  const version = stringValue(value.version);
  const item = packageName ? `${packageName}${version ? `@${version}` : ''}` : stringValue(value.item) || stringValue(value.auditId) || 'Unknown item';
  const auditId = stringValue(value.auditId) || stringValue(value.id) || item;

  return {
    id: auditId,
    auditId,
    time: formatTime(createdAt),
    createdAt,
    verdict,
    type: normalizeType(value.type, packageName),
    item,
    repository: stringValue(value.repository) || 'unknown/repo',
    source: normalizeSource(value.source),
    riskScore: numberValue(value.riskScore),
    ecosystem: stringValue(value.ecosystem),
    packageName,
    version,
    actor: stringValue(value.actor),
    policyId: stringValue(value.policyId),
    reasons: stringArray(value.reasons),
    evidence: normalizeEvidence(value.evidence),
    recommendedVersion: stringValue(value.recommendedVersion) || null
  };
}

function normalizeVerdictKind(value: unknown): VerdictKind {
  return value === 'allow' || value === 'warn' || value === 'block' ? value : 'warn';
}

function normalizeType(value: unknown, packageName?: string): VerdictType {
  if (value === 'Tool Call' || value === 'Repository' || value === 'Dependency') return value;
  return packageName ? 'Dependency' : 'Tool Call';
}

function normalizeSource(value: unknown): SourceKind {
  const normalized = stringValue(value).toLowerCase();
  if (normalized.includes('github')) return 'GitHub';
  if (normalized.includes('foundry')) return 'Foundry';
  if (normalized.includes('azure')) return 'Azure';
  if (normalized.includes('local')) return 'Local';
  return 'Policy API';
}

function normalizeEvidence(value: unknown): VerdictRow['evidence'] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    const evidence = item as Record<string, unknown>;
    return {
      source: stringValue(evidence.source) || 'pounce-policy',
      label: stringValue(evidence.label) || 'Policy evidence',
      url: stringValue(evidence.url) || null
    };
  });
}

function buildTimeline(verdicts: VerdictRow[]): TimelineRow[] {
  if (verdicts.length === 0) return [];

  const grouped = new Map<string, TimelineRow>();
  for (const row of verdicts.slice(0, 24)) {
    const name = row.type === 'Dependency' ? row.repository : row.item;
    const existing = grouped.get(name) ?? { name, source: row.source, points: [] };
    existing.points.push(row.verdict);
    grouped.set(name, existing);
  }

  return [...grouped.values()].slice(0, 6).map((row) => ({
    ...row,
    points: row.points.slice(0, 8)
  }));
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit'
  }).format(date);
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function numberValue(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && item.length > 0) : [];
}
