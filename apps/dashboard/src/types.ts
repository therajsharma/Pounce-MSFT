export type VerdictKind = 'allow' | 'warn' | 'block';
export type SourceKind = 'GitHub' | 'Foundry' | 'Azure' | 'Local' | 'Policy API';
export type VerdictType = 'Dependency' | 'Tool Call' | 'Repository';

export interface EvidenceItem {
  source: string;
  label: string;
  url?: string | null;
}

export interface VerdictRow {
  id: string;
  auditId: string;
  time: string;
  createdAt: string;
  verdict: VerdictKind;
  type: VerdictType;
  item: string;
  repository: string;
  source: SourceKind;
  riskScore: number;
  ecosystem?: string;
  packageName?: string;
  version?: string;
  actor?: string;
  policyId?: string;
  reasons: string[];
  evidence: EvidenceItem[];
  recommendedVersion?: string | null;
}

export interface TimelineRow {
  name: string;
  source: SourceKind;
  points: VerdictKind[];
}

export interface ServiceFeed {
  name: string;
  status: string;
  updatedAgo: string;
}

export interface ServiceStatus {
  service: string;
  status: string;
  mode: string;
  integrations: Record<string, string>;
  feeds: ServiceFeed[];
}

export interface ExceptionResponse {
  statusCode: number;
  exceptionId?: string;
  auditId?: string;
  approver?: string;
  status?: string;
  reason?: string;
  requestedAt?: string;
  error?: string;
}
