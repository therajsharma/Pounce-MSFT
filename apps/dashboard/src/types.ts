export type VerdictKind = 'allow' | 'warn' | 'block';

export interface VerdictRow {
  id: string;
  time: string;
  verdict: VerdictKind;
  type: 'Dependency' | 'Tool Call' | 'Repository';
  item: string;
  repository: string;
  source: 'GitHub' | 'Foundry' | 'Azure';
  riskScore: number;
}

export interface TimelineRow {
  name: string;
  source: 'GitHub' | 'Foundry' | 'Azure';
  points: VerdictKind[];
}

