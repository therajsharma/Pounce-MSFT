import type { TimelineRow, VerdictRow } from './types';

export const verdictRows: VerdictRow[] = [
  {
    id: 'ps-demo-block-event-stream',
    auditId: 'ps-demo-block-event-stream',
    time: '9:41:02 AM',
    createdAt: '2026-06-04T09:41:02Z',
    verdict: 'block',
    type: 'Dependency',
    item: 'event-stream@3.3.7',
    repository: 'org/agent-service',
    source: 'GitHub',
    riskScore: 92,
    ecosystem: 'npm',
    packageName: 'event-stream',
    version: '3.3.7',
    actor: 'github-actions',
    policyId: 'known-malware',
    reasons: ['Known malicious package', 'Malicious behavior detected', 'High impact to agent runtime'],
    evidence: [
      {
        source: 'seeded-intel',
        label: 'Matches seeded malware signature',
        url: 'https://example.invalid/pounce/demo-intel/event-stream'
      }
    ],
    recommendedVersion: null
  },
  {
    id: 'ps-demo-warn-minimist',
    auditId: 'ps-demo-warn-minimist',
    time: '9:37:18 AM',
    createdAt: '2026-06-04T09:37:18Z',
    verdict: 'warn',
    type: 'Dependency',
    item: 'minimist@1.2.8',
    repository: 'org/cli-tool',
    source: 'GitHub',
    riskScore: 45,
    ecosystem: 'npm',
    packageName: 'minimist',
    version: '1.2.8',
    actor: 'github-actions',
    policyId: 'manual-review',
    reasons: ['Version needs manual review', 'No active block policy matched'],
    evidence: [{ source: 'pounce-policy', label: 'Manual review policy' }],
    recommendedVersion: '1.2.8'
  },
  {
    id: 'ps-demo-allow-tool',
    auditId: 'ps-demo-allow-tool',
    time: '9:35:44 AM',
    createdAt: '2026-06-04T09:35:44Z',
    verdict: 'allow',
    type: 'Tool Call',
    item: 'm365_send_message',
    repository: 'org/agent-service',
    source: 'Foundry',
    riskScore: 18,
    actor: 'foundry-agent',
    policyId: 'tool-allow',
    reasons: ['Tool call matched allowed action policy'],
    evidence: [{ source: 'foundry', label: 'Allowed tool route' }],
    recommendedVersion: null
  },
  {
    id: 'ps-demo-warn-axios',
    auditId: 'ps-demo-warn-axios',
    time: '9:33:12 AM',
    createdAt: '2026-06-04T09:33:12Z',
    verdict: 'warn',
    type: 'Dependency',
    item: 'axios@1.8.2',
    repository: 'org/webhook-runner',
    source: 'GitHub',
    riskScore: 40,
    ecosystem: 'npm',
    packageName: 'axios',
    version: '1.8.2',
    actor: 'github-actions',
    policyId: 'seeded-safe-baseline',
    reasons: ['Dependency is allowed with warning'],
    evidence: [{ source: 'pounce-policy', label: 'Seeded warning policy' }],
    recommendedVersion: '1.8.2'
  },
  {
    id: 'ps-demo-allow-azure',
    auditId: 'ps-demo-allow-azure',
    time: '9:31:08 AM',
    createdAt: '2026-06-04T09:31:08Z',
    verdict: 'allow',
    type: 'Tool Call',
    item: 'azure_storage_write',
    repository: 'org/agent-service',
    source: 'Azure',
    riskScore: 22,
    actor: 'azure-agent',
    policyId: 'tool-allow',
    reasons: ['Storage action stayed inside approved resource group'],
    evidence: [{ source: 'azure-audit', label: 'Approved storage scope' }],
    recommendedVersion: null
  },
  {
    id: 'ps-demo-block-repo',
    auditId: 'ps-demo-block-repo',
    time: '9:28:55 AM',
    createdAt: '2026-06-04T09:28:55Z',
    verdict: 'block',
    type: 'Repository',
    item: 'org/infra-templates',
    repository: 'org/infra-templates',
    source: 'GitHub',
    riskScore: 88,
    actor: 'github-actions',
    policyId: 'repo-provenance-block',
    reasons: ['Repository provenance failed policy checks'],
    evidence: [{ source: 'github', label: 'Repository trust policy' }],
    recommendedVersion: null
  }
];

export const timelineRows: TimelineRow[] = [
  { name: 'm365_send_message', source: 'Foundry', points: ['allow', 'allow', 'allow', 'warn', 'allow', 'allow', 'allow', 'block'] },
  { name: 'github_create_pr', source: 'GitHub', points: ['allow', 'warn', 'allow', 'allow', 'allow', 'warn', 'allow', 'block'] },
  { name: 'azure_storage_write', source: 'Azure', points: ['allow', 'allow', 'allow', 'allow', 'allow', 'allow', 'allow', 'allow'] },
  { name: 'foundry_run_tool', source: 'Foundry', points: ['allow', 'allow', 'warn', 'allow', 'allow', 'allow', 'warn', 'allow'] },
  { name: 'github_check_run', source: 'GitHub', points: ['allow', 'allow', 'allow', 'allow', 'warn', 'allow', 'allow', 'block'] }
];
