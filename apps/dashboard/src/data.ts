import type { TimelineRow, VerdictRow } from './types';

export const verdictRows: VerdictRow[] = [
  {
    id: 'ps-demo-block-event-stream',
    time: '9:41:02 AM',
    verdict: 'block',
    type: 'Dependency',
    item: 'event-stream@3.3.7',
    repository: 'org/agent-service',
    source: 'GitHub',
    riskScore: 92
  },
  {
    id: 'ps-demo-warn-minimist',
    time: '9:37:18 AM',
    verdict: 'warn',
    type: 'Dependency',
    item: 'minimist@1.2.8',
    repository: 'org/cli-tool',
    source: 'GitHub',
    riskScore: 45
  },
  {
    id: 'ps-demo-allow-tool',
    time: '9:35:44 AM',
    verdict: 'allow',
    type: 'Tool Call',
    item: 'm365_send_message',
    repository: 'org/agent-service',
    source: 'Foundry',
    riskScore: 18
  },
  {
    id: 'ps-demo-warn-axios',
    time: '9:33:12 AM',
    verdict: 'warn',
    type: 'Dependency',
    item: 'axios@1.8.2',
    repository: 'org/webhook-runner',
    source: 'GitHub',
    riskScore: 40
  },
  {
    id: 'ps-demo-allow-azure',
    time: '9:31:08 AM',
    verdict: 'allow',
    type: 'Tool Call',
    item: 'azure_storage_write',
    repository: 'org/agent-service',
    source: 'Azure',
    riskScore: 22
  },
  {
    id: 'ps-demo-block-repo',
    time: '9:28:55 AM',
    verdict: 'block',
    type: 'Repository',
    item: 'org/infra-templates',
    repository: 'org/infra-templates',
    source: 'GitHub',
    riskScore: 88
  }
];

export const timelineRows: TimelineRow[] = [
  { name: 'm365_send_message', source: 'Foundry', points: ['allow', 'allow', 'allow', 'warn', 'allow', 'allow', 'allow', 'block'] },
  { name: 'github_create_pr', source: 'GitHub', points: ['allow', 'warn', 'allow', 'allow', 'allow', 'warn', 'allow', 'block'] },
  { name: 'azure_storage_write', source: 'Azure', points: ['allow', 'allow', 'allow', 'allow', 'allow', 'allow', 'allow', 'allow'] },
  { name: 'foundry_run_tool', source: 'Foundry', points: ['allow', 'allow', 'warn', 'allow', 'allow', 'allow', 'warn', 'allow'] },
  { name: 'github_check_run', source: 'GitHub', points: ['allow', 'allow', 'allow', 'allow', 'warn', 'allow', 'allow', 'block'] }
];

