import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';

const statusPayload = {
  service: 'pounce-sentinel-policy-api',
  status: 'healthy',
  mode: 'azure-ready',
  integrations: {
    foundry: 'configured-by-openapi',
    github: 'action-ready',
    teams: 'bot-ready',
    azureAudit: 'cosmos'
  },
  feeds: [
    { name: 'seeded-malware-intel', status: 'fresh', updatedAgo: '1 min' },
    { name: 'security-advisories', status: 'fresh', updatedAgo: '3 min' }
  ]
};

const verdictsPayload = {
  statusCode: 200,
  count: 3,
  verdicts: [
    {
      auditId: 'ps-live-block',
      verdict: 'block',
      riskScore: 92,
      ecosystem: 'npm',
      packageName: 'event-stream',
      version: '3.3.7',
      source: 'github',
      repository: 'org/agent-service',
      actor: 'github-actions',
      reasons: ['Known malicious package'],
      evidence: [{ source: 'seeded-intel', label: 'Known malware fixture' }],
      recommendedVersion: null,
      policyId: 'known-malware',
      createdAt: new Date().toISOString()
    },
    {
      auditId: 'ps-live-warn',
      verdict: 'warn',
      riskScore: 58,
      ecosystem: 'npm',
      packageName: 'lodash',
      version: '^4.17.21',
      source: 'github',
      repository: 'org/web',
      actor: 'github-actions',
      reasons: ['Dependency version is not exact'],
      evidence: [{ source: 'pounce-policy', label: 'Exact-version policy' }],
      recommendedVersion: '4.17.21',
      policyId: 'exact-version-required',
      createdAt: new Date().toISOString()
    },
    {
      auditId: 'ps-live-allow',
      verdict: 'allow',
      riskScore: 12,
      ecosystem: 'npm',
      packageName: 'react',
      version: '19.2.0',
      source: 'github',
      repository: 'org/web',
      actor: 'github-actions',
      reasons: ['Exact version allowed'],
      evidence: [{ source: 'pounce-policy', label: 'Seeded local allow policy' }],
      recommendedVersion: '19.2.0',
      policyId: 'seeded-safe-baseline',
      createdAt: new Date().toISOString()
    }
  ]
};

describe('Pounce Sentinel dashboard', () => {
  beforeEach(() => {
    vi.stubGlobal('open', vi.fn());
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/v1/status')) {
        return jsonResponse(statusPayload);
      }
      if (url.endsWith('/v1/verdicts')) {
        return jsonResponse(verdictsPayload);
      }
      if (url.endsWith('/v1/exceptions') && init?.method === 'POST') {
        return jsonResponse({ statusCode: 202, exceptionId: 'ex-ps-live-block', status: 'pending-cloud-workflow' }, 202);
      }
      return jsonResponse({ error: 'not found' }, 404);
    }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('loads live policy API data into the queue', async () => {
    render(<App />);

    expect(await screen.findByText('Policy API healthy')).toBeInTheDocument();
    expect(screen.getAllByText('event-stream@3.3.7')).toHaveLength(2);
    expect(screen.getByText('lodash@^4.17.21')).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith('/api/v1/status', expect.any(Object));
    expect(fetch).toHaveBeenCalledWith('/api/v1/verdicts', expect.any(Object));
  });

  it('filters rows and updates the selected decision panel', async () => {
    render(<App />);

    await screen.findByText('lodash@^4.17.21');
    fireEvent.change(screen.getByLabelText('Verdict'), { target: { value: 'warn' } });

    await waitFor(() => expect(screen.queryByText('event-stream@3.3.7')).not.toBeInTheDocument());
    expect(screen.getAllByText('lodash@^4.17.21')).toHaveLength(2);

    fireEvent.change(screen.getByLabelText('Verdict'), { target: { value: 'all' } });
    fireEvent.click(screen.getAllByText('lodash@^4.17.21')[0]);

    expect(screen.getByText('exact-version-required')).toBeInTheDocument();
  });

  it('submits exception approvals through the dashboard API', async () => {
    render(<App />);

    await screen.findAllByText('event-stream@3.3.7');
    fireEvent.click(screen.getByText('Approve exception'));
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Temporary incident response approval' } });
    fireEvent.click(screen.getByText('Submit exception'));

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith('/api/v1/exceptions', expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('Temporary incident response approval')
      }));
    });
    expect(await screen.findByText('Exception requested for event-stream@3.3.7')).toBeInTheDocument();
  });
});

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}
