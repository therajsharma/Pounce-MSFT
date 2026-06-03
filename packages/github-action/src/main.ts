import * as core from '@actions/core';
import * as github from '@actions/github';
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { extractPackageJsonDependencies, extractRequirementsDependencies } from './diff.js';

interface VerdictResponse {
  verdict: 'allow' | 'warn' | 'block';
  riskScore: number;
  packageName: string;
  version: string;
  reasons: string[];
  auditId: string;
}

async function run(): Promise<void> {
  const apiBaseUrl = core.getInput('api-base-url', { required: true }).replace(/\/$/, '');
  const apiKey = core.getInput('api-key');
  const manifestPath = core.getInput('manifest-path') || 'package.json';
  const manifest = await readFile(manifestPath, 'utf-8');
  const dependencies = basename(manifestPath) === 'requirements.txt'
    ? extractRequirementsDependencies(manifest)
    : extractPackageJsonDependencies(manifest);

  const blocked: VerdictResponse[] = [];

  for (const dependency of dependencies) {
    const response = await fetch(`${apiBaseUrl}/v1/vet-dependency`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(apiKey ? { 'x-functions-key': apiKey } : {})
      },
      body: JSON.stringify({
        ...dependency,
        source: 'github',
        repository: github.context.repo.owner + '/' + github.context.repo.repo,
        actor: github.context.actor
      })
    });

    if (!response.ok) {
      throw new Error(`Pounce API returned ${response.status}`);
    }

    const verdict = (await response.json()) as VerdictResponse;
    core.info(`${verdict.verdict.toUpperCase()} ${verdict.packageName}@${verdict.version}: ${verdict.reasons.join('; ')}`);

    if (verdict.verdict === 'block') {
      blocked.push(verdict);
    }
  }

  if (blocked.length > 0) {
    core.setFailed(`Pounce Sentinel blocked ${blocked.length} dependency change(s): ${blocked.map((item) => item.auditId).join(', ')}`);
  }
}

run().catch((error: unknown) => {
  core.setFailed(error instanceof Error ? error.message : String(error));
});

