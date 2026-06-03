export type TeamsCommand =
  | { kind: 'status' }
  | { kind: 'explain'; auditId: string }
  | { kind: 'approve'; auditId: string; reason: string }
  | { kind: 'unknown'; text: string };

export function parseCommand(text: string): TeamsCommand {
  const normalized = text.trim();
  const [command, auditId, ...rest] = normalized.split(/\s+/);

  if (!command || command.toLowerCase() === 'status') {
    return { kind: 'status' };
  }

  if (command.toLowerCase() === 'explain' && auditId) {
    return { kind: 'explain', auditId };
  }

  if (command.toLowerCase() === 'approve' && auditId) {
    return { kind: 'approve', auditId, reason: rest.join(' ') || 'Approved from Teams demo flow' };
  }

  return { kind: 'unknown', text };
}

export function commandHelp(): string {
  return 'Try `status`, `explain <auditId>`, or `approve <auditId> <reason>`.';
}

