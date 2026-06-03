import { describe, expect, it } from 'vitest';
import { parseCommand } from './commands.js';

describe('Teams command parser', () => {
  it('parses status', () => {
    expect(parseCommand('status')).toEqual({ kind: 'status' });
  });

  it('parses explain', () => {
    expect(parseCommand('explain ps-123')).toEqual({ kind: 'explain', auditId: 'ps-123' });
  });

  it('parses approve with reason', () => {
    expect(parseCommand('approve ps-123 emergency fix')).toEqual({
      kind: 'approve',
      auditId: 'ps-123',
      reason: 'emergency fix'
    });
  });
});
