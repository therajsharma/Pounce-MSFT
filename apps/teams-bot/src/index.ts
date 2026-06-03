import express from 'express';
import { commandHelp, parseCommand } from './commands.js';

const app = express();
app.use(express.json());

const apiBaseUrl = process.env.POUNCE_SENTINEL_API_BASE_URL ?? 'http://localhost:7071/api';
const port = Number(process.env.PORT ?? 3978);

app.get('/healthz', (_req, res) => {
  res.json({ status: 'healthy', service: 'pounce-sentinel-teams-bot' });
});

app.post('/api/messages', async (req, res) => {
  const text = String(req.body?.text ?? '');
  const command = parseCommand(text);

  if (command.kind === 'unknown') {
    res.json({ type: 'message', text: commandHelp() });
    return;
  }

  if (command.kind === 'status') {
    const status = await fetch(`${apiBaseUrl}/v1/status`).then((response) => response.json());
    res.json({ type: 'message', text: `Pounce Sentinel is ${status.status}. GitHub is ${status.integrations.github}.` });
    return;
  }

  if (command.kind === 'explain') {
    res.json({ type: 'message', text: `Verdict ${command.auditId}: open the dashboard decision panel for evidence and recommendation.` });
    return;
  }

  res.json({ type: 'message', text: `Exception request queued for ${command.auditId}. Reason: ${command.reason}` });
});

app.listen(port, () => {
  console.log(`Pounce Sentinel Teams bot listening on ${port}`);
});

