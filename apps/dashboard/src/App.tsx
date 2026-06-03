import {
  Activity,
  AlertTriangle,
  Bell,
  Box,
  Calendar,
  CheckCircle2,
  ChevronDown,
  FileText,
  Filter,
  GitBranch,
  Github,
  Home,
  LayoutDashboard,
  LockKeyhole,
  MoreHorizontal,
  RefreshCcw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X
} from 'lucide-react';
import { timelineRows, verdictRows } from './data';
import type { TimelineRow, VerdictKind, VerdictRow } from './types';

const selected = verdictRows[0];

export function App() {
  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Main navigation">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={24} />
          </div>
          <div>
            <strong>Pounce Sentinel</strong>
            <span>Agentic Supply-Chain Security</span>
          </div>
        </div>

        <nav className="nav-list">
          <NavItem icon={<Home size={18} />} label="Overview" active />
          <NavItem icon={<Shield size={18} />} label="Risk Queue" badge="12" />
          <NavItem icon={<Box size={18} />} label="Dependencies" />
          <NavItem icon={<Activity size={18} />} label="Tool Calls" />
          <NavItem icon={<GitBranch size={18} />} label="Repos" />
          <NavItem icon={<ShieldCheck size={18} />} label="Policies" />
          <NavItem icon={<LockKeyhole size={18} />} label="Exceptions" />
          <NavItem icon={<FileText size={18} />} label="Audit Log" />
          <NavItem icon={<LayoutDashboard size={18} />} label="Reports" />
          <NavItem icon={<Settings size={18} />} label="Settings" />
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <StatusStrip />
          <div className="top-actions">
            <button aria-label="Search"><Search size={20} /></button>
            <button aria-label="Notifications"><Bell size={20} /></button>
            <button aria-label="Settings"><Settings size={20} /></button>
            <button className="avatar">AB</button>
            <ChevronDown size={16} />
          </div>
        </header>

        <div className="content-grid">
          <section className="queue-column" aria-label="Risk queue">
            <div className="tabs">
              <button className="tab active">Risk Queue <span>12</span></button>
              <button className="tab">Dependencies</button>
              <button className="tab">Tool Calls</button>
              <button className="tab">Repos</button>
            </div>

            <div className="filters">
              <button className="icon-button"><Filter size={18} /></button>
              <SelectLabel label="All verdicts" />
              <SelectLabel label="All sources" />
              <SelectLabel label="All repos" />
              <SelectLabel label="Last 24 hours" icon={<Calendar size={16} />} />
              <button className="icon-button"><RefreshCcw size={18} /></button>
            </div>

            <VerdictTable rows={verdictRows} />
            <Timeline rows={timelineRows} />
          </section>

          <DecisionPanel row={selected} />
        </div>

        <footer className="healthbar">
          <Health label="Feeds" detail="Updated 1 min ago" />
          <Health label="Security advisories" detail="Updated 3 min ago" />
          <Health label="SBOMs" detail="Updated 2 min ago" />
          <Health label="Policy bundles" detail="Updated 2 min ago" />
          <div className="azure-health">
            <strong>Azure deployment</strong>
            <span><CheckCircle2 size={15} /> Healthy · East US</span>
          </div>
        </footer>
      </section>
    </main>
  );
}

function NavItem({ icon, label, active, badge }: { icon: React.ReactNode; label: string; active?: boolean; badge?: string }) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`}>
      {icon}
      <span>{label}</span>
      {badge ? <strong>{badge}</strong> : null}
    </button>
  );
}

function StatusStrip() {
  const items = [
    { icon: <ShieldCheck size={24} />, title: 'Protected', detail: 'All systems healthy' },
    { dot: true, title: 'Foundry tool live', detail: '1 agent tool active' },
    { dot: true, title: 'GitHub gate active', detail: 'Policy enforcement on' },
    { dot: true, title: 'Azure audit on', detail: 'Logging + monitoring' }
  ];

  return (
    <div className="status-strip">
      {items.map((item) => (
        <div className="status-card" key={item.title}>
          {item.dot ? <span className="status-dot" /> : item.icon}
          <div>
            <strong>{item.title}</strong>
            <span>{item.detail}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function SelectLabel({ label, icon }: { label: string; icon?: React.ReactNode }) {
  return (
    <button className="select-label">
      {label}
      {icon ?? <ChevronDown size={16} />}
    </button>
  );
}

function VerdictTable({ rows }: { rows: VerdictRow[] }) {
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Verdict</th>
            <th>Type</th>
            <th>Item</th>
            <th>Repository</th>
            <th>Source</th>
            <th>Risk Score</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className={row.id === selected.id ? 'selected' : ''}>
              <td>{row.time}</td>
              <td><VerdictPill verdict={row.verdict} /></td>
              <td>{row.type}</td>
              <td className="item-cell">{row.item}</td>
              <td>{row.repository}</td>
              <td><SourceLabel source={row.source} /></td>
              <td><RiskScore value={row.riskScore} verdict={row.verdict} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VerdictPill({ verdict }: { verdict: VerdictKind }) {
  const icon = verdict === 'block' ? <ShieldAlert size={15} /> : verdict === 'warn' ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />;
  return <span className={`verdict ${verdict}`}>{icon}{verdict[0].toUpperCase() + verdict.slice(1)}</span>;
}

function SourceLabel({ source }: { source: VerdictRow['source'] }) {
  if (source === 'GitHub') return <span className="source"><Github size={16} /> GitHub</span>;
  if (source === 'Azure') return <span className="source azure">A Azure</span>;
  return <span className="source foundry">F Foundry</span>;
}

function RiskScore({ value, verdict }: { value: number; verdict: VerdictKind }) {
  return <span className={`risk-score ${verdict}`}>{value}</span>;
}

function Timeline({ rows }: { rows: TimelineRow[] }) {
  return (
    <section className="timeline-card">
      <div className="section-header">
        <h2>Recent agent tool calls</h2>
        <SelectLabel label="Last 24 hours" />
      </div>
      <div className="timeline">
        {rows.map((row) => (
          <div className="timeline-row" key={row.name}>
            <span className="timeline-name">{row.name}</span>
            <div className="timeline-track">
              {row.points.map((point, index) => (
                <span className={`timeline-point ${point}`} key={`${row.name}-${index}`} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="legend">
        <span><i className="allow" /> Allow</span>
        <span><i className="warn" /> Warn</span>
        <span><i className="block" /> Block</span>
        <a href="#tool-calls">View all tool calls</a>
      </div>
    </section>
  );
}

function DecisionPanel({ row }: { row: VerdictRow }) {
  return (
    <aside className="decision-panel" aria-label="Decision detail">
      <div className="panel-title">
        <div>
          <span className="panel-icon"><ShieldAlert size={16} /></span>
          <strong>Blocked dependency</strong>
        </div>
        <X size={18} />
      </div>

      <h1>{row.item}</h1>
      <dl className="metadata">
        <div><dt>Repository</dt><dd>{row.repository}</dd></div>
        <div><dt>Source</dt><dd><SourceLabel source={row.source} /></dd></div>
        <div><dt>First seen</dt><dd>May 19, 2025 9:41 AM</dd></div>
        <div><dt>Policy</dt><dd>Supply Chain High Risk</dd></div>
        <div><dt>Risk score</dt><dd><span className="critical-score">92 Critical</span></dd></div>
        <div><dt>Verdict</dt><dd><VerdictPill verdict="block" /></dd></div>
      </dl>

      <div className="panel-tabs">
        <button className="active">Details</button>
        <button>Vulnerabilities <span>3</span></button>
        <button>Provenance</button>
        <button>Policy</button>
      </div>

      <section className="panel-section">
        <h2>Summary</h2>
        <ul className="finding-list">
          <li><Shield size={16} /> Known malicious package <span>Critical</span></li>
          <li><Activity size={16} /> Malicious behavior detected <span>Critical</span></li>
          <li><AlertTriangle size={16} /> High impact to agent runtime <span className="high">High</span></li>
        </ul>
      </section>

      <section className="panel-section">
        <h2>Evidence</h2>
        <p>Matches seeded malware signature, obfuscated code fixture, and known data exfiltration behavior.</p>
      </section>

      <section className="panel-section">
        <h2>Recommendation</h2>
        <p>Do not allow this dependency. Replace with a safe alternative or open an exception workflow.</p>
      </section>

      <div className="panel-actions">
        <button className="primary"><ShieldCheck size={17} /> Approve exception</button>
        <button><Github size={17} /> Open PR</button>
        <button className="icon-button"><MoreHorizontal size={17} /></button>
      </div>
    </aside>
  );
}

function Health({ label, detail }: { label: string; detail: string }) {
  return (
    <div className="health-item">
      <strong>{label}</strong>
      <span><i /> Fresh</span>
      <em>{detail}</em>
    </div>
  );
}

