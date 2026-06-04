import {
  Activity,
  AlertTriangle,
  Bell,
  Box,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ExternalLink,
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
import { useEffect, useMemo, useState } from 'react';
import { fallbackDashboardData, loadDashboardData, requestException } from './api';
import type { DashboardData } from './api';
import type { FormEvent } from 'react';
import type { ServiceFeed, SourceKind, TimelineRow, VerdictKind, VerdictRow, VerdictType } from './types';

type QueueTab = 'Risk Queue' | 'Dependencies' | 'Tool Calls' | 'Repos';
type PanelTab = 'Details' | 'Vulnerabilities' | 'Provenance' | 'Policy';
type SidebarItem = 'Overview' | 'Risk Queue' | 'Dependencies' | 'Tool Calls' | 'Repos' | 'Policies' | 'Exceptions' | 'Audit Log' | 'Reports' | 'Settings';

const queueTabs: QueueTab[] = ['Risk Queue', 'Dependencies', 'Tool Calls', 'Repos'];
const panelTabs: PanelTab[] = ['Details', 'Vulnerabilities', 'Provenance', 'Policy'];

export function App() {
  const [data, setData] = useState<DashboardData>(() => fallbackDashboardData());
  const [selectedId, setSelectedId] = useState<string | null>(data.verdicts[0]?.id ?? null);
  const [activeNav, setActiveNav] = useState<SidebarItem>('Overview');
  const [activeTab, setActiveTab] = useState<QueueTab>('Risk Queue');
  const [panelTab, setPanelTab] = useState<PanelTab>('Details');
  const [verdictFilter, setVerdictFilter] = useState<'all' | VerdictKind>('all');
  const [sourceFilter, setSourceFilter] = useState<'all' | SourceKind>('all');
  const [repoFilter, setRepoFilter] = useState('all');
  const [timeFilter, setTimeFilter] = useState('24h');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [showSearch, setShowSearch] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [exceptionOpen, setExceptionOpen] = useState(false);
  const [exceptionReason, setExceptionReason] = useState('');
  const [submittingException, setSubmittingException] = useState(false);

  useEffect(() => {
    void refreshDashboard({ initial: true });
  }, []);

  const counts = useMemo(() => countVerdicts(data.verdicts), [data.verdicts]);
  const repositories = useMemo(() => ['all', ...new Set(data.verdicts.map((row) => row.repository))], [data.verdicts]);
  const sources = useMemo(() => ['all', ...new Set(data.verdicts.map((row) => row.source))] as Array<'all' | SourceKind>, [data.verdicts]);
  const selected = data.verdicts.find((row) => row.id === selectedId) ?? data.verdicts[0] ?? null;

  const visibleRows = useMemo(() => {
    return data.verdicts
      .filter((row) => matchesTab(row, activeTab))
      .filter((row) => verdictFilter === 'all' || row.verdict === verdictFilter)
      .filter((row) => sourceFilter === 'all' || row.source === sourceFilter)
      .filter((row) => repoFilter === 'all' || row.repository === repoFilter)
      .filter((row) => matchesTime(row, timeFilter))
      .filter((row) => matchesQuery(row, query));
  }, [activeTab, data.verdicts, query, repoFilter, sourceFilter, timeFilter, verdictFilter]);

  useEffect(() => {
    if (visibleRows.length > 0 && !visibleRows.some((row) => row.id === selectedId)) {
      setSelectedId(visibleRows[0].id);
    }
  }, [selectedId, visibleRows]);

  async function refreshDashboard(options: { initial?: boolean } = {}) {
    if (options.initial) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    try {
      const nextData = await loadDashboardData();
      setData(nextData);
      setError(null);
      setSelectedId((current) => current && nextData.verdicts.some((row) => row.id === current) ? current : nextData.verdicts[0]?.id ?? null);
      if (!options.initial) setToast('Dashboard refreshed from policy API');
    } catch (loadError) {
      const message = loadError instanceof Error ? loadError.message : String(loadError);
      setError(message);
      setData((current) => current.fromFallback ? current : fallbackDashboardData());
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  async function submitException(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || exceptionReason.trim().length === 0) return;

    setSubmittingException(true);
    try {
      const response = await requestException(selected.auditId, exceptionReason.trim());
      if (response.error) throw new Error(response.error);
      setToast(`Exception requested for ${selected.item}`);
      setExceptionOpen(false);
      setExceptionReason('');
    } catch (submitError) {
      setToast(submitError instanceof Error ? submitError.message : String(submitError));
    } finally {
      setSubmittingException(false);
    }
  }

  function openPullRequest() {
    if (!selected) return;
    const repo = selected.repository.includes('/') ? selected.repository : 'therajsharma/Pounce-MSFT';
    const title = encodeURIComponent(`Remediate ${selected.item}`);
    const branch = slug(`pounce-remediate-${selected.item}`);
    const url = `https://github.com/${repo}/compare/main...${branch}?quick_pull=1&title=${title}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  function selectQueue(tab: QueueTab, nav: SidebarItem = tab) {
    setActiveNav(nav);
    setActiveTab(tab);
    setShowSettings(false);
    setShowNotifications(false);
  }

  function selectAction(nav: SidebarItem, action: () => void) {
    setActiveNav(nav);
    setShowSettings(false);
    setShowNotifications(false);
    action();
  }

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
          <NavItem icon={<Home size={18} />} label="Overview" active={activeNav === 'Overview'} onClick={() => selectQueue('Risk Queue', 'Overview')} />
          <NavItem icon={<Shield size={18} />} label="Risk Queue" badge={String(counts.block + counts.warn)} active={activeNav === 'Risk Queue'} onClick={() => selectQueue('Risk Queue')} />
          <NavItem icon={<Box size={18} />} label="Dependencies" active={activeNav === 'Dependencies'} onClick={() => selectQueue('Dependencies')} />
          <NavItem icon={<Activity size={18} />} label="Tool Calls" active={activeNav === 'Tool Calls'} onClick={() => selectQueue('Tool Calls')} />
          <NavItem icon={<GitBranch size={18} />} label="Repos" active={activeNav === 'Repos'} onClick={() => selectQueue('Repos')} />
          <NavItem icon={<ShieldCheck size={18} />} label="Policies" active={activeNav === 'Policies'} onClick={() => selectAction('Policies', () => setPanelTab('Policy'))} />
          <NavItem icon={<LockKeyhole size={18} />} label="Exceptions" active={activeNav === 'Exceptions'} onClick={() => selectAction('Exceptions', () => setExceptionOpen(true))} />
          <NavItem icon={<FileText size={18} />} label="Audit Log" active={activeNav === 'Audit Log'} onClick={() => selectAction('Audit Log', () => setToast(`${data.verdicts.length} audit records loaded`))} />
          <NavItem icon={<LayoutDashboard size={18} />} label="Reports" active={activeNav === 'Reports'} onClick={() => selectAction('Reports', () => setToast(`${counts.block} blocked, ${counts.warn} warnings, ${counts.allow} allowed`))} />
          <NavItem icon={<Settings size={18} />} label="Settings" active={activeNav === 'Settings'} onClick={() => {
            setActiveNav('Settings');
            setShowNotifications(false);
            setShowSettings((value) => !value);
          }} />
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <StatusStrip status={data.status} counts={counts} fallback={data.fromFallback} />
          <div className="top-actions">
            {showSearch ? (
              <label className="top-search">
                <Search size={16} />
                <input aria-label="Search verdicts" value={query} onChange={(event) => setQuery(event.target.value)} autoFocus />
              </label>
            ) : null}
            <button aria-label="Search" onClick={() => setShowSearch((value) => !value)}><Search size={20} /></button>
            <button aria-label="Notifications" onClick={() => setShowNotifications((value) => !value)}><Bell size={20} /></button>
            <button aria-label="Settings" onClick={() => {
              setActiveNav('Settings');
              setShowNotifications(false);
              setShowSettings((value) => !value);
            }}><Settings size={20} /></button>
            <button className="avatar" aria-label="Dashboard user">AB</button>
            <ChevronDown size={16} />
          </div>
          {showNotifications ? <Popover title="Notifications" lines={[`${counts.block} blocked verdicts`, `${counts.warn} warnings need review`, error ? 'API fallback is active' : 'Policy API is reachable']} /> : null}
          {showSettings ? <Popover title="Runtime" lines={[`Mode: ${data.status.mode}`, `Service: ${data.status.service}`, `Records: ${data.verdicts.length}`]} /> : null}
        </header>

        <div className="content-grid">
          <section className="queue-column" aria-label="Risk queue">
            <div className="tabs">
              {queueTabs.map((tab) => (
                <button key={tab} className={`tab ${tab === activeTab ? 'active' : ''}`} onClick={() => selectQueue(tab)}>
                  {tab} {tab === 'Risk Queue' ? <span>{counts.block + counts.warn}</span> : null}
                </button>
              ))}
            </div>

            <div className="filters">
              <button className="icon-button" aria-label="Clear filters" onClick={() => {
                setVerdictFilter('all');
                setSourceFilter('all');
                setRepoFilter('all');
                setTimeFilter('24h');
                setQuery('');
              }}><Filter size={18} /></button>
              <SelectControl label="Verdict" value={verdictFilter} onChange={(value) => setVerdictFilter(value as 'all' | VerdictKind)} options={['all', 'block', 'warn', 'allow']} />
              <SelectControl label="Source" value={sourceFilter} onChange={(value) => setSourceFilter(value as 'all' | SourceKind)} options={sources} />
              <SelectControl label="Repository" value={repoFilter} onChange={setRepoFilter} options={repositories} />
              <SelectControl label="Window" value={timeFilter} onChange={setTimeFilter} options={['24h', '7d', 'all']} icon={<Calendar size={16} />} />
              <button className="icon-button" aria-label="Refresh dashboard" disabled={refreshing} onClick={() => void refreshDashboard()}>
                <RefreshCcw size={18} />
              </button>
            </div>

            {error ? <Banner tone="warn" message={`Live API fallback active: ${error}`} /> : null}
            {loading ? <Banner tone="info" message="Loading live policy data..." /> : null}
            <VerdictTable rows={visibleRows} selectedId={selected?.id} onSelect={setSelectedId} />
            <Timeline rows={data.timeline} />
          </section>

          {selected ? (
            <DecisionPanel
              row={selected}
              activeTab={panelTab}
              onTabChange={setPanelTab}
              onApprove={() => setExceptionOpen(true)}
              onOpenPr={openPullRequest}
            />
          ) : (
            <aside className="decision-panel empty-state" aria-label="Decision detail">
              <strong>No matching verdicts</strong>
              <p>Adjust filters or refresh the dashboard.</p>
            </aside>
          )}
        </div>

        <footer className="healthbar">
          <FeedHealth feeds={data.status.feeds} />
          <div className="azure-health">
            <strong>Azure deployment</strong>
            <span><CheckCircle2 size={15} /> {data.status.status} · {data.status.mode}</span>
          </div>
        </footer>
      </section>

      {exceptionOpen && selected ? (
        <div className="modal-backdrop" role="presentation">
          <form className="modal" role="dialog" aria-modal="true" aria-labelledby="exception-title" onSubmit={submitException}>
            <div className="modal-header">
              <strong id="exception-title">Approve exception</strong>
              <button type="button" className="icon-button" aria-label="Close exception dialog" onClick={() => setExceptionOpen(false)}><X size={16} /></button>
            </div>
            <p>{selected.item} in {selected.repository}</p>
            <label>
              Reason
              <textarea value={exceptionReason} onChange={(event) => setExceptionReason(event.target.value)} required rows={4} />
            </label>
            <div className="panel-actions">
              <button type="submit" className="primary" disabled={submittingException || exceptionReason.trim().length === 0}>
                {submittingException ? 'Submitting...' : 'Submit exception'}
              </button>
              <button type="button" onClick={() => setExceptionOpen(false)}>Cancel</button>
            </div>
          </form>
        </div>
      ) : null}

      {toast ? <button className="toast" onClick={() => setToast(null)}>{toast}</button> : null}
    </main>
  );
}

function NavItem({ icon, label, active, badge, onClick }: { icon: React.ReactNode; label: string; active?: boolean; badge?: string; onClick: () => void }) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>
      {icon}
      <span>{label}</span>
      {badge ? <strong>{badge}</strong> : null}
    </button>
  );
}

function StatusStrip({ status, counts, fallback }: { status: DashboardData['status']; counts: ReturnType<typeof countVerdicts>; fallback: boolean }) {
  const healthy = status.status === 'healthy' && !fallback;
  const items = [
    { icon: healthy ? <ShieldCheck size={24} /> : <AlertTriangle size={24} />, title: healthy ? 'Protected' : 'Fallback mode', detail: healthy ? 'Policy API healthy' : 'Using demo backup' },
    { dot: true, title: 'Foundry tool', detail: status.integrations.foundry ?? 'not configured' },
    { dot: true, title: 'GitHub gate', detail: `${counts.block} blocks · ${counts.warn} warnings` },
    { dot: true, title: 'Azure audit', detail: status.integrations.azureAudit ?? status.mode }
  ];

  return (
    <div className="status-strip">
      {items.map((item) => (
        <div className="status-card" key={item.title}>
          {item.dot ? <span className={`status-dot ${healthy ? '' : 'warn'}`} /> : item.icon}
          <div>
            <strong>{item.title}</strong>
            <span>{item.detail}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function SelectControl({ label, value, options, icon, onChange }: { label: string; value: string; options: string[]; icon?: React.ReactNode; onChange: (value: string) => void }) {
  return (
    <label className="select-label">
      <span className="sr-only">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
        {options.map((option) => <option key={option} value={option}>{formatOption(option)}</option>)}
      </select>
      {icon ?? <ChevronDown size={16} />}
    </label>
  );
}

function VerdictTable({ rows, selectedId, onSelect }: { rows: VerdictRow[]; selectedId?: string; onSelect: (id: string) => void }) {
  if (rows.length === 0) {
    return <div className="table-shell empty-state">No verdicts match the current filters.</div>;
  }

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
            <tr key={row.id} className={row.id === selectedId ? 'selected' : ''} onClick={() => onSelect(row.id)}>
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
  if (source === 'Foundry') return <span className="source foundry">F Foundry</span>;
  return <span className="source">{source}</span>;
}

function RiskScore({ value, verdict }: { value: number; verdict: VerdictKind }) {
  return <span className={`risk-score ${verdict}`}>{value}</span>;
}

function Timeline({ rows }: { rows: TimelineRow[] }) {
  return (
    <section className="timeline-card" id="tool-calls">
      <div className="section-header">
        <h2>Recent policy activity</h2>
        <span className="mini-label">Live audit trail</span>
      </div>
      {rows.length === 0 ? <p className="muted">No policy activity loaded yet.</p> : (
        <div className="timeline">
          {rows.map((row) => (
            <div className="timeline-row" key={row.name}>
              <span className="timeline-name">{row.name}</span>
              <div className="timeline-track" aria-label={`${row.name} verdict history`}>
                {row.points.map((point, index) => (
                  <span className={`timeline-point ${point}`} key={`${row.name}-${index}`} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="legend">
        <span><i className="allow" /> Allow</span>
        <span><i className="warn" /> Warn</span>
        <span><i className="block" /> Block</span>
        <a href="#tool-calls">View all tool calls</a>
      </div>
    </section>
  );
}

function DecisionPanel({ row, activeTab, onTabChange, onApprove, onOpenPr }: { row: VerdictRow; activeTab: PanelTab; onTabChange: (tab: PanelTab) => void; onApprove: () => void; onOpenPr: () => void }) {
  return (
    <aside className="decision-panel" aria-label="Decision detail">
      <div className="panel-title">
        <div>
          <span className={`panel-icon ${row.verdict}`}><ShieldAlert size={16} /></span>
          <strong>{row.verdict === 'block' ? 'Blocked' : row.verdict === 'warn' ? 'Needs review' : 'Allowed'} {row.type.toLowerCase()}</strong>
        </div>
        <span className="audit-id">{row.auditId}</span>
      </div>

      <h1>{row.item}</h1>
      <dl className="metadata">
        <div><dt>Repository</dt><dd>{row.repository}</dd></div>
        <div><dt>Source</dt><dd><SourceLabel source={row.source} /></dd></div>
        <div><dt>First seen</dt><dd>{formatDateTime(row.createdAt)}</dd></div>
        <div><dt>Policy</dt><dd>{row.policyId ?? 'policy-api'}</dd></div>
        <div><dt>Risk score</dt><dd><span className="critical-score">{row.riskScore} {scoreLabel(row.riskScore)}</span></dd></div>
        <div><dt>Verdict</dt><dd><VerdictPill verdict={row.verdict} /></dd></div>
      </dl>

      <div className="panel-tabs">
        {panelTabs.map((tab) => (
          <button key={tab} className={tab === activeTab ? 'active' : ''} onClick={() => onTabChange(tab)}>
            {tab}{tab === 'Vulnerabilities' ? <span>{Math.max(row.reasons.length, row.evidence.length)}</span> : null}
          </button>
        ))}
      </div>

      <PanelContent tab={activeTab} row={row} />

      <div className="panel-actions">
        <button className="primary" onClick={onApprove}><ShieldCheck size={17} /> Approve exception</button>
        <button onClick={onOpenPr}><Github size={17} /> Open PR</button>
        <button className="icon-button" aria-label="More actions" onClick={() => navigator.clipboard?.writeText(row.auditId)}><MoreHorizontal size={17} /></button>
      </div>
    </aside>
  );
}

function PanelContent({ tab, row }: { tab: PanelTab; row: VerdictRow }) {
  if (tab === 'Vulnerabilities') {
    return (
      <section className="panel-section">
        <h2>Signals</h2>
        <ul className="finding-list">
          {(row.reasons.length > 0 ? row.reasons : ['No blocking reasons recorded']).map((reason) => (
            <li key={reason}><AlertTriangle size={16} /> {reason} <span className={row.verdict === 'warn' ? 'high' : ''}>{scoreLabel(row.riskScore)}</span></li>
          ))}
        </ul>
      </section>
    );
  }

  if (tab === 'Provenance') {
    return (
      <section className="panel-section">
        <h2>Evidence</h2>
        {row.evidence.length === 0 ? <p>No evidence links were returned for this verdict.</p> : (
          <ul className="evidence-list">
            {row.evidence.map((item) => (
              <li key={`${item.source}-${item.label}`}>
                <strong>{item.source}</strong>
                {item.url ? <a href={item.url} target="_blank" rel="noreferrer">{item.label} <ExternalLink size={13} /></a> : <span>{item.label}</span>}
              </li>
            ))}
          </ul>
        )}
      </section>
    );
  }

  if (tab === 'Policy') {
    return (
      <section className="panel-section">
        <h2>Policy</h2>
        <p>{row.policyId ?? 'No policy id returned'} decided this verdict for {row.actor ?? 'unknown actor'}.</p>
        <p>{row.recommendedVersion ? `Recommended version: ${row.recommendedVersion}` : 'No safe replacement is attached to this verdict.'}</p>
      </section>
    );
  }

  return (
    <>
      <section className="panel-section">
        <h2>Summary</h2>
        <ul className="finding-list">
          {(row.reasons.length > 0 ? row.reasons.slice(0, 3) : ['Verdict returned by policy API']).map((reason) => (
            <li key={reason}><Shield size={16} /> {reason} <span className={row.verdict === 'warn' ? 'high' : ''}>{scoreLabel(row.riskScore)}</span></li>
          ))}
        </ul>
      </section>

      <section className="panel-section">
        <h2>Recommendation</h2>
        <p>{recommendation(row)}</p>
      </section>
    </>
  );
}

function FeedHealth({ feeds }: { feeds: ServiceFeed[] }) {
  const visibleFeeds = feeds.length > 0 ? feeds : [{ name: 'policy-api', status: 'unknown', updatedAgo: 'unknown' }];
  return visibleFeeds.slice(0, 4).map((feed) => (
    <div className="health-item" key={feed.name}>
      <strong>{feed.name}</strong>
      <span><i /> {feed.status}</span>
      <em>Updated {feed.updatedAgo} ago</em>
    </div>
  ));
}

function Banner({ tone, message }: { tone: 'info' | 'warn'; message: string }) {
  return <div className={`banner ${tone}`} role="status">{message}</div>;
}

function Popover({ title, lines }: { title: string; lines: string[] }) {
  return (
    <div className="popover" role="status">
      <strong>{title}</strong>
      {lines.map((line) => <span key={line}>{line}</span>)}
    </div>
  );
}

function countVerdicts(rows: VerdictRow[]) {
  return rows.reduce((counts, row) => {
    counts[row.verdict] += 1;
    return counts;
  }, { allow: 0, warn: 0, block: 0 });
}

function matchesTab(row: VerdictRow, tab: QueueTab): boolean {
  if (tab === 'Dependencies') return row.type === 'Dependency';
  if (tab === 'Tool Calls') return row.type === 'Tool Call';
  if (tab === 'Repos') return row.type === 'Repository';
  return row.verdict !== 'allow';
}

function matchesTime(row: VerdictRow, filter: string): boolean {
  if (filter === 'all') return true;
  const timestamp = new Date(row.createdAt).getTime();
  if (Number.isNaN(timestamp)) return true;
  const windowMs = filter === '7d' ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
  return Date.now() - timestamp <= windowMs;
}

function matchesQuery(row: VerdictRow, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  return [row.item, row.repository, row.source, row.policyId, row.actor, row.auditId].some((value) => value?.toLowerCase().includes(normalized));
}

function formatOption(value: string): string {
  if (value === 'all') return 'All';
  if (value === '24h') return 'Last 24 hours';
  if (value === '7d') return 'Last 7 days';
  return value;
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  }).format(date);
}

function scoreLabel(score: number): string {
  if (score >= 80) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

function recommendation(row: VerdictRow): string {
  if (row.verdict === 'block') return row.recommendedVersion ? `Replace with ${row.recommendedVersion} before merging.` : 'Do not allow this dependency or action without an approved exception.';
  if (row.verdict === 'warn') return 'Review the evidence and approve only if the runtime owner accepts the risk.';
  return 'No action required. Keep the audit record for traceability.';
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
}
