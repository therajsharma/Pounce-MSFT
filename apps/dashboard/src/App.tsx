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
type DashboardSettings = {
  defaultWindow: string;
  autoRefresh: boolean;
  notifyBlocks: boolean;
  compactRows: boolean;
  riskThreshold: number;
};
type ReportGroup = {
  name: string;
  total: number;
  block: number;
  warn: number;
  allow: number;
  maxRisk: number;
};
type ReportData = {
  total: number;
  counts: ReturnType<typeof countVerdicts>;
  averageRisk: number;
  critical: number;
  high: number;
  repositories: ReportGroup[];
  sources: ReportGroup[];
  policies: ReportGroup[];
  types: ReportGroup[];
};

const queueTabs: QueueTab[] = ['Risk Queue', 'Dependencies', 'Tool Calls', 'Repos'];
const panelTabs: PanelTab[] = ['Details', 'Vulnerabilities', 'Provenance', 'Policy'];
const settingsStorageKey = 'pounce-dashboard-settings';
const defaultDashboardSettings: DashboardSettings = {
  defaultWindow: '24h',
  autoRefresh: true,
  notifyBlocks: true,
  compactRows: false,
  riskThreshold: 70
};

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
  const [settings, setSettings] = useState<DashboardSettings>(() => loadDashboardSettings());
  const [copyFallbackText, setCopyFallbackText] = useState<string | null>(null);
  const [exceptionOpen, setExceptionOpen] = useState(false);
  const [exceptionReason, setExceptionReason] = useState('');
  const [submittingException, setSubmittingException] = useState(false);

  useEffect(() => {
    void refreshDashboard({ initial: true });
  }, []);

  useEffect(() => {
    if (!settings.autoRefresh) return undefined;
    const interval = window.setInterval(() => void refreshDashboard(), 30_000);
    return () => window.clearInterval(interval);
  }, [settings.autoRefresh]);

  const counts = useMemo(() => countVerdicts(data.verdicts), [data.verdicts]);
  const repositories = useMemo(() => ['all', ...new Set(data.verdicts.map((row) => row.repository))], [data.verdicts]);
  const sources = useMemo(() => ['all', ...new Set(data.verdicts.map((row) => row.source))] as Array<'all' | SourceKind>, [data.verdicts]);
  const selected = data.verdicts.find((row) => row.id === selectedId) ?? data.verdicts[0] ?? null;
  const report = useMemo(() => buildReport(data.verdicts), [data.verdicts]);

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
    setShowNotifications(false);
  }

  function selectAction(nav: SidebarItem, action: () => void) {
    setActiveNav(nav);
    setShowNotifications(false);
    action();
  }

  async function copyReportSummary() {
    const summary = reportSummary(report, data.status.mode);
    try {
      await writeClipboardText(summary);
      setToast('Report summary copied');
    } catch {
      setCopyFallbackText(summary);
      setToast('Summary ready to copy manually');
    }
  }

  function exportReportCsv() {
    const csv = toCsv(data.verdicts);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `pounce-report-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
    setToast('Report CSV exported');
  }

  function saveSettings() {
    persistDashboardSettings(settings);
    setTimeFilter(settings.defaultWindow);
    setToast('Settings saved');
  }

  function resetSettings() {
    setSettings(defaultDashboardSettings);
    persistDashboardSettings(defaultDashboardSettings);
    setTimeFilter(defaultDashboardSettings.defaultWindow);
    setToast('Settings reset');
  }

  return (
    <main className={`app-shell ${settings.compactRows ? 'compact' : ''}`}>
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
          <NavItem icon={<LayoutDashboard size={18} />} label="Reports" active={activeNav === 'Reports'} onClick={() => selectAction('Reports', () => undefined)} />
          <NavItem icon={<Settings size={18} />} label="Settings" active={activeNav === 'Settings'} onClick={() => {
            setActiveNav('Settings');
            setShowNotifications(false);
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
            }}><Settings size={20} /></button>
            <button className="avatar" aria-label="Dashboard user">AB</button>
            <ChevronDown size={16} />
          </div>
          {showNotifications ? <Popover title="Notifications" lines={[settings.notifyBlocks ? `${counts.block} blocked verdicts` : 'Block notifications muted', `${counts.warn} warnings need review`, error ? 'API fallback is active' : 'Policy API is reachable']} /> : null}
        </header>

        <div className={`content-grid ${activeNav === 'Reports' || activeNav === 'Settings' ? 'single-view' : ''}`}>
          {activeNav === 'Reports' ? (
            <ReportsView report={report} mode={data.status.mode} rows={data.verdicts} threshold={settings.riskThreshold} onCopySummary={() => void copyReportSummary()} onExportCsv={exportReportCsv} />
          ) : activeNav === 'Settings' ? (
            <SettingsView
              status={data.status}
              settings={settings}
              onSettingsChange={setSettings}
              onRefresh={() => void refreshDashboard()}
              onSave={saveSettings}
              onReset={resetSettings}
              records={data.verdicts.length}
              refreshing={refreshing}
            />
          ) : (
            <>
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
            </>
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

      {copyFallbackText ? (
        <div className="modal-backdrop" role="presentation">
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="copy-fallback-title">
            <div className="modal-header">
              <strong id="copy-fallback-title">Report summary</strong>
              <button type="button" className="icon-button" aria-label="Close report summary" onClick={() => setCopyFallbackText(null)}><X size={16} /></button>
            </div>
            <p>Clipboard access was blocked by the browser. The generated summary is ready below.</p>
            <label>
              Summary
              <textarea value={copyFallbackText} readOnly rows={8} onFocus={(event) => event.currentTarget.select()} />
            </label>
            <div className="panel-actions">
              <button type="button" className="primary" onClick={() => setCopyFallbackText(null)}>Done</button>
            </div>
          </div>
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
      {feed.trustState ? <em>{formatOption(feed.trustState)} · {feed.activeItemCount ?? 0} items</em> : null}
      {feed.warnings?.slice(0, 1).map((warning) => (
        <em className="feed-warning" key={`${feed.name}-${warning.code ?? warning.detail}`}>{warning.detail ?? warning.code}</em>
      ))}
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

function ReportsView({ report, mode, rows, threshold, onCopySummary, onExportCsv }: { report: ReportData; mode: string; rows: VerdictRow[]; threshold: number; onCopySummary: () => void; onExportCsv: () => void }) {
  const highRiskRows = rows.filter((row) => row.riskScore >= threshold).slice(0, 6);

  return (
    <section className="workspace-view" aria-labelledby="reports-title">
      <div className="view-header">
        <div>
          <span className="mini-label">Security reporting</span>
          <h1 id="reports-title">Reports</h1>
          <p>Policy verdicts, blocked supply-chain events, and remediation targets from the live dashboard feed.</p>
        </div>
        <div className="panel-actions view-actions">
          <button type="button" onClick={onCopySummary}><FileText size={17} /> Copy summary</button>
          <button type="button" className="primary" onClick={onExportCsv}><LayoutDashboard size={17} /> Export CSV</button>
        </div>
      </div>

      <div className="metric-grid">
        <MetricCard icon={<ShieldCheck size={20} />} label="Total verdicts" value={report.total} detail={`${mode} runtime`} />
        <MetricCard icon={<ShieldAlert size={20} />} label="Blocked" value={report.counts.block} detail={`${formatPercent(report.counts.block, report.total)} of feed`} tone="block" />
        <MetricCard icon={<AlertTriangle size={20} />} label="Warnings" value={report.counts.warn} detail={`${formatPercent(report.counts.warn, report.total)} need review`} tone="warn" />
        <MetricCard icon={<Activity size={20} />} label="Average risk" value={report.averageRisk} detail={`${report.critical} critical · ${report.high} high`} />
      </div>

      <section className="report-panel">
        <div className="section-header">
          <h2>Verdict distribution</h2>
          <span className="mini-label">{report.total} records</span>
        </div>
        <DistributionBar report={report} />
        <div className="distribution-legend">
          <span><i className="block" /> Block {report.counts.block}</span>
          <span><i className="warn" /> Warn {report.counts.warn}</span>
          <span><i className="allow" /> Allow {report.counts.allow}</span>
        </div>
      </section>

      <div className="report-grid">
        <section className="report-panel">
          <div className="section-header">
            <h2>Top repositories</h2>
            <span className="mini-label">By verdict volume</span>
          </div>
          <GroupSummaryTable rows={report.repositories} emptyLabel="No repository records loaded." />
        </section>

        <section className="report-panel">
          <div className="section-header">
            <h2>Policy outcomes</h2>
            <span className="mini-label">Blocked and warned rules</span>
          </div>
          <GroupSummaryTable rows={report.policies} emptyLabel="No policy records loaded." />
        </section>
      </div>

      <div className="report-grid">
        <section className="report-panel">
          <div className="section-header">
            <h2>Source coverage</h2>
            <span className="mini-label">GitHub, Foundry, Azure</span>
          </div>
          <GroupSummaryTable rows={report.sources} emptyLabel="No source records loaded." />
        </section>

        <section className="report-panel">
          <div className="section-header">
            <h2>High-risk watchlist</h2>
            <span className="mini-label">Risk score {threshold}+</span>
          </div>
          {highRiskRows.length === 0 ? <p className="muted">No records are above the configured threshold.</p> : (
            <div className="analytics-table">
              <table>
                <thead>
                  <tr>
                    <th>Item</th>
                    <th>Verdict</th>
                    <th>Risk</th>
                    <th>Repository</th>
                  </tr>
                </thead>
                <tbody>
                  {highRiskRows.map((row) => (
                    <tr key={row.id}>
                      <td className="item-cell">{row.item}</td>
                      <td><VerdictPill verdict={row.verdict} /></td>
                      <td><RiskScore value={row.riskScore} verdict={row.verdict} /></td>
                      <td>{row.repository}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

function SettingsView({ status, settings, onSettingsChange, onRefresh, onSave, onReset, records, refreshing }: { status: DashboardData['status']; settings: DashboardSettings; onSettingsChange: (settings: DashboardSettings) => void; onRefresh: () => void; onSave: () => void; onReset: () => void; records: number; refreshing: boolean }) {
  const integrations = Object.entries(status.integrations);
  const feeds = status.feeds.length > 0 ? status.feeds : [{ name: 'policy-api', status: 'unknown', updatedAgo: 'unknown' }];

  return (
    <section className="workspace-view" aria-labelledby="settings-title">
      <div className="view-header">
        <div>
          <span className="mini-label">Dashboard controls</span>
          <h1 id="settings-title">Settings</h1>
          <p>Configure dashboard defaults, live refresh behavior, notification scope, and deployment health visibility.</p>
        </div>
        <div className="panel-actions view-actions">
          <button type="button" onClick={onRefresh} disabled={refreshing}><RefreshCcw size={17} /> {refreshing ? 'Refreshing...' : 'Refresh now'}</button>
          <button type="button" onClick={onReset}>Reset defaults</button>
          <button type="button" className="primary" onClick={onSave}><ShieldCheck size={17} /> Save settings</button>
        </div>
      </div>

      <div className="settings-grid">
        <section className="settings-panel runtime-panel">
          <div className="section-header">
            <h2>Runtime</h2>
            <span className="mini-label">{status.status}</span>
          </div>
          <dl className="runtime-list">
            <div><dt>Service</dt><dd>{status.service}</dd></div>
            <div><dt>Mode</dt><dd>{status.mode}</dd></div>
            <div><dt>Records</dt><dd>{records}</dd></div>
            <div><dt>Azure audit</dt><dd>{status.integrations.azureAudit ?? 'not configured'}</dd></div>
          </dl>
        </section>

        <section className="settings-panel">
          <div className="section-header">
            <h2>Workspace preferences</h2>
            <span className="mini-label">Saved in this browser</span>
          </div>
          <div className="settings-form">
            <label className="setting-field">
              <span>Default time window</span>
              <select aria-label="Default time window" value={settings.defaultWindow} onChange={(event) => onSettingsChange({ ...settings, defaultWindow: event.currentTarget.value })}>
                {['24h', '7d', 'all'].map((option) => <option key={option} value={option}>{formatOption(option)}</option>)}
              </select>
            </label>

            <label className="toggle-row">
              <input type="checkbox" checked={settings.autoRefresh} onChange={(event) => onSettingsChange({ ...settings, autoRefresh: event.currentTarget.checked })} />
              <span><strong>Auto refresh</strong><em>Poll the policy API every 30 seconds while this dashboard is open.</em></span>
            </label>

            <label className="toggle-row">
              <input type="checkbox" checked={settings.notifyBlocks} onChange={(event) => onSettingsChange({ ...settings, notifyBlocks: event.currentTarget.checked })} />
              <span><strong>Block notifications</strong><em>Keep blocked verdicts visible in the notification tray.</em></span>
            </label>

            <label className="toggle-row">
              <input type="checkbox" checked={settings.compactRows} onChange={(event) => onSettingsChange({ ...settings, compactRows: event.currentTarget.checked })} />
              <span><strong>Compact queue rows</strong><em>Reduce table height for dense review sessions.</em></span>
            </label>

            <label className="setting-field">
              <span>High-risk marker <strong>{settings.riskThreshold}+</strong></span>
              <input aria-label="High-risk marker" type="range" min="40" max="95" step="5" value={settings.riskThreshold} onChange={(event) => onSettingsChange({ ...settings, riskThreshold: Number(event.currentTarget.value) })} />
            </label>
          </div>
        </section>

        <section className="settings-panel">
          <div className="section-header">
            <h2>Integrations</h2>
            <span className="mini-label">{integrations.length} configured</span>
          </div>
          <div className="status-list">
            {integrations.length === 0 ? <p className="muted">No integrations were returned by the API.</p> : integrations.map(([name, value]) => (
              <div className="status-row" key={name}>
                <span><i /> {formatOption(name)}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="settings-panel">
          <div className="section-header">
            <h2>Feeds</h2>
            <span className="mini-label">Policy inputs</span>
          </div>
          <div className="status-list">
            {feeds.map((feed) => (
              <div className="status-row" key={feed.name}>
                <span><i /> {feed.name}</span>
                <strong>{feed.status} · {feed.updatedAgo} · {feed.selectedFrom ?? 'unknown'}</strong>
                {feed.warnings?.slice(0, 1).map((warning) => (
                  <em className="feed-warning" key={`${feed.name}-${warning.code ?? warning.detail}`}>{warning.detail ?? warning.code}</em>
                ))}
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}

function MetricCard({ icon, label, value, detail, tone }: { icon: React.ReactNode; label: string; value: number | string; detail: string; tone?: VerdictKind }) {
  return (
    <div className={`metric-card ${tone ?? ''}`}>
      <span className="metric-icon">{icon}</span>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <em>{detail}</em>
      </div>
    </div>
  );
}

function DistributionBar({ report }: { report: ReportData }) {
  const segments: Array<{ key: VerdictKind; value: number }> = [
    { key: 'block', value: report.counts.block },
    { key: 'warn', value: report.counts.warn },
    { key: 'allow', value: report.counts.allow }
  ];

  return (
    <div className="distribution-bar" aria-label="Verdict distribution">
      {report.total === 0 ? <span className="distribution-empty">No verdicts</span> : segments.map((segment) => (
        segment.value > 0 ? <span key={segment.key} className={`distribution-segment ${segment.key}`} style={{ width: segmentWidth(segment.value, report.total) }} title={`${segment.key}: ${segment.value}`} /> : null
      ))}
    </div>
  );
}

function GroupSummaryTable({ rows, emptyLabel }: { rows: ReportGroup[]; emptyLabel: string }) {
  if (rows.length === 0) return <p className="muted">{emptyLabel}</p>;

  return (
    <div className="analytics-table">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Total</th>
            <th>Blocked</th>
            <th>Max risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name}>
              <td className="item-cell">{row.name}</td>
              <td>{row.total}</td>
              <td>{row.block}</td>
              <td><RiskScore value={row.maxRisk} verdict={row.block > 0 ? 'block' : row.warn > 0 ? 'warn' : 'allow'} /></td>
            </tr>
          ))}
        </tbody>
      </table>
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

function buildReport(rows: VerdictRow[]): ReportData {
  const counts = countVerdicts(rows);
  const totalRisk = rows.reduce((sum, row) => sum + row.riskScore, 0);

  return {
    total: rows.length,
    counts,
    averageRisk: rows.length > 0 ? Math.round(totalRisk / rows.length) : 0,
    critical: rows.filter((row) => row.riskScore >= 80).length,
    high: rows.filter((row) => row.riskScore >= 50 && row.riskScore < 80).length,
    repositories: summarizeGroups(rows, (row) => row.repository),
    sources: summarizeGroups(rows, (row) => row.source),
    policies: summarizeGroups(rows, (row) => row.policyId ?? 'policy-api'),
    types: summarizeGroups(rows, (row) => row.type)
  };
}

function summarizeGroups(rows: VerdictRow[], selectName: (row: VerdictRow) => string): ReportGroup[] {
  const grouped = new Map<string, ReportGroup>();

  for (const row of rows) {
    const name = selectName(row) || 'unknown';
    const summary = grouped.get(name) ?? { name, total: 0, block: 0, warn: 0, allow: 0, maxRisk: 0 };
    summary.total += 1;
    summary[row.verdict] += 1;
    summary.maxRisk = Math.max(summary.maxRisk, row.riskScore);
    grouped.set(name, summary);
  }

  return [...grouped.values()].sort((a, b) => b.total - a.total || b.maxRisk - a.maxRisk || a.name.localeCompare(b.name)).slice(0, 6);
}

function reportSummary(report: ReportData, mode: string): string {
  return [
    `Pounce Sentinel report (${mode})`,
    `Verdicts: ${report.total}`,
    `Blocked: ${report.counts.block}`,
    `Warnings: ${report.counts.warn}`,
    `Allowed: ${report.counts.allow}`,
    `Average risk: ${report.averageRisk}`,
    `Top repository: ${report.repositories[0]?.name ?? 'none'}`
  ].join('\n');
}

function toCsv(rows: VerdictRow[]): string {
  const header = ['auditId', 'createdAt', 'verdict', 'riskScore', 'type', 'item', 'repository', 'source', 'policyId', 'actor'];
  const body = rows.map((row) => header.map((field) => csvCell(String(row[field as keyof VerdictRow] ?? ''))).join(','));
  return [header.join(','), ...body].join('\n');
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

async function writeClipboardText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    const writePromise = navigator.clipboard.writeText(value);
    writePromise.catch(() => undefined);
    try {
      await withTimeout(writePromise, 800);
      return;
    } catch {
      // Fall back for embedded browsers that deny async clipboard writes.
    }
  }

  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.inset = '0 auto auto 0';
  textarea.style.opacity = '0';
  textarea.style.pointerEvents = 'none';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();

  try {
    if (typeof document.execCommand !== 'function' || !document.execCommand('copy')) throw new Error('copy command rejected');
    return;
  } finally {
    textarea.remove();
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeoutId = window.setTimeout(() => reject(new Error('clipboard write timed out')), timeoutMs);
    promise.then(resolve, reject).finally(() => window.clearTimeout(timeoutId));
  });
}

function loadDashboardSettings(): DashboardSettings {
  if (typeof window === 'undefined') return defaultDashboardSettings;

  try {
    const raw = window.localStorage.getItem(settingsStorageKey);
    if (!raw) return defaultDashboardSettings;
    return normalizeSettings(JSON.parse(raw) as Partial<DashboardSettings>);
  } catch {
    return defaultDashboardSettings;
  }
}

function persistDashboardSettings(settings: DashboardSettings): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(settingsStorageKey, JSON.stringify(normalizeSettings(settings)));
}

function normalizeSettings(settings: Partial<DashboardSettings>): DashboardSettings {
  const defaultWindow = settings.defaultWindow === '7d' || settings.defaultWindow === 'all' ? settings.defaultWindow : '24h';
  const riskThreshold = Number.isFinite(settings.riskThreshold) ? Number(settings.riskThreshold) : defaultDashboardSettings.riskThreshold;

  return {
    defaultWindow,
    autoRefresh: typeof settings.autoRefresh === 'boolean' ? settings.autoRefresh : defaultDashboardSettings.autoRefresh,
    notifyBlocks: typeof settings.notifyBlocks === 'boolean' ? settings.notifyBlocks : defaultDashboardSettings.notifyBlocks,
    compactRows: typeof settings.compactRows === 'boolean' ? settings.compactRows : defaultDashboardSettings.compactRows,
    riskThreshold: Math.min(95, Math.max(40, riskThreshold))
  };
}

function formatPercent(value: number, total: number): string {
  if (total === 0) return '0%';
  return `${Math.round((value / total) * 100)}%`;
}

function segmentWidth(value: number, total: number): string {
  if (total === 0 || value === 0) return '0%';
  return `${Math.max(3, Math.round((value / total) * 100))}%`;
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
}
