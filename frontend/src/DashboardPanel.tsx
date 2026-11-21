import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, BarChart3, CheckCircle2, Clock3, FolderOpen, RefreshCw, X } from "lucide-react";

type Project = { id: string; name: string };
type Run = { id: string; workflow_id: string; workflow_name: string; status: string; queued_at: string; started_at?: string | null; finished_at?: string | null; findings: number };
type Summary = {
  metrics: { projects: number; workflows: number; scans: number; findings: number; severity: Record<string, number>; scanners: Record<string, number> };
  trend: Array<{ date: string; scans: number; findings: number }>;
  recent_runs: Run[];
  projects: Project[];
};

async function getJson(url: string) {
  const response = await fetch(url, { credentials: "include" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Не удалось загрузить Dashboard.");
  return data;
}

const severityLabels: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export default function DashboardPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [days, setDays] = useState("30");
  const [severity, setSeverity] = useState("");
  const [scanner, setScanner] = useState("");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const query = useMemo(() => {
    const params = new URLSearchParams({ days });
    if (projectId) params.set("project_id", projectId);
    if (severity) params.set("severity", severity);
    if (scanner) params.set("scanner", scanner);
    return params.toString();
  }, [days, projectId, severity, scanner]);

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [projectData, dashboard] = await Promise.all([
        getJson("/api/projects"),
        getJson("/api/dashboard/summary?" + query),
      ]);
      setProjects(projectData || []);
      setSummary(dashboard as Summary);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка загрузки Dashboard.");
    } finally { setLoading(false); }
  }, [query]);

  useEffect(() => {
    if (open) void load();
  }, [open, load]);

  if (!open) return null;
  const maxTrend = Math.max(1, ...(summary?.trend || []).map(item => item.findings));
  const scannerOptions = Object.keys(summary?.metrics.scanners || {});
  const recentRuns = summary?.recent_runs || [];

  return <div className="dashboard-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="dashboard-panel" role="dialog" aria-modal="true" aria-labelledby="dashboard-title">
      <header className="dashboard-header">
        <div><span className="section-caption">WORKSPACE ANALYTICS</span><h2 id="dashboard-title"><BarChart3 size={18}/> Обзор безопасности</h2></div>
        <div className="dashboard-header-actions"><button type="button" className="ghost" onClick={() => void load()} disabled={loading}><RefreshCw size={13}/> Обновить</button><button type="button" className="icon-button" onClick={onClose} aria-label="Закрыть"><X size={17}/></button></div>
      </header>
      <div className="dashboard-filters">
        <label>Период<select value={days} onChange={event => setDays(event.target.value)}><option value="7">7 дней</option><option value="30">30 дней</option><option value="90">90 дней</option></select></label>
        <label>Проект<select value={projectId} onChange={event => setProjectId(event.target.value)}><option value="">Все проекты</option>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
        <label>Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="">Все уровни</option>{Object.entries(severityLabels).map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <label>Scanner<select value={scanner} onChange={event => setScanner(event.target.value)}><option value="">Все сканеры</option>{scannerOptions.map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      </div>
      {error && <div className="dashboard-error">{error}</div>}
      {loading && !summary ? <div className="dashboard-loading"><Activity size={18}/> Загружаем аналитику Workspace…</div> : summary && <>
        <div className="dashboard-metrics">
          <article><span>PROJECTS</span><b><FolderOpen size={16}/>{summary.metrics.projects}</b></article>
          <article><span>WORKFLOWS</span><b><BarChart3 size={16}/>{summary.metrics.workflows}</b></article>
          <article><span>SCANS · {days}D</span><b><Activity size={16}/>{summary.metrics.scans}</b></article>
          <article><span>FINDINGS</span><b><AlertTriangle size={16}/>{summary.metrics.findings}</b></article>
        </div>
        <div className="dashboard-content-grid">
          <section className="dashboard-card">
            <div className="dashboard-card-heading"><b>Findings по severity</b><small>Выберите уровень для фильтрации</small></div>
            <div className="dashboard-severity">
              {Object.entries(severityLabels).map(([key,label]) => <button type="button" key={key} className={"dashboard-severity-item severity-" + key + (severity === key ? " selected" : "")} onClick={() => setSeverity(current => current === key ? "" : key)}>
                <span>{label}</span><b>{summary.metrics.severity[key] || 0}</b>
              </button>)}
            </div>
          </section>
          <section className="dashboard-card">
            <div className="dashboard-card-heading"><b>Динамика за период</b><small>Количество findings по дате запуска</small></div>
            {summary.trend.length ? <div className="dashboard-trend">
              {summary.trend.map(item => <div className="dashboard-trend-column" key={item.date} title={item.date + ": " + item.findings + " findings"}>
                <span style={{ height: Math.max(3, item.findings / maxTrend * 100) + "%" }}/>
                <small>{item.date.slice(5)}</small>
              </div>)}
            </div> : <div className="dashboard-empty">За выбранный период запусков нет.</div>}
          </section>
        </div>
        <section className="dashboard-card dashboard-runs">
          <div className="dashboard-card-heading"><b>Последние запуски</b><small>{recentRuns.length} последних запусков в выбранной области</small></div>
          {recentRuns.length ? <div className="dashboard-run-list">
            {recentRuns.map(run => <div className="dashboard-run-row" key={run.id}>
              <span className={"dashboard-run-status status-" + run.status}><i/>{run.status}</span>
              <b>{run.workflow_name}</b>
              <small>{new Date(run.queued_at).toLocaleString()}</small>
              <span className="dashboard-run-findings">{run.findings} findings</span>
              <a href={"/api/runs/" + run.id + "/report.html"} target="_blank" rel="noreferrer">HTML</a>
              <a href={"/api/runs/" + run.id + "/report.json"} target="_blank" rel="noreferrer">JSON</a>
            </div>)}
          </div> : <div className="dashboard-empty"><CheckCircle2 size={17}/> Запусков за выбранный период пока нет.</div>}
        </section>
      </>}
      <footer className="dashboard-footer"><span><Clock3 size={12}/> Данные ограничены активным Workspace</span><button type="button" onClick={onClose}>Закрыть обзор</button></footer>
    </section>
  </div>;
}
