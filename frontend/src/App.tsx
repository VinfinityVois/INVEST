import { memo, useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, Controls, MiniMap, Handle, Position, addEdge, reconnectEdge,
  useEdgesState, useNodesState,
  type Connection, type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Activity, AlertTriangle, Bot, Check, ChevronDown, CircleHelp, CirclePlay,
  Code2, GitBranch, Layers3, LockKeyhole, Plus, Search, Shield, Trash2,
  UploadCloud, Workflow, X, Zap, Copy, Save, RefreshCw, ArrowLeftRight,
  PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen,
} from "lucide-react";

type Manifest = { type: string; title: string; category: string; description: string };
type Finding = { id?: string; fingerprint?: string; rule_id: string; severity: string; path: string; line?: number; message?: string; masked_value?: string; why_it_matters?: string; recommendation?: string; cwe?: string[]; cve?: string | null; code_context?: Array<{ line: number; text: string; is_finding: boolean }>; start_line?: number; end_line?: number; code_context_redacted?: boolean; ai_explanation?: { root_cause: string; impact: string; recommendation: string; confidence: number; evidence_limits: string } };
type FindingLifecycle = { state: "open" | "accepted_risk" | "fixed" | "false_positive"; reason: string; expires_at?: string | null };
type Telemetry = {
  run_id?: string; status: string; source?: string; queued_at?: string; started_at?: string;
  finished_at?: string; duration_ms?: number | null; total_findings: number;
  severity: Record<string, number>;
  scanners: Array<{ node_id?: string; type: string; status: string; findings: number; duration_ms?: number | null }>;
  completed_nodes?: number; total_nodes?: number; current_node?: string | null;
  security_gate?: { decision: "PASS" | "WARN" | "BLOCK"; blocked: boolean; counts: Record<string, number>; policy: { block_on: string[]; warn_on: string[] } } | null;
  trace?: Array<{ node_id: string; type: string; status: string; duration_ms?: number; findings?: number }>;
  scanner_progress?: { files_scanned: number; total_files: number; current_file: string } | null;
  node_results?: Record<string, { status?: string; message?: string; findings?: number; explained_count?: number; total_findings?: number; explanations?: Array<{ root_cause?: string; impact?: string; recommendation?: string }> }>;
};
type NodeData = { label: string; nodeType: string; category: string; description: string; config: Record<string, unknown>; executionStatus?: "idle" | "queued" | "running" | "completed" | "failed" | "blocked" | "configuration_required"; executionDetail?: string; executionNotes?: string[] };
type FlowNode = Node<NodeData>;

const formatDuration = (ms?: number | null) => ms == null ? "—" : ms < 1000 ? `${Math.round(ms)} мс` : ms < 60000 ? `${(ms / 1000).toFixed(1)} с` : `${Math.floor(ms / 60000)} мин ${Math.round((ms % 60000) / 1000)} с`;
const formatDate = (value?: string) => value ? new Date(value).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";

const categoryMeta: Record<string, { label: string; tone: string }> = {
  Trigger: { label: "Триггер", tone: "blue" }, Source: { label: "Источник", tone: "cyan" },
  Security: { label: "Security", tone: "violet" }, Logic: { label: "Логика", tone: "amber" },
  AI: { label: "AI", tone: "pink" }, Notify: { label: "Уведомления", tone: "green" },
  CI: { label: "CI / Gate", tone: "green" },
};
const seedNodes: FlowNode[] = [
  { id: "trigger", type: "workflow", position: { x: 70, y: 190 }, data: { label: "Manual trigger", nodeType: "trigger.manual", category: "Trigger", description: "Ручной запуск проверки по кнопке «Запустить».", config: {} } },
  { id: "source", type: "workflow", position: { x: 300, y: 190 }, data: { label: "Project source", nodeType: "source.upload", category: "Source", description: "Выбери ZIP-архив или Git-репозиторий. Пока источник не задан, сканеры не запускаются.", config: {} } },
  { id: "secrets", type: "workflow", position: { x: 550, y: 100 }, data: { label: "Secrets scanner", nodeType: "scan.secrets", category: "Security", description: "Ищет токены, ключи и другие потенциально раскрытые секреты.", config: {} } },
  { id: "sca", type: "workflow", position: { x: 550, y: 285 }, data: { label: "Dependency scanner", nodeType: "scan.sca", category: "Security", description: "Проверяет Gradle-зависимости по локальному advisory snapshot.", config: {} } },
  { id: "sast", type: "workflow", position: { x: 550, y: 470 }, data: { label: "Kotlin SAST", nodeType: "scan.sast", category: "Security", description: "Статически анализирует Kotlin/Spring-код на поддерживаемые классы проблем.", config: {} } },
  { id: "merge", type: "workflow", position: { x: 850, y: 285 }, data: { label: "Merge findings", nodeType: "findings.merge", category: "Logic", description: "Объединяет результаты сканеров и удаляет дубликаты по fingerprint.", config: {} } },
  { id: "gate", type: "workflow", position: { x: 1120, y: 285 }, data: { label: "Security Gate", nodeType: "ci.gate", category: "CI", description: "Блокирует workflow при CRITICAL/HIGH находках; пороги настраиваются в конфигурации.", config: { block_on: ["CRITICAL", "HIGH"], warn_on: ["MEDIUM", "LOW", "INFO"] } } },
  { id: "ai-explain", type: "workflow", position: { x: 1120, y: 70 }, data: { label: "AI explanation", nodeType: "ai.explain", category: "AI", description: "Объясняет подтверждённые находки: причина, влияние и рекомендации. Требует LLM-настройки в корневом .env.", config: { language: "ru", max_findings: 20 } } },
];
const seedEdges: Edge[] = [
  { id: "e1", source: "trigger", target: "source", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 }, label: "запуск" },
  { id: "e2", source: "source", target: "secrets", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } },
  { id: "e3", source: "source", target: "sca", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } },
  { id: "e4", source: "source", target: "sast", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } },
  { id: "e5", source: "secrets", target: "merge", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } },
  { id: "e6", source: "sca", target: "merge", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } },
  { id: "e7", source: "sast", target: "merge", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } },
  { id: "e8", source: "merge", target: "gate", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 }, label: "policy" },
  { id: "e9", source: "merge", target: "ai-explain", type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 }, label: "объяснение" },
];

function WorkflowNode({ data, selected }: NodeProps<FlowNode>) {
  const meta = categoryMeta[data.category] || { label: data.category, tone: "slate" };
  const statusLabel = data.executionStatus === "running" ? "ВЫПОЛНЯЕТСЯ"
    : data.executionStatus === "completed" ? "ЗАВЕРШЁН"
    : data.executionStatus === "failed" ? "ОШИБКА"
    : data.executionStatus === "blocked" ? "ЗАБЛОКИРОВАН"
    : data.executionStatus === "configuration_required" ? "НУЖНА НАСТРОЙКА"
    : data.executionStatus === "queued" ? "В ОЧЕРЕДИ" : "ГОТОВ К ЗАПУСКУ";
  return <div title={data.executionDetail || data.description} className={"workflow-node tone-" + meta.tone + (selected ? " is-selected" : "") + (data.executionStatus && data.executionStatus !== "idle" ? " node-" + data.executionStatus : "")}>
    <Handle type="target" position={Position.Left} />
    <div className="node-topline"><span>{meta.label}</span><span className="node-state">{data.executionStatus === "running" && <i className="node-live-dot" />}{statusLabel}</span></div>
    <div className="node-main"><div className="node-symbol">{data.category === "Security" ? <Shield size={17} /> : data.category === "Source" ? <GitBranch size={17} /> : data.category === "Trigger" ? <Zap size={17} /> : data.category === "AI" ? <Bot size={17} /> : <Workflow size={17} />}</div>
      <div className="node-copy"><b>{data.label}</b><small>{data.nodeType}</small></div></div>
    <p className="node-description">{data.description}</p>
    {data.executionDetail && <div className="node-execution-detail">{data.executionDetail}</div>}
    {data.executionNotes?.map((note, index) => <div className="node-ai-note" key={index}><b>AI · {index + 1}</b><span>{note}</span></div>)}
    <div className="node-footer"><span>ВХОД / ВЫХОД</span><span className="node-port-label">●</span></div>
    <Handle type="source" position={Position.Right} />
  </div>;
}
const nodeTypes = { workflow: memo(WorkflowNode) };

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(seedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(seedEdges);
  const [manifests, setManifests] = useState<Manifest[]>([]);
  const [workflowId, setWorkflowId] = useState<string | null>(null);
  const [notice, setNotice] = useState("Подключение к API…");
  const [result, setResult] = useState("Граф готов к проверке.");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [findingStates, setFindingStates] = useState<Record<string, FindingLifecycle>>({});
  const [findingHistory, setFindingHistory] = useState<Record<string, Array<{ details: Record<string, unknown>; created_at: string }>>>({});
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [lastRunId, setLastRunId] = useState<string | null>(() => window.localStorage.getItem("invest.lastRunId"));
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [gitUrl, setGitUrl] = useState("");
  const [gitRef, setGitRef] = useState("");
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("Все");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("source");
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [showResult, setShowResult] = useState(true);
  const [configText, setConfigText] = useState("{}");
  const [configError, setConfigError] = useState("");
  const [edgeLabel, setEdgeLabel] = useState("");
  const [leftCollapsed, setLeftCollapsed] = useState(false);
  const [rightCollapsed, setRightCollapsed] = useState(false);

  useEffect(() => {
    fetch("/api/node-types").then(response => { if (!response.ok) throw new Error(); return response.json(); })
      .then((data: Manifest[]) => { setManifests(data); setNotice("API подключён · реестр компонентов синхронизирован"); })
      .catch(() => setNotice("API недоступен · проверьте backend :8000"));
  }, []);

  useEffect(() => {
    if (!workflowId) { setTelemetry(null); return; }
    let active = true;
    fetch("/api/workflows/" + workflowId + "/telemetry/latest")
      .then(response => response.ok ? response.json() : null)
      .then((data: Telemetry | null) => { if (active && data) setTelemetry(data); })
      .catch(() => { if (active) setTelemetry(null); });
    return () => { active = false; };
  }, [workflowId]);

  useEffect(() => {
    if (!workflowId) { setFindingStates({}); return; }
    let active = true;
    fetch("/api/workflows/" + workflowId + "/finding-states")
      .then(response => response.ok ? response.json() : [])
      .then((rows: Array<FindingLifecycle & { fingerprint: string }>) => {
        if (active) setFindingStates(Object.fromEntries(rows.map(row => [row.fingerprint, row])));
      })
      .catch(() => undefined);
    return () => { active = false; };
  }, [workflowId]);

  useEffect(() => {
    if (!lastRunId) return;
    let active = true;
    fetch("/api/runs/" + lastRunId + "/telemetry")
      .then(response => response.ok ? response.json() : null)
      .then((data: Telemetry | null) => { if (active && data) setTelemetry(data); })
      .catch(() => undefined);
    return () => { active = false; };
  }, [lastRunId]);

  useEffect(() => {
    if (!telemetry) return;
    const trace = new Map((telemetry.trace || []).map(item => [item.node_id, item]));
    const current = telemetry.current_node || null;
    const nodeResults = telemetry.node_results || {};
    setNodes(currentNodes => currentNodes.map(node => {
      const step = trace.get(node.id);
      const output = nodeResults[node.id];
      const status = current === node.id ? "running"
        : step?.status === "failed" ? "failed"
        : step?.status === "blocked" ? "blocked"
        : step?.status === "configuration_required" ? "configuration_required"
        : step?.status === "completed" || step?.status === "ready" ? "completed"
        : telemetry.status === "queued" ? "queued" : "idle";
      let detail = output?.message || "";
      let notes: string[] = [];
      if (node.data.nodeType === "ai.explain" && output) {
        notes = (output.explanations || []).map(item => [item.root_cause, item.recommendation].filter(Boolean).join(" · ")).filter(Boolean);
        detail = output.status === "configuration_required" ? "Нужен LLM-провайдер: заполните LLM_BASE_URL, LLM_MODEL и LLM_API_KEY."
          : output.status === "failed" ? "AI-провайдер не вернул корректный ответ. Проверьте доступность и настройки."
          : output.status === "completed" ? `Объяснено находок: ${output.explained_count ?? 0} из ${output.total_findings ?? 0}.` : detail;
      } else if (node.data.nodeType === "source.git" && output?.status === "ready") {
        detail = "Репозиторий клонирован в изолированную рабочую область.";
      } else if (node.data.nodeType === "source.upload" && output?.status === "ready") {
        detail = "Каталог проекта доступен сканерам.";
      } else if (status === "idle" && telemetry.status === "running") {
        detail = "Ожидает завершения предыдущих связанных блоков.";
      }
      return { ...node, data: { ...node.data, executionStatus: status, executionDetail: detail, executionNotes: notes } };
    }));
    setEdges(currentEdges => currentEdges.map(edge => {
      const sourceStep = trace.get(edge.source);
      const targetStep = trace.get(edge.target);
      const active = current === edge.target && (sourceStep?.status === "completed" || sourceStep?.status === "ready");
      const complete = !!sourceStep && !!targetStep && ["completed", "ready"].includes(sourceStep.status) && ["completed", "ready"].includes(targetStep.status);
      return { ...edge, animated: active, className: active ? "edge-active" : complete ? "edge-completed" : "edge-idle" };
    }));
  }, [telemetry, setNodes, setEdges]);

  const selectedNode = nodes.find(node => node.id === selectedNodeId) || null;
  const selectedEdge = edges.find(edge => edge.id === selectedEdgeId) || null;
  useEffect(() => {
    setConfigText(selectedNode ? JSON.stringify(selectedNode.data.config || {}, null, 2) : "{}");
    setConfigError("");
  }, [selectedNodeId, nodes.find(n => n.id === selectedNodeId)?.data.config]);
  useEffect(() => { setEdgeLabel(selectedEdge?.label?.toString() || ""); }, [selectedEdgeId, selectedEdge?.label]);

  const onConnect = useCallback((connection: Connection) => {
    setEdges(current => addEdge({ ...connection, id: "edge-" + Date.now(), type: "smoothstep", animated: false, className: "edge-idle", style: { stroke: "#6686a5", strokeWidth: 2 } }, current));
    setSelectedNodeId(null); setSelectedEdgeId(null);
  }, [setEdges]);
  const onReconnect = useCallback((oldEdge: Edge, newConnection: Connection) => {
    setEdges(current => reconnectEdge(oldEdge, newConnection, current, { shouldReplaceId: false }));
  }, [setEdges]);

  const addNode = (manifest: Manifest) => {
    const id = manifest.type + "-" + Date.now();
    const position = { x: 180 + (nodes.length % 3) * 245, y: 90 + Math.floor(nodes.length / 3) * 145 };
    const node: FlowNode = { id, type: "workflow", position, data: { label: manifest.title, nodeType: manifest.type, category: manifest.category, description: manifest.description, config: {} } };
    setNodes(current => [...current, node]); setSelectedNodeId(id); setSelectedEdgeId(null);
  };
  const updateNode = (id: string, patch: Partial<NodeData>) => setNodes(current => current.map(node => node.id === id ? { ...node, data: { ...node.data, ...patch } } : node));
  const deleteSelectedNode = () => {
    if (!selectedNodeId) return;
    setNodes(current => current.filter(node => node.id !== selectedNodeId));
    setEdges(current => current.filter(edge => edge.source !== selectedNodeId && edge.target !== selectedNodeId));
    setSelectedNodeId(null);
  };
  const duplicateSelectedNode = () => {
    if (!selectedNode) return;
    const id = selectedNode.data.nodeType + "-" + Date.now();
    const copy: FlowNode = { ...selectedNode, id, position: { x: selectedNode.position.x + 55, y: selectedNode.position.y + 55 }, selected: false, data: { ...selectedNode.data, config: { ...selectedNode.data.config } } };
    setNodes(current => [...current, copy]); setSelectedNodeId(id);
  };
  const replaceSelectedNode = (type: string) => {
    if (!selectedNode) return;
    const manifest = manifests.find(item => item.type === type);
    if (!manifest) return;
    updateNode(selectedNode.id, { nodeType: manifest.type, label: manifest.title, category: manifest.category, description: manifest.description, config: {} });
  };
  const saveNodeConfig = () => {
    if (!selectedNode) return;
    try {
      const parsed = JSON.parse(configText);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("Конфигурация должна быть JSON-объектом.");
      updateNode(selectedNode.id, { config: parsed as Record<string, unknown> }); setConfigError(""); setResult("Настройки блока сохранены в графе.");
    } catch (error) { setConfigError(error instanceof Error ? error.message : "Некорректный JSON"); }
  };
  const deleteSelectedEdge = () => {
    if (!selectedEdgeId) return;
    setEdges(current => current.filter(edge => edge.id !== selectedEdgeId)); setSelectedEdgeId(null);
  };
  const updateEdgeEndpoint = (field: "source" | "target", value: string) => {
    if (!selectedEdgeId) return;
    setEdges(current => current.map(edge => edge.id === selectedEdgeId ? { ...edge, [field]: value } : edge));
  };

  const graph = useMemo(() => ({
    name: "Security pipeline",
    nodes: nodes.map(node => ({ id: node.id, type: node.data.nodeType, position: node.position, config: node.data.config || {} })),
    edges: edges.map(edge => ({ id: edge.id, source: edge.source, target: edge.target, source_handle: edge.sourceHandle, target_handle: edge.targetHandle })),
  }), [nodes, edges]);

  const uploadArchive = async (file?: File) => {
    if (!file) return;
    setUploading(true); setFindings([]);
    try {
      const form = new FormData(); form.append("file", file);
      const response = await fetch("/api/sources/upload", { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data));
      const sourceNode = nodes.find(node => node.data.category === "Source");
      if (sourceNode) updateNode(sourceNode.id, { nodeType: "source.upload", label: "Workspace source", description: "Сканирует безопасно распакованный ZIP-каталог.", config: { path: data.path }, executionStatus: "idle", executionDetail: "" });
      setResult("Архив принят · " + data.files + " файлов · " + Math.round(data.expanded_bytes / 1024) + " KiB распаковано. Источник обновлён.");
    } catch (error) { setResult("Ошибка загрузки ZIP: " + String(error)); }
    finally { setUploading(false); }
  };
  const persistWorkflow = async () => {
    const response = await fetch(workflowId ? "/api/workflows/" + workflowId : "/api/workflows", {
      method: workflowId ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(graph),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(data));
    setWorkflowId(data.id); return data.id as string;
  };
  const saveWorkflow = async () => {
    setBusy(true);
    try { const id = await persistWorkflow(); setResult("Сохранено · workflow " + id); }
    catch (error) { setResult("Не удалось сохранить workflow: " + String(error)); }
    finally { setBusy(false); }
  };
  const validateWorkflow = async () => {
    setBusy(true);
    try {
      const response = await fetch("/api/workflows/validate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(graph) });
      const data = await response.json(); setResult(JSON.stringify(data, null, 2)); setShowResult(true);
    } catch { setResult("Не удалось связаться с API. Проверьте backend."); setShowResult(true); }
    finally { setBusy(false); }
  };
  const runWorkflow = async () => {
    setBusy(true); setFindings([]);
    try {
      const id = await persistWorkflow();
      const response = await fetch("/api/workflows/" + id + "/runs", { method: "POST" });
      const queued = await response.json();
      if (!response.ok) throw new Error(JSON.stringify(queued));
      setShowResult(true);
      setResult("Задание поставлено в очередь · " + queued.run_id);
      setLastRunId(queued.run_id); window.localStorage.setItem("invest.lastRunId", queued.run_id);

      setTelemetry({ status: "queued", total_findings: 0, severity: {}, scanners: [], completed_nodes: 0, total_nodes: nodes.length });\n      const completed = await new Promise<Telemetry>((resolve, reject) => {
        const stream = new EventSource("/api/runs/" + queued.run_id + "/events");
        let settled = false;
        let fallbackStarted = false;
        const finish = (data: Telemetry) => {
          if (settled) return;
          settled = true; stream.close(); window.clearTimeout(timeout); resolve(data);
        };
        const fallback = async () => {
          if (fallbackStarted || settled) return;
          fallbackStarted = true; stream.close();
          try {
            for (let attempt = 0; attempt < 300; attempt += 1) {
              await new Promise(resolveWait => window.setTimeout(resolveWait, 1000));
              const response = await fetch("/api/runs/" + queued.run_id + "/telemetry");
              if (!response.ok) throw new Error("Не удалось получить телеметрию задания");
              const data: Telemetry = await response.json();
              setTelemetry(data);
              if (["completed", "partial", "failed"].includes(data.status)) { finish(data); return; }
            }
            throw new Error("Превышено время ожидания worker. Задание сохранено в очереди.");
          } catch (error) {
            if (!settled) { settled = true; window.clearTimeout(timeout); reject(error); }
          }
        };
        const timeout = window.setTimeout(() => { void fallback(); }, 300000);
        stream.onmessage = event => {
          try {
            const data: Telemetry = JSON.parse(event.data);
            setTelemetry(data);
            setResult("Выполнение · " + data.completed_nodes + "/" + data.total_nodes + " блоков");
            if (["completed", "partial", "failed"].includes(data.status)) finish(data);
          } catch { /* Ignore malformed telemetry frame and keep the stream alive. */ }
        };
        stream.onerror = () => { void fallback(); };
      });
      const findingsResponse = await fetch("/api/runs/" + queued.run_id + "/findings");
      if (findingsResponse.ok) setFindings(await findingsResponse.json());
      const telemetryResponse = await fetch("/api/runs/" + queued.run_id + "/telemetry");
      if (telemetryResponse.ok) setTelemetry(await telemetryResponse.json());
      setResult("Проверка завершена · " + completed.status + " · " + completed.total_findings + " находок");
      if (completed.status === "failed") setResult("Проверка завершилась с ошибкой.");
    } catch (error) { setResult("Запуск не выполнен: " + String(error)); setShowResult(true); }
    finally { setBusy(false); }
  };
  const updateFindingLifecycle = async (finding: Finding, state: FindingLifecycle["state"]) => {
    if (!workflowId || !finding.fingerprint) return;
    const reason = window.prompt("Причина изменения статуса уязвимости:", state === "open" ? "Повторная проверка" : "");
    if (reason === null || !reason.trim()) return;
    try {
      const response = await fetch("/api/workflows/" + workflowId + "/findings/" + finding.fingerprint + "/state", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ state, reason: reason.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось изменить статус");
      setFindingStates(current => ({ ...current, [finding.fingerprint!]: data }));
      setResult("Статус уязвимости обновлён · " + state);
    } catch (error) { setResult("Ошибка статуса уязвимости: " + String(error)); }
  };
  const loadFindingHistory = async (fingerprint: string) => {
    if (!workflowId) return;
    try {
      const response = await fetch("/api/workflows/" + workflowId + "/findings/" + fingerprint + "/history");
      if (!response.ok) throw new Error("Не удалось загрузить историю");
      const history = await response.json();
      setFindingHistory(current => ({ ...current, [fingerprint]: history }));
    } catch (error) { setResult(String(error)); }
  };
  const categories = ["Все", ...Array.from(new Set(manifests.map(item => item.category)))];
  const filtered = manifests.filter(item => (category === "Все" || item.category === category) && (item.title + " " + item.description + " " + item.type).toLowerCase().includes(search.toLowerCase()));

  return <main className="shell">
    <header className="topbar">
      <div className="brand"><div className="mark"><Shield size={19} /></div><div><b>INVEST <span>／</span> SECURITY WORKFLOW</b><small>VISUAL SECURITY AUTOMATION PLATFORM</small></div></div>
      <div className="status"><i className={notice.startsWith("API подключён") ? "online" : ""} />{notice}</div>
      <div className="actions"><span className="revision"><GitBranch size={13} /> feat / platform-foundation</span>
        <button className="ghost" disabled={busy} onClick={saveWorkflow}><Save size={13} /> Сохранить</button>
        <button className="validate" disabled={busy} onClick={validateWorkflow}><Check size={14} /> Проверить</button>
        <button className="run" disabled={busy} onClick={runWorkflow}><CirclePlay size={14} /> {busy ? "Выполняется…" : "Запустить"}</button>
      </div>
    </header>
    <div className={"layout" + (leftCollapsed ? " left-collapsed" : "") + (rightCollapsed ? " right-collapsed" : "")}>
      <aside className={"panel palette" + (leftCollapsed ? " is-collapsed" : "")}>
        {leftCollapsed ? <button className="collapsed-rail" onClick={() => setLeftCollapsed(false)} title="Развернуть библиотеку блоков" aria-label="Развернуть библиотеку блоков"><PanelLeftOpen size={17} /><span>БЛОКИ</span></button> : <>
        <div className="panel-heading"><div><div className="eyebrow">WORKFLOW BUILDER</div><h3><Workflow size={17} /> Библиотека блоков</h3></div><div className="panel-heading-actions"><span className="counter">{manifests.length}</span><button className="icon-button collapse-control" onClick={() => setLeftCollapsed(true)} title="Свернуть библиотеку блоков" aria-label="Свернуть библиотеку блоков"><PanelLeftClose size={14} /></button></div></div>
        <p className="panel-intro">Добавляй компоненты на холст. Настройки, замена и удаление доступны в инспекторе выбранного блока.</p>
        <div className="searchbox"><Search size={14} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Найти блок или назначение…" /><kbd>/</kbd></div>
        <div className="category-filters">{categories.map(item => <button key={item} className={category === item ? "active" : ""} onClick={() => setCategory(item)}>{item}</button>)}</div>
        <div className="source-section">
          <div className="section-caption">ИСТОЧНИК ПРОЕКТА</div>
          <label className="archive-upload"><UploadCloud size={15} /><span>{uploading ? "Загрузка и проверка…" : "Загрузить ZIP проекта"}</span><input type="file" accept=".zip,application/zip" disabled={uploading || busy} onChange={event => { void uploadArchive(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
          <small className="upload-hint">До 50 MiB · архив проверяется · файлы проекта не исполняются</small>
          <div className="source-divider"><span>ИЛИ КЛОНИРОВАТЬ ЧЕРЕЗ GIT</span></div>
          <label className="source-field">HTTPS-ссылка репозитория<input value={gitUrl} onChange={event => setGitUrl(event.target.value)} placeholder="https://github.com/owner/repository.git" disabled={busy || uploading}/></label>
          <label className="source-field">Ветка или тег<input value={gitRef} onChange={event => setGitRef(event.target.value)} placeholder="main (необязательно)" disabled={busy || uploading}/></label>
          <button className="git-source-button" disabled={busy || uploading || !gitUrl.trim()} onClick={() => {
            const sourceNode = nodes.find(node => node.data.category === "Source");
            if (!sourceNode) { setResult("В графе отсутствует блок-источник."); return; }
            updateNode(sourceNode.id, { nodeType: "source.git", label: "Git repository", description: "Клонирует разрешённый HTTPS-репозиторий в изолированную рабочую область.", config: { url: gitUrl.trim(), ...(gitRef.trim() ? { ref: gitRef.trim() } : {}) }, executionStatus: "idle", executionDetail: "" });
            setResult("Git-источник настроен. Добавьте точный URL в ALLOWED_TARGETS корневого .env, затем нажмите «Запустить».");
          }}><GitBranch size={13}/> Использовать Git-источник</button>
          <small className="upload-hint">Только HTTPS и точное совпадение с ALLOWED_TARGETS в корневом .env. Клонирование выполняется worker при запуске.</small>
        </div>
        <div className="section-caption library-caption">КОМПОНЕНТЫ API</div>
        {filtered.map(manifest => <article className="library-item" key={manifest.type}>
          <div className="library-main"><div className={"library-icon tone-" + (categoryMeta[manifest.category] || {tone:"slate"}).tone}><Code2 size={15} /></div><div className="library-copy"><b>{manifest.title}</b><small>{manifest.type}</small></div><button className="add-node" title="Добавить блок на холст" onClick={() => addNode(manifest)}><Plus size={15} /></button></div>
          <details className="node-help"><summary><CircleHelp size={12} /> Что делает блок <ChevronDown size={12} /></summary><p>{manifest.description}</p><span>{categoryMeta[manifest.category]?.label || manifest.category} · тип: {manifest.type}</span></details>
        </article>)}
        {!manifests.length && <div className="empty-library">Загружаем реестр компонентов API…</div>}
        {manifests.length > 0 && filtered.length === 0 && <div className="empty-library">Ничего не найдено.</div>}
        <div className="palette-note"><LockKeyhole size={14} /><span>Код репозитория анализируется как данные, без запуска его скриптов.</span></div>
        </>}
      </aside>

      <section className="editor">
        <div className="editor-head"><div><span className="eyebrow">EDITOR / WORKFLOW 001</span><h1>Security pipeline</h1><p>Перетаскивай блоки, соединяй порты, выбирай элемент для редактирования</p></div>
          <div className="counts"><span><Layers3 size={13} />{nodes.length} блоков</span><span><GitBranch size={13} />{edges.length} связей</span></div></div>
        <div className="flow"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes}
          onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect} onReconnect={onReconnect}
          onNodeClick={(_, node) => { setSelectedNodeId(node.id); setSelectedEdgeId(null); }}
          onEdgeClick={(_, edge) => { setSelectedEdgeId(edge.id); setSelectedNodeId(null); }}
          onPaneClick={() => { setSelectedNodeId(null); setSelectedEdgeId(null); }}
          edgesReconnectable deleteKeyCode={["Backspace", "Delete"]} fitView fitViewOptions={{ padding: 0.2 }}>
          <Background color="#31445c" gap={22} size={1} /><MiniMap pannable zoomable nodeColor={node => node.type === "workflow" ? "#426b91" : "#526176"} /><Controls />
        </ReactFlow></div>
        <div className="flow-foot"><span><Activity size={13} /> Редактор графа <i /> Сетка 22 px</span><span>Связь можно выбрать и перетащить за конец для переназначения</span></div>
      </section>

      <aside className={"panel inspector" + (rightCollapsed ? " is-collapsed" : "")}>
        {rightCollapsed ? <button className="collapsed-rail" onClick={() => setRightCollapsed(false)} title="Развернуть инспектор" aria-label="Развернуть инспектор"><PanelRightOpen size={17} /><span>ИНСПЕКТОР</span></button> : <>
        <div className="inspector-top"><div><div className="eyebrow">INSPECTOR / EDITOR</div><h3><Activity size={17} /> Свойства элемента</h3></div><div className="panel-heading-actions"><button className="icon-button collapse-control" onClick={() => setRightCollapsed(true)} title="Свернуть инспектор" aria-label="Свернуть инспектор"><PanelRightClose size={14} /></button><button className="icon-button" title={showResult ? "Свернуть результат" : "Показать результат"} onClick={() => setShowResult(value => !value)}>{showResult ? <X size={14} /> : <ChevronDown size={14} />}</button></div></div>
        {selectedNode && <section className="edit-section">
          <div className="section-caption">РЕДАКТИРОВАНИЕ БЛОКА</div>
          <label className="field-label">Название блока<input value={selectedNode.data.label} onChange={event => updateNode(selectedNode.id, { label: event.target.value })} /></label>
          <label className="field-label">Заменить тип блока<select value={selectedNode.data.nodeType} onChange={event => replaceSelectedNode(event.target.value)}><option value={selectedNode.data.nodeType}>{selectedNode.data.nodeType}</option>{manifests.filter(item => item.type !== selectedNode.data.nodeType).map(item => <option key={item.type} value={item.type}>{item.title} · {item.type}</option>)}</select></label>
          {selectedNode.data.nodeType === "ai.explain" ? <>
            <div className="ai-node-guide"><div><Bot size={16}/><b>AI-АНАЛИЗАТОР ПОДКЛЮЧЁН К ГРАФУ</b></div><p>Получает находки из блока Merge findings. Ключ API хранится только в корневом .env и не вводится здесь.</p><ol><li>Добавь LLM_BASE_URL, LLM_MODEL и LLM_API_KEY в .env</li><li>Перезапусти api и worker</li><li>Запусти workflow — объяснения появятся в карточках находок</li></ol></div>
            <label className="field-label">Язык объяснений<select value={String(selectedNode.data.config.language || "ru")} onChange={event => updateNode(selectedNode.id, { config: { ...selectedNode.data.config, language: event.target.value } })}><option value="ru">Русский</option><option value="en">English</option></select></label>
            <label className="field-label">Максимум находок<input type="number" min={1} max={25} value={Number(selectedNode.data.config.max_findings ?? 20)} onChange={event => updateNode(selectedNode.id, { config: { ...selectedNode.data.config, max_findings: Math.max(1, Math.min(25, Number(event.target.value) || 1)) } })}/></label>
            <p className="edit-hint">AI не меняет severity, не создаёт новые уязвимости и не влияет на Security Gate. Ветка AI независима от проверки политики.</p>
          </> : <>
            <label className="field-label">Конфигурация (JSON)<textarea className="config-editor" spellCheck={false} value={configText} onChange={event => setConfigText(event.target.value)} /></label>
            {configError && <p className="config-error">{configError}</p>}
            <button className="save-config" onClick={saveNodeConfig}><Check size={13} /> Применить настройки</button>
          </>}
          {selectedNode.data.nodeType !== "ai.explain" && <><button className="save-config" onClick={saveNodeConfig}><Check size={13} /> Применить настройки</button>{configError && <p className="config-error">{configError}</p>}</>}
          <div className="element-actions"><button className="ghost" onClick={duplicateSelectedNode}><Copy size={13} /> Дублировать</button><button className="danger" onClick={deleteSelectedNode}><Trash2 size={13} /> Удалить блок</button></div>
          <p className="edit-hint">Замена сохраняет позицию и связи блока, но сбрасывает его конфигурацию. Удаление также удаляет связанные рёбра.</p>
        </section>}
        {selectedEdge && <section className="edit-section">
          <div className="section-caption">РЕДАКТИРОВАНИЕ СВЯЗИ</div>
          <label className="field-label">Откуда (источник)<select value={selectedEdge.source} onChange={event => updateEdgeEndpoint("source", event.target.value)}>{nodes.map(node => <option key={node.id} value={node.id}>{node.data.label} · {node.id}</option>)}</select></label>
          <label className="field-label">Куда (получатель)<select value={selectedEdge.target} onChange={event => updateEdgeEndpoint("target", event.target.value)}>{nodes.map(node => <option key={node.id} value={node.id}>{node.data.label} · {node.id}</option>)}</select></label>
          <label className="field-label">Подпись связи<input value={edgeLabel} onChange={event => { setEdgeLabel(event.target.value); setEdges(current => current.map(edge => edge.id === selectedEdge.id ? { ...edge, label: event.target.value } : edge)); }} placeholder="например: success" /></label>
          <div className="element-actions"><button className="danger" onClick={deleteSelectedEdge}><Trash2 size={13} /> Удалить связь</button></div>
          <p className="edit-hint">Также можно создать связь, потянув линию от правого порта одного блока к левому порту другого. Перетащи конец существующей связи, чтобы перенаправить её.</p>
        </section>}
        {!selectedNode && !selectedEdge && <div className="empty-inspector"><Workflow size={26} /><b>Ничего не выбрано</b><p>Выбери блок или линию на холсте. Здесь появятся доступные настройки и действия.</p></div>}
        <div className="inspector-tabs"><span className="tab-active">Результаты</span><span className="tab-state">{busy ? "RUNNING" : "IDLE"}</span></div>
        <div className="runtime"><div><Bot size={18} /></div><section><b>Workflow runtime</b><small>Исполнитель графа API</small></section><label className={busy ? "running" : ""}>{busy ? "RUNNING" : "READY"}</label></div>
        <section className="telemetry-card">
          <div className="telemetry-heading"><div><div className="section-caption">RUN TELEMETRY</div><b>Последний запуск</b></div><span className={"telemetry-status status-" + (telemetry?.status || "empty")}>{telemetry?.status === "completed" ? "УСПЕШНО" : telemetry?.status === "partial" ? "ЧАСТИЧНО" : telemetry?.status === "failed" ? "ОШИБКА" : telemetry?.status === "running" ? "В РАБОТЕ" : telemetry?.status === "queued" ? "В ОЧЕРЕДИ" : "НЕТ ДАННЫХ"}</span></div>
          {telemetry && telemetry.status !== "never_run" ? <>
            {telemetry.security_gate && <div className={"security-gate-result gate-" + telemetry.security_gate.decision.toLowerCase()}><span>SECURITY GATE</span><strong>{telemetry.security_gate.decision}</strong><small>BLOCK: {telemetry.security_gate.policy.block_on.join(", ")} · WARN: {telemetry.security_gate.policy.warn_on.join(", ")}</small></div>}
          <div className="telemetry-metrics">
              <div><strong>{formatDuration(telemetry.duration_ms)}</strong><small>ДЛИТЕЛЬНОСТЬ</small></div>
              <div><strong>{telemetry.total_findings}</strong><small>НАХОДКИ</small></div>
              <div><strong>{telemetry.completed_nodes || 0}/{telemetry.total_nodes || 0}</strong><small>ШАГИ</small></div>
            </div>
            <div className="telemetry-time"><span>Начало: {formatDate(telemetry.started_at || telemetry.queued_at)}</span><span>Завершение: {formatDate(telemetry.finished_at)}</span></div>
            {telemetry.status === "running" && <div className="telemetry-progress"><i style={{ width: `${telemetry.total_nodes ? Math.min(100, (telemetry.completed_nodes || 0) / telemetry.total_nodes * 100) : 0}%` }} /></div>}
            <div className="severity-strip">{["CRITICAL","HIGH","MEDIUM","LOW","INFO"].filter(level => (telemetry.severity?.[level] || 0) > 0).map(level => <span key={level} className={"severity-" + level.toLowerCase()}>{level} <b>{telemetry.severity[level]}</b></span>)}</div>
            {telemetry.scanners?.length > 0 && <div className="scanner-telemetry">{telemetry.scanners.map(scanner => <div key={scanner.node_id || scanner.type}><span>{scanner.type.replace("scan.", "").toUpperCase()}</span><small>{scanner.status}</small><b>{scanner.findings} · {formatDuration(scanner.duration_ms)}</b></div>)}</div>}
            {telemetry.current_node && <div className="telemetry-current"><span className="live-pulse" /> Сейчас выполняется: <b>{telemetry.current_node}</b></div>}
            {telemetry.scanner_progress && <div className="scanner-file-progress">
              <div><span>АНАЛИЗ ФАЙЛОВ</span><b>{telemetry.scanner_progress.files_scanned} / {telemetry.scanner_progress.total_files}</b></div>
              <div className="scanner-file-track"><i style={{ width: telemetry.scanner_progress.total_files ? Math.min(100, telemetry.scanner_progress.files_scanned / telemetry.scanner_progress.total_files * 100) + "%" : "0%" }} /></div>
              <small>Сейчас: {telemetry.scanner_progress.current_file}</small>
            </div>}
            {telemetry.trace && telemetry.trace.length > 0 && <div className="execution-timeline">
              <div className="execution-timeline-title">ХОД ВЫПОЛНЕНИЯ <span>{telemetry.trace.length} / {telemetry.total_nodes || telemetry.trace.length}</span></div>
              {telemetry.trace.map((step, index) => <div className={"execution-step step-" + step.status} key={step.node_id}>
                <i>{step.status === "completed" ? "✓" : step.status === "failed" ? "!" : step.status === "blocked" ? "Ⅱ" : index + 1}</i>
                <span><b>{step.type}</b><small>{step.status === "completed" ? "Завершён" : step.status === "failed" ? "Ошибка" : step.status === "blocked" ? "Заблокирован" : step.status}</small></span>
                <em>{formatDuration(step.duration_ms)}</em>
                {typeof step.findings === "number" && <strong>{step.findings} находок</strong>}
              </div>)}
              {telemetry.status === "running" && telemetry.current_node && <div className="execution-active"><span className="live-pulse" /> Выполняется {telemetry.current_node}…</div>}
            </div>}
          </> : <p className="telemetry-empty">Запусков пока нет. Телеметрия появится после первой проверки.</p>}
        </section>
        <div className="findings-head"><b>Результаты безопасности</b><span>{findings.length}</span></div>
        {findings.length === 0 ? <p className="empty-findings">После запуска здесь появятся находки SAST, SCA и Secrets Scanner.</p> :
          findings.map((finding, index) => <article className="finding" key={finding.id || finding.rule_id + index}>
            <div><strong>{finding.rule_id}</strong><label>{finding.severity}</label></div>
            <small className="finding-location">{finding.path}{finding.line ? ":" + finding.line : ""}</small>
            <p>{finding.message || "Потенциальная проблема; проверьте контекст."}</p>
            {finding.why_it_matters && <div className="finding-explanation"><b>ПОЧЕМУ ЭТО ПРОБЛЕМА</b><p>{finding.why_it_matters}</p></div>}
            {finding.recommendation && <div className="finding-remediation"><b>КАК ИСПРАВИТЬ</b><p>{finding.recommendation}</p></div>}
            {finding.ai_explanation && <div className="finding-ai-explanation">
              <div><Bot size={13} /><b>AI EXPLANATION</b><span>{Math.round(finding.ai_explanation.confidence * 100)}% confidence</span></div>
              <p><b>Причина:</b> {finding.ai_explanation.root_cause}</p>
              <p><b>Влияние:</b> {finding.ai_explanation.impact}</p>
              <p><b>Рекомендация:</b> {finding.ai_explanation.recommendation}</p>
              {finding.ai_explanation.evidence_limits && <small>Ограничения анализа: {finding.ai_explanation.evidence_limits}</small>}
            </div>}
            {(finding.cwe?.length || finding.cve) && <div className="finding-identifiers">{finding.cwe?.map(value => <span key={value}>{value}</span>)}{finding.cve && <span>{finding.cve}</span>}</div>}
            {finding.masked_value && <code>{finding.masked_value}</code>}
            <button className="source-preview-toggle" onClick={() => setSelectedFinding(current => current?.fingerprint === finding.fingerprint ? null : finding)}>
              <Code2 size={13} /> {selectedFinding?.fingerprint === finding.fingerprint ? "Скрыть фрагмент" : "Показать место в коде"}
            </button>
            {selectedFinding?.fingerprint === finding.fingerprint && <div className="source-code-preview">
              <div className="source-code-head"><span>{finding.path}</span><b>СТРОКА {finding.line || "—"}</b></div>
              {finding.code_context_redacted && <p className="source-redacted-note">Строки исходника скрыты целиком: этот фрагмент содержит секретные данные.</p>}{finding.code_context?.length ? <pre>{finding.code_context.map(row => <span key={row.line} className={row.is_finding ? "code-line code-line-hit" : "code-line"}><i>{row.line}</i><code>{row.text || " "}</code></span>)}</pre> : <p>Фрагмент недоступен. Откройте файл проекта по указанному пути.</p>}
            </div>}
            {finding.fingerprint && <div className="finding-lifecycle">
              <label>Статус
                <select value={findingStates[finding.fingerprint]?.state || "open"} onChange={event => void updateFindingLifecycle(finding, event.target.value as FindingLifecycle["state"])}>
                  <option value="open">Открыта</option><option value="accepted_risk">Принятый риск</option><option value="fixed">Исправлена</option><option value="false_positive">Ложное срабатывание</option>
                </select>
              </label>
              <button className="history-button" onClick={() => void loadFindingHistory(finding.fingerprint!)}>История</button>
              {findingHistory[finding.fingerprint] && <div className="finding-history">{findingHistory[finding.fingerprint].length ? findingHistory[finding.fingerprint].map((entry, index) => <p key={index}><b>{String(entry.details.new_state || "изменение")}</b> · {formatDate(entry.created_at)}<small>{String(entry.details.reason || "")}</small></p>) : <small>Изменений пока нет.</small>}</div>}
            </div>}
          </article>)}
        {showResult && <section className="result-section"><div className="result-title"><span>Последний ответ API</span><AlertTriangle size={13} /></div><pre>{result}</pre></section>}
        <div className="safe"><Shield size={16} /><div><b>Изолированный анализ</b><p>Проект не запускается. ZIP проверяется, Git ограничен allowlist. Секреты маскируются.</p></div></div>
        </>}
      </aside>
    </div>
    <footer><span>INVEST · AI SECURITY WORKFLOW</span><span>EDITOR · 0.6.0</span></footer>
  </main>;
}