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
type Finding = { id?: string; rule_id: string; severity: string; path: string; line?: number; message?: string; masked_value?: string };
type Telemetry = {
  run_id?: string; status: string; source?: string; queued_at?: string; started_at?: string;
  finished_at?: string; duration_ms?: number | null; total_findings: number;
  severity: Record<string, number>;
  scanners: Array<{ node_id?: string; type: string; status: string; findings: number; duration_ms?: number | null }>;
  completed_nodes?: number; total_nodes?: number; current_node?: string | null;
};
type NodeData = { label: string; nodeType: string; category: string; description: string; config: Record<string, unknown> };
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
  { id: "source", type: "workflow", position: { x: 300, y: 190 }, data: { label: "Workspace source", nodeType: "source.upload", category: "Source", description: "Передаёт сканерам каталог проекта из безопасного workspace.", config: { path: "sample" } } },
  { id: "secrets", type: "workflow", position: { x: 550, y: 100 }, data: { label: "Secrets scanner", nodeType: "scan.secrets", category: "Security", description: "Ищет токены, ключи и другие потенциально раскрытые секреты.", config: {} } },
  { id: "sca", type: "workflow", position: { x: 550, y: 285 }, data: { label: "Dependency scanner", nodeType: "scan.sca", category: "Security", description: "Проверяет Gradle-зависимости по локальному advisory snapshot.", config: {} } },
  { id: "sast", type: "workflow", position: { x: 550, y: 470 }, data: { label: "Kotlin SAST", nodeType: "scan.sast", category: "Security", description: "Статически анализирует Kotlin/Spring-код на поддерживаемые классы проблем.", config: {} } },
  { id: "merge", type: "workflow", position: { x: 850, y: 285 }, data: { label: "Merge findings", nodeType: "findings.merge", category: "Logic", description: "Объединяет результаты сканеров и удаляет дубликаты по fingerprint.", config: {} } },
];
const seedEdges: Edge[] = [
  { id: "e1", source: "trigger", target: "source", animated: true, label: "запуск" },
  { id: "e2", source: "source", target: "secrets", animated: true },
  { id: "e3", source: "source", target: "sca", animated: true },
  { id: "e4", source: "source", target: "sast", animated: true },
  { id: "e5", source: "secrets", target: "merge", animated: true },
  { id: "e6", source: "sca", target: "merge", animated: true },
  { id: "e7", source: "sast", target: "merge", animated: true },
];

function WorkflowNode({ data, selected }: NodeProps<FlowNode>) {
  const meta = categoryMeta[data.category] || { label: data.category, tone: "slate" };
  return <div className={"workflow-node tone-" + meta.tone + (selected ? " is-selected" : "")}>
    <Handle type="target" position={Position.Left} />
    <div className="node-topline"><span>{meta.label}</span><span className="node-dot" /></div>
    <div className="node-main"><div className="node-symbol">{data.category === "Security" ? <Shield size={17} /> : data.category === "Source" ? <GitBranch size={17} /> : data.category === "Trigger" ? <Zap size={17} /> : data.category === "AI" ? <Bot size={17} /> : <Workflow size={17} />}</div>
      <div className="node-copy"><b>{data.label}</b><small>{data.nodeType}</small></div></div>
    <p className="node-description">{data.description}</p>
    <div className="node-footer"><span>INPUT / OUTPUT</span><span className="node-port-label">●</span></div>
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
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
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

  const selectedNode = nodes.find(node => node.id === selectedNodeId) || null;
  const selectedEdge = edges.find(edge => edge.id === selectedEdgeId) || null;
  useEffect(() => {
    setConfigText(selectedNode ? JSON.stringify(selectedNode.data.config || {}, null, 2) : "{}");
    setConfigError("");
  }, [selectedNodeId, nodes.find(n => n.id === selectedNodeId)?.data.config]);
  useEffect(() => { setEdgeLabel(selectedEdge?.label?.toString() || ""); }, [selectedEdgeId, selectedEdge?.label]);

  const onConnect = useCallback((connection: Connection) => {
    setEdges(current => addEdge({ ...connection, id: "edge-" + Date.now(), animated: true, style: { stroke: "#70b7f4", strokeWidth: 2 } }, current));
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
      if (!response.ok) throw new Error(data.detail || "Не удалось загрузить архив");
      const sourceNode = nodes.find(node => node.data.nodeType === "source.upload");
      if (sourceNode) updateNode(sourceNode.id, { config: { ...sourceNode.data.config, path: data.path } });
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

      const completed = await new Promise<Telemetry>((resolve, reject) => {
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
          <label className="field-label">Конфигурация (JSON)<textarea className="config-editor" spellCheck={false} value={configText} onChange={event => setConfigText(event.target.value)} /></label>
          {configError && <p className="config-error">{configError}</p>}
          <button className="save-config" onClick={saveNodeConfig}><Check size={13} /> Применить настройки</button>
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
            <div className="telemetry-metrics">
              <div><strong>{formatDuration(telemetry.duration_ms)}</strong><small>ДЛИТЕЛЬНОСТЬ</small></div>
              <div><strong>{telemetry.total_findings}</strong><small>НАХОДКИ</small></div>
              <div><strong>{telemetry.completed_nodes || 0}/{telemetry.total_nodes || 0}</strong><small>ШАГИ</small></div>
            </div>
            <div className="telemetry-time"><span>Начало: {formatDate(telemetry.started_at || telemetry.queued_at)}</span><span>Завершение: {formatDate(telemetry.finished_at)}</span></div>
            {telemetry.status === "running" && <div className="telemetry-progress"><i style={{ width: `${telemetry.total_nodes ? Math.min(100, (telemetry.completed_nodes || 0) / telemetry.total_nodes * 100) : 0}%` }} /></div>}
            <div className="severity-strip">{["CRITICAL","HIGH","MEDIUM","LOW","INFO"].filter(level => (telemetry.severity?.[level] || 0) > 0).map(level => <span key={level} className={"severity-" + level.toLowerCase()}>{level} <b>{telemetry.severity[level]}</b></span>)}</div>
            {telemetry.scanners?.length > 0 && <div className="scanner-telemetry">{telemetry.scanners.map(scanner => <div key={scanner.node_id || scanner.type}><span>{scanner.type.replace("scan.", "").toUpperCase()}</span><small>{scanner.status}</small><b>{scanner.findings} · {formatDuration(scanner.duration_ms)}</b></div>)}</div>}
            {telemetry.current_node && <div className="telemetry-current">Сейчас выполняется: <b>{telemetry.current_node}</b></div>}
          </> : <p className="telemetry-empty">Запусков пока нет. Телеметрия появится после первой проверки.</p>}
        </section>
        <div className="findings-head"><b>Результаты безопасности</b><span>{findings.length}</span></div>
        {findings.length === 0 ? <p className="empty-findings">После запуска здесь появятся находки SAST, SCA и Secrets Scanner.</p> :
          findings.map((finding, index) => <article className="finding" key={finding.id || finding.rule_id + index}><div><strong>{finding.rule_id}</strong><label>{finding.severity}</label></div><small>{finding.path}{finding.line ? ":" + finding.line : ""}</small><p>{finding.message || "Потенциальная проблема; проверьте контекст."}</p>{finding.masked_value && <code>{finding.masked_value}</code>}</article>)}
        {showResult && <section className="result-section"><div className="result-title"><span>Последний ответ API</span><AlertTriangle size={13} /></div><pre>{result}</pre></section>}
        <div className="safe"><Shield size={16} /><div><b>Изолированный анализ</b><p>Проект не запускается. ZIP проверяется, Git ограничен allowlist. Секреты маскируются.</p></div></div>
        </>}
      </aside>
    </div>
    <footer><span>INVEST · AI SECURITY WORKFLOW</span><span>EDITOR · 0.4.0</span></footer>
  </main>;
}