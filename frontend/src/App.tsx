import { memo, useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, Controls, MiniMap, Handle, Position, addEdge,
  useEdgesState, useNodesState,
  type Connection, type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Activity, AlertTriangle, Bot, Check, ChevronDown, CircleHelp, CirclePlay,
  Code2, GitBranch, Layers3, LockKeyhole, Plus, Search, Shield, UploadCloud,
  Workflow, X, Zap,
} from "lucide-react";

type Manifest = { type: string; title: string; category: string; description: string };
type Finding = { id?: string; rule_id: string; severity: string; path: string; line?: number; message?: string; masked_value?: string };
type NodeData = { label: string; nodeType: string; category: string; description: string };
type FlowNode = Node<NodeData>;

const categoryMeta: Record<string, { label: string; tone: string }> = {
  Trigger: { label: "Триггер", tone: "blue" },
  Source: { label: "Источник", tone: "cyan" },
  Security: { label: "Security", tone: "violet" },
  Logic: { label: "Логика", tone: "amber" },
  AI: { label: "AI", tone: "pink" },
  Notify: { label: "Уведомления", tone: "green" },
  CI: { label: "CI / Gate", tone: "green" },
};

const seedNodes: FlowNode[] = [
  { id: "trigger", type: "workflow", position: { x: 70, y: 190 }, data: { label: "Manual trigger", nodeType: "trigger.manual", category: "Trigger", description: "Ручной запуск проверки по кнопке «Запустить»." } },
  { id: "source", type: "workflow", position: { x: 300, y: 190 }, data: { label: "Workspace source", nodeType: "source.upload", category: "Source", description: "Передаёт сканерам каталог проекта из безопасного workspace." } },
  { id: "secrets", type: "workflow", position: { x: 550, y: 100 }, data: { label: "Secrets scanner", nodeType: "scan.secrets", category: "Security", description: "Ищет токены, ключи и другие потенциально раскрытые секреты." } },
  { id: "sca", type: "workflow", position: { x: 550, y: 285 }, data: { label: "Dependency scanner", nodeType: "scan.sca", category: "Security", description: "Проверяет Gradle-зависимости по локальному advisory snapshot." } },
  { id: "sast", type: "workflow", position: { x: 550, y: 470 }, data: { label: "Kotlin SAST", nodeType: "scan.sast", category: "Security", description: "Статически анализирует Kotlin/Spring-код на поддерживаемые классы проблем." } },
  { id: "merge", type: "workflow", position: { x: 850, y: 285 }, data: { label: "Merge findings", nodeType: "findings.merge", category: "Logic", description: "Объединяет результаты сканеров и удаляет дубликаты по fingerprint." } },
];
const seedEdges: Edge[] = [
  { id: "e1", source: "trigger", target: "source", animated: true },
  { id: "e2", source: "source", target: "secrets", animated: true },
  { id: "e3", source: "source", target: "sca", animated: true },
  { id: "e4", source: "source", target: "sast", animated: true },
  { id: "e5", source: "secrets", target: "merge", animated: true },
  { id: "e6", source: "sca", target: "merge", animated: true },
  { id: "e7", source: "sast", target: "merge", animated: true },
];

function WorkflowNode({ data, selected }: NodeProps<FlowNode>) {
  const meta = categoryMeta[data.category] || { label: data.category, tone: "slate" };
  return <div className={`workflow-node tone-${meta.tone} ${selected ? "is-selected" : ""}`}>
    <Handle type="target" position={Position.Left} />
    <div className="node-topline"><span>{meta.label}</span><span className="node-dot" /></div>
    <div className="node-main">
      <div className="node-symbol">{data.category === "Security" ? <Shield size={17} /> : data.category === "Source" ? <GitBranch size={17} /> : data.category === "Trigger" ? <Zap size={17} /> : data.category === "AI" ? <Bot size={17} /> : <Workflow size={17} />}</div>
      <div className="node-copy"><b>{data.label}</b><small>{data.nodeType}</small></div>
    </div>
    <p className="node-description">{data.description}</p>
    <div className="node-footer"><span>INPUT / OUTPUT</span><span className="node-port-label">●</span></div>
    <Handle type="source" position={Position.Right} />
  </div>;
}
const nodeTypes = { workflow: memo(WorkflowNode) };

const typeById = (id: string) =>
  id === "trigger" ? "trigger.manual" :
  id === "source" ? "source.upload" :
  id === "secrets" ? "scan.secrets" :
  id === "merge" ? "findings.merge" : id.replace(/-\d+$/, "");

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(seedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(seedEdges);
  const [manifests, setManifests] = useState<Manifest[]>([]);
  const [workflowId, setWorkflowId] = useState<string | null>(null);
  const [sourcePath, setSourcePath] = useState("sample");
  const [gitUrl, setGitUrl] = useState("");
  const [gitRef, setGitRef] = useState("");
  const [notice, setNotice] = useState("Подключение к API…");
  const [result, setResult] = useState("Граф готов к проверке.");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("Все");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("source");
  const [showResult, setShowResult] = useState(true);

  useEffect(() => {
    fetch("/api/node-types")
      .then(response => { if (!response.ok) throw new Error(); return response.json(); })
      .then((data: Manifest[]) => { setManifests(data); setNotice("API подключён · реестр компонентов синхронизирован"); })
      .catch(() => setNotice("API недоступен · проверьте backend :8000"));
  }, []);

  const onConnect = useCallback((connection: Connection) =>
    setEdges(current => addEdge({ ...connection, animated: true, style: { stroke: "#5b91c7", strokeWidth: 1.8 } }, current)), [setEdges]);

  const addNode = (manifest: Manifest) => {
    const id = manifest.type + "-" + Date.now();
    const position = { x: 180 + (nodes.length % 3) * 245, y: 90 + Math.floor(nodes.length / 3) * 145 };
    setNodes(current => [...current, { id, type: "workflow", position, data: { label: manifest.title, nodeType: manifest.type, category: manifest.category, description: manifest.description } }]);
    setSelectedNodeId(id);
  };

  const selectedNode = nodes.find(node => node.id === selectedNodeId) || null;
  const graph = useMemo(() => ({
    name: "Security pipeline",
    nodes: nodes.map(node => ({
      id: node.id,
      type: node.data.nodeType || typeById(node.id),
      position: node.position,
      config: (node.data.nodeType || typeById(node.id)) === "source.upload" ? { path: sourcePath } : (node.data.nodeType || typeById(node.id)) === "source.git" ? { url: gitUrl, ref: gitRef || undefined } : {},
    })),
    edges: edges.map(edge => ({ id: edge.id, source: edge.source, target: edge.target, source_handle: edge.sourceHandle, target_handle: edge.targetHandle })),
  }), [nodes, edges, sourcePath, gitUrl, gitRef]);

  const uploadArchive = async (file?: File) => {
    if (!file) return;
    setUploading(true); setFindings([]);
    try {
      const form = new FormData(); form.append("file", file);
      const response = await fetch("/api/sources/upload", { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось загрузить архив");
      setSourcePath(data.path);
      setResult(`Архив принят · ${data.files} файлов · ${Math.round(data.expanded_bytes / 1024)} KiB распаковано. Источник обновлён.`);
    } catch (error) { setResult(`Ошибка загрузки ZIP: ${String(error)}`); }
    finally { setUploading(false); }
  };

  const persistWorkflow = async () => {
    const response = await fetch(workflowId ? `/api/workflows/${workflowId}` : "/api/workflows", {
      method: workflowId ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(graph),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(data));
    setWorkflowId(data.id); return data.id as string;
  };

  const saveWorkflow = async () => {
    setBusy(true);
    try { const id = await persistWorkflow(); setResult(`Сохранено · workflow ${id}`); }
    catch (error) { setResult(`Не удалось сохранить workflow: ${String(error)}`); }
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
      const response = await fetch(`/api/workflows/${id}/runs`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(JSON.stringify(data));
      setResult(JSON.stringify(data, null, 2)); setShowResult(true);
      const findingsResponse = await fetch(`/api/runs/${data.run_id}/findings`);
      if (findingsResponse.ok) setFindings(await findingsResponse.json());
    } catch (error) { setResult(`Запуск не выполнен: ${String(error)}`); setShowResult(true); }
    finally { setBusy(false); }
  };

  const categories = ["Все", ...Array.from(new Set(manifests.map(item => item.category)))];
  const filtered = manifests.filter(item => (category === "Все" || item.category === category) && `${item.title} ${item.description} ${item.type}`.toLowerCase().includes(search.toLowerCase()));

  return <main className="shell">
    <header className="topbar">
      <div className="brand"><div className="mark"><Shield size={19} /></div><div><b>INVEST <span>／</span> SECURITY WORKFLOW</b><small>VISUAL SECURITY AUTOMATION PLATFORM</small></div></div>
      <div className="status"><i className={notice.startsWith("API подключён") ? "online" : ""} />{notice}</div>
      <div className="actions">
        <span className="revision"><GitBranch size={13} /> feat / platform-foundation</span>
        <button className="ghost" disabled={busy} onClick={saveWorkflow}>Сохранить</button>
        <button className="validate" disabled={busy} onClick={validateWorkflow}><Check size={14} /> Проверить</button>
        <button className="run" disabled={busy} onClick={runWorkflow}><CirclePlay size={14} /> {busy ? "Выполняется…" : "Запустить"}</button>
      </div>
    </header>

    <div className="layout">
      <aside className="panel palette">
        <div className="panel-heading"><div><div className="eyebrow">WORKFLOW BUILDER</div><h3><Workflow size={17} /> Библиотека блоков</h3></div><span className="counter">{manifests.length}</span></div>
        <p className="panel-intro">Собирайте проверку из компонентов. Нажмите на блок, чтобы добавить его на холст, или раскройте описание.</p>
        <div className="searchbox"><Search size={14} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Найти блок или назначение…" /><kbd>/</kbd></div>
        <div className="category-filters">{categories.map(item => <button key={item} className={category === item ? "active" : ""} onClick={() => setCategory(item)}>{item}</button>)}</div>

        <div className="source-section">
          <div className="section-caption">ИСТОЧНИК ПРОЕКТА</div>
          <label className="field-label">Путь в WORKSPACE_ROOT<input value={sourcePath} onChange={event => setSourcePath(event.target.value)} placeholder="путь после загрузки ZIP" /></label>
          <label className="archive-upload"><UploadCloud size={15} /><span>{uploading ? "Загрузка и проверка…" : "Загрузить ZIP проекта"}</span><input type="file" accept=".zip,application/zip" disabled={uploading || busy} onChange={event => { void uploadArchive(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
          <small className="upload-hint">До 50 MiB · архив проверяется · файлы проекта не исполняются</small>
          <details className="source-advanced"><summary>Настройки Git-источника <ChevronDown size={13} /></summary>
            <label className="field-label">Git HTTPS URL<input value={gitUrl} onChange={event => setGitUrl(event.target.value)} placeholder="https://github.com/org/repository" /></label>
            <label className="field-label">Ветка или тег<input value={gitRef} onChange={event => setGitRef(event.target.value)} placeholder="main (по умолчанию)" /></label>
            <small className="upload-hint">Доступны только точные адреса из ALLOWED_TARGETS backend.</small>
          </details>
        </div>

        <div className="section-caption library-caption">КОМПОНЕНТЫ API</div>
        {filtered.map(manifest => <article className="library-item" key={manifest.type}>
          <div className="library-main"><div className={"library-icon tone-" + (categoryMeta[manifest.category] || {tone:"slate"}).tone}><Code2 size={15} /></div><div className="library-copy"><b>{manifest.title}</b><small>{manifest.type}</small></div><button className="add-node" title="Добавить блок на холст" onClick={() => addNode(manifest)}><Plus size={15} /></button></div>
          <details className="node-help"><summary><CircleHelp size={12} /> Что делает блок <ChevronDown size={12} /></summary><p>{manifest.description}</p><span>{categoryMeta[manifest.category]?.label || manifest.category} · тип: {manifest.type}</span></details>
        </article>)}
        {!manifests.length && <div className="empty-library">Загружаем реестр компонентов API…</div>}
        {manifests.length > 0 && filtered.length === 0 && <div className="empty-library">Ничего не найдено. Измени запрос или категорию.</div>}
        <div className="palette-note"><LockKeyhole size={14} /><span>Безопасный режим: код репозитория анализируется как данные, без запуска его скриптов.</span></div>
      </aside>

      <section className="editor">
        <div className="editor-head"><div><span className="eyebrow">EDITOR / WORKFLOW 001</span><h1>Security pipeline</h1><p>Поток анализа проекта · выбери блок, чтобы посмотреть назначение</p></div>
          <div className="counts"><span><Layers3 size={13} />{nodes.length} блоков</span><span><GitBranch size={13} />{edges.length} связей</span></div>
        </div>
        <div className="flow"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect} onNodeClick={(_, node) => setSelectedNodeId(node.id)} fitView fitViewOptions={{ padding: 0.18 }}>
          <Background color="#27374c" gap={22} size={1} />
          <MiniMap pannable zoomable nodeColor={node => node.type === "workflow" ? "#426b91" : "#526176"} />
          <Controls />
        </ReactFlow></div>
        <div className="flow-foot"><span><Activity size={13} /> Редактор графа <i /> Сетка 22 px</span><span>Соединяй выходы блоков с совместимыми входами</span></div>
      </section>

      <aside className="panel inspector">
        <div className="inspector-top"><div><div className="eyebrow">INSPECTOR / RUNTIME</div><h3><Activity size={17} /> Панель анализа</h3></div><button className="icon-button" title={showResult ? "Свернуть результат" : "Показать результат"} onClick={() => setShowResult(value => !value)}>{showResult ? <X size={14} /> : <ChevronDown size={14} />}</button></div>
        <div className="inspector-tabs"><span className="tab-active">Инспектор</span><span>Выполнение</span><span className="tab-state">{busy ? "RUNNING" : "IDLE"}</span></div>
        <section className="selected-card">
          <div className="section-caption">ВЫБРАННЫЙ БЛОК</div>
          {selectedNode ? <><div className="selected-title"><span className="selected-symbol"><Workflow size={16} /></span><div><b>{selectedNode.data.label}</b><small>{selectedNode.data.nodeType}</small></div></div><p>{selectedNode.data.description}</p><div className="selected-meta"><span>{selectedNode.data.category}</span><span>ID · {selectedNode.id.slice(0, 18)}</span></div></> : <p>Выбери блок на холсте, чтобы увидеть его назначение.</p>}
        </section>
        <div className="runtime"><div><Bot size={18} /></div><section><b>Workflow runtime</b><small>Базовый синхронный executor</small></section><label className={busy ? "running" : ""}>{busy ? "RUNNING" : "READY"}</label></div>
        <div className="findings-head"><b>Результаты безопасности</b><span>{findings.length}</span></div>
        {findings.length === 0 ? <p className="empty-findings">После запуска здесь появятся находки SAST, SCA и Secrets Scanner.</p> :
          findings.map((finding, index) => <article className="finding" key={finding.id || finding.rule_id + index}>
            <div><strong>{finding.rule_id}</strong><label>{finding.severity}</label></div><small>{finding.path}{finding.line ? ":" + finding.line : ""}</small><p>{finding.message || "Потенциальная проблема; проверьте контекст."}</p>{finding.masked_value && <code>{finding.masked_value}</code>}
          </article>)}
        {showResult && <section className="result-section"><div className="result-title"><span>Последний ответ API</span><AlertTriangle size={13} /></div><pre>{result}</pre></section>}
        <div className="safe"><Shield size={16} /><div><b>Изолированный анализ</b><p>Проект не запускается. ZIP проверяется, Git ограничен allowlist. Секреты маскируются.</p></div></div>
      </aside>
    </div>
    <footer><span>INVEST · AI SECURITY WORKFLOW</span><span>EDITOR FOUNDATION · 0.3.0</span></footer>
  </main>;
}
