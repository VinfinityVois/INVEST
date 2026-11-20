import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, Controls, MiniMap, addEdge, useEdgesState, useNodesState,
  type Connection, type Edge, type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Activity, AlertTriangle, Bot, Check, CirclePlay, GitBranch, Layers3, Plus, Shield, Workflow } from "lucide-react";

type Manifest = { type: string; title: string; category: string; description: string };
type Finding = { id?: string; rule_id: string; severity: string; path: string; line?: number; message?: string; masked_value?: string };

const seedNodes: Node[] = [
  { id: "trigger", position: { x: 80, y: 170 }, data: { label: "Manual trigger" }, style: { border: "1px solid #3b82f6", background: "#111a2a", color: "#dbeafe", borderRadius: 9, padding: 12, width: 170 } },
  { id: "source", position: { x: 270, y: 170 }, data: { label: "Workspace source" }, style: { border: "1px solid #64748b", background: "#18202c", color: "#dbe4f0", borderRadius: 9, padding: 12, width: 170 } },
  { id: "secrets", position: { x: 470, y: 170 }, data: { label: "Secrets scanner" }, style: { border: "1px solid #8b5cf6", background: "#1b1530", color: "#ede9fe", borderRadius: 9, padding: 12, width: 170 } },
  { id: "merge", position: { x: 760, y: 170 }, data: { label: "Merge findings" }, style: { border: "1px solid #0d9488", background: "#102522", color: "#ccfbf1", borderRadius: 9, padding: 12, width: 170 } },
];
const seedEdges: Edge[] = [
  { id: "e1", source: "trigger", target: "source", animated: true },
  { id: "e2", source: "source", target: "secrets", animated: true },
  { id: "e3", source: "secrets", target: "merge", animated: true },
];
const typeById = (id: string) =>
  id === "trigger" ? "trigger.manual" :
  id === "source" ? "source.upload" :
  id === "secrets" ? "scan.secrets" :
  id === "merge" ? "findings.merge" : id.replace(/-\d+$/, "");

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState(seedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(seedEdges);
  const [manifests, setManifests] = useState<Manifest[]>([]);
  const [workflowId, setWorkflowId] = useState<string | null>(null);
  const [sourcePath, setSourcePath] = useState("sample");
  const [notice, setNotice] = useState("Подключение к API…");
  const [result, setResult] = useState("Граф готов к проверке.");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch("/api/node-types")
      .then(response => { if (!response.ok) throw new Error(); return response.json(); })
      .then(data => { setManifests(data); setNotice("API подключён · реестр нод загружен"); })
      .catch(() => setNotice("API недоступен · backend :8000"));
  }, []);

  const onConnect = useCallback((connection: Connection) =>
    setEdges(current => addEdge({ ...connection, animated: true }, current)), [setEdges]);

  const addNode = (manifest: Manifest) => {
    const id = manifest.type + "-" + Date.now();
    setNodes(current => [...current, {
      id,
      position: { x: 220 + Math.random() * 360, y: 80 + Math.random() * 280 },
      data: { label: manifest.title },
      style: { border: "1px solid #465a76", background: "#151d2a", color: "#e2e8f0", borderRadius: 9, padding: 12, width: 180 },
    }]);
  };

  const graph = useMemo(() => ({
    name: "Security pipeline",
    nodes: nodes.map(node => ({
      id: node.id,
      type: typeById(node.id),
      position: node.position,
      config: node.id === "source" || node.id.startsWith("source.upload-") ? { path: sourcePath } : {},
    })),
    edges: edges.map(edge => ({
      id: edge.id, source: edge.source, target: edge.target,
      source_handle: edge.sourceHandle, target_handle: edge.targetHandle,
    })),
  }), [nodes, edges, sourcePath]);

  const persistWorkflow = async () => {
    const response = await fetch(workflowId ? `/api/workflows/${workflowId}` : "/api/workflows", {
      method: workflowId ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(graph),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(data));
    setWorkflowId(data.id);
    return data.id as string;
  };

  const saveWorkflow = async () => {
    setBusy(true);
    try {
      const id = await persistWorkflow();
      setResult(`Сохранено · workflow ${id}`);
    } catch (error) {
      setResult(`Не удалось сохранить workflow: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const validateWorkflow = async () => {
    setBusy(true);
    try {
      const response = await fetch("/api/workflows/validate", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(graph),
      });
      const data = await response.json();
      setResult(JSON.stringify(data, null, 2));
    } catch {
      setResult("Не удалось связаться с API. Проверьте backend.");
    } finally {
      setBusy(false);
    }
  };

  const runWorkflow = async () => {
    setBusy(true);
    try {
      const id = await persistWorkflow();
      const response = await fetch(`/api/workflows/${id}/runs`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(JSON.stringify(data));
      setResult(JSON.stringify(data, null, 2));
      const findingsResponse = await fetch(`/api/runs/${data.run_id}/findings`);
      if (findingsResponse.ok) setFindings(await findingsResponse.json());
    } catch (error) {
      setResult(`Запуск не выполнен: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  };

  return <main className="shell">
    <header className="topbar">
      <div className="brand"><div className="mark"><Shield size={19} /></div><div><b>SECURITY WORKFLOW</b><small>VISUAL AUTOMATION PLATFORM</small></div></div>
      <div className="status"><i />{notice}</div>
      <div className="actions">
        <button className="ghost"><GitBranch size={14} /> draft</button>
        <button className="ghost" disabled={busy} onClick={saveWorkflow}>Сохранить</button>
        <button className="validate" disabled={busy} onClick={validateWorkflow}><Check size={14} /> Проверить</button>
        <button className="run" disabled={busy} onClick={runWorkflow}><CirclePlay size={14} /> Запустить</button>
      </div>
    </header>
    <div className="layout">
      <aside className="panel palette">
        <div className="eyebrow">WORKFLOW BUILDER</div><h3><Workflow size={17} /> Компоненты</h3>
        <p>Добавляйте ноды на холст и соединяйте их.</p>
        <label className="source-config">Каталог в WORKSPACE_ROOT<input value={sourcePath} onChange={event => setSourcePath(event.target.value)} placeholder="например, sample" /></label>
        {["Trigger", "Source", "Security", "Logic", "AI", "Notify", "CI"].map(category =>
          <section key={category}><h4>{category}</h4>
            {manifests.filter(manifest => manifest.category === category).map(manifest =>
              <button className="node-add" key={manifest.type} onClick={() => addNode(manifest)}><Plus size={13} />{manifest.title}</button>
            )}
          </section>
        )}
        {!manifests.length && <small>Ожидание API…</small>}
      </aside>
      <section className="editor">
        <div className="editor-head"><div><span className="eyebrow">EDITOR / WORKFLOW 001</span><h1>Security pipeline</h1></div>
          <div className="counts"><span><Layers3 size={13} />{nodes.length} нод</span><span><GitBranch size={13} />{edges.length} связей</span></div>
        </div>
        <div className="flow"><ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect} fitView>
          <Background color="#263246" gap={22} size={1} /><MiniMap pannable zoomable /><Controls />
        </ReactFlow></div>
        <div className="flow-foot"><span><Activity size={13} /> Редактор графа</span><span>Проверяйте типы портов перед запуском</span></div>
      </section>
      <aside className="panel inspector">
        <div className="eyebrow">EXECUTION</div><h3><Activity size={17} /> Выполнение</h3>
        <div className="runtime"><div><Bot size={18} /></div><section><b>Workflow runtime</b><small>P0 · synchronous executor</small></section><label>{busy ? "RUNNING" : "READY"}</label></div>
        <div className="result-title">Последний результат <AlertTriangle size={13} /></div><pre>{result}</pre>
        <div className="findings-head"><b>Findings</b><span>{findings.length}</span></div>
        {findings.length === 0 ? <p className="empty-findings">После запуска здесь появятся обнаруженные проблемы.</p> :
          findings.map((finding, index) => <article className="finding" key={finding.id || finding.rule_id + index}>
            <div><strong>{finding.rule_id}</strong><label>{finding.severity}</label></div>
            <small>{finding.path}{finding.line ? `:${finding.line}` : ""}</small>
            <p>{finding.message || "Возможный секрет; значение замаскировано."}</p>
            {finding.masked_value && <code>{finding.masked_value}</code>}
          </article>)
        }
        <div className="safe"><Shield size={16} /><div><b>Безопасный режим</b><p>Исходный код рассматривается как данные. Команды проекта не запускаются.</p></div></div>
      </aside>
    </div>
    <footer><span>INVEST · AI SECURITY WORKFLOW</span><span>FOUNDATION BUILD 0.2.0</span></footer>
  </main>;
}
