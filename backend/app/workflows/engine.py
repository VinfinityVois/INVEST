from collections import defaultdict, deque
from .registry import NodeRegistry
from .schemas import WorkflowGraph
from .validator import validate_graph

class WorkflowExecutionError(RuntimeError): pass

def execute_graph(graph: WorkflowGraph, registry: NodeRegistry):
    result=validate_graph(graph,registry)
    if not result.valid:
        raise WorkflowExecutionError("; ".join(i.message for i in result.issues if i.severity=="error"))
    nodes={n.id:n for n in graph.nodes}; outgoing=defaultdict(list); indegree={n.id:0 for n in graph.nodes}
    for e in graph.edges: outgoing[e.source].append(e.target); indegree[e.target]+=1
    q=deque(k for k,v in indegree.items() if v==0); order=[]
    while q:
        cur=q.popleft(); order.append(cur)
        for nxt in outgoing[cur]:
            indegree[nxt]-=1
            if indegree[nxt]==0:q.append(nxt)
    trace=[]; outputs={}
    for nid in order:
        node=nodes[nid]
        if node.type=="trigger.manual": out={"triggered":True}
        elif node.type in {"source.git","source.upload"}: out={"status":"adapter_required"}
        elif node.type.startswith("scan."): out={"status":"scanner_pending","findings":[]}
        elif node.type=="findings.merge": out={"status":"ok","findings":[]}
        elif node.type=="logic.if": out={"branch":"false"}
        elif node.type=="ai.explain": out={"status":"llm_profile_required"}
        else: out={"status":"adapter_required"}
        outputs[nid]=out; trace.append({"node_id":nid,"type":node.type,"status":out.get("status","completed")})
    return {"status":"completed","order":order,"trace":trace,"outputs":outputs}
