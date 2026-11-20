from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph
from app.workflows.engine import execute_graph, WorkflowExecutionError

app=FastAPI(title="AI Security Workflow API",version="0.1.0")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.get("/health")
def health(): return {"status":"ok","service":"api"}

@app.get("/api/node-types")
def node_types(): return [m.model_dump() for m in registry.all()]

@app.post("/api/workflows/validate")
def validate_workflow(graph:WorkflowGraph): return validate_graph(graph,registry).model_dump()

@app.post("/api/workflows/run")
def run_workflow(graph:WorkflowGraph):
    try:return execute_graph(graph,registry)
    except WorkflowExecutionError as exc:raise HTTPException(status_code=422,detail=str(exc)) from exc
