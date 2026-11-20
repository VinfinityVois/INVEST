from uuid import UUID
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from app.db import SessionLocal
from app.models import Workflow, WorkflowVersion
from app.workflows.registry import registry
from app.workflows.schemas import WorkflowGraph
from app.workflows.validator import validate_graph
from app.workflows.engine import execute_graph, WorkflowExecutionError

app=FastAPI(title="AI Security Workflow API",version="0.1.0")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.get("/health")
def health():
    return {"status":"ok","service":"api"}

@app.get("/health/db")
def database_health():
    try:
        with SessionLocal() as session: session.execute(text("SELECT 1"))
        return {"status":"ok","service":"postgres"}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503,detail="Database unavailable") from exc

@app.get("/api/node-types")
def node_types():
    return [m.model_dump() for m in registry.all()]

@app.post("/api/workflows/validate")
def validate_workflow(graph:WorkflowGraph):
    return validate_graph(graph,registry).model_dump()

@app.get("/api/workflows")
def list_workflows():
    with SessionLocal() as session:
        rows=session.scalars(select(Workflow).order_by(Workflow.updated_at.desc())).all()
        return [{"id":str(w.id),"name":w.name,"description":w.description,"updated_at":w.updated_at} for w in rows]

@app.post("/api/workflows",status_code=201)
def create_workflow(graph:WorkflowGraph):
    validation=validate_graph(graph,registry)
    if not validation.valid:
        raise HTTPException(status_code=422,detail=validation.model_dump())
    with SessionLocal() as session:
        workflow=Workflow(name=graph.name)
        session.add(workflow)
        session.flush()
        session.add(WorkflowVersion(workflow_id=workflow.id,version=1,graph=graph.model_dump(mode="json")))
        session.commit()
        return {"id":str(workflow.id),"name":workflow.name,"version":1}

@app.get("/api/workflows/{workflow_id}")
def get_workflow(workflow_id:UUID):
    with SessionLocal() as session:
        workflow=session.get(Workflow,workflow_id)
        if workflow is None: raise HTTPException(status_code=404,detail="Workflow not found")
        version=session.scalar(select(WorkflowVersion).where(WorkflowVersion.workflow_id==workflow_id).order_by(WorkflowVersion.version.desc()).limit(1))
        return {"id":str(workflow.id),"name":workflow.name,"version":version.version if version else 0,"graph":version.graph if version else None}

@app.put("/api/workflows/{workflow_id}")
def update_workflow(workflow_id:UUID,graph:WorkflowGraph):
    validation=validate_graph(graph,registry)
    if not validation.valid:
        raise HTTPException(status_code=422,detail=validation.model_dump())
    with SessionLocal() as session:
        workflow=session.get(Workflow,workflow_id)
        if workflow is None: raise HTTPException(status_code=404,detail="Workflow not found")
        latest=session.scalar(select(WorkflowVersion).where(WorkflowVersion.workflow_id==workflow_id).order_by(WorkflowVersion.version.desc()).limit(1))
        version=(latest.version if latest else 0)+1
        workflow.name=graph.name
        session.add(WorkflowVersion(workflow_id=workflow_id,version=version,graph=graph.model_dump(mode="json")))
        session.commit()
        return {"id":str(workflow.id),"name":workflow.name,"version":version}

@app.post("/api/workflows/run")
def run_workflow(graph:WorkflowGraph):
    try:
        return execute_graph(graph,registry)
    except WorkflowExecutionError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc
