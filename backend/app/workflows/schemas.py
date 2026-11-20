from typing import Any, Literal
from pydantic import BaseModel, Field

class Port(BaseModel):
    name: str
    data_type: str

class NodeManifest(BaseModel):
    type: str
    title: str
    category: str
    description: str
    inputs: list[Port] = Field(default_factory=list)
    outputs: list[Port] = Field(default_factory=list)
    config_schema: dict[str, Any] = Field(default_factory=dict)

class WorkflowNode(BaseModel):
    id: str
    type: str
    position: dict[str, float] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)

class WorkflowEdge(BaseModel):
    id: str
    source: str
    target: str
    source_handle: str | None = None
    target_handle: str | None = None

class WorkflowGraph(BaseModel):
    name: str = "Untitled workflow"
    nodes: list[WorkflowNode]
    edges: list[WorkflowEdge]

class ValidationIssue(BaseModel):
    code: str
    message: str
    node_id: str | None = None
    edge_id: str | None = None
    severity: Literal["error", "warning"] = "error"

class ValidationResult(BaseModel):
    valid: bool
    issues: list[ValidationIssue]
