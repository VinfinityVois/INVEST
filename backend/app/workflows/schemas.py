from typing import Any, Literal

from pydantic import BaseModel, Field


class Port(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    data_type: str = Field(min_length=1, max_length=80)


class NodeManifest(BaseModel):
    type: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=160)
    category: str = Field(min_length=1, max_length=80)
    description: str = Field(max_length=1000)
    inputs: list[Port] = Field(default_factory=list, max_length=100)
    outputs: list[Port] = Field(default_factory=list, max_length=100)
    config_schema: dict[str, Any] = Field(default_factory=dict, max_length=100)


class WorkflowNode(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    type: str = Field(min_length=1, max_length=100)
    position: dict[str, float] = Field(default_factory=dict, max_length=10)
    config: dict[str, Any] = Field(default_factory=dict, max_length=100)


class WorkflowEdge(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    source: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=120)
    source_handle: str | None = Field(default=None, max_length=80)
    target_handle: str | None = Field(default=None, max_length=80)


class WorkflowGraph(BaseModel):
    name: str = Field(default="Untitled workflow", min_length=1, max_length=200)
    nodes: list[WorkflowNode] = Field(max_length=500)
    edges: list[WorkflowEdge] = Field(max_length=2000)


class ValidationIssue(BaseModel):
    code: str
    message: str
    node_id: str | None = None
    edge_id: str | None = None
    severity: Literal["error", "warning"] = "error"


class ValidationResult(BaseModel):
    valid: bool
    issues: list[ValidationIssue]
