from typing import Any, Literal

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: list[str] = Field(default_factory=list)
    status: str = "UNKNOWN"


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(min_length=1)


class GraphDTO(BaseModel):
    source: Literal["neo4j"] = "neo4j"
    graph_id: str | None = None
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
