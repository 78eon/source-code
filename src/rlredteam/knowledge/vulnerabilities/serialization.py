"""Safe tagged snapshot/model codec; no executable deserialization."""

from dataclasses import is_dataclass

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge.serialization import canonical_json, encode, load_document
from rlredteam.knowledge.serialization import model_types as knowledge_types
from rlredteam.knowledge.validation import ModelError

from .constraints import ComparisonScheme, EnrichedVersionConstraint, MatchResult, VersionOperator
from .models import (
    AffectedProduct,
    DefaultStatus,
    KnowledgeConflict,
    KnowledgeKind,
    ProductAlias,
    VulnerabilityKnowledgeEntry,
)
from .snapshot import VulnerabilityKnowledgeSnapshot

JSON_SCHEMA = "security-rl-enriched-vulnerability-json-v1"


def model_types():
    from .builder import EnrichedKnowledgeManifest
    from .source_models import (
        CanonicalProductKey,
        DuplicateKnowledgeRecord,
        LocalSourceType,
        NormalizedVulnerabilitySourceRecord,
        QualityFlag,
        SourceClassification,
        SourcePrecedencePolicy,
    )

    return {
        **knowledge_types(),
        **{
            t.__name__: t
            for t in (
                Provenance,
                ComparisonScheme,
                EnrichedVersionConstraint,
                MatchResult,
                VersionOperator,
                AffectedProduct,
                DefaultStatus,
                KnowledgeConflict,
                KnowledgeKind,
                ProductAlias,
                VulnerabilityKnowledgeEntry,
                VulnerabilityKnowledgeSnapshot,
                CanonicalProductKey,
                DuplicateKnowledgeRecord,
                LocalSourceType,
                NormalizedVulnerabilitySourceRecord,
                QualityFlag,
                SourceClassification,
                SourcePrecedencePolicy,
                EnrichedKnowledgeManifest,
            )
        },
    }


def dumps(value):
    if type(value) not in model_types().values() or not is_dataclass(value):
        raise ModelError("unsupported enriched model")
    return canonical_json({"schema": JSON_SCHEMA, "model": encode(value)})


def loads(text):
    return load_document(text, schema=JSON_SCHEMA, allowed=model_types())
