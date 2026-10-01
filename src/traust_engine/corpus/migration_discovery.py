"""Discover contract artifacts independently of the census population."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage import Binding
from traust_contracts.v1.storage.store import storage_profiles

from traust_engine.corpus.store_ingest import _canonical_repo_url

FILENAME_ALIASES = {
    "security-audit": "report",
    "container-audit": "report",
    "findings-current": "report",
    "findings-layer": "layer",
    "remediation-verification": "verification",
    "priv-profile": "operator-priv-profile",
}


class DiscoveryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class BindingOverride(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope_id: str | None = None
    subject_id: str | None = None
    run_id: str | None = None
    layer_id: str | None = None


class MigrationOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exclude: list[str] = Field(default_factory=list)
    schemas: dict[str, str] = Field(default_factory=dict)
    bindings: dict[str, BindingOverride] = Field(default_factory=dict)

    @field_validator("exclude", "schemas", "bindings", mode="before")
    @classmethod
    def relative_patterns(cls, value: Any) -> Any:
        if not isinstance(value, (list, dict)):
            raise ValueError("Expected a list or mapping of relative path patterns")
        for pattern in value:
            if (
                not isinstance(pattern, str)
                or not pattern
                or pattern.startswith("/")
                or ".." in pattern.split("/")
                or "\\" in pattern
            ):
                raise ValueError("Migration patterns must be nonempty relative POSIX paths")
        return value

    @field_validator("schemas")
    @classmethod
    def known_schemas(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value.values()) - set(storage_profiles()):
            raise ValueError("Migration schema override names an unknown contract")
        return value

    def exclusion(self, relative: str) -> str | None:
        return next((rule for rule in self.exclude if fnmatchcase(relative, rule)), None)


def load_config(path: Path) -> tuple[CorpusConfig, MigrationOptions]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Deployment configuration must be an object")
    options = MigrationOptions.model_validate(data.pop("migration", {}))
    return CorpusConfig.model_validate(data), options


@dataclass(frozen=True)
class Artifact:
    relative: str
    family: str
    base: str

    @property
    def subject(self) -> str:
        subject = (Path(self.relative).parent / self.base).as_posix()
        return subject + "#cloud-config" if self.family.startswith("cloud-config-") else subject


class ArtifactCatalog:
    def __init__(self, root: Path, config: CorpusConfig, options: MigrationOptions) -> None:
        self.root = root
        self.config = config
        self.options = options
        self.artifacts: dict[str, Artifact] = {}
        self.references: dict[str, set[str]] = defaultdict(set)
        self.repositories: dict[str, set[str]] = defaultdict(set)
        self.reference_names: dict[str, set[str]] = defaultdict(set)
        self._profiles = storage_profiles()
        self._routes = {name: name for name in self._profiles} | FILENAME_ALIASES

    def is_candidate(self, relative: str) -> bool:
        stem = Path(relative).stem
        return any(fnmatchcase(relative, pattern) for pattern in self.options.schemas) or any(
            stem == suffix or stem.endswith("-" + suffix) for suffix in self._routes
        )

    def identify(self, relative: str, document: Any) -> Artifact:
        explicit = {
            family
            for pattern, family in self.options.schemas.items()
            if fnmatchcase(relative, pattern)
        }
        if len(explicit) > 1:
            raise DiscoveryError("ambiguous_schema", "Conflicting configured schema routes")
        stem = Path(relative).stem
        routed = explicit.pop() if explicit else None

        filename_family = None
        base = stem
        for suffix in sorted(self._routes, key=len, reverse=True):
            if stem == suffix or stem.endswith("-" + suffix):
                filename_family = self._routes[suffix]
                base = self._base(stem, suffix)
                if suffix == "container-audit":
                    base = stem
                if suffix == "findings-current":
                    metadata = document.get("metadata", {}) if isinstance(document, dict) else {}
                    additional = (
                        metadata.get("additional", {}) if isinstance(metadata, dict) else {}
                    )
                    cumulative = (
                        additional.get("cumulative", {}) if isinstance(additional, dict) else {}
                    )
                    source = (
                        cumulative.get("source_audit") if isinstance(cumulative, dict) else None
                    )
                    sibling = self.root / Path(relative).parent / f"{base}-cloud-config-audit.json"
                    cloud = (
                        str(source).endswith("-cloud-config-audit.json")
                        if source
                        else sibling.is_file()
                    )
                    if cloud:
                        filename_family = "cloud-config-findings-current"
                break

        declared = None
        if isinstance(document, dict):
            schema = document.get("$schema")
            if isinstance(schema, str):
                name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json")
                if name not in self._profiles:
                    raise DiscoveryError("unknown_contract", "Artifact declares an unknown schema")
                declared = name
            tag = document.get("artifact")
            if isinstance(tag, str):
                if tag not in self._profiles:
                    raise DiscoveryError(
                        "unknown_contract", "Artifact declares an unknown contract"
                    )
                if declared and declared != tag:
                    raise DiscoveryError("ambiguous_schema", "Conflicting artifact declarations")
                declared = tag
        if len({name for name in (routed, filename_family, declared) if name}) > 1:
            raise DiscoveryError("ambiguous_schema", "Filename, route and declaration disagree")
        family = routed or filename_family
        if family is None:
            raise DiscoveryError(
                "unrecognized_artifact",
                "No published filename route; configure migration.schemas for this file",
            )
        if routed and not filename_family:
            base = self._base(stem, routed)
        return Artifact(relative, family, base)

    @staticmethod
    def _base(stem: str, suffix: str) -> str:
        return stem[: -len(suffix) - 1] if stem.endswith("-" + suffix) else stem

    def add(self, artifact: Artifact, document: Any) -> None:
        self.artifacts[artifact.relative] = artifact
        if artifact.family not in {
            "report",
            "cloud-config-audit",
            "cloud-config-findings-current",
            "triage",
            "layer",
        }:
            return
        for reference in (artifact.relative, str(Path(artifact.relative).with_suffix(".md"))):
            self.references[reference].add(artifact.subject)
            self.reference_names[Path(reference).name].add(reference)
        if isinstance(document, dict):
            metadata = document.get("metadata")
            repository = metadata.get("repository") if isinstance(metadata, dict) else None
            if isinstance(repository, str) and artifact.family in {"report", "cloud-config-audit"}:
                key = _canonical_repo_url(repository)
                if key:
                    self.repositories[key].add(artifact.subject)

    def source_subjects(self, reference: str, relative: str) -> set[str]:
        subjects: set[str] = set()
        local = (Path(relative).parent / reference).as_posix()
        for path in self.reference_names.get(Path(reference).name, ()):
            if reference == path or reference.endswith("/" + path) or local == path:
                subjects.update(self.references[path])
        return subjects

    def binding(self, artifact: Artifact, document: dict[str, Any]) -> Binding:
        overrides: dict[str, str] = {}
        for pattern, override in self.options.bindings.items():
            if fnmatchcase(artifact.relative, pattern):
                for key, value in override.model_dump(exclude_none=True).items():
                    if key in overrides and overrides[key] != value:
                        raise DiscoveryError("ambiguous_binding", "Conflicting configured bindings")
                    overrides[key] = value
        required = self._profiles[artifact.family]["required"]
        subject = overrides.get("subject_id", artifact.subject)
        if artifact.family == "layer" and "layer_id" not in overrides:
            reference = document.get("metadata", {}).get("audit_report")
            if isinstance(reference, str):
                owners = self.source_subjects(reference, artifact.relative)
                if len(owners) > 1:
                    raise DiscoveryError("unresolved_binding", "Layer audit reference is ambiguous")
                if owners:
                    subject = next(iter(owners))
        lane = artifact.family in {"validation", "pqc-facts", "pqc-readiness", "pqc-blockers"}
        if "subject_id" in required and "subject_id" not in overrides:
            candidates: set[str] | None = None
            if artifact.family == "validation":
                candidates = set()
                for source in document.get("source_reports", []):
                    reference = source.get("path") if isinstance(source, dict) else None
                    if isinstance(reference, str):
                        candidates.update(self.source_subjects(reference, artifact.relative))
                lane = True
            elif artifact.family in {"pqc-facts", "pqc-readiness", "pqc-blockers"}:
                metadata = document.get("metadata", {})
                repository = metadata.get("repository") or document.get("repository")
                candidates = self.repositories.get(_canonical_repo_url(repository) or "", set())
                lane = True
            if candidates is not None:
                if len(candidates) != 1:
                    raise DiscoveryError(
                        "unresolved_binding",
                        "Artifact subject has zero or multiple source matches; "
                        "supply an explicit binding",
                    )
                subject = next(iter(candidates))
        tree = subject.split("/", 1)[0]
        try:
            scope = overrides.get("scope_id") or (
                self.config.scope.id
                if self.config.scope.mode == "single"
                else self.config.scope_for(tree)
            )
        except (KeyError, ValueError):
            raise DiscoveryError(
                "unresolved_binding", "Scope requires deployment metadata or an explicit binding"
            ) from None
        run = Path(artifact.relative).parent.as_posix() if lane else subject
        values: dict[str, Any] = {"scope_id": scope}
        if "subject_id" in required:
            values.update(subject_id=subject, run_id="corpus:run:" + run)
        if "layer_id" in required:
            values["layer_id"] = "corpus:layer:" + subject
        return Binding(**(values | overrides))
