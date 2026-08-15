"""Rule metadata contract and evaluation interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib import resources

from ruamel.yaml import YAML

from gha_threatlens.models import Fact, Finding, Reference, WorkflowIR


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    title: str
    summary: str
    category: str
    default_severity: str
    applicable: str
    remediation: str
    references: tuple[Reference, ...]
    cwe_ids: tuple[str, ...] = ()


class Rule(ABC):
    """A rule emits findings and facts. Correlation is a later phase."""

    spec: RuleSpec

    @abstractmethod
    def evaluate(self, workflow: WorkflowIR) -> tuple[tuple[Finding, ...], tuple[Fact, ...]]:
        raise NotImplementedError


def load_rule_spec(rule_id: str) -> RuleSpec:
    filename = f"{rule_id.lower()}.yml"
    with (
        resources.files("gha_threatlens.rules")
        .joinpath("metadata", filename)
        .open("r", encoding="utf-8") as handle
    ):
        data = YAML(typ="safe").load(handle)
    references = tuple(
        Reference(title=item["title"], url=item["url"]) for item in data.get("references", [])
    )
    return RuleSpec(
        rule_id=data["id"],
        title=data["title"],
        summary=data["summary"],
        category=data["category"],
        default_severity=data["default_severity"],
        applicable=data["applicable"],
        remediation=data["remediation"],
        references=references,
        cwe_ids=tuple(data.get("cwe_ids") or ()),
    )
