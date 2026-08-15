"""GITHUB_TOKEN permission catalogue and inheritance.

A local YAML scan cannot see repository, organisation, enterprise, fork, or
Dependabot defaults. Missing `permissions` is therefore UNKNOWN, never write.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from gha_threatlens.models import (
    PermissionAccess,
    PermissionPreset,
    PermissionSet,
    SourceLocation,
)
from gha_threatlens.parser import as_mapping, location_of_key, scalar_text

# GitHub token scopes documented for workflow permissions.
# https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
PERMISSION_SCOPES: tuple[str, ...] = (
    "actions",
    "artifact-metadata",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)

HIGH_IMPACT_WRITE_SCOPES: frozenset[str] = frozenset(
    {
        "contents",
        "packages",
        "id-token",
        "actions",
        "deployments",
        "security-events",
        "attestations",
        "pages",
        "artifact-metadata",
    }
)

MEDIUM_IMPACT_WRITE_SCOPES: frozenset[str] = frozenset(
    {
        "pull-requests",
        "issues",
        "checks",
        "statuses",
        "discussions",
        "repository-projects",
        "models",
    }
)

_ACCESS_ALIASES = {
    "read": PermissionAccess.READ,
    "write": PermissionAccess.WRITE,
    "none": PermissionAccess.NONE,
}


def parse_permissions(value: Any, path: str, parent: SourceLocation) -> PermissionSet:
    if value is None:
        return PermissionSet(preset=PermissionPreset.UNSET, declared=False, location=parent)

    text = scalar_text(value)
    if text is not None and as_mapping(value) is None:
        lowered = text.strip().lower()
        location = location_of_key({"permissions": value}, "permissions", path, parent)
        if lowered == "read-all":
            return PermissionSet(preset=PermissionPreset.READ_ALL, declared=True, location=location)
        if lowered == "write-all":
            return PermissionSet(
                preset=PermissionPreset.WRITE_ALL, declared=True, location=location
            )
        return PermissionSet(
            preset=PermissionPreset.UNSET,
            declared=True,
            location=location,
            scopes={"<unrecognised>": PermissionAccess.UNKNOWN},
        )

    mapping = as_mapping(value)
    if mapping is None:
        return PermissionSet(preset=PermissionPreset.UNSET, declared=True, location=parent)

    if len(mapping) == 0:
        return PermissionSet(
            preset=PermissionPreset.EMPTY,
            declared=True,
            location=parent,
            scopes=dict.fromkeys(PERMISSION_SCOPES, PermissionAccess.NONE),
        )

    scopes: dict[str, PermissionAccess] = {}
    for key, raw in mapping.items():
        name = str(key).strip().lower()
        access_text = (scalar_text(raw) or "").strip().lower()
        scopes[name] = _ACCESS_ALIASES.get(access_text, PermissionAccess.UNKNOWN)
    return PermissionSet(
        preset=PermissionPreset.EXPLICIT,
        declared=True,
        location=parent,
        scopes=scopes,
    )


def effective_job_permissions(workflow: PermissionSet, job: PermissionSet) -> PermissionSet:
    """Job-level `permissions` replaces the workflow declaration entirely."""

    if job.declared:
        return job
    return workflow


def privilege_label(permissions: PermissionSet) -> str:
    if permissions.preset is PermissionPreset.WRITE_ALL:
        return "write-all"
    if permissions.preset is PermissionPreset.READ_ALL:
        return "read-all"
    if permissions.preset is PermissionPreset.EMPTY:
        return "none"
    if permissions.preset is PermissionPreset.UNSET:
        return "unknown-default"
    writes = permissions.write_scopes()
    if writes:
        return ",".join(writes)
    if any(access is PermissionAccess.READ for access in permissions.scopes.values()):
        return "read"
    return "none"


def has_high_impact_write(permissions: PermissionSet) -> bool:
    if permissions.preset is PermissionPreset.WRITE_ALL:
        return True
    return any(scope in HIGH_IMPACT_WRITE_SCOPES for scope in permissions.write_scopes())


def permission_uncertainty(permissions: PermissionSet) -> bool:
    return permissions.preset is PermissionPreset.UNSET or any(
        access is PermissionAccess.UNKNOWN for access in permissions.scopes.values()
    )


def mapping_from_permission_set(permissions: PermissionSet) -> Mapping[str, PermissionAccess]:
    return permissions.scopes
