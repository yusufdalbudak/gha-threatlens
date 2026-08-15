"""Convert parsed YAML into a typed workflow intermediate representation."""

from __future__ import annotations

import re
from typing import Any

from gha_threatlens.errors import UnsupportedStructureError
from gha_threatlens.models import (
    ActionRef,
    ActionRefKind,
    JobIR,
    JobPurpose,
    PermissionPreset,
    PermissionSet,
    ShellKind,
    SourceLocation,
    StepIR,
    TriggerIR,
    WorkflowIR,
)
from gha_threatlens.parser import (
    as_mapping,
    as_sequence,
    location_of_key,
    location_of_node,
    location_of_value,
    scalar_text,
)
from gha_threatlens.permissions import parse_permissions
from gha_threatlens.trust import default_shell, infer_event_trust

FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_REF = re.compile(
    r"^(?P<owner>[^/]+)/(?P<repo>[^/@]+)(?P<path>(?:/[^@]+)?)(?:@(?P<ref>.+))?$"
)
PURPOSE_RELEASE = re.compile(
    r"\b(release|publish|deploy|pypi|npm.?publish|ghcr|docker.?push)\b", re.I
)
PURPOSE_TEST = re.compile(r"\b(test|lint|format|typecheck|unit)\b", re.I)
PURPOSE_BUILD = re.compile(r"\b(build|compile|package)\b", re.I)

GITHUB_HOSTED_RUNNERS = frozenset(
    {
        "ubuntu-latest",
        "ubuntu-24.04",
        "ubuntu-22.04",
        "ubuntu-20.04",
        "windows-latest",
        "windows-2025",
        "windows-2022",
        "windows-2019",
        "macos-latest",
        "macos-14",
        "macos-13",
        "macos-12",
        "macos-15",
        "macos-26",
    }
)


def normalise_workflow(data: Any, relative_path: str, text: str) -> WorkflowIR:
    mapping = as_mapping(data)
    if mapping is None:
        raise UnsupportedStructureError(
            f"{relative_path} is not a YAML mapping and cannot be a GitHub Actions workflow."
        )

    warnings: list[str] = []
    root_location = location_of_node(mapping, relative_path)
    name = scalar_text(mapping.get("name"))
    triggers, trigger_warnings = _parse_triggers(mapping, relative_path, root_location)
    warnings.extend(trigger_warnings)

    permissions_value = mapping.get("permissions")
    permissions = parse_permissions(
        permissions_value,
        relative_path,
        location_of_key(mapping, "permissions", relative_path, root_location)
        if "permissions" in mapping
        else root_location,
    )

    jobs_value = mapping.get("jobs")
    jobs_mapping = as_mapping(jobs_value)
    jobs: list[JobIR] = []
    if jobs_mapping is None:
        if "jobs" in mapping:
            warnings.append("The jobs key is present but is not a mapping.")
    else:
        for job_id, job_value in jobs_mapping.items():
            job = _parse_job(
                str(job_id),
                job_value,
                relative_path,
                location_of_key(jobs_mapping, job_id, relative_path, root_location),
            )
            jobs.append(job)

    jobs.sort(key=lambda item: item.job_id)
    return WorkflowIR(
        name=name,
        path=relative_path,
        triggers=tuple(triggers),
        permissions=permissions,
        jobs=tuple(jobs),
        parse_warnings=tuple(warnings),
        location=root_location,
        raw_text=text,
    )


def parse_action_ref(raw: str) -> ActionRef:
    value = raw.strip()
    if value.startswith(("./", "../", "/")):
        return ActionRef(raw=value, kind=ActionRefKind.LOCAL, path=value)
    if value.startswith("docker://"):
        return ActionRef(
            raw=value,
            kind=ActionRefKind.DOCKER,
            docker_image=value.removeprefix("docker://"),
        )

    match = GITHUB_REF.match(value)
    if match is None:
        return ActionRef(raw=value, kind=ActionRefKind.UNKNOWN)

    owner = match.group("owner")
    repo = match.group("repo")
    path = match.group("path").lstrip("/") or None
    ref = match.group("ref")
    kind = ActionRefKind.GITHUB
    if path and path.endswith((".yml", ".yaml")):
        kind = ActionRefKind.REUSABLE_WORKFLOW
    immutable = bool(ref and FULL_SHA.fullmatch(ref))
    return ActionRef(
        raw=value,
        kind=kind,
        owner=owner,
        repository=repo,
        path=path,
        ref=ref,
        is_immutable_sha=immutable,
    )


def _parse_triggers(
    mapping: Any,
    path: str,
    fallback: SourceLocation,
) -> tuple[list[TriggerIR], list[str]]:
    warnings: list[str] = []
    key = _on_key(mapping)
    if key is None:
        warnings.append("Workflow has no `on` trigger key.")
        return [], warnings
    if key is True:
        warnings.append(
            "Trigger key was parsed as boolean true; treating it as the GitHub Actions `on` key. "
            "Save the file as YAML 1.2 to avoid this ambiguity."
        )

    value = mapping[key]
    location = location_of_value(mapping, key, path, fallback)
    triggers: list[TriggerIR] = []

    text = scalar_text(value)
    if text is not None and as_mapping(value) is None and as_sequence(value) is None:
        triggers.append(
            TriggerIR(
                event_name=text,
                configuration={},
                trust_level=infer_event_trust(text),
                location=location,
            )
        )
        return triggers, warnings

    sequence = as_sequence(value)
    if sequence is not None and as_mapping(value) is None:
        for item in sequence:
            name = scalar_text(item)
            if name is None:
                continue
            triggers.append(
                TriggerIR(
                    event_name=name,
                    configuration={},
                    trust_level=infer_event_trust(name),
                    location=location_of_node(item, path, location),
                )
            )
        triggers.sort(key=lambda item: item.event_name)
        return triggers, warnings

    event_map = as_mapping(value)
    if event_map is None:
        warnings.append("Unrecognised trigger structure under `on`.")
        return [], warnings

    for event_name, config in event_map.items():
        name = str(event_name)
        configuration: dict[str, object] = {}
        config_map = as_mapping(config)
        if config_map is not None:
            configuration = {str(k): _plain(v) for k, v in config_map.items()}
        elif config is not None:
            configuration = {"value": _plain(config)}
        triggers.append(
            TriggerIR(
                event_name=name,
                configuration=configuration,
                trust_level=infer_event_trust(name),
                location=location_of_key(event_map, event_name, path, location),
            )
        )
    triggers.sort(key=lambda item: item.event_name)
    return triggers, warnings


def _on_key(mapping: Any) -> Any:
    if "on" in mapping:
        return "on"
    if True in mapping:
        return True
    return None


def _parse_job(job_id: str, value: Any, path: str, location: SourceLocation) -> JobIR:
    mapping = as_mapping(value)
    if mapping is None:
        return JobIR(
            job_id=job_id,
            name=None,
            runner_labels=(),
            permissions=PermissionSet(
                preset=PermissionPreset.UNSET, declared=False, location=location
            ),
            environment=None,
            needs=(),
            if_condition=None,
            steps=(),
            location=location,
            purpose=JobPurpose.UNKNOWN,
            is_self_hosted=False,
        )

    runner_labels = _runner_labels(mapping.get("runs-on"))
    permissions = parse_permissions(
        mapping.get("permissions"),
        path,
        location_of_key(mapping, "permissions", path, location)
        if "permissions" in mapping
        else location,
    )
    environment = _environment_name(mapping.get("environment"))
    needs = _string_list(mapping.get("needs"))
    if_condition = scalar_text(mapping.get("if"))
    reusable_text = scalar_text(mapping.get("uses"))
    reusable = parse_action_ref(reusable_text) if reusable_text else None
    steps = _parse_steps(mapping.get("steps"), path, location, runner_labels)
    name = scalar_text(mapping.get("name"))
    purpose = infer_job_purpose(job_id, name, steps)
    is_self_hosted = _is_self_hosted(runner_labels)
    return JobIR(
        job_id=job_id,
        name=name,
        runner_labels=runner_labels,
        permissions=permissions,
        environment=environment,
        needs=needs,
        if_condition=if_condition,
        steps=steps,
        location=location,
        purpose=purpose,
        is_self_hosted=is_self_hosted,
        reusable_workflow=reusable,
    )


def _parse_steps(
    value: Any,
    path: str,
    fallback: SourceLocation,
    runner_labels: tuple[str, ...],
) -> tuple[StepIR, ...]:
    sequence = as_sequence(value)
    if sequence is None:
        return ()
    steps: list[StepIR] = []
    for index, item in enumerate(sequence):
        mapping = as_mapping(item)
        step_location = location_of_node(item, path, fallback)
        if mapping is None:
            steps.append(
                StepIR(
                    index=index,
                    name=None,
                    uses=None,
                    run=None,
                    shell=ShellKind.UNKNOWN,
                    environment={},
                    inputs={},
                    location=step_location,
                )
            )
            continue
        uses_text = scalar_text(mapping.get("uses"))
        uses = parse_action_ref(uses_text) if uses_text else None
        run = scalar_text(mapping.get("run"))
        shell = default_shell(runner_labels, scalar_text(mapping.get("shell")))
        environment = _string_map(mapping.get("env"))
        inputs = _string_map(mapping.get("with"))
        steps.append(
            StepIR(
                index=index,
                name=scalar_text(mapping.get("name")),
                uses=uses,
                run=run,
                shell=shell,
                environment=environment,
                inputs=inputs,
                location=location_of_key(mapping, "run", path, step_location)
                if run is not None
                else location_of_key(mapping, "uses", path, step_location)
                if uses is not None
                else step_location,
                if_condition=scalar_text(mapping.get("if")),
            )
        )
    return tuple(steps)


def infer_job_purpose(job_id: str, name: str | None, steps: tuple[StepIR, ...]) -> JobPurpose:
    haystack = " ".join(
        part
        for part in (
            job_id,
            name or "",
            " ".join(step.name or "" for step in steps),
            " ".join(step.uses.raw if step.uses else "" for step in steps),
            " ".join(step.run or "" for step in steps),
        )
        if part
    )
    if PURPOSE_RELEASE.search(haystack):
        if re.search(r"\bdeploy", haystack, re.I) and not re.search(
            r"\b(release|publish|pypi|npm)", haystack, re.I
        ):
            return JobPurpose.DEPLOY
        return JobPurpose.RELEASE
    if PURPOSE_TEST.search(haystack):
        return JobPurpose.TEST
    if PURPOSE_BUILD.search(haystack):
        return JobPurpose.BUILD
    return JobPurpose.UNKNOWN


def _runner_labels(value: Any) -> tuple[str, ...]:
    text = scalar_text(value)
    if text is not None and as_mapping(value) is None and as_sequence(value) is None:
        return (text,)
    sequence = as_sequence(value)
    if sequence is not None:
        labels = [item for item in (scalar_text(entry) for entry in sequence) if item]
        return tuple(labels)
    mapping = as_mapping(value)
    if mapping is not None:
        group = mapping.get("group")
        raw_labels = mapping.get("labels")
        collected: list[str] = []
        group_text = scalar_text(group)
        if group_text:
            collected.append(group_text)
        collected.extend(_runner_labels(raw_labels))
        return tuple(collected)
    return ()


def _is_self_hosted(labels: tuple[str, ...]) -> bool:
    lowered = {label.lower() for label in labels}
    if "self-hosted" in lowered:
        return True
    if not lowered:
        return False
    return not any(
        label.lower() in GITHUB_HOSTED_RUNNERS or label.lower().startswith("ubuntu-")
        for label in labels
    )


def _environment_name(value: Any) -> str | None:
    text = scalar_text(value)
    if text is not None and as_mapping(value) is None:
        return text
    mapping = as_mapping(value)
    if mapping is None:
        return None
    return scalar_text(mapping.get("name"))


def _string_list(value: Any) -> tuple[str, ...]:
    text = scalar_text(value)
    if text is not None and as_sequence(value) is None:
        return (text,)
    sequence = as_sequence(value)
    if sequence is None:
        return ()
    return tuple(item for item in (scalar_text(entry) for entry in sequence) if item)


def _string_map(value: Any) -> dict[str, str]:
    mapping = as_mapping(value)
    if mapping is None:
        return {}
    result: dict[str, str] = {}
    for key, raw in mapping.items():
        text = scalar_text(raw)
        if text is None:
            continue
        result[str(key)] = text
    return result


def _plain(value: Any) -> object:
    mapping = as_mapping(value)
    if mapping is not None:
        return {str(k): _plain(v) for k, v in mapping.items()}
    sequence = as_sequence(value)
    if sequence is not None:
        return [_plain(item) for item in sequence]
    text = scalar_text(value)
    if text is not None:
        return text
    return None
