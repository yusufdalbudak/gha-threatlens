from gha_threatlens.rules.base import Rule, RuleSpec, load_rule_spec
from gha_threatlens.rules.dangerous_pr_target import DangerousPrTargetRule
from gha_threatlens.rules.excessive_permissions import ExcessivePermissionsRule
from gha_threatlens.rules.expression_injection import ExpressionInjectionRule
from gha_threatlens.rules.mutable_action_ref import MutableActionRefRule

__all__ = ["RULES", "Rule", "RuleSpec", "all_rules", "load_rule_spec", "rule_by_id", "rule_ids"]

RULES: tuple[Rule, ...] = (
    MutableActionRefRule(),
    ExcessivePermissionsRule(),
    ExpressionInjectionRule(),
    DangerousPrTargetRule(),
)


def all_rules() -> tuple[Rule, ...]:
    return RULES


def rule_by_id(rule_id: str) -> Rule | None:
    needle = rule_id.strip().upper()
    for rule in RULES:
        if rule.spec.rule_id.upper() == needle:
            return rule
    return None


def rule_ids() -> tuple[str, ...]:
    return tuple(rule.spec.rule_id for rule in RULES)
