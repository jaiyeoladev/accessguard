from datetime import datetime, timedelta, timezone

from accessguard.catalog import GLOBAL_ADMIN_TEMPLATE, classify_role
from accessguard.config import Settings
from accessguard.demo_data import demo_snapshot
from accessguard.engine import evaluate, skipped_rules
from accessguard.models import Application, Credential, RoleAssignment, TenantSnapshot, User
from accessguard.rules import RULES

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
ALL_CAPS = {c: True for c in ("sign_in_activity", "mfa_registration", "directory_roles", "app_permissions",
                              "delegated_grants", "app_owners")}


def snapshot(**kw) -> TenantSnapshot:
    base = dict(tenant_id="t", tenant_name="Test", collected_at=NOW, source="test", capabilities=dict(ALL_CAPS))
    base.update(kw)
    return TenantSnapshot(**base)


def user(uid, **kw) -> User:
    return User(id=uid, display_name=uid, upn=f"{uid}@example.com", created=NOW - timedelta(days=400), **kw)


def ga(principal_id: str) -> RoleAssignment:
    priv, crit = classify_role(GLOBAL_ADMIN_TEMPLATE, "Global Administrator")
    return RoleAssignment(principal_id, "user", principal_id, GLOBAL_ADMIN_TEMPLATE, "Global Administrator",
                          GLOBAL_ADMIN_TEMPLATE, priv, crit)


def rule_ids(snap, settings=None):
    return [f.rule_id for f in evaluate(snap, settings or Settings(), NOW)]


def test_demo_tenant_exercises_every_rule():
    found = set(rule_ids(demo_snapshot(NOW)))
    assert {r.id for r in RULES} <= found


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_dormant_threshold_boundary():
    snap = snapshot(users=[
        user("active", last_sign_in=NOW - timedelta(days=89)),
        user("dormant", last_sign_in=NOW - timedelta(days=91)),
        user("disabled", account_enabled=False, last_sign_in=NOW - timedelta(days=300)),
    ])
    findings = [f for f in evaluate(snap, Settings(), NOW) if f.rule_id == "AG-001"]
    assert [f.object_id for f in findings] == ["dormant"]
    assert findings[0].severity == "medium"


def test_never_signed_in_respects_grace_period():
    snap = snapshot(users=[
        User("new", "new", "new@example.com", created=NOW - timedelta(days=10), last_sign_in=None),
        User("old", "old", "old@example.com", created=NOW - timedelta(days=45), last_sign_in=None),
    ])
    assert [f.object_id for f in evaluate(snap, Settings(), NOW) if f.rule_id == "AG-001"] == ["old"]


def test_dormant_admin_is_high_severity():
    snap = snapshot(users=[user("admin", last_sign_in=NOW - timedelta(days=200), mfa_registered=True)],
                    role_assignments=[ga("admin")])
    dormant = [f for f in evaluate(snap, Settings(), NOW) if f.rule_id == "AG-001"]
    assert dormant[0].severity == "high"


def test_rules_skip_when_data_unavailable():
    caps = dict(ALL_CAPS, sign_in_activity=False)
    snap = snapshot(users=[user("dormant", last_sign_in=NOW - timedelta(days=300))], capabilities=caps)
    assert "AG-001" not in rule_ids(snap)
    assert "AG-001" in {r.id for r in skipped_rules(snap)}


def test_admin_without_mfa_is_critical_but_unknown_mfa_is_not_flagged():
    snap = snapshot(
        users=[user("nomfa", last_sign_in=NOW, mfa_registered=False), user("unknown", last_sign_in=NOW)],
        role_assignments=[ga("nomfa"), ga("unknown")],
    )
    mfa = [f for f in evaluate(snap, Settings(), NOW) if f.rule_id == "AG-003"]
    assert [(f.object_id, f.severity) for f in mfa] == [("nomfa", "critical")]


def test_global_admin_count():
    users = [user(f"a{i}", last_sign_in=NOW, mfa_registered=True) for i in range(5)]
    roles = [ga(u.id) for u in users]
    assert "AG-004" in rule_ids(snapshot(users=users, role_assignments=roles))
    assert "AG-004" not in rule_ids(snapshot(users=users[:4], role_assignments=roles[:4]))


def test_credential_expiry_and_lifetime():
    app = Application("app", "appid", "App", owners=["Owner"], credentials=[
        Credential("secret", "k1", "soon", NOW - timedelta(days=100), NOW + timedelta(days=10)),
        Credential("secret", "k2", "expired", NOW - timedelta(days=400), NOW - timedelta(days=5)),
        Credential("secret", "k3", "long", NOW - timedelta(days=10), NOW + timedelta(days=720)),
        Credential("certificate", "k4", "cert", NOW - timedelta(days=10), NOW + timedelta(days=720)),
    ])
    findings = evaluate(snapshot(applications=[app]), Settings(), NOW)
    expiry = {f.key: f.severity for f in findings if f.rule_id == "AG-010"}
    assert expiry == {"k1": "medium", "k2": "low"}
    assert [f.key for f in findings if f.rule_id == "AG-011"] == ["k3"]  # certificates are not "long-lived secrets"


def test_fingerprint_is_stable_across_runs():
    a = {f.fingerprint for f in evaluate(demo_snapshot(NOW), Settings(), NOW)}
    b = {f.fingerprint for f in evaluate(demo_snapshot(NOW), Settings(), NOW)}
    assert a == b
