from accessguard.anomaly import privilege_weight, robust_z_scores
from accessguard.models import RoleAssignment, ServicePrincipal


def test_outlier_detected_and_robust_to_itself():
    scores = robust_z_scores({"a": 1, "b": 1, "c": 2, "d": 1, "e": 2, "f": 1, "g": 20})
    assert scores["g"] > 3.5
    assert all(abs(scores[k]) < 3.5 for k in "abcdef")


def test_needs_a_peer_group():
    assert robust_z_scores({"a": 1, "b": 50}) == {}


def test_no_spread_returns_nothing():
    assert robust_z_scores({k: 3.0 for k in "abcdef"}) == {}


def test_mad_zero_falls_back_to_mean_absolute_deviation():
    scores = robust_z_scores({"a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1, "g": 30})
    assert scores["g"] > 3.5


def test_privilege_weight_ranks_critical_above_read():
    reader = ServicePrincipal("r", "r", "Reader", app_permissions=["User.Read.All"])
    writer = ServicePrincipal("w", "w", "Writer", app_permissions=["RoleManagement.ReadWrite.Directory"])
    admin_role = RoleAssignment("w", "servicePrincipal", "Writer", "x", "Global Administrator", "x", True, True)
    assert privilege_weight(reader, []) == 1
    assert privilege_weight(writer, [admin_role]) == 18
