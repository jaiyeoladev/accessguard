"""Peer-based anomaly scoring for non-human identities.

Each service principal gets a *privilege score* from the permissions and roles it holds.
Scores are compared with the rest of the tenant's non-human identities using a robust
z-score (median and median absolute deviation), so a handful of extreme values cannot
drag the baseline up the way a mean and standard deviation would.
"""
from __future__ import annotations

from collections.abc import Iterable
from statistics import median

from .catalog import CRITICAL_APP_PERMISSIONS, HIGH_APP_PERMISSIONS, HIGH_RISK_DELEGATED
from .models import RoleAssignment, ServicePrincipal

MIN_PEER_GROUP = 5


def privilege_weight(sp: ServicePrincipal, roles: Iterable[RoleAssignment]) -> float:
    weight = 0.0
    for perm in sp.app_permissions:
        if perm in CRITICAL_APP_PERMISSIONS:
            weight += 8
        elif perm in HIGH_APP_PERMISSIONS:
            weight += 4
        else:
            weight += 1
    for scope in sp.delegated_admin_consent:
        weight += 3 if scope in HIGH_RISK_DELEGATED else 0.5
    for role in roles:
        weight += 10 if role.critical else 6 if role.privileged else 2
    return weight


def robust_z_scores(values: dict[str, float]) -> dict[str, float]:
    """Modified z-scores (Iglewicz & Hoaglin). Returns {} when there is no usable spread."""
    if len(values) < MIN_PEER_GROUP:
        return {}
    xs = list(values.values())
    med = median(xs)
    mad = median(abs(x - med) for x in xs)
    if mad > 0:
        scale = mad / 0.6745
    else:
        mean_ad = sum(abs(x - med) for x in xs) / len(xs)
        if mean_ad == 0:
            return {}
        scale = mean_ad * 1.253314
    return {key: (value - med) / scale for key, value in values.items()}
