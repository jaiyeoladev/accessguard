import base64
import json

import pytest

from accessguard.catalog import GLOBAL_ADMIN_TEMPLATE, GRAPH_APP_ID, MICROSOFT_TENANT_ID
from accessguard.collector import collect
from accessguard.config import Settings
from accessguard.engine import evaluate
from accessguard.graph_client import GraphClient, GraphError


class FakeResponse:
    def __init__(self, status_code=200, body=None, headers=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.reason = "reason"
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params, headers))
        return self.responses.pop(0)


def client(responses, token="header.payload.sig"):
    return GraphClient(Settings(), session=FakeSession(responses), token_provider=lambda: token, sleep=lambda s: None)


def test_get_all_follows_next_link():
    c = client([
        FakeResponse(body={"value": [1, 2], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=x"}),
        FakeResponse(body={"value": [3]}),
    ])
    assert c.get_all("/users") == [1, 2, 3]


def test_retries_on_throttling():
    c = client([FakeResponse(429, {"error": {"message": "slow down"}}, {"Retry-After": "1"}), FakeResponse(body={"ok": True})])
    assert c.get("/organization") == {"ok": True}


def test_raises_graph_error_with_message():
    c = client([FakeResponse(403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})])
    with pytest.raises(GraphError) as exc:
        c.get("/users")
    assert exc.value.status == 403 and "Insufficient" in exc.value.message


def test_refuses_to_send_token_outside_graph():
    c = client([])
    with pytest.raises(GraphError):
        c.get("https://evil.example.com/steal")


def test_granted_app_roles_reads_token_claims():
    payload = base64.urlsafe_b64encode(json.dumps({"roles": ["User.Read.All"]}).encode()).decode().rstrip("=")
    assert client([], token=f"h.{payload}.s").granted_app_roles() == ["User.Read.All"]


def test_client_is_read_only():
    public = {name for name in dir(GraphClient) if not name.startswith("_")}
    assert public == {"get", "get_all", "granted_app_roles"}


# --- collector -------------------------------------------------------------

class FakeGraph:
    def __init__(self, routes, roles=()):
        self.routes = routes
        self.roles = list(roles)

    def granted_app_roles(self):
        return self.roles

    def get(self, path, params=None):
        handler = self.routes.get(path)
        if handler is None:
            raise GraphError(404, "not found", path)
        result = handler(params or {}) if callable(handler) else handler
        if isinstance(result, Exception):
            raise result
        return result

    def get_all(self, path, params=None):
        return self.get(path, params).get("value", [])


def tenant_routes():
    return {
        "/organization": {"value": [{"id": "t", "displayName": "Test Org"}]},
        "/users": lambda p: GraphError(403, "Forbidden") if "signInActivity" in p.get("$select", "") else {"value": [
            {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@example.com", "userType": "Member",
             "accountEnabled": True, "createdDateTime": "2024-01-01T00:00:00Z"}]},
        "/reports/authenticationMethods/userRegistrationDetails": {"value": [{"id": "u1", "isMfaRegistered": False}]},
        "/servicePrincipals": {"value": [
            {"id": "gsp", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID},
            {"id": "sp1", "appId": "a1", "displayName": "HR Agent", "appOwnerOrganizationId": "t"}]},
        "/servicePrincipals/gsp": {"id": "gsp", "appRoles": [{"id": "r1", "value": "Directory.ReadWrite.All"}]},
        "/servicePrincipals/gsp/appRoleAssignedTo": {"value": [
            {"principalId": "sp1", "principalType": "ServicePrincipal", "appRoleId": "r1"}]},
        "/oauth2PermissionGrants": {"value": []},
        "/applications": {"value": [{
            "id": "app1", "appId": "a1", "displayName": "HR Agent", "owners": [], "keyCredentials": [],
            "passwordCredentials": [{"keyId": "k1", "displayName": "s", "startDateTime": "2025-01-01T00:00:00Z",
                                     "endDateTime": "2027-01-01T00:00:00.1234567Z"}]}]},
        "/roleManagement/directory/roleDefinitions": {"value": [
            {"id": GLOBAL_ADMIN_TEMPLATE, "templateId": GLOBAL_ADMIN_TEMPLATE, "displayName": "Global Administrator"}]},
        "/roleManagement/directory/roleAssignments": {"value": [
            {"principalId": "u1", "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE, "directoryScopeId": "/"}]},
    }


def test_collector_maps_graph_data_and_degrades_gracefully():
    settings = Settings(tenant_id="t")
    snap = collect(FakeGraph(tenant_routes(), roles=["Directory.Read.All", "Mail.Send"]), settings)

    assert snap.tenant_name == "Test Org"
    assert snap.capabilities["sign_in_activity"] is False
    assert any("Sign-in activity" in w for w in snap.warnings)
    assert any("Mail.Send" in w for w in snap.warnings)  # least-privilege self-check

    alice = snap.users[0]
    assert alice.mfa_registered is False
    agent = next(sp for sp in snap.service_principals if sp.id == "sp1")
    assert agent.app_permissions == ["Directory.ReadWrite.All"] and agent.is_ai_agent
    assert snap.applications[0].owners == []
    assert snap.applications[0].credentials[0].end.year == 2027
    role = snap.role_assignments[0]
    assert (role.principal_type, role.privileged, role.critical) == ("user", True, True)

    ids = {f.rule_id for f in evaluate(snap, settings)}
    assert {"AG-003", "AG-008", "AG-014"} <= ids
    assert "AG-001" not in ids  # skipped: no sign-in data


def test_collector_falls_back_when_role_assignments_need_a_filter():
    routes = tenant_routes()
    calls = []

    def assignments(params):
        calls.append(params)
        if "$filter" not in params:
            return GraphError(400, "Filter required")
        return {"value": [{"principalId": "u1", "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE}]}

    routes["/roleManagement/directory/roleAssignments"] = assignments
    snap = collect(FakeGraph(routes), Settings(tenant_id="t"))
    assert len(snap.role_assignments) == 1 and len(calls) == 2
