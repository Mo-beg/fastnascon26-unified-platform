"""Run with: python manage.py test"""
from django.db import connection
from rest_framework.test import APIClient, APITestCase

from .models import AuditLog, AuditLogImmutableError, User, Workspace


def register(client, name, username):
    r = client.post(
        "/api/auth/register/",
        {"workspace_name": name, "username": username, "email": f"{username}@example.com",
         "password": "S3cure-pass-123"},
        format="json",
    )
    assert r.status_code == 201, r.data
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Token {r.data['token']}")
    return c, r.data["user"]


class TenantIsolationTests(APITestCase):
    def setUp(self):
        self.a, self.a_user = register(APIClient(), "Acme", "alice")
        self.b, self.b_user = register(APIClient(), "Beta", "bob")

    def test_register_login_me(self):
        r = APIClient().post("/api/auth/login/", {"username": "alice", "password": "S3cure-pass-123"}, format="json")
        self.assertEqual(r.status_code, 200)
        me = self.a.get("/api/me/").data
        self.assertEqual(me["role"], "owner")
        self.assertTrue(me["permissions"]["export"])

    def test_requires_auth(self):
        self.assertEqual(APIClient().get("/api/contacts/").status_code, 401)

    def test_cannot_see_or_touch_other_workspace(self):
        cid = self.b.post("/api/companies/", {"name": "Beta Co"}, format="json").data["id"]
        self.assertEqual(self.a.get("/api/companies/").data["count"], 0)
        self.assertEqual(self.a.get(f"/api/companies/{cid}/").status_code, 404)
        self.assertEqual(self.a.patch(f"/api/companies/{cid}/", {"name": "x"}, format="json").status_code, 404)
        self.assertEqual(self.a.delete(f"/api/companies/{cid}/").status_code, 404)

    def test_cannot_link_to_other_workspace_records(self):
        cid = self.b.post("/api/companies/", {"name": "Beta Co"}, format="json").data["id"]
        r = self.a.post("/api/contacts/", {"first_name": "X", "company": cid}, format="json")
        self.assertEqual(r.status_code, 400)
        contact = self.a.post("/api/contacts/", {"first_name": "Ann"}, format="json").data["id"]
        r = self.b.post("/api/opportunities/", {"name": "Evil", "contact": contact}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_workspace_in_body_is_ignored(self):
        other = Workspace.objects.get(name="Beta")
        r = self.a.post("/api/companies/", {"name": "Sneaky", "workspace": str(other.pk)}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.b.get("/api/companies/").data["count"], 0)

    def test_custom_fields_validate_custom_data(self):
        r = self.a.post(
            "/api/custom-fields/",
            {"name": "Tier", "key": "tier", "entity_type": "contact", "data_type": "dropdown",
             "options": ["gold", "silver"], "is_required": True},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        post = lambda data: self.a.post("/api/contacts/", data, format="json")  # noqa: E731
        self.assertEqual(post({"first_name": "A"}).status_code, 400)  # required
        self.assertEqual(post({"first_name": "A", "custom_data": {"tier": "bronze"}}).status_code, 400)
        self.assertEqual(post({"first_name": "A", "custom_data": {"nope": 1}}).status_code, 400)
        self.assertEqual(post({"first_name": "A", "custom_data": {"tier": "gold"}}).status_code, 201)

    def test_permission_flags(self):
        ws = Workspace.objects.get(name="Acme")
        User.objects.create_user("viewer", password="x", workspace=ws)  # role=user, view only
        from rest_framework.authtoken.models import Token
        tok = Token.objects.create(user=User.objects.get(username="viewer"))
        v = APIClient()
        v.credentials(HTTP_AUTHORIZATION=f"Token {tok.key}")
        self.assertEqual(v.get("/api/contacts/").status_code, 200)
        self.assertEqual(v.post("/api/contacts/", {"first_name": "Z"}, format="json").status_code, 403)
        self.assertEqual(v.post("/api/custom-fields/", {}, format="json").status_code, 403)
        self.assertEqual(v.get("/api/audit-logs/").status_code, 403)

    def test_audit_log_records_and_is_tamper_evident(self):
        cid = self.a.post("/api/contacts/", {"first_name": "Ann"}, format="json").data["id"]
        self.a.patch(f"/api/contacts/{cid}/", {"phone": "123"}, format="json")
        self.a.delete(f"/api/contacts/{cid}/")
        actions = [e["action"] for e in self.a.get("/api/audit-logs/").data["results"]]
        self.assertEqual(actions, ["delete", "update", "create", "create"])  # newest first; last = workspace
        ws = Workspace.objects.get(name="Acme")
        self.assertEqual(AuditLog.verify_chain(ws.pk), (True, None))

        with self.assertRaises(AuditLogImmutableError):
            AuditLog.objects.filter(workspace=ws).update(action="other")
        with self.assertRaises(AuditLogImmutableError):
            AuditLog.objects.filter(workspace=ws).delete()

        first = AuditLog.objects.filter(workspace=ws).order_by("id").first()
        with connection.cursor() as cur:  # tamper below the ORM
            cur.execute("UPDATE api_auditlog SET target_repr = 'forged' WHERE id = %s", [first.pk])
        ok, bad_id = AuditLog.verify_chain(ws.pk)
        self.assertFalse(ok)
        self.assertEqual(bad_id, first.pk)
