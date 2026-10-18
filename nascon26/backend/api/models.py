"""
Core multi-tenant models: Workspace, User, CRM entities, CustomField, AuditLog.

Tenancy rules
-------------
* Every tenant-owned row has a non-null FK to Workspace.
* Related records (contact -> company, opportunity -> contact, ...) must live in
  the same workspace. This is enforced in the API layer (scoped serializer
  fields) AND again in TenantModel.save() as defense in depth.
* Workspaces are never hard-deleted (PROTECT everywhere); offboarding is
  `is_active=False` plus an async purge job.

Audit log
---------
Append-only and hash-chained per workspace (each entry stores the hash of the
previous one), so edits/removals are detectable via AuditLog.verify_chain().
See the SQL at the bottom of this file for DB-level enforcement.
"""
import hashlib
import ipaddress
import json
import uuid
from datetime import timezone as dt_timezone

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import MinValueValidator, RegexValidator
from django.db import models, transaction
from django.utils import timezone


# --------------------------------------------------------------------------
# Workspace & User
# --------------------------------------------------------------------------
class Workspace(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=80, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class User(AbstractUser):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Admin"
        USER = "user", "User"

    PERMISSION_FLAGS = ("view", "create", "edit", "delete", "export", "manage_integrations")

    # Null only for platform superusers (createsuperuser); they have no tenant access.
    workspace = models.ForeignKey(
        Workspace, null=True, blank=True, on_delete=models.PROTECT, related_name="users"
    )
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)

    # Granular flags, only consulted for role=USER. Owner/Admin implicitly have all.
    can_view = models.BooleanField(default=True)
    can_create = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    can_export = models.BooleanField(default=False)
    can_manage_integrations = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workspace", "email"],
                condition=~models.Q(email=""),
                name="uniq_user_email_per_workspace",
            )
        ]

    @property
    def is_workspace_admin(self):
        return self.role in (self.Role.OWNER, self.Role.ADMIN)

    def can(self, action: str) -> bool:
        """can('view' | 'create' | 'edit' | 'delete' | 'export' | 'manage_integrations')"""
        if action not in self.PERMISSION_FLAGS or not self.is_active:
            return False
        if self.is_workspace_admin:
            return True
        return bool(getattr(self, f"can_{action}"))


# --------------------------------------------------------------------------
# Tenant base
# --------------------------------------------------------------------------
class TenantModel(models.Model):
    """Abstract base: UUID pk, workspace FK, timestamps, cross-tenant FK guard."""

    # Names of FK fields that must point at rows in the SAME workspace.
    TENANT_RELATIONS = ()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workspace = models.ForeignKey(Workspace, on_delete=models.PROTECT, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self._assert_same_workspace()
        super().save(*args, **kwargs)

    def _assert_same_workspace(self):
        for name in self.TENANT_RELATIONS:
            field = self._meta.get_field(name)
            related_id = getattr(self, field.attname)
            if related_id is None:
                continue
            ok = field.related_model._default_manager.filter(
                pk=related_id, workspace_id=self.workspace_id
            ).exists()
            if not ok:
                raise ValidationError({name: "Related record belongs to a different workspace."})


# --------------------------------------------------------------------------
# CRM core
# --------------------------------------------------------------------------
class Company(TenantModel):
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255, blank=True)
    industry = models.CharField(max_length=120, blank=True)
    custom_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "companies"
        indexes = [models.Index(fields=["workspace", "name"])]

    def __str__(self):
        return self.name


class Contact(TenantModel):
    TENANT_RELATIONS = ("company",)

    company = models.ForeignKey(
        Company, null=True, blank=True, on_delete=models.SET_NULL, related_name="contacts"
    )
    first_name = models.CharField(max_length=120)
    last_name = models.CharField(max_length=120, blank=True)
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=40, blank=True)
    job_title = models.CharField(max_length=120, blank=True)
    custom_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["first_name", "last_name"]
        indexes = [
            models.Index(fields=["workspace", "email"]),
            models.Index(fields=["workspace", "company"]),
        ]

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def __str__(self):
        return self.full_name


class Opportunity(TenantModel):
    class Stage(models.TextChoices):
        LEAD = "lead", "Lead"
        QUALIFIED = "qualified", "Qualified"
        PROPOSAL = "proposal", "Proposal"
        NEGOTIATION = "negotiation", "Negotiation"
        WON = "won", "Closed Won"
        LOST = "lost", "Closed Lost"

    TENANT_RELATIONS = ("contact", "company", "owner")

    name = models.CharField(max_length=255)
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE, related_name="opportunities")
    company = models.ForeignKey(
        Company, null=True, blank=True, on_delete=models.SET_NULL, related_name="opportunities"
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_opportunities",
    )
    stage = models.CharField(max_length=20, choices=Stage.choices, default=Stage.LEAD)
    value = models.DecimalField(
        max_digits=14, decimal_places=2, default=0, validators=[MinValueValidator(0)]
    )
    currency = models.CharField(max_length=3, default="USD")
    expected_close_date = models.DateField(null=True, blank=True)
    custom_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "opportunities"
        indexes = [
            models.Index(fields=["workspace", "stage"]),
            models.Index(fields=["workspace", "contact"]),
        ]

    def __str__(self):
        return self.name


class CustomField(TenantModel):
    """
    Admin-defined field definition. Values live in the target entity's
    `custom_data` JSON column, keyed by `key`, and are validated against these
    definitions in the serializer layer.
    """

    class EntityType(models.TextChoices):
        CONTACT = "contact", "Contact"
        COMPANY = "company", "Company"
        OPPORTUNITY = "opportunity", "Opportunity"

    class DataType(models.TextChoices):
        TEXT = "text", "Text"
        NUMBER = "number", "Number"
        DATE = "date", "Date"
        DROPDOWN = "dropdown", "Dropdown"
        CHECKBOX = "checkbox", "Checkbox"

    name = models.CharField(max_length=120)
    key = models.CharField(
        max_length=50,
        validators=[RegexValidator(r"^[a-z][a-z0-9_]{0,49}$", "Use lowercase letters, digits, underscores.")],
    )
    entity_type = models.CharField(max_length=20, choices=EntityType.choices)
    data_type = models.CharField(max_length=20, choices=DataType.choices)
    options = models.JSONField(default=list, blank=True)  # dropdown choices
    is_required = models.BooleanField(default=False)
    position = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["entity_type", "position", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["workspace", "entity_type", "key"], name="uniq_customfield_key_per_entity"
            )
        ]

    def __str__(self):
        return f"{self.entity_type}.{self.key}"


# --------------------------------------------------------------------------
# Audit log (append-only, hash-chained)
# --------------------------------------------------------------------------
class AuditLogImmutableError(Exception):
    pass


class AuditLogQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise AuditLogImmutableError("Audit log entries cannot be modified.")

    def delete(self):
        raise AuditLogImmutableError("Audit log entries cannot be deleted.")

    def bulk_create(self, *args, **kwargs):
        raise AuditLogImmutableError("Use AuditLog.record() so the hash chain stays intact.")

    def bulk_update(self, *args, **kwargs):
        raise AuditLogImmutableError("Audit log entries cannot be modified.")


class AuditLog(models.Model):
    class Action(models.TextChoices):
        CREATE = "create", "Create"
        UPDATE = "update", "Update"
        DELETE = "delete", "Delete"
        EXPORT = "export", "Export"
        PERMISSION_CHANGE = "permission_change", "Permission change"
        OTHER = "other", "Other"

    id = models.BigAutoField(primary_key=True)
    workspace = models.ForeignKey(Workspace, on_delete=models.PROTECT, related_name="audit_logs")
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name="+"
    )
    actor_repr = models.CharField(max_length=255)  # survives even if user is anonymised
    action = models.CharField(max_length=30, choices=Action.choices)
    target_type = models.CharField(max_length=100)  # e.g. "api.contact"
    target_id = models.CharField(max_length=64)
    target_repr = models.CharField(max_length=255, blank=True)
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, editable=False)
    prev_hash = models.CharField(max_length=64, blank=True, editable=False)
    entry_hash = models.CharField(max_length=64, editable=False)

    objects = AuditLogQuerySet.as_manager()

    class Meta:
        ordering = ["-id"]
        indexes = [
            models.Index(fields=["workspace", "timestamp"]),
            models.Index(fields=["workspace", "target_type", "target_id"]),
        ]

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.actor_repr} {self.action} {self.target_type}:{self.target_id}"

    # -- hashing --------------------------------------------------------
    def compute_hash(self) -> str:
        payload = {
            "workspace": str(self.workspace_id),
            "actor": self.actor_repr,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "target_repr": self.target_repr,
            "ip_address": self.ip_address,
            "before": self.before,
            "after": self.after,
            "timestamp": self.timestamp.astimezone(dt_timezone.utc).isoformat(),
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), cls=DjangoJSONEncoder)
        return hashlib.sha256(blob.encode()).hexdigest()

    # -- immutability ---------------------------------------------------
    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AuditLogImmutableError("Audit log entries cannot be modified.")
        with transaction.atomic():
            # Serialise writers per workspace so the chain has no forks.
            Workspace.objects.select_for_update().only("pk").get(pk=self.workspace_id)
            last = (
                AuditLog.objects.filter(workspace_id=self.workspace_id)
                .order_by("-id")
                .values_list("entry_hash", flat=True)
                .first()
            )
            self.prev_hash = last or ""
            self.timestamp = timezone.now()
            self.entry_hash = self.compute_hash()
            super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AuditLogImmutableError("Audit log entries cannot be deleted.")

    # -- API ------------------------------------------------------------
    @classmethod
    def record(cls, *, workspace_id, actor, action, target, before=None, after=None, request=None):
        entry = cls(
            workspace_id=workspace_id,
            actor=actor,
            actor_repr=actor.get_username() if actor else "system",
            action=action,
            target_type=target._meta.label_lower,
            target_id=str(target.pk),
            target_repr=str(target)[:255],
            before=before,
            after=after,
            ip_address=_client_ip(request),
        )
        entry.save()
        return entry

    @classmethod
    def verify_chain(cls, workspace_id):
        """Return (True, None) if intact, else (False, id_of_first_bad_entry)."""
        prev = ""
        for e in cls.objects.filter(workspace_id=workspace_id).order_by("id").iterator():
            if e.prev_hash != prev or e.entry_hash != e.compute_hash():
                return False, e.id
            prev = e.entry_hash
        return True, None


def _client_ip(request):
    if request is None:
        return None
    # NOTE: behind a reverse proxy, configure it to set REMOTE_ADDR correctly
    # rather than trusting X-Forwarded-For from clients.
    raw = request.META.get("REMOTE_ADDR")
    try:
        return str(ipaddress.ip_address(raw))
    except (ValueError, TypeError):
        return None


def snapshot_instance(instance):
    """JSON-safe dict of an instance's concrete fields, for audit before/after."""
    data = {}
    for f in instance._meta.concrete_fields:
        if f.name in ("created_at", "updated_at"):
            continue
        data[f.attname] = getattr(instance, f.attname)
    return json.loads(json.dumps(data, cls=DjangoJSONEncoder))


# --------------------------------------------------------------------------
# DB-level tamper resistance (put in a RunSQL migration after AuditLog's):
#
#   CREATE FUNCTION api_auditlog_append_only() RETURNS trigger AS $$
#   BEGIN RAISE EXCEPTION 'api_auditlog is append-only'; END;
#   $$ LANGUAGE plpgsql;
#   CREATE TRIGGER auditlog_no_update_delete BEFORE UPDATE OR DELETE
#     ON api_auditlog FOR EACH ROW EXECUTE FUNCTION api_auditlog_append_only();
#   CREATE TRIGGER auditlog_no_truncate BEFORE TRUNCATE
#     ON api_auditlog FOR EACH STATEMENT EXECUTE FUNCTION api_auditlog_append_only();
#
# Ideally the app's DB role also lacks UPDATE/DELETE on that table.
# --------------------------------------------------------------------------
