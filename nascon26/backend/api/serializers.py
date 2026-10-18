"""
DRF serializers.

Security notes
--------------
* `workspace` is never writable or exposed; views inject it from request.user.
* Every related-object field uses WorkspaceScopedRelatedField, so a client can't
  attach a record to another tenant's company/contact/user by guessing a UUID
  (it fails as "object does not exist", leaking nothing).
* `custom_data` is validated against the workspace's CustomField definitions.
"""
import datetime
import uuid

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils.text import slugify
from rest_framework import serializers

from .models import AuditLog, Company, Contact, CustomField, Opportunity, User, Workspace

READ_ONLY = ("id", "created_at", "updated_at")


class WorkspaceScopedRelatedField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        queryset = super().get_queryset()
        request = self.context.get("request")
        if request is None or not request.user.is_authenticated:
            return queryset.none()
        return queryset.filter(workspace_id=request.user.workspace_id)


# --------------------------------------------------------------------------
# Custom field validation
# --------------------------------------------------------------------------
def _coerce(defn, value):
    t = defn.data_type
    DT = CustomField.DataType
    if t == DT.TEXT:
        if not isinstance(value, str) or len(value) > 2000:
            raise serializers.ValidationError("Expected text (max 2000 chars).")
        return value
    if t == DT.NUMBER:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise serializers.ValidationError("Expected a number.")
        return value
    if t == DT.DATE:
        try:
            return datetime.date.fromisoformat(value).isoformat()
        except (TypeError, ValueError):
            raise serializers.ValidationError("Expected a date in YYYY-MM-DD format.")
    if t == DT.DROPDOWN:
        if value not in defn.options:
            raise serializers.ValidationError("Not one of the allowed options.")
        return value
    if t == DT.CHECKBOX:
        if not isinstance(value, bool):
            raise serializers.ValidationError("Expected true or false.")
        return value
    raise serializers.ValidationError("Unsupported field type.")


def clean_custom_data(data, definitions):
    if not isinstance(data, dict):
        raise serializers.ValidationError({"custom_data": "Must be an object."})
    defs = {d.key: d for d in definitions}
    errors, cleaned = {}, {}
    for key in data.keys() - defs.keys():
        errors[key] = "Unknown custom field."
    for key, defn in defs.items():
        value = data.get(key)
        if value is None or value == "":
            if defn.is_required:
                errors[key] = "This field is required."
            continue
        try:
            cleaned[key] = _coerce(defn, value)
        except serializers.ValidationError as exc:
            errors[key] = exc.detail
    if errors:
        raise serializers.ValidationError({"custom_data": errors})
    return cleaned


class CustomDataMixin:
    entity_type = None  # set on subclasses

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if self.instance is None or "custom_data" in attrs:
            definitions = CustomField.objects.filter(
                workspace_id=self.context["request"].user.workspace_id,
                entity_type=self.entity_type,
            )
            attrs["custom_data"] = clean_custom_data(attrs.get("custom_data", {}), definitions)
        return attrs


# --------------------------------------------------------------------------
# CRM serializers
# --------------------------------------------------------------------------
class CompanySerializer(CustomDataMixin, serializers.ModelSerializer):
    entity_type = CustomField.EntityType.COMPANY

    class Meta:
        model = Company
        fields = ["id", "name", "domain", "industry", "custom_data", "created_at", "updated_at"]
        read_only_fields = READ_ONLY


class ContactSerializer(CustomDataMixin, serializers.ModelSerializer):
    entity_type = CustomField.EntityType.CONTACT

    company = WorkspaceScopedRelatedField(
        queryset=Company.objects.all(), required=False, allow_null=True
    )
    full_name = serializers.CharField(read_only=True)
    opportunity_ids = serializers.PrimaryKeyRelatedField(
        source="opportunities", many=True, read_only=True
    )

    class Meta:
        model = Contact
        fields = [
            "id", "company", "first_name", "last_name", "full_name", "email", "phone",
            "job_title", "custom_data", "opportunity_ids", "created_at", "updated_at",
        ]
        read_only_fields = READ_ONLY


class OpportunitySerializer(CustomDataMixin, serializers.ModelSerializer):
    entity_type = CustomField.EntityType.OPPORTUNITY

    contact = WorkspaceScopedRelatedField(queryset=Contact.objects.all())
    company = WorkspaceScopedRelatedField(
        queryset=Company.objects.all(), required=False, allow_null=True
    )
    owner = WorkspaceScopedRelatedField(
        queryset=User.objects.all(), required=False, allow_null=True
    )

    class Meta:
        model = Opportunity
        fields = [
            "id", "name", "contact", "company", "owner", "stage", "value", "currency",
            "expected_close_date", "custom_data", "created_at", "updated_at",
        ]
        read_only_fields = READ_ONLY

    def validate(self, attrs):
        attrs = super().validate(attrs)
        contact = attrs.get("contact") or getattr(self.instance, "contact", None)
        if "company" in attrs:
            company = attrs["company"]
        else:
            company = self.instance.company if self.instance else None

        if contact is not None and contact.company_id:
            if company is None and self.instance is None:
                attrs["company"] = contact.company  # default to the contact's company
            elif company is not None and company.pk != contact.company_id:
                raise serializers.ValidationError(
                    {"company": "Must match the contact's company."}
                )
        return attrs


class CustomFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomField
        fields = [
            "id", "name", "key", "entity_type", "data_type", "options",
            "is_required", "position", "created_at", "updated_at",
        ]
        read_only_fields = READ_ONLY

    def validate(self, attrs):
        attrs = super().validate(attrs)
        inst = self.instance

        if inst:  # changing these would orphan stored values
            for name in ("key", "entity_type", "data_type"):
                if name in attrs and attrs[name] != getattr(inst, name):
                    raise serializers.ValidationError({name: "Cannot be changed after creation."})

        data_type = attrs.get("data_type", inst.data_type if inst else None)
        if data_type == CustomField.DataType.DROPDOWN:
            options = attrs.get("options", inst.options if inst else [])
            if (
                not isinstance(options, list)
                or not options
                or not all(isinstance(o, str) and o.strip() for o in options)
                or len(set(options)) != len(options)
            ):
                raise serializers.ValidationError(
                    {"options": "Dropdowns need a non-empty list of unique, non-blank strings."}
                )
        else:
            attrs["options"] = []

        if inst is None:
            exists = CustomField.objects.filter(
                workspace_id=self.context["request"].user.workspace_id,
                entity_type=attrs["entity_type"],
                key=attrs["key"],
            ).exists()
            if exists:
                raise serializers.ValidationError(
                    {"key": "A custom field with this key already exists for that entity."}
                )
        return attrs


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = [
            "id", "actor", "actor_repr", "action", "target_type", "target_id",
            "target_repr", "before", "after", "ip_address", "timestamp",
        ]
        read_only_fields = fields


# --------------------------------------------------------------------------
# Auth / onboarding
# --------------------------------------------------------------------------
class RegisterSerializer(serializers.Serializer):
    """Creates a brand-new workspace and its first Owner user."""

    workspace_name = serializers.CharField(max_length=200)
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value

    def validate(self, attrs):
        try:
            validate_password(
                attrs["password"], user=User(username=attrs["username"], email=attrs["email"])
            )
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)})
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        name = validated_data["workspace_name"].strip()
        base = slugify(name)[:60] or "workspace"
        workspace = Workspace.objects.create(name=name, slug=f"{base}-{uuid.uuid4().hex[:6]}")
        return User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            workspace=workspace,
            role=User.Role.OWNER,
        )


class MeSerializer(serializers.ModelSerializer):
    workspace_name = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "role", "workspace", "workspace_name", "permissions"]
        read_only_fields = fields

    def get_workspace_name(self, user):
        return user.workspace.name if user.workspace_id else None

    def get_permissions(self, user):
        return {flag: user.can(flag) for flag in User.PERMISSION_FLAGS}
