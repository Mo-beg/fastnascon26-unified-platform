"""
Tenant-scoped DRF viewsets.

The ONLY source of the workspace is `request.user.workspace_id`; client input
(query string, body, URL) is never trusted for tenancy. All reads are filtered
by it, all writes stamp it, and every mutation is written to the audit log in
the same DB transaction as the change.
"""
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from rest_framework import status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from .models import AuditLog, Company, Contact, CustomField, Opportunity, snapshot_instance
from .permissions import HasWorkspacePermission, IsWorkspaceAdmin, IsWorkspaceAdminOrReadOnly
from .serializers import (
    AuditLogSerializer,
    CompanySerializer,
    ContactSerializer,
    CustomFieldSerializer,
    MeSerializer,
    OpportunitySerializer,
    RegisterSerializer,
)


class WorkspaceQuerysetMixin:
    """Filters every queryset to the authenticated user's workspace."""

    filter_params = ()  # exact-match query params, e.g. ?stage=won

    def get_queryset(self):
        qs = super().get_queryset().filter(workspace_id=self.request.user.workspace_id)
        for param in self.filter_params:
            value = self.request.query_params.get(param)
            if value:
                try:
                    qs = qs.filter(**{param: value})
                except (ValueError, DjangoValidationError):
                    return qs.none()
        return qs


class WorkspaceScopedViewSet(WorkspaceQuerysetMixin, viewsets.ModelViewSet):
    permission_classes = [HasWorkspacePermission]
    filter_backends = [SearchFilter, OrderingFilter]

    def _audit(self, action, instance, before, after):
        AuditLog.record(
            workspace_id=self.request.user.workspace_id,
            actor=self.request.user,
            action=action,
            target=instance,
            before=before,
            after=after,
            request=self.request,
        )

    @transaction.atomic
    def perform_create(self, serializer):
        instance = serializer.save(workspace_id=self.request.user.workspace_id)
        self._audit(AuditLog.Action.CREATE, instance, None, snapshot_instance(instance))

    @transaction.atomic
    def perform_update(self, serializer):
        before = snapshot_instance(serializer.instance)
        instance = serializer.save()
        after = snapshot_instance(instance)
        if before != after:
            self._audit(AuditLog.Action.UPDATE, instance, before, after)

    @transaction.atomic
    def perform_destroy(self, instance):
        before = snapshot_instance(instance)
        self._audit(AuditLog.Action.DELETE, instance, before, None)  # log first: pk is cleared by delete()
        instance.delete()


class CompanyViewSet(WorkspaceScopedViewSet):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    search_fields = ["name", "domain", "industry"]
    ordering_fields = ["name", "created_at"]


class ContactViewSet(WorkspaceScopedViewSet):
    queryset = Contact.objects.select_related("company").prefetch_related("opportunities")
    serializer_class = ContactSerializer
    filter_params = ("company",)
    search_fields = ["first_name", "last_name", "email", "company__name"]
    ordering_fields = ["first_name", "last_name", "created_at"]


class OpportunityViewSet(WorkspaceScopedViewSet):
    queryset = Opportunity.objects.select_related("contact", "company", "owner")
    serializer_class = OpportunitySerializer
    filter_params = ("stage", "contact", "company", "owner")
    search_fields = ["name", "contact__first_name", "contact__last_name"]
    ordering_fields = ["value", "expected_close_date", "created_at"]


class CustomFieldViewSet(WorkspaceScopedViewSet):
    """Owner/Admin may define fields; everyone with `view` may read them."""

    queryset = CustomField.objects.all()
    serializer_class = CustomFieldSerializer
    permission_classes = [IsWorkspaceAdminOrReadOnly]
    filter_params = ("entity_type",)


class AuditLogViewSet(WorkspaceQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    """Read-only, Owner/Admin only. Filter with ?target_type=core.contact&target_id=<uuid>."""

    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsWorkspaceAdmin]
    filter_params = ("target_type", "target_id", "action")


# --------------------------------------------------------------------------
# Auth / onboarding
# --------------------------------------------------------------------------
class RegisterView(APIView):
    """POST: create a workspace + its Owner. Returns an auth token."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @transaction.atomic
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        AuditLog.record(
            workspace_id=user.workspace_id,
            actor=user,
            action=AuditLog.Action.CREATE,
            target=user.workspace,
            after=snapshot_instance(user.workspace),
            request=request,
        )
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {"token": token.key, "user": MeSerializer(user).data}, status=status.HTTP_201_CREATED
        )


class MeView(APIView):
    """GET: the current user, their role, workspace and effective permissions."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(MeSerializer(request.user).data)
