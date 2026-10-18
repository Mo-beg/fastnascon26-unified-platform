"""Django admin for inspecting data. Superusers have no workspace, so they can't use the API."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import AuditLog, Company, Contact, CustomField, Opportunity, User, Workspace


@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "created_at")
    search_fields = ("name", "slug")


@admin.register(User)
class WorkspaceUserAdmin(UserAdmin):
    list_display = ("username", "email", "workspace", "role", "is_active")
    list_filter = ("role", "is_active", "workspace")
    fieldsets = UserAdmin.fieldsets + (
        (
            "Workspace & permissions",
            {
                "fields": (
                    "workspace", "role", "can_view", "can_create", "can_edit",
                    "can_delete", "can_export", "can_manage_integrations",
                )
            },
        ),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (("Workspace", {"fields": ("workspace", "role")}),)


class TenantAdmin(admin.ModelAdmin):
    list_filter = ("workspace",)


@admin.register(Company)
class CompanyAdmin(TenantAdmin):
    list_display = ("name", "domain", "workspace")
    search_fields = ("name", "domain")


@admin.register(Contact)
class ContactAdmin(TenantAdmin):
    list_display = ("first_name", "last_name", "email", "company", "workspace")
    search_fields = ("first_name", "last_name", "email")


@admin.register(Opportunity)
class OpportunityAdmin(TenantAdmin):
    list_display = ("name", "stage", "value", "contact", "workspace")
    list_filter = ("workspace", "stage")


@admin.register(CustomField)
class CustomFieldAdmin(TenantAdmin):
    list_display = ("name", "key", "entity_type", "data_type", "workspace")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Strictly read-only."""

    list_display = ("id", "timestamp", "workspace", "actor_repr", "action", "target_type", "target_id")
    list_filter = ("workspace", "action")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
