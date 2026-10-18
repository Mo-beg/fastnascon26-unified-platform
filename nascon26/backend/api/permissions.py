"""DRF permissions mapping viewset actions to the per-user permission flags."""
from rest_framework.permissions import SAFE_METHODS, BasePermission

ACTION_TO_FLAG = {
    "list": "view",
    "retrieve": "view",
    "create": "create",
    "update": "edit",
    "partial_update": "edit",
    "destroy": "delete",
    "export": "export",
}


def _in_active_workspace(user):
    return bool(
        user
        and user.is_authenticated
        and user.workspace_id
        and user.workspace.is_active
    )


class HasWorkspacePermission(BasePermission):
    """Deny by default: unknown actions are rejected, not allowed."""

    def has_permission(self, request, view):
        if not _in_active_workspace(request.user):
            return False
        flag = ACTION_TO_FLAG.get(getattr(view, "action", None))
        return flag is not None and request.user.can(flag)

    def has_object_permission(self, request, view, obj):
        # Defense in depth; querysets are already workspace-filtered.
        return obj.workspace_id == request.user.workspace_id


class IsWorkspaceAdminOrReadOnly(BasePermission):
    """Anyone with `view` may read; only Owner/Admin may write (custom fields)."""

    def has_permission(self, request, view):
        if not _in_active_workspace(request.user):
            return False
        if request.method in SAFE_METHODS:
            return request.user.can("view")
        return request.user.is_workspace_admin

    def has_object_permission(self, request, view, obj):
        return obj.workspace_id == request.user.workspace_id


class IsWorkspaceAdmin(BasePermission):
    def has_permission(self, request, view):
        return _in_active_workspace(request.user) and request.user.is_workspace_admin

    def has_object_permission(self, request, view, obj):
        return obj.workspace_id == request.user.workspace_id
