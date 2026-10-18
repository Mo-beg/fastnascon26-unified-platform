from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter

from .views import (
    AuditLogViewSet,
    CompanyViewSet,
    ContactViewSet,
    CustomFieldViewSet,
    MeView,
    OpportunityViewSet,
    RegisterView,
)

router = DefaultRouter()
router.register("companies", CompanyViewSet, basename="company")
router.register("contacts", ContactViewSet, basename="contact")
router.register("opportunities", OpportunityViewSet, basename="opportunity")
router.register("custom-fields", CustomFieldViewSet, basename="customfield")
router.register("audit-logs", AuditLogViewSet, basename="auditlog")

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="register"),  # new workspace + owner
    path("auth/login/", obtain_auth_token, name="login"),  # {"username","password"} -> {"token"}
    path("me/", MeView.as_view(), name="me"),
    path("", include(router.urls)),
]
