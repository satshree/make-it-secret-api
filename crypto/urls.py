from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "crypto"

urlpatterns = [
    path("encrypt/", csrf_exempt(views.EncryptView.as_view()), name="encrypt"),
    path("decrypt/", csrf_exempt(views.DecryptView.as_view()), name="decrypt"),
]
