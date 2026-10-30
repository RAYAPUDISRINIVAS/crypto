from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),

    path("signup/", views.Signup, name="signup"),
    path("login/", views.Login, name="login"),
    path("logout/", views.Logout, name="logout"),

    path("home/", views.user_home, name="user_home"),

    path("keys/", views.view_keys, name="view_keys"),
    path("keys/generate/", views.generate_key, name="generate_key"),
    path("keys/revoke/<int:version>/", views.revoke_key, name="revoke_key"),
    path("keys/destroy/<int:version>/", views.destroy_key, name="destroy_key"),
    path("keys/rotate/", views.rotate_and_reencrypt, name="rotate_and_reencrypt"),

    path("encrypt/", views.encrypt_data, name="encrypt_data"),
    path("ciphertexts/", views.list_ciphertexts, name="list_ciphertexts"),
    path("decrypt/<int:item_id>/", views.decrypt_data, name="decrypt_data"),
]