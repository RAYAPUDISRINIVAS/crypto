from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from cryptography.fernet import Fernet


def _master_fernet() -> Fernet:
    master_key = settings.KEYAPP_MASTER_KEY
    if not master_key:
        raise ImproperlyConfigured("KEYAPP_MASTER_KEY must be set in the environment.")
    return Fernet(master_key.encode("utf-8"))

def generate_user_key() -> bytes:
    return Fernet.generate_key()  # bytes

def wrap_user_key(user_key: bytes) -> str:
    """Encrypt user key with master key (store this in DB)."""
    token = _master_fernet().encrypt(user_key)
    return token.decode("utf-8")

def unwrap_user_key(wrapped_key: str) -> bytes:
    """Decrypt wrapped key from DB back into raw user key."""
    return _master_fernet().decrypt(wrapped_key.encode("utf-8"))

def encrypt_with_user_key(user_key: bytes, plaintext: str) -> str:
    f = Fernet(user_key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_with_user_key(user_key: bytes, ciphertext: str) -> str:
    f = Fernet(user_key)
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")