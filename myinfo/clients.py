from . import settings
from .libs.myinfo_client import MyInfoClient
from .libs.myinfo_security import MyInfoSecurity


def get_myinfo_client_from_settings():
  return MyInfoClient(
    settings.MYINFO_ROOT,
    settings.MYINFO_CLIENT_ID,
    settings.MYINFO_SECRET,
    settings.MYINFO_ATTRS,
    settings.MYINFO_CALLBACK_URL,
    MyInfoSecurity(
      settings.MYINFO_PUBLIC_CERT,
      settings.MYINFO_PRIVATE_KEY
    ),
    cert_verify=settings.CERT_VERIFY
  )
