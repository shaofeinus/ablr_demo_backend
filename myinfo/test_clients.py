from unittest import mock

from django.test import TestCase

from . import settings
from .clients import get_myinfo_client_from_settings


class GetMyInfoClientFromSettingsTestCase(TestCase):

  @mock.patch('myinfo.clients.MyInfoSecurity')
  @mock.patch('myinfo.clients.MyInfoClient')
  def test(self, mock_myinfo_client_class, mock_myinfo_security_class):
    mock_mock_myinfo_security_obj = mock.Mock()
    mock_myinfo_security_class.return_value = mock_mock_myinfo_security_obj

    get_myinfo_client_from_settings()

    mock_myinfo_client_class.assert_called_with(
      settings.MYINFO_ROOT,
      settings.MYINFO_CLIENT_ID,
      settings.MYINFO_SECRET,
      settings.MYINFO_ATTRS,
      settings.MYINFO_CALLBACK_URL,
      mock_mock_myinfo_security_obj,
      cert_verify=settings.CERT_VERIFY
    )
    mock_myinfo_security_class.assert_called_with(
      settings.MYINFO_PUBLIC_CERT,
      settings.MYINFO_PRIVATE_KEY
    )
