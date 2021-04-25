from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from urllib.parse import quote, urlencode
from unittest import mock

from django.test import TestCase
from django.utils.encoding import force_bytes, force_text

from myinfo import settings
from .myinfo_security import MyInfoSecurity


class MyInfoSecurityTestCase(TestCase):

  def setUp(self):
    self.public_cert = settings.MYINFO_PUBLIC_CERT
    self.private_key = settings.MYINFO_PRIVATE_KEY

  def get_test_client(self):
    return MyInfoSecurity(self.public_cert, self.private_key)

  def test_create_signature(self):
    message = '123'
    expected_signature = force_text(
      b64encode(
        serialization.load_pem_private_key(
          force_bytes(self.private_key),
          password=None,
          backend=default_backend()
        ).sign(
          force_bytes(message),
          padding.PKCS1v15(),
          hashes.SHA256()
        )
      )
    )

    client = self.get_test_client()
    signature = client.create_signature(message)

    self.assertEqual(signature, expected_signature)

  @mock.patch.object(MyInfoSecurity, 'create_signature')
  @mock.patch('time.time')
  def test_generate_authorization_header(self, mock_time, mock_create_signature):
    url = 'url'
    params = {'foo': 'bar'}
    method = 'GET'
    app_id = 'app_id'
    curr_time = 100
    expected_timestamp = int(curr_time * 1000)
    expected_nonce = expected_timestamp * 100
    expected_base_string = '{}&{}&{}'.format(
      method.upper(),
      url,
      urlencode(
        sorted(
          {
            'app_id': app_id,
            'nonce': expected_nonce,
            'signature_method': 'RS256',
            'timestamp': expected_timestamp,
            **params
          }.items()
        ),
        safe=',/:',
        quote_via=quote
      )
    )
    expected_signature = 'signature'
    expected_auth_header = (
      f'PKI_SIGN '
      f'app_id="{app_id}",'
      f'timestamp="{expected_timestamp}",'
      f'nonce="{expected_nonce}",'
      'signature_method="RS256",'
      f'signature="{expected_signature}"'
    )

    mock_time.return_value = curr_time
    mock_create_signature.return_value = expected_signature

    client = self.get_test_client()
    auth_header = client.generate_authorization_header(url, params, method, app_id)

    mock_create_signature.assert_called_with(expected_base_string)
    self.assertEqual(auth_header, expected_auth_header)

  @mock.patch('jwt.decode')
  def test_get_decoded_access_token(self, mock_jwt_decode):
    access_token = '123'
    expected_decoded_access_token = {'foo': 'bar'}
    mock_jwt_decode.return_value = expected_decoded_access_token

    client = self.get_test_client()
    decoded_access_token = client.get_decoded_access_token(access_token)

    mock_jwt_decode.assert_called_with(
      access_token,
      client.public_key,
      algorithms=['RS256'],
      options={'verify_aud': False}
    )
    self.assertEqual(decoded_access_token, expected_decoded_access_token)

  @mock.patch('jwt.decode')
  @mock.patch('jwcrypto.jwk.JWK.from_pem')
  @mock.patch('jwcrypto.jwe.JWE')
  def test_get_decrypted_person_data(self, mock_jwe, mock_jwk_from_pem, mock_jwt_decode):
    person_data = 'abc'
    jwe_payload = '"jwe_payload"'
    private_key = 'private'
    expected_decoded = 'jwe_payload'
    expected_person_data = {'foo': 'bar'}
    mock_jwe.return_value.payload = jwe_payload
    mock_jwk_from_pem.return_value = private_key
    mock_jwt_decode.return_value = expected_person_data

    client = self.get_test_client()
    decoded_person_data = client.get_decrypted_person_data(person_data)

    mock_jwe.return_value.deserialize.assert_called_with(
      person_data,
      key=private_key
    )
    mock_jwt_decode.assert_called_with(
      expected_decoded,
      client.public_key,
      algorithms=['RS256']
    )
    self.assertEqual(decoded_person_data, expected_person_data)
