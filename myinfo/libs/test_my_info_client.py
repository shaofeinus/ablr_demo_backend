import requests

from unittest import mock
from urllib.parse import quote, urlencode

from django.test import TestCase

from .myinfo_client import MyInfoClient


class MyInfoClientTestCase(TestCase):

  def setUp(self):
    # Test client variables
    self.root = 'root'
    self.client_id = 'client'
    self.secret = 'secret'
    self.attributes = 'foo,bar'
    self.callback_url = 'callback_url'
    self.mock_security_obj = mock.Mock()

  def get_test_client(self):
    return MyInfoClient(
      self.root,
      self.client_id,
      self.secret,
      self.attributes,
      self.callback_url,
      self.mock_security_obj
    )

  @mock.patch.object(requests.Session, 'request')
  def test_request(self, mock_session_request):
    url = 'url'
    method = 'GET'
    auth_header = 'header'
    params = {'foo': 'bar'}
    data = {'bar': 'foo'}

    expected_headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cache-Control': 'no-cache',
      'Authorization': auth_header
    }
    expected_response_data = {'foobar': 'foobar'}
    mock_session_request.return_value.json.return_value = expected_response_data

    client = self.get_test_client()
    response_data = client.request(
      url,
      method=method,
      auth_header=auth_header,
      params=params,
      data=data
    )

    mock_session_request.assert_called_with(
      method,
      url=url,
      params=params,
      data=data,
      timeout=30,
      verify=True,
      headers=expected_headers,
    )
    self.assertEqual(response_data, expected_response_data)

  @mock.patch.object(MyInfoClient, 'request')
  def test_get_access_token(self, mock_client_request):
    auth_code = 'code'
    expected_auth_header = {'foo': 'bar'}
    self.mock_security_obj.generate_authorization_header.return_value = expected_auth_header
    expected_response_data = {'bar': 'foo'}
    mock_client_request.return_value = expected_response_data
    expected_api_url = f'{self.root}/token'
    expected_data = {
      'client_id': self.client_id,
      'client_secret': self.secret,
      'code': auth_code,
      'grant_type': 'authorization_code',
      'redirect_uri': self.callback_url,
    }

    client = self.get_test_client()
    response_data = client.get_access_token(auth_code)

    mock_client_request.assert_called_with(
      expected_api_url,
      method='POST',
      auth_header=expected_auth_header,
      data=expected_data
    )
    self.mock_security_obj.generate_authorization_header.assert_called_with(
      url=expected_api_url,
      params=expected_data,
      method='POST',
      app_id=self.client_id
    )
    self.assertEqual(response_data, expected_response_data)

  def test_get_authorise_url(self):
    state = 'state'
    querystring = urlencode(
      {
        'client_id': self.client_id,
        'attributes': self.attributes,
        'purpose': 'credit risk assessment',
        'state': state,
        'redirect_uri': self.callback_url,
      },
      safe=',/:',
      quote_via=quote
    )
    expected_authorise_url = f'{self.root}/authorise?{querystring}'

    client = self.get_test_client()
    authorise_url = client.get_authorise_url(state)
    self.assertEqual(authorise_url, expected_authorise_url)

  @mock.patch.object(MyInfoClient, 'request')
  def test_get_person(self, mock_client_request):
    uinfin = 'uinfin'
    access_token = 'access_token'
    expected_auth_header = 'header'
    self.mock_security_obj.generate_authorization_header.return_value = expected_auth_header
    expected_auth_header_with_access_token = expected_auth_header + ',Bearer access_token'
    expected_response_data = {'foo': 'bar'}
    mock_client_request.return_value = expected_response_data
    expected_api_url = f'{self.root}/person/{uinfin}/'
    expected_params = {
      'client_id': self.client_id,
      'attributes': self.attributes
    }

    client = self.get_test_client()
    response_data = client.get_person(uinfin, access_token)

    mock_client_request.assert_called_with(
      expected_api_url,
      method='GET',
      auth_header=expected_auth_header_with_access_token,
      params=expected_params
    )
    self.mock_security_obj.generate_authorization_header.assert_called_with(
      url=expected_api_url,
      params=expected_params,
      method='GET',
      app_id=self.client_id
    )
    self.assertEqual(response_data, expected_response_data)

  @mock.patch.object(MyInfoClient, 'get_person')
  @mock.patch.object(MyInfoClient, 'get_access_token')
  def test_get_person_from_code(self, mock_get_access_token, mock_get_person):
    code = 'code'
    access_token = 'token'
    uinfin = 'uinfin'
    person_data = {'foo': 'bar'}
    decrypted_person_data = {'bar': 'foo'}
    mock_get_access_token.return_value = {'access_token': access_token}
    mock_get_person.return_value = person_data
    self.mock_security_obj.get_decoded_access_token.return_value = {'sub': uinfin}
    self.mock_security_obj.get_decrypted_person_data.return_value = decrypted_person_data

    client = self.get_test_client()
    response_data = client.get_person_from_code(code)

    mock_get_access_token.assert_called_with(code)
    mock_get_person.assert_called_with(uinfin=uinfin, access_token=access_token)
    self.mock_security_obj.get_decoded_access_token.assert_called_with(access_token)
    self.mock_security_obj.get_decrypted_person_data.assert_called_with(person_data)
    self.assertEqual(decrypted_person_data, response_data)
