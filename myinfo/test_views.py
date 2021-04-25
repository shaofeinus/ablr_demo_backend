from unittest import mock
from requests import HTTPError

from rest_framework.test import APITestCase


class MockMyInfoClientMixin:
  """
  Creates a mock MyInfoClient instance that can be accessed by self.mock_myinfo_client
  """

  def setUp(self):
    self.get_myinfo_client_from_settings_patcher = mock.patch('myinfo.views.clients.get_myinfo_client_from_settings')
    self.mock_get_myinfo_client_from_settings = self.get_myinfo_client_from_settings_patcher.start()
    self.addCleanup(self.get_myinfo_client_from_settings_patcher.stop)
    self.mock_myinfo_client = mock.Mock()
    self.mock_get_myinfo_client_from_settings.return_value = self.mock_myinfo_client


class AuthoriseUrlViewTestCase(MockMyInfoClientMixin,
                               APITestCase):

  def make_request(self, params):
    return self.client.get('/api/myinfo/authorise-url', data=params)

  def test_success(self):
    state = 'state'
    expected_url = 'url'
    self.mock_myinfo_client.get_authorise_url.return_value = expected_url

    response = self.make_request({'state': state})

    self.mock_myinfo_client.get_authorise_url.assert_called_with(state)
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.data, {'authorise_url': expected_url})

  def test_invalid_state(self):
    response = self.make_request({'state': '12345678901234567'})

    self.mock_myinfo_client.get_authorise_url.assert_not_called()
    self.assertEqual(response.status_code, 400)
    self.assertEqual(response.data, {'state': ['Ensure this field has no more than 16 characters.']})

  def test_no_state(self):
    response = self.make_request({'state': ''})
    self.assertEqual(response.status_code, 400)
    self.assertEqual(response.data, {'state': ['This field may not be blank.']})

    response = self.make_request({})
    self.assertEqual(response.status_code, 400)
    self.assertEqual(response.data, {'state': ['This field is required.']})

    self.mock_myinfo_client.get_authorise_url.assert_not_called()

  def test_failed_to_generate_authorise_url(self):
    state = 'state'
    self.mock_myinfo_client.get_authorise_url.side_effect = ValueError('Error')

    response = self.make_request({'state': state})
    self.mock_myinfo_client.get_authorise_url.assert_called_with(state)
    self.assertEqual(response.status_code, 500)
    self.assertEqual(response.data, {'message': 'failed to generate authorise url'})


class PersonalDataViewTestCase(MockMyInfoClientMixin,
                               APITestCase):

  def make_request(self, params):
    return self.client.get('/api/myinfo/personal-data', data=params)

  def test_success(self):
    code = 'state'
    expected_personal_data = {'foo': 'bar'}
    self.mock_myinfo_client.get_person_from_code.return_value = expected_personal_data

    response = self.make_request({'code': code})

    self.mock_myinfo_client.get_person_from_code.assert_called_with(code)
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.data, expected_personal_data)

  def test_no_code(self):
    response = self.make_request({'code': ''})
    self.assertEqual(response.status_code, 400)
    self.assertEqual(response.data, {'code': ['This field may not be blank.']})

    response = self.make_request({})
    self.assertEqual(response.status_code, 400)
    self.assertEqual(response.data, {'code': ['This field is required.']})

    self.mock_myinfo_client.get_person_from_code.assert_not_called()

  def test_failed_to_retrieve_personal_data(self):
    code = 'code'
    self.mock_myinfo_client.get_person_from_code.side_effect = HTTPError('Error')

    response = self.make_request({'code': code})
    self.mock_myinfo_client.get_person_from_code.assert_called_with(code)
    self.assertEqual(response.status_code, 500)
    self.assertEqual(response.data, {'message': 'failed to retrieve personal data'})

  def test_authentication_error(self):
    code = 'code'
    self.mock_myinfo_client.get_person_from_code.side_effect = ValueError('Error')

    response = self.make_request({'code': code})
    self.mock_myinfo_client.get_person_from_code.assert_called_with(code)
    self.assertEqual(response.status_code, 500)
    self.assertEqual(response.data, {'message': 'authentication error'})
