import logging
import time
import requests

from json import JSONDecodeError
from urllib.parse import quote, urlencode

from myinfo.libs.myinfo_security import MyInfoSecurity

log = logging.getLogger(__name__)


class MyInfoClient(object):
  """
  See API doc at https://public.cloud.myinfo.gov.sg/myinfo/api/myinfo-kyc-v3.1.1.html
  Test data: https://www.ndi-api.gov.sg/library/trusted-data/myinfo/resources-personas.
  """

  def __init__(
      self,
      root: str,
      client_id: str,
      secret: str,
      attributes: str,
      callback_url: str,
      security_obj: MyInfoSecurity,
      cert_verify: bool = True,
      timeout: int = 30
  ):
    """
    Initialize a request session to interface with remote API
    """
    self.root = root
    self.client_id = client_id
    self.secret = secret
    self.attributes = attributes
    self.callback_url = callback_url
    self.cert_verify = cert_verify
    self.timeout = timeout
    self.session = requests.Session()
    self.security_obj = security_obj

  def request(self, api_url, method='GET', auth_header=None, params=None, data=None):
    """
    Returns:
        dict or str

    Raises:
        requests.RequestException
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Cache-Control': 'no-cache'}
    if auth_header:
      headers['Authorization'] = auth_header

    log.info('headers = %s', headers)
    response = self.session.request(
      method,
      url=api_url,
      params=params,
      data=data,
      timeout=self.timeout,
      verify=self.cert_verify,
      headers=headers,
    )

    response.raise_for_status()

    try:
      return response.json()
    except JSONDecodeError:
      return response.text

  def get_access_token(self, auth_code: str):
    """
    Generate an access token when presented with a valid authcode obtained from the Authorise API.
    This token can then be used to request for the user's data that were consented.

    """
    api_url = f'{self.root}/token'
    params = {
      'client_id': self.client_id,
      'client_secret': self.secret,
      'code': auth_code,
      'grant_type': 'authorization_code',
      'redirect_uri': self.callback_url,
    }
    auth_header = self.security_obj.generate_authorization_header(
      url=api_url, params=params, method='POST', app_id=self.client_id
    )
    log.info('auth_header: %s', auth_header)

    resp = self.request(api_url, method='POST', auth_header=auth_header, data=params)

    return resp

  def get_person(self, uinfin, access_token):
    """
    Return user's data from MyInfo when presented with a valid access token obtained from the Token API.
    """
    api_url = f'{self.root}/person/{uinfin}/'
    params = {'client_id': self.client_id, 'attributes': self.attributes}
    auth_header = self.security_obj.generate_authorization_header(
      url=api_url, params=params, method='GET', app_id=self.client_id
    )

    auth_header += f',Bearer {access_token}'
    log.info('auth_header: %s', auth_header)

    resp = self.request(api_url, method='GET', auth_header=auth_header, params=params)

    return resp

  def get_person_from_code(self, code):
    """
    Return user's data from MyInfo with the code in the redirection url.
    """
    access_token_resp = self.get_access_token(code)
    access_token = access_token_resp['access_token']
    # Wait for a while before fetching personal data to avoid timing mismatch issue when fetching data from MyInfo
    time.sleep(2)
    decoded_access_token = self.security_obj.get_decoded_access_token(access_token)
    uinfin = decoded_access_token['sub']
    person_data_resp = self.get_person(uinfin=uinfin, access_token=access_token)

    decrypted_person_data_resp = self.security_obj.get_decrypted_person_data(person_data_resp)

    return decrypted_person_data_resp

  def get_authorise_url(self, state):
    """
    Return a redirect URL to SingPass login page for user's authentication and consent.
    """

    query = {
      'client_id': self.client_id,
      'attributes': self.attributes,
      'purpose': 'credit risk assessment',
      'state': state,
      'redirect_uri': self.callback_url,
    }
    querystring = urlencode(query, safe=',/:', quote_via=quote)
    authorise_url = f'{self.root}/authorise?{querystring}'
    return authorise_url
