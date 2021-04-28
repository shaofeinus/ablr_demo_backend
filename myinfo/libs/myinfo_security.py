import jwt
import logging
import time

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode
from jwcrypto import jwe, jwk
from urllib.parse import quote, urlencode

from django.utils.encoding import force_bytes, force_text

log = logging.getLogger(__name__)


class MyInfoSecurity:

  def __init__(self, public_cert, private_key):
    self.public_cert = public_cert
    self.private_key = private_key
    self.cert_obj = load_pem_x509_certificate(force_bytes(self.public_cert), default_backend())
    self.public_key = self.cert_obj.public_key()

  def create_signature(self, raw_message: str) -> str:
    private_key = serialization.load_pem_private_key(
      force_bytes(self.private_key), password=None, backend=default_backend()
    )
    signature = private_key.sign(force_bytes(raw_message), padding.PKCS1v15(), hashes.SHA256())
    return force_text(b64encode(signature))

  def generate_authorization_header(self, url, params, method, app_id):
    """
    See: https://www.ndi-api.gov.sg/assets/lib/trusted-data/myinfo/specs/myinfo-kyc-v2.1.1.yaml.html#section/Security/Request-Signing  # noqa: E501
    """
    # A) Construct the Authorisation Token Parameters
    timestamp = int(time.time() * 1000)
    nonce = timestamp * 100
    default_apex_headers = {
      'app_id': app_id,
      'nonce': nonce,
      'signature_method': 'RS256',
      'timestamp': timestamp,
    }

    # B) Forming the Base String
    # Base String is a representation of the entire request (ensures message integrity)
    base_params = default_apex_headers.copy()
    base_params.update(params)
    query = sorted(base_params.items())
    base_params_str = urlencode(query, safe=',/:', quote_via=quote)

    base_string = f'{method.upper()}&{url}&{base_params_str}'

    # C) Signing Base String to get Digital Signature
    signature = self.create_signature(base_string)
    log.info('Signature: %s', signature)

    # D) Assembling the Authorization Header
    return (
      f'PKI_SIGN '
      f'app_id="{app_id}",'
      f'timestamp="{timestamp}",'
      f'nonce="{nonce}",'
      'signature_method="RS256",'
      f'signature="{signature}"'
    )

  def get_decoded_access_token(self, access_token: str) -> dict:
    return jwt.decode(
      access_token,
      self.public_key,
      algorithms=['RS256'],
      options={
        'verify_aud': False,
        # Do not verify nbf due to possible mismatch of timings between systems
        'verify_nbf': False
      }
    )

  def get_decrypted_person_data(self, person_data: str) -> dict:
    jwetoken = jwe.JWE()
    private_key = jwk.JWK.from_pem(force_bytes(self.private_key))
    jwetoken.deserialize(person_data, key=private_key)
    decoded = force_text(jwetoken.payload)
    decoded = decoded.strip('"')
    log.debug('decoded = %s', decoded)
    return jwt.decode(decoded, self.public_key, algorithms=['RS256'])
