import logging

from requests import HTTPError
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.serializers import Serializer, CharField

from . import clients

log = logging.getLogger(__name__)


class AuthoriseUrlView(APIView):
  class GetRequestSerializer(Serializer):
    state = CharField(max_length=16)

  def get(self, request):
    """
    Generates an authorise url to retrieve personal data from MyInfo
    """

    # Parse request
    request_serializer = self.GetRequestSerializer(data=request.query_params)
    request_serializer.is_valid(raise_exception=True)
    request_data = request_serializer.validated_data
    state = request_data['state']

    # Generate authorization url
    try:
      client = clients.get_myinfo_client_from_settings()
      authorise_url = client.get_authorise_url(state)
    except Exception as e:
      log.warning(f'state:{state} | failed to generate authorise url: {e}')
      return Response({'message': 'failed to generate authorise url'}, 500)

    return Response({
      'authorise_url': authorise_url
    })


class PersonalDataView(APIView):
  class GetRequestSerializer(Serializer):
    code = CharField()

  def get(self, request):
    """
    Retrieves the personal data from MyInfo based on the code from the redirect url
    """

    # Parse request
    request_serializer = self.GetRequestSerializer(data=request.query_params)
    request_serializer.is_valid(raise_exception=True)
    request_data = request_serializer.validated_data
    code = request_data['code']

    # Retrieve personal data
    try:
      client = clients.get_myinfo_client_from_settings()
      person_data = client.get_person_from_code(code)
    except Exception as e:
      if isinstance(e, HTTPError):
        message = 'failed to retrieve personal data'
      else:
        message = 'authentication error'
      log.warning(f'code: {code} | {message} | {e}')
      return Response({'message': message}, 500)

    return Response(person_data)
