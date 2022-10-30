from rest_framework.renderers import JSONRenderer
from http import HTTPStatus


class CustomRenderer(JSONRenderer):

    def render(self, data, accepted_media_type=None, renderer_context=None):
        status_code = renderer_context['response'].status_code
        # Using the description's of the HTTPStatus class as error message.
        http_code_to_message = {v.value: v.description for v in HTTPStatus}

        response = {
          "status": True,
          "code": status_code,
          "data": data,
          "message": http_code_to_message[status_code]
        }

        if not str(status_code).startswith('2'):
            response["status"] = False
            response["data"] = None
            try:
                response["message"] = data["detail"]
            except KeyError:
                response["data"] = data

        return super(CustomRenderer, self).render(response, accepted_media_type, renderer_context)