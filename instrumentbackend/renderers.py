from rest_framework.renderers import JSONRenderer


class CustomRenderer(JSONRenderer):

    def render(self, data, accepted_media_type=None, renderer_context=None):
        status_code = renderer_context['response'].status_code

        response = {
          "status": True,
          "code": status_code,
          "data": data,
          "message": "Data available"
        }

        if not str(status_code).startswith('2'):
            response["status"] = False
            response["data"] = None
            message = None 

            try:
                message = data["detail"]
            except KeyError:
                message = list(data.values())[0][0]
            except:
                message = "Something went wrong."

            response["message"] = message

        return super(CustomRenderer, self).render(response, accepted_media_type, renderer_context)