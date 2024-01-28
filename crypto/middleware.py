from django.conf import settings
from django.http import HttpResponse


class AuthenticatePublicAPIMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path.startswith('/api/'):
            try:
                key = request.META.get("HTTP_APP")
                if key != settings.CLIENT_APP_HEADER:
                    raise Exception
            except:
                return HttpResponse("Unauthorized.", status=401)

        return None
