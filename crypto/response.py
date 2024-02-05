import json
from django.conf import settings
from django.http import HttpResponse


def send_with_cors(response):
    """Django Response object with CORS Headers."""

    if settings.CORS_ORIGIN_ALLOW_ALL:
        response["Access-Control-Allow-Origin"] = "*"
    else:
        response["Access-Control-Allow-Origin"] = settings.CORS_ALLOWED_ORIGINS

    response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response["Allow"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response


def success_response(data=None, message=None, error=None, status=200):
    """
    Django Response object with CORS Headers for Success Response.

    Default HTTP Status Code: 200 OK
    """

    new_data = {}
    new_data["status"] = True

    if message:
        new_data["message"] = message

    if error:
        new_data["error"] = error

    if type(data) in (list, dict):
        new_data["results"] = data

    response = HttpResponse(json.dumps(new_data),
                            status=status, content_type='application/json')
    return send_with_cors(response)


def error_response(
    message, data=None, error=None, status=500
):
    """
    Django Response object with CORS Headers for Error Response.

    Default HTTP Status Code: 500 INTERNAL SERVER ERROR
    """

    new_data = {}
    new_data["status"] = False
    new_data["message"] = message

    if error:
        new_data["error"] = error

    if type(data) in (list, dict):
        new_data["results"] = data
    response = HttpResponse(json.dumps(new_data),
                            status=status, content_type='application/json')
    return send_with_cors(response)


def file_response(file_data, filename=None):
    """
    Django Response object with CORS Headers for Success File Response.

    Default HTTP Status Code: 200 OK
    """
    response = HttpResponse(file_data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return send_with_cors(response)
