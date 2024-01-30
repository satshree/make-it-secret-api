import pytz
import json
from django.conf import settings


def decode_request_body(request):
    try:
        return request.body.decode("utf-8")
    except:
        return request


def parse_request_body(request):
    try:
        return json.loads(decode_request_body(request))
    except:
        try:
            return request.data
        except:
            return request


def parse_date(date, format="%Y-%m-%d %H:%M:%S"):
    try:
        return date.astimezone(pytz.timezone(settings.TIME_ZONE)).strftime(format)
    except:
        return date
