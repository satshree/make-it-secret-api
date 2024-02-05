import os
from django.views import View
from .crypto import encrypt, decrypt
from .utilities import parse_request_body
from .response import success_response, error_response, file_response


class MainView(View):
    class Meta:
        abstract = True

    def success_response(self, message=None, data=None, status=200):
        return success_response(data, message, status=status)

    def error_response(self, message=None, data=None, error=None, status=500):
        return error_response(message, data, error, status)

    def file_response(self, file_data, file_name=None):
        return file_response(file_data, file_name)


class EncryptView(MainView):
    def post(self, request, *args, **kwargs):
        file_name = "encryptedfile.mis"
        try:
            # PARSE REQUEST BODY
            data = parse_request_body(request)

            # GET FILE AND KEY
            key = data.POST.get("key")
            file_instance = data.FILES.get("file")

            if not key:
                return self.error_response(message="'key' is required!", status=400)

            if not file_instance:
                return self.error_response(message="'file' is required!", status=400)

            encrypted_file = encrypt(key, file_instance)
            file_name = encrypted_file.name.split(os.path.sep).pop()
        except Exception as e:
            print("-" * 100)
            print("Exception caught from 'crypto.views.EncryptView.post'")
            print(str(e))
            print("-" * 100)

            return self.error_response(message="Something went wrong", error=str(e))
        else:
            response = self.file_response(
                file_data=encrypted_file, file_name=file_name)
            return response


class DecryptView(MainView):
    def post(self, request, *args, **kwargs):
        file_name = ""
        try:
            # PARSE REQUEST BODY
            data = parse_request_body(request)

            # GET FILE AND KEY
            key = data.POST.get("key")
            file_instance = data.FILES.get("file")

            if not key:
                return self.error_response(message="'key' is required!", status=400)

            if not file_instance:
                return self.error_response(message="'file' is required!", status=400)

            decrypted_file = decrypt(key, file_instance)
            file_name = decrypted_file.name.split(os.path.sep).pop()
        except Exception as e:
            print("-" * 100)
            print("Exception caught from 'crypto.views.DecryptView.post'")
            print(str(e))
            print("-" * 100)

            return self.error_response(message="Something went wrong", error=str(e), status=555)
        else:
            response = self.file_response(
                file_data=decrypted_file, file_name=file_name)
            return response
