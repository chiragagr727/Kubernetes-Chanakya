from rest_framework.views import exception_handler
from chanakya.utils.custom_exception import CustomException
from rest_framework.response import Response


def custom_exception_handler(exc, context):
    if isinstance(exc, CustomException):
        data = {
            'detail': exc.detail,
            'message': exc.message,
            'status': exc.status_code,
        }
        return Response(data, status=exc.status_code)
    return exception_handler(exc, context)


handler500 = custom_exception_handler
