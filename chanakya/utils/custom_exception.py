from rest_framework import status


class CustomException(Exception):
    message = None
    status_code = None
    detail = None

    def __init__(self, detail=None, message=None, status_code=None):
        self.message = message or self.message
        self.status_code = status_code or self.status_code
        self.detail = detail or self.detail


class DataNotFound(CustomException):
    message = "Data Not Found"
    status_code = status.HTTP_404_NOT_FOUND

    @classmethod
    def check_required_fields(cls, request_data, required_fields):
        for field in required_fields:
            if field not in request_data or not request_data[field].strip():
                raise cls(f"{field.capitalize()} is required")


class InvalidData(CustomException):
    message = "Check Your Data"
    status_code = status.HTTP_400_BAD_REQUEST


class Unauthorized(CustomException):
    message = "Unauthorized Access"
    status_code = status.HTTP_401_UNAUTHORIZED


class InvalidRequest(CustomException):
    message = "Try After Sometime"
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE


class DataAlreadyExist(CustomException):
    message = "Data Already Exist"
    status_code = status.HTTP_409_CONFLICT


class RateLimitExceed(CustomException):
    message = "Limit Exceed"
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
