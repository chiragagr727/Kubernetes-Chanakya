from storages.backends.s3boto3 import S3Boto3Storage
from chanakya.utils import sentry
from chanakya.utils import custom_exception
import os


class MediaStorage(S3Boto3Storage):
    bucket_name = os.environ.get("BUCKET_NAME_FOR_CHATS")


class S3BucketService:

    def upload_file(self, file, file_path, file_name):
        try:
            file_path_within_bucket = os.path.join(file_path, file_name)
            media_storage = MediaStorage()
            media_storage.save(file_path_within_bucket, file)
            file_url = media_storage.url(file_path_within_bucket)
            return file_url
        except Exception as e:
            sentry.capture_error_for_mini_io(message=f"Failed to upload file in bucket: check logs",
                                             mini_io_host=os.environ.get("E2E_HOST_URL"),
                                             exception=e)

    def delete_file(self, file_path, file_name):
        try:
            file_path_within_bucket = os.path.join(file_path, file_name)
            media_storage = MediaStorage()
            media_storage.delete(file_path_within_bucket)
            return {"status": True, "message": "File Deleted Successfully"}
        except Exception as e:
            return {"status": False, "message": f"File Deletion Failed: {e}"}


def upload_file_in_mini_io(base_folder, file, file_name, user):
    try:
        if user:
            file_path = base_folder + str(user.id)
        file_path = base_folder
        client = S3BucketService()
        url = client.upload_file(file, file_path, file_name)
        return url
    except Exception as e:
        raise custom_exception.InvalidData(f"Error While Fetching File:: {e}")