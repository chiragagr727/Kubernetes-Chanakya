from datetime import datetime
from collections import defaultdict
from chanakya.models.conversation import ConversationModel, MessageModel
import json
from uuid import UUID
import os
from chanakya.utils.e2e_network_bucket import upload_file_in_mini_io
from django.shortcuts import redirect


class SuperAdminRetrieveDataSet:

    def __init__(self, request):
        self.request = request
        if not self.request.user.is_superuser:
            raise redirect("/403/")

    def retrieve_by_date(self, from_date: datetime, to_date: datetime):
        try:
            date_from = datetime.combine(from_date, datetime.min.time())
            date_to = datetime.combine(to_date, datetime.min.time())
            conversation_between_dates = ConversationModel.objects.filter(
                updated__gte=date_from,
                updated__lte=date_to
            ).prefetch_related('messages').order_by('updated')

            chats_between_dates = MessageModel.objects.filter(
                conversation__in=conversation_between_dates
            ).order_by('updated').values()
            file_data = json_export(chats_between_dates, user=None)
            if file_data is not None:
                date_folder = f"{str(date_from)}_{str(date_to)}"
                base_folder = os.environ.get("FOLDER_NAME_FOR_CHAT") + str(date_folder)
                file_name = f"conversation_record_from_{str(from_date)}_to_{str(to_date)}.json"
                with open(file_name, 'w') as temp_file:
                    temp_file.write(file_data)
                with open(file_name, 'rb') as temp_file:
                    url = upload_file_in_mini_io(base_folder=base_folder, file=temp_file, file_name=file_name,
                                                 user=None)
                    os.remove(file_name)
                    return {"message": "Success", "file_name": file_name}
            else:
                return {"message": "No Data Found"}
        except Exception as e:
            return {"message": str(e)}


class RetrieveConversationData:

    def retrieve_by_user(self, user):

        try:
            conversation_of_user = ConversationModel.objects.filter(user_id=user.id).prefetch_related(
                'messages').order_by('updated')

            chats_between_dates = MessageModel.objects.filter(conversation__in=conversation_of_user).order_by(
                'updated').values()
            return json_export(chats_between_dates, user=user)

        except Exception as e:
            return f"error: {str(e)}"


def json_export(chats_between_dates, user):
    try:
        chats_grouped_by_conversation = defaultdict(list)

        for chat in chats_between_dates:
            chat_dict = convert_uuids_and_dates(chat)
            chats_grouped_by_conversation[chat_dict['conversation_id']].append(chat_dict)

        chats_grouped_list = [
            {'conversation_id': conversation_id, 'messages': messages}
            for conversation_id, messages in chats_grouped_by_conversation.items()
        ]

        if user:
            user_data = {
                "id": str(user.id),
                "email": user.email,
                "preferred_language": user.preferred_language,
                "task_interests": user.task_interests,
                "profile_bio": user.profile_bio
            }
            chats_grouped_list.append(user_data)
        file_content = json.dumps(chats_grouped_list, default=str)

        return file_content

    except Exception as e:
        return f"Failed to save messages: {str(e)}"


def convert_uuids_and_dates(data):
    """Recursively converts UUIDs and datetimes to strings."""
    if isinstance(data, dict):
        return {k: convert_uuids_and_dates(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_uuids_and_dates(v) for v in data]
    elif isinstance(data, UUID):
        return str(data)
    elif isinstance(data, datetime):
        return data.isoformat()
    else:
        return data
