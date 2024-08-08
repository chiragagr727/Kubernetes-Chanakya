import requests
from rest_framework import viewsets, status
from chanakya.enums.tts_embedding import speaker_embedding, gpt_cond_latent
from chanakya.utils import custom_exception
from rest_framework.response import Response


class TextToSpeechApiView(viewsets.ViewSet):

    def create(self, request):
        try:
            text = request.data.get('text', None)
            user_info = request.META.get('user', None)
            if not text:
                raise custom_exception.DataNotFound("text is required")
            headers = {"Content-Type": "application/json"}
            url = "http://164.52.217.88:8000/tts"
            data = {
                "speaker_embedding": speaker_embedding,
                "gpt_cond_latent": gpt_cond_latent,
                "text": text,
                "language": "en",
            }
            response = requests.post(url, json=data, headers=headers)
            binary_data = {"binary_data": response.content}
            if response.status_code == 200:
                return Response(binary_data, status=response.status_code)
            else:
                error = {"error": response.text}
                return Response(error, status=response.status_code)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
