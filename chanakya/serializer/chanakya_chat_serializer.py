from rest_framework import serializers
import re


class ChanakyaSearchRequestSerializer(serializers.Serializer):
    query = serializers.CharField(required=True, error_messages={'required': 'Query is required.'})
    conversation_id = serializers.CharField(required=True, allow_blank=False,
                                            error_messages={'required': 'Conversation is required.'})

    is_ios = serializers.BooleanField(required=False, default=False)

    def validate_query(self, value):
        sentences = re.split(r'[.!?]', value)
        sentences = [sentence for sentence in sentences if sentence.strip()]
        if len(sentences) > 10000:
            raise serializers.ValidationError('Query text exceeds')
        return value
