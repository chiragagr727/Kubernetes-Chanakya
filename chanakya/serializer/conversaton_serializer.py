from rest_framework import serializers
from chanakya.models.conversation import ConversationModel, MessageModel


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = MessageModel
        fields = ['id', 'content', 'role', 'created', 'updated']


class ConversationSerializer(serializers.ModelSerializer):
    messages = serializers.SerializerMethodField()

    class Meta:
        model = ConversationModel
        fields = ['id', 'title', 'created', 'updated', 'messages']

    def get_messages(self, obj):
        view = self.context.get('view', None)
        if view and 'pk' in view.kwargs:
            return MessageSerializer(obj.messages.all(), many=True).data
        return None
