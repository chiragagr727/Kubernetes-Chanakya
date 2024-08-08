from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import serializers
from chanakya.enums import suggestion_enum
from django.core.cache import cache
from random import choice, sample


class QuestionSerializer(serializers.Serializer):
    value = serializers.CharField()
    icon = serializers.URLField()
    prompt = serializers.CharField()


class SuggestionViewSet(viewsets.ViewSet):
    serializer_class = QuestionSerializer

    def list(self, request):
        cache_key = 'suggestions'
        data = cache.get(cache_key)

        if not data:
            categories = [suggestion_enum.Productivity, suggestion_enum.Travel, suggestion_enum.FoodAndDiet,
                          suggestion_enum.History, suggestion_enum.Technology, suggestion_enum.HealthAndWellness,
                          suggestion_enum.Education,
                          suggestion_enum.Creativity, suggestion_enum.Funny, suggestion_enum.PhilosophyAndHypotheticals,
                          suggestion_enum.MathAndScience]

            limit = request.query_params.get('limit')
            if limit:
                try:
                    limit = int(limit)
                except ValueError:
                    limit = None
            else:
                limit = None

            chosen_categories = sample(categories, min(limit, len(categories)) if limit else len(categories))
            data = []
            for category in chosen_categories:
                suggestion_prompt = choice(category.suggestions)
                data.append({
                    "value": suggestion_prompt.suggestions,
                    "prompt": suggestion_prompt.prompt,
                    "icon": category.logos
                })

            cache.set(cache_key, data, timeout=86400)

        serializer = self.serializer_class(data, many=True)
        return Response(serializer.data)
