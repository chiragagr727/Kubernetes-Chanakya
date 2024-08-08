from django.apps import AppConfig


class ChanakyaConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'chanakya'

    def ready(self):
        import chanakya.models.user
        import chanakya.signals.prompt_cache_update
