from django.apps import AppConfig


class OwmConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'OWM'

    def ready(self):
        import OWM.signals # Import signals to ensure they are registered
