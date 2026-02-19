from django.conf import settings
from django.contrib.auth.models import User
from django.db import models


class Task(models.Model):
    """Ancien modèle de tâches (non utilisé dans la nouvelle version)."""

    title = models.CharField(max_length=200)
    complete = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class FranceConnectProfile(models.Model):
    """Liaison entre un utilisateur Django et un identifiant France Connect (sub)."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='france_connect_profile',
    )
    sub = models.CharField(max_length=255, unique=True, db_index=True)

    class Meta:
        verbose_name = 'Profil France Connect'
        verbose_name_plural = 'Profils France Connect'

    def __str__(self):
        return f"FC {self.sub} → {self.user.username}"


class GoogleProfile(models.Model):
    """Liaison entre un utilisateur Django et un identifiant Google (sub)."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='google_profile',
    )
    sub = models.CharField(max_length=255, unique=True, db_index=True)

    class Meta:
        verbose_name = 'Profil Google'
        verbose_name_plural = 'Profils Google'

    def __str__(self):
        return f"Google {self.sub} → {self.user.username}"


class Series(models.Model):
    """Modèle représentant une série TV dans la watchlist."""

    PROVIDER_CHOICES = [
        ('netflix', 'Netflix'),
        ('amazon', 'Amazon Prime Video'),
        ('apple', 'Apple TV+'),
        ('manual', 'Ajout manuel'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='series',
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=200)
    tmdb_id = models.IntegerField(null=True, blank=True)
    overview = models.TextField(blank=True, default='')
    vote_average = models.FloatField(default=0.0)
    poster_path = models.CharField(max_length=500, blank=True, default='')
    provider = models.CharField(
        max_length=20, choices=PROVIDER_CHOICES, default='manual'
    )
    watched = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Série'
        verbose_name_plural = 'Séries'
        ordering = ['-created']
        unique_together = ('user', 'tmdb_id')

    def __str__(self):
        return self.title

    def poster_url(self):
        if self.poster_path:
            return f'https://image.tmdb.org/t/p/w200{self.poster_path}'
        return ''