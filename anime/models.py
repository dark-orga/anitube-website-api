from django.db import models
from authentication.models import User


class AnimeCache(models.Model):
    mal_id = models.IntegerField(unique=True)
    title = models.CharField(max_length=255)
    image_url = models.URLField()
    synopsis = models.TextField(null=True, blank=True)
    episodes = models.IntegerField(null=True, blank=True)
    genres = models.JSONField(default=list)
    score = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class UserWatchlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='watchlist')
    anime = models.ForeignKey(AnimeCache, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=[
        ('watching', 'Currently Watching'),
        ('completed', 'Completed'),
        ('on_hold', 'On Hold'),
        ('dropped', 'Dropped'),
        ('plan_to_watch', 'Plan to Watch'),
    ])
    current_episode = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'anime')

    def __str__(self):
        return f"{self.user.username} - {self.anime.title}"
