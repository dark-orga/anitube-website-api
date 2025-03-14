# anime/api/serializers.py
from rest_framework import serializers
from .models import AnimeCache, UserWatchlist


class AnimeCacheSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnimeCache
        fields = [
            'id', 'mal_id', 'title', 'image_url', 'synopsis',
            'episodes', 'genres', 'score', 'created_at', 'updated_at'
        ]


class UserWatchlistSerializer(serializers.ModelSerializer):
    anime_details = AnimeCacheSerializer(source='anime', read_only=True)

    class Meta:
        model = UserWatchlist
        fields = [
            'id', 'anime', 'anime_details', 'status', 'current_episode', 
            'created_at', 'updated_at'
        ]
        read_only_fields = ['user']
