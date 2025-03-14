import requests
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AnimeCache, UserWatchlist
from .serializers import AnimeCacheSerializer, UserWatchlistSerializer

# Jikan API base URL
JIKAN_API_BASE = "https://api.jikan.moe/v4"


class AnimeCacheViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for accessing cached anime data"""
    queryset = AnimeCache.objects.all()
    serializer_class = AnimeCacheSerializer
    permission_classes = [IsAuthenticated]


class UserWatchlistViewSet(viewsets.ModelViewSet):
    """ViewSet for managing user watchlist"""
    serializer_class = UserWatchlistSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserWatchlist.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class AnimeSearchAPIView(APIView):
    """View for searching anime using Jikan API"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        query = request.query_params.get('q', '')
        if not query:
            return Response({"error": "Search query is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Call Jikan API
            response = requests.get(f"{JIKAN_API_BASE}/anime", params={"q": query, "limit": 15})
            response.raise_for_status()
            data = response.json()

            # Cache results in our database
            for item in data.get('data', []):
                AnimeCache.objects.update_or_create(
                    mal_id=item['mal_id'],
                    defaults={
                        'title': item['title'],
                        'image_url': item['images']['jpg']['image_url'],
                        'synopsis': item.get('synopsis'),
                        'episodes': item.get('episodes'),
                        'genres': [genre['name'] for genre in item.get('genres', [])],
                        'score': item.get('score')
                    }
                )

            return Response(data)
        except requests.RequestException as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def anime_details(request, mal_id):
    """Get detailed information about a specific anime"""
    try:
        # Try to get from cache first
        anime = AnimeCache.objects.filter(mal_id=mal_id).first()

        # If not in cache or needs refresh, fetch from API
        if not anime:
            response = requests.get(f"{JIKAN_API_BASE}/anime/{mal_id}")
            response.raise_for_status()
            anime_data = response.json()['data']

            anime, _ = AnimeCache.objects.update_or_create(
                mal_id=anime_data['mal_id'],
                defaults={
                    'title': anime_data['title'],
                    'image_url': anime_data['images']['jpg']['image_url'],
                    'synopsis': anime_data.get('synopsis'),
                    'episodes': anime_data.get('episodes'),
                    'genres': [genre['name'] for genre in anime_data.get('genres', [])],
                    'score': anime_data.get('score')
                }
            )

        serializer = AnimeCacheSerializer(anime)
        return Response(serializer.data)
    except requests.RequestException as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
