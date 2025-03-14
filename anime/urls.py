from django.urls import path
from .views import (anime_details, AnimeSearchAPIView)

urlpatterns = [
    path('api/search/', AnimeSearchAPIView.as_view(), name='anime-search'),
    path(
        '<int:mal_id>/details/',
        anime_details,
        name='anime-details'
    ),
]
