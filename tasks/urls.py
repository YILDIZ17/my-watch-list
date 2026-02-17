from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name="list"),
    path('series/<str:pk>/', views.detail_series, name="detail"),
    path('series/<str:pk>/toggle/', views.toggle_watched, name="toggle_watched"),
    path('series/<str:pk>/delete/', views.delete_series, name="delete"),
    path(
        'import/<str:provider>/',
        views.import_series,
        name="import_series",
    ),
    path('clear/', views.clear_watchlist, name='clear_watchlist'),
]