from django.urls import path

from . import views

urlpatterns = [
    # Authentification
    path('accounts/login/', views.login_view, name='login'),
    path('accounts/logout/', views.logout_view, name='logout'),
    path('accounts/signup/', views.signup, name='signup'),
    path('france-connect/', views.france_connect_authorize, name='france_connect_authorize'),
    path('callback/', views.france_connect_callback, name='france_connect_callback'),
    path('google/', views.google_authorize, name='google_authorize'),
    path('google-callback/', views.google_callback, name='google_callback'),

    # Watchlist
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