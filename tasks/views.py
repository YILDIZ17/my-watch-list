import requests
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect, render

from .models import Series

TMDB_BASE_URL = 'https://api.themoviedb.org/3'

PROVIDER_IDS = {
    'netflix': 8,
    'amazon': 119,
    'apple': 350,
}

PROVIDER_LABELS = {
    'netflix': 'Netflix',
    'amazon': 'Amazon Prime Video',
    'apple': 'Apple TV+',
}


def _fetch_series_from_tmdb(provider_key, count=10):
    """Récupère des séries depuis TMDB pour un fournisseur donné.

    Retourne jusqu'à `count` séries qui ne sont PAS déjà en base,
    en paginant dans les résultats TMDB si besoin.
    """
    provider_id = PROVIDER_IDS[provider_key]
    existing_tmdb_ids = set(
        Series.objects.filter(tmdb_id__isnull=False).values_list(
            'tmdb_id', flat=True
        )
    )

    api_key = getattr(settings, 'TMDB_API_KEY', None)
    if not api_key:
        raise RuntimeError(
            'TMDB_API_KEY n’est pas configurée dans settings.py'
        )

    new_series = []
    page = 1
    max_pages = 10

    while len(new_series) < count and page <= max_pages:
        params = {
            'sort_by': 'vote_average.desc',
            'with_watch_providers': provider_id,
            'watch_region': 'FR',
            'with_watch_monetization_types': 'flatrate',
            'vote_count.gte': 100,
            'language': 'fr-FR',
            'page': page,
            'api_key': api_key,
        }

        response = requests.get(
            f'{TMDB_BASE_URL}/discover/tv',
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        results = data.get('results', [])

        if not results:
            break

        for show in results:
            tmdb_id = show['id']
            if tmdb_id not in existing_tmdb_ids:
                new_series.append(
                    {
                        'title': show.get('name', 'Sans titre'),
                        'tmdb_id': tmdb_id,
                        'overview': show.get('overview', ''),
                        'vote_average': show.get('vote_average', 0),
                        'poster_path': show.get('poster_path', ''),
                        'provider': provider_key,
                    }
                )
                existing_tmdb_ids.add(tmdb_id)

            if len(new_series) >= count:
                break

        page += 1

    return new_series


def index(request):
    """Vue listant toutes les séries de la watchlist."""
    series_list = Series.objects.all()

    context = {
        'series_list': series_list,
        'version': getattr(settings, 'VERSION', '1.0.0'),
    }
    return render(request, 'tasks/list.html', context)


def detail_series(request, pk):
    """Vue détail pour une série."""
    series = Series.objects.get(id=pk)
    context = {'series': series}
    return render(request, 'tasks/detail.html', context)


def toggle_watched(request, pk):
    """Bascule l'état 'vue / non vue' d'une série."""
    if request.method == 'POST':
        series = Series.objects.get(id=pk)
        series.watched = not series.watched
        series.save()
    return redirect('detail', pk=pk)


def delete_series(request, pk):
    """Supprime une série de la watchlist."""
    item = Series.objects.get(id=pk)

    if request.method == "POST":
        item.delete()
        return redirect('/')

    context = {'item': item}
    return render(request, 'tasks/delete.html', context)


def import_series(request, provider):
    """Importe 10 séries d’un fournisseur (Netflix / Amazon / Apple)."""
    if request.method != 'POST':
        return redirect('/')

    if provider not in PROVIDER_IDS:
        messages.error(request, f'Fournisseur inconnu : {provider}')
        return redirect('/')

    try:
        new_series = _fetch_series_from_tmdb(provider, count=10)

        created_count = 0
        for s in new_series:
            Series.objects.create(**s)
            created_count += 1

        label = PROVIDER_LABELS[provider]
        if created_count > 0:
            messages.success(
                request,
                f'{created_count} séries {label} ajoutées à la watchlist !',
            )
        else:
            messages.info(
                request,
                f'Aucune nouvelle série {label} à ajouter '
                f'(toutes déjà présentes).',
            )

    except (requests.RequestException, RuntimeError) as e:
        messages.error(
            request,
            f'Erreur lors de la récupération des séries : {e}',
        )

    return redirect('/')


def clear_watchlist(request):
    """Supprime toutes les séries de la watchlist."""
    if request.method == 'POST':
        deleted, _ = Series.objects.all().delete()
        if deleted:
            messages.success(
                request,
                'Toutes les séries ont été supprimées de la watchlist.',
            )
        else:
            messages.info(
                request,
                'La watchlist était déjà vide.',
            )
    return redirect('/')