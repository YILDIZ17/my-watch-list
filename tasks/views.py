import secrets
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, redirect, render

from .models import FranceConnectProfile, GoogleProfile, Series

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


def _fetch_series_from_tmdb(user, provider_key, count=10):
    """Récupère des séries depuis TMDB pour un fournisseur donné.

    Retourne jusqu'à `count` séries qui ne sont PAS déjà en base,
    en paginant dans les résultats TMDB si besoin.
    """
    provider_id = PROVIDER_IDS[provider_key]
    existing_tmdb_ids = set(
        Series.objects.filter(user=user, tmdb_id__isnull=False).values_list(
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


@login_required
def index(request):
    """Vue listant toutes les séries de la watchlist."""
    series_list = Series.objects.filter(user=request.user)

    context = {
        'series_list': series_list,
        'version': getattr(settings, 'VERSION', '1.0.0'),
    }
    return render(request, 'tasks/list.html', context)


@login_required
def detail_series(request, pk):
    """Vue détail pour une série."""
    series = get_object_or_404(Series, id=pk, user=request.user)
    context = {'series': series}
    return render(request, 'tasks/detail.html', context)


@login_required
def toggle_watched(request, pk):
    """Bascule l'état 'vue / non vue' d'une série."""
    if request.method == 'POST':
        series = get_object_or_404(Series, id=pk, user=request.user)
        series.watched = not series.watched
        series.save()
    return redirect('detail', pk=pk)


@login_required
def delete_series(request, pk):
    """Supprime une série de la watchlist."""
    item = get_object_or_404(Series, id=pk, user=request.user)

    if request.method == "POST":
        item.delete()
        return redirect('/')

    context = {'item': item}
    return render(request, 'tasks/delete.html', context)


@login_required
def import_series(request, provider):
    """Importe 10 séries d’un fournisseur (Netflix / Amazon / Apple)."""
    if request.method != 'POST':
        return redirect('/')

    if provider not in PROVIDER_IDS:
        messages.error(request, f'Fournisseur inconnu : {provider}')
        return redirect('/')

    try:
        new_series = _fetch_series_from_tmdb(request.user, provider, count=10)

        created_count = 0
        for s in new_series:
            Series.objects.create(user=request.user, **s)
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


@login_required
def clear_watchlist(request):
    """Supprime toutes les séries de la watchlist."""
    if request.method == 'POST':
        deleted, _ = Series.objects.filter(user=request.user).delete()
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


def login_view(request):
    """Page de connexion : formulaire classique + bouton France Connect."""
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            next_url = request.POST.get('next') or request.GET.get('next') or settings.LOGIN_REDIRECT_URL
            return redirect(next_url)
    else:
        form = AuthenticationForm(request)

    return render(request, 'registration/login.html', {'form': form})


def signup(request):
    """Création de compte utilisateur."""
    if request.user.is_authenticated:
        return redirect('list')

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(
                request,
                'Compte créé avec succès, bienvenue dans votre watchlist !',
            )
            return redirect('list')
    else:
        form = UserCreationForm()

    return render(request, 'registration/signup.html', {'form': form})


def logout_view(request):
    """Déconnexion simple puis redirection vers la page de login."""
    logout(request)
    messages.info(request, "Vous avez été déconnecté.")
    return redirect('login')


# --- Authentification France Connect et Google ---


def france_connect_authorize(request):
    """Redirige vers l'endpoint d'autorisation France Connect (API v1)."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    request.session['france_connect_state'] = state
    request.session['france_connect_nonce'] = nonce

    params = {
        'response_type': 'code',
        'client_id': settings.FRANCE_CONNECT_CLIENT_ID,
        'redirect_uri': settings.FRANCE_CONNECT_REDIRECT_URI,
        'scope': 'openid profile email',
        'state': state,
        'nonce': nonce,
    }
    url = f"{settings.FRANCE_CONNECT_BASE_URL}/api/v1/authorize?{urlencode(params)}"
    return redirect(url)


def france_connect_callback(request):
    """
    Callback France Connect : échange du code contre un token, récupération userinfo,
    puis création du compte si inconnu et connexion.
    """
    state_sent = request.session.pop('france_connect_state', None)
    code = request.GET.get('code')
    state_received = request.GET.get('state')
    error = request.GET.get('error')
    error_description = request.GET.get('error_description', '')

    if error:
        messages.error(
            request,
            f"France Connect a renvoyé une erreur : {error}. "
            f"{error_description if error_description else 'Vérifiez la configuration (redirect_uri, client_id).'}"
        )
        return redirect('login')

    if not code:
        messages.error(request, "Code d'autorisation manquant dans la réponse France Connect.")
        return redirect('login')

    if state_sent is None:
        messages.error(request, "Session expirée. Veuillez réessayer.")
        return redirect('login')

    if state_received != state_sent:
        messages.error(request, "Paramètres de sécurité invalides. Veuillez réessayer.")
        return redirect('login')

    # Échange code -> token
    token_url = f"{settings.FRANCE_CONNECT_BASE_URL}/api/v1/token"
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.FRANCE_CONNECT_REDIRECT_URI,
        'client_id': settings.FRANCE_CONNECT_CLIENT_ID,
        'client_secret': settings.FRANCE_CONNECT_CLIENT_SECRET,
    }
    try:
        token_resp = requests.post(token_url, data=token_data, timeout=10)
        token_resp.raise_for_status()
        token_json = token_resp.json()
    except requests.HTTPError as e:
        error_detail = ''
        try:
            error_detail = token_resp.json().get('error_description', '')
        except:
            pass
        messages.error(
            request,
            f"Erreur HTTP lors de l'échange du code France Connect : {e}. {error_detail}"
        )
        return redirect('login')
    except requests.RequestException as e:
        messages.error(request, f"Erreur lors de l'échange du code France Connect : {e}")
        return redirect('login')

    access_token = token_json.get('access_token')
    if not access_token:
        messages.error(request, "France Connect n'a pas renvoyé de jeton d'accès.")
        return redirect('login')

    # Récupération des infos utilisateur (userinfo)
    userinfo_url = f"{settings.FRANCE_CONNECT_BASE_URL}/api/v1/userinfo?schema=openid"
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        userinfo_resp = requests.get(userinfo_url, headers=headers, timeout=10)
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except requests.HTTPError as e:
        messages.error(
            request,
            f"Erreur HTTP lors de la récupération des informations France Connect : {e}. "
            "Vérifiez que le token d'accès est valide."
        )
        return redirect('login')
    except requests.RequestException as e:
        messages.error(request, f"Impossible de récupérer les informations France Connect : {e}")
        return redirect('login')

    sub = userinfo.get('sub')
    if not sub:
        messages.error(request, "Identifiant France Connect (sub) manquant.")
        return redirect('login')

    # Liaison ou création du compte
    try:
        profile = FranceConnectProfile.objects.get(sub=sub)
        user = profile.user
    except FranceConnectProfile.DoesNotExist:
        # Création automatique du compte utilisateur
        given_name = userinfo.get('given_name') or ''
        family_name = userinfo.get('family_name') or ''
        email = userinfo.get('email') or ''
        base_username = f"fc_{sub}"[:150]
        username = base_username
        idx = 0
        while User.objects.filter(username=username).exists():
            idx += 1
            username = f"{base_username}_{idx}"[:150]

        user = User.objects.create_user(
            username=username,
            email=email or f"{username}@franceconnect.local",
            first_name=given_name,
            last_name=family_name,
            password=None,
        )
        user.set_unusable_password()
        user.save()
        FranceConnectProfile.objects.create(user=user, sub=sub)

    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    messages.success(request, "Connexion réussie avec France Connect.")
    return redirect(settings.LOGIN_REDIRECT_URL)


def google_authorize(request):
    """Redirige vers l'endpoint d'autorisation Google OAuth2."""
    state = secrets.token_urlsafe(32)
    request.session['google_oauth_state'] = state

    params = {
        'response_type': 'code',
        'client_id': settings.GOOGLE_CLIENT_ID,
        'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        'scope': 'openid email profile',
        'state': state,
    }
    url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return redirect(url)


def google_callback(request):
    """
    Callback Google : échange du code contre un token, récupération userinfo,
    puis création du compte si inconnu et connexion.
    """
    state_sent = request.session.pop('google_oauth_state', None)
    code = request.GET.get('code')
    state_received = request.GET.get('state')
    error = request.GET.get('error')

    if error:
        messages.error(
            request,
            f"Google a renvoyé une erreur : {error}. "
            "Vérifiez la configuration (redirect_uri, client_id)."
        )
        return redirect('login')

    if not code or state_sent is None or state_received != state_sent:
        messages.error(request, "Paramètres de retour Google invalides.")
        return redirect('login')

    # Échange code -> token
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
    }
    try:
        token_resp = requests.post(token_url, data=token_data, timeout=10)
        token_resp.raise_for_status()
        token_json = token_resp.json()
    except requests.RequestException as e:
        messages.error(request, f"Erreur lors de l'échange du code Google : {e}")
        return redirect('login')

    access_token = token_json.get('access_token')
    if not access_token:
        messages.error(request, "Google n'a pas renvoyé de jeton d'accès.")
        return redirect('login')

    # Récupération des infos utilisateur (userinfo)
    userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        userinfo_resp = requests.get(userinfo_url, headers=headers, timeout=10)
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except requests.RequestException as e:
        messages.error(request, "Impossible de récupérer les informations Google.")
        return redirect('login')

    # Google renvoie "sub" (OpenID Connect) ou "id"
    sub = userinfo.get('sub') or userinfo.get('id')
    if not sub:
        messages.error(request, "Identifiant Google (sub) manquant.")
        return redirect('login')

    # Liaison ou création du compte
    try:
        profile = GoogleProfile.objects.get(sub=sub)
        user = profile.user
    except GoogleProfile.DoesNotExist:
        given_name = userinfo.get('given_name') or ''
        family_name = userinfo.get('family_name') or ''
        email = userinfo.get('email') or ''
        base_username = f"google_{sub}"[:150]
        username = base_username
        idx = 0
        while User.objects.filter(username=username).exists():
            idx += 1
            username = f"{base_username}_{idx}"[:150]

        user = User.objects.create_user(
            username=username,
            email=email or f"{username}@google.local",
            first_name=given_name,
            last_name=family_name,
            password=None,
        )
        user.set_unusable_password()
        user.save()
        GoogleProfile.objects.create(user=user, sub=sub)

    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    messages.success(request, "Connexion réussie avec Google.")
    return redirect(settings.LOGIN_REDIRECT_URL)