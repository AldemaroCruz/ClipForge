"""Explicit PostgreSQL/authentication fixtures, never an application bypass.

The caller must provide a disposable database and CLIPFORGE_AUTH_TEST_DATABASE=1.
All synthetic project adoption is requested by exact ID in fixture code. No
application route assigns existing or ownerless files to a signed-in user.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import tempfile
from urllib.parse import urlsplit

from fastapi.testclient import TestClient as RawTestClient

_USERS = {}
_PREPARED = set()
_DATABASE_ENV = {key: value for key, value in os.environ.items()
                 if key.startswith('CLIPFORGE_DATABASE_') or key == 'CLIPFORGE_AUTH_TEST_DATABASE'}


def auth_environment():
    """Preserve explicit isolated DB settings in legacy provider-env fixtures."""
    return {**_DATABASE_ENV, **{key: value for key, value in os.environ.items()
            if key.startswith(('CLIPFORGE_DATABASE_', 'CLIPFORGE_AUTH_'))}}


def prepare_database(origin='http://127.0.0.1'):
    if os.environ.get('CLIPFORGE_AUTH_TEST_DATABASE') != '1':
        raise RuntimeError('Auth fixtures require an explicitly isolated PostgreSQL test database')
    parts = urlsplit(origin)
    if parts.scheme != 'http' or parts.hostname not in {'127.0.0.1', 'localhost', '::1'}:
        raise ValueError('Fixture origin must be local HTTP')
    os.environ['CLIPFORGE_AUTH_PROFILE'] = 'local-http'
    os.environ['CLIPFORGE_AUTH_ORIGIN'] = origin
    os.environ.setdefault('CLIPFORGE_DATABASE_SCHEMA', 'auth01_test_' + secrets.token_hex(8))
    if not os.environ['CLIPFORGE_DATABASE_SCHEMA'].startswith('auth01_test_'):
        raise ValueError('Fixture schema must be explicitly test-owned')
    from app.auth_db import get_engine
    from app.auth_migrations import upgrade
    engine = get_engine()
    marker = (id(engine), os.environ['CLIPFORGE_DATABASE_SCHEMA'])
    if marker not in _PREPARED:
        upgrade(engine)
        _PREPARED.add(marker)
    return engine


def fixture_user(identity, *, origin='http://127.0.0.1', admin=False):
    """Create a persistent real user for this explicit synthetic fixture."""
    engine = prepare_database(origin)
    from app.auth import create_user, principal_for_user
    key = (id(engine), str(identity), admin)
    if key not in _USERS:
        username = 'qa_' + secrets.token_hex(10)
        password = secrets.token_urlsafe(24)
        user = create_user(username, password, is_admin=admin)
        user_id = user['id'] if isinstance(user, dict) else user.id
        _USERS[key] = {'username': username, 'password': password,
                       'principal': principal_for_user(user_id)}
    return _USERS[key]


def own_fixture_projects(principal, project_ids):
    """Explicitly map only caller-listed synthetic IDs in the disposable DB."""
    if os.environ.get('CLIPFORGE_AUTH_TEST_DATABASE') != '1':
        raise RuntimeError('Synthetic ownership requires an isolated test database')
    from sqlalchemy import delete
    from sqlalchemy.orm import Session
    from app.auth_db import get_engine
    from app.auth_models import Project
    from app.auth import register_project
    ids = tuple(project_ids)
    if any(len(value) != 32 or any(c not in '0123456789abcdef' for c in value) for value in ids):
        raise ValueError('Synthetic project ID must be a lowercase UUID hex string')
    with Session(get_engine()) as session, session.begin():
        for project_id in ids:
            session.execute(delete(Project).where(Project.id == project_id))
    for project_id in ids:
        register_project(project_id, principal)


def http_login(client, username, password, origin):
    challenge = client.get('/auth/csrf')
    if challenge.status_code != 200:
        raise AssertionError('Fixture CSRF challenge failed: HTTP ' + str(challenge.status_code))
    response = client.post('/auth/login', json={'username': username, 'password': password},
        headers={'Origin': origin, 'X-CSRF-Token': challenge.json()['csrf_token']})
    if response.status_code != 200:
        raise AssertionError('Fixture login failed: HTTP ' + str(response.status_code))
    return response.json()['csrf_token']


class AuthenticatedTestClient(RawTestClient):
    """The legacy API tests keep exercising real auth and CSRF on every request."""
    def __init__(self, app, *args, projects=(), fixture_identity=None, **kwargs):
        from app import main
        root = Path(main.ROOT).resolve()
        temporary = Path(tempfile.gettempdir()).resolve()
        if root == temporary or not root.is_relative_to(temporary):
            raise ValueError('Legacy authenticated fixtures require their own temporary data root')
        origin = 'http://127.0.0.1'
        fixture = fixture_user(fixture_identity or str(root), origin=origin)
        kwargs.setdefault('base_url', origin)
        super().__init__(app, *args, **kwargs)
        self.fixture_principal = fixture['principal']
        self.fixture_identity = fixture_identity or str(root)
        token = http_login(self, fixture['username'], fixture['password'], origin)
        self.headers.update({'Origin': origin, 'X-CSRF-Token': token})
        self.own_projects(*projects)

    def own_projects(self, *project_ids):
        own_fixture_projects(self.fixture_principal, project_ids)


def prepare_browser_fixture(origin, identity, project_ids, *, admin=False):
    """Return only in-memory login data; caller never writes it to artifacts."""
    fixture = fixture_user(identity, origin=origin, admin=admin)
    own_fixture_projects(fixture['principal'], project_ids)
    return fixture


def browser_login(context, origin, fixture):
    response = context.request.get(origin + '/auth/csrf')
    if response.status != 200:
        raise AssertionError('Browser fixture CSRF request failed')
    response = context.request.post(origin + '/auth/login',
        data={'username': fixture['username'], 'password': fixture['password']},
        headers={'Origin': origin, 'X-CSRF-Token': response.json()['csrf_token']})
    if response.status != 200:
        raise AssertionError('Browser fixture login failed: HTTP ' + str(response.status))
    return response.json()['csrf_token']
