"""AUTH-01 acceptance against real disposable PostgreSQL, no auth bypass.

Synthetic media below exercises HTTP ownership/Range/ZIP routing only. Existing
native-media tests retain their real encode/decode/render checks separately.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from auth_support import auth_environment, prepare_database, http_login
with tempfile.TemporaryDirectory(prefix='clipforge-auth-import-') as bootstrap:
    with patch.dict(os.environ, {'CLIPFORGE_DATA_DIR': bootstrap}):
        from app import main
from app import auth, auth_db, auth_migrations
from app.auth_models import User, Workspace, Membership, Project, AuthSession, LoginAttempt
from app.presentation import Presentation
from app.state import write_json_atomic

ORIGIN = 'http://127.0.0.1'


class AuthPostgresTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='clipforge-auth-case-')
        self.root = Path(self.temporary.name)
        self.root_patch = patch.object(main, 'ROOT', self.root)
        self.root_patch.start()
        self.schema = 'auth01_test_' + secrets.token_hex(8)
        self.environment = patch.dict(os.environ, {**auth_environment(),
            'CLIPFORGE_DATABASE_SCHEMA': self.schema,
            'CLIPFORGE_AUTH_PROFILE': 'local-http', 'CLIPFORGE_AUTH_ORIGIN': ORIGIN})
        self.environment.start()
        auth_db.reset_engine()
        self.engine = prepare_database(ORIGIN)
        self.password = secrets.token_urlsafe(24)
        self.admin = auth.bootstrap_admin('fixture_admin', self.password)
        self.alice = auth.create_user('fixture_alice', self.password)
        self.bob = auth.create_user('fixture_bob', self.password)
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        # This schema was created by this case in the explicitly test-owned DB.
        if not re.fullmatch(r'auth01_test_[0-9a-f]{16}', self.schema):
            raise ValueError('Refusing to remove an unowned schema')
        with self.engine.begin() as connection:
            connection.execute(text('DROP SCHEMA "' + self.schema + '" CASCADE'))
        auth_db.reset_engine()
        self.environment.stop()
        self.root_patch.stop()
        self.temporary.cleanup()
        main.JOBS.clear()

    def client(self, user=None, *, base_url=ORIGIN):
        client = TestClient(main.app, base_url=base_url, raise_server_exceptions=False)
        self.clients.append(client)
        if user is not None:
            csrf = http_login(client, user.username, self.password, base_url)
            client.headers.update({'Origin': base_url, 'X-CSRF-Token': csrf})
        return client

    def attempt(self, client, username, password):
        challenge = client.get('/auth/csrf')
        self.assertEqual(challenge.status_code, 200)
        return client.post('/auth/login', json={'username': username, 'password': password},
            headers={'Origin': ORIGIN, 'X-CSRF-Token': challenge.json()['csrf_token']})

    def seed_project(self, owner):
        job_id, export_id = uuid.uuid4().hex, uuid.uuid4().hex
        auth.register_project(job_id, owner)
        folder = self.root / job_id
        folder.mkdir()
        payload = b'auth01 synthetic HTTP bytes; native codecs are tested elsewhere' * 8
        (folder / 'input.mp4').write_bytes(payload)
        (folder / 'clip_01.mp4').write_bytes(payload)
        write_json_atomic(folder / 'job.json', {'id': job_id, 'status': 'completed',
            'clips': [{'file': 'clip_01.mp4', 'start': 0, 'end': 2}],
            'options': Presentation().model_dump(), 'source_filename': 'private-fixture.mp4'})
        write_json_atomic(folder / 'transcript.json', [{'start': 0, 'end': 2, 'text': 'private authored fixture'}])
        export = folder / 'exports' / export_id
        export.mkdir(parents=True)
        for name, content in [('clip.mp4', payload), ('clip.srt', b'1\n00:00:00,000 --> 00:00:02,000\nfixture\n'), ('clip.vtt', b'WEBVTT\n')]:
            (export / name).write_bytes(content)
        main.persist_export(job_id, {'id': export_id, 'job_id': job_id, 'status': 'completed',
            'start': 0, 'end': 2, 'clip_file': 'clip_01.mp4', 'options': Presentation().model_dump(),
            'title': 'Synthetic owned export', 'cues': [{'start': 0, 'end': 2, 'text': 'fixture'}]})
        return job_id, export_id

    def test_users_private_workspaces_and_independent_sessions(self):
        alice, bob = self.client(self.alice), self.client(self.bob)
        self.assertEqual(alice.get('/auth/me').json()['user']['id'], self.alice.id)
        self.assertEqual(bob.get('/auth/me').json()['user']['id'], self.bob.id)
        self.assertNotEqual(self.alice.workspace_id, self.bob.workspace_id)
        self.assertTrue(alice.cookies.get('clipforge_session') != bob.cookies.get('clipforge_session'), 'Independent session identifiers')
        with Session(self.engine) as database:
            memberships = database.scalars(select(Membership)).all()
            self.assertEqual(len(memberships), 3)
            self.assertEqual(len(database.scalars(select(Workspace)).all()), 3)

    def test_passwords_argon2id_and_sessions_store_only_hashes(self):
        alice = self.client(self.alice)
        raw = alice.cookies.get('clipforge_session')
        with Session(self.engine) as database:
            user = database.get(User, self.alice.id)
            self.assertTrue(user.password_hash.startswith('$argon2id$'), 'Argon2id encoded password hash required')
            self.assertTrue(PasswordHasher().verify(user.password_hash, self.password))
            sessions = database.scalars(select(AuthSession).where(AuthSession.user_id == self.alice.id)).all()
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].token_hash == hashlib.sha256(raw.encode()).hexdigest(), 'Only session token digest is persisted')
            self.assertTrue(raw not in repr(sessions[0].__dict__), 'Raw token absent from stored session')
        public = alice.get('/auth/me').text
        self.assertTrue(self.password not in public and raw not in public and 'password_hash' not in public, 'No credentials in public user response')

    def test_login_errors_do_not_enumerate_accounts(self):
        client = self.client()
        wrong = self.attempt(client, self.alice.username, secrets.token_urlsafe(24))
        missing = self.attempt(client, 'nonexistent_user', secrets.token_urlsafe(24))
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.json(), missing.json())
        self.assertTrue(self.password not in wrong.text, 'No password echoed by login')

    def test_login_rate_limit_persists_across_clients(self):
        for _ in range(5):
            reply = self.attempt(self.client(), self.alice.username, secrets.token_urlsafe(24))
            self.assertEqual(reply.status_code, 401)
        limited = self.attempt(self.client(), self.alice.username, self.password)
        self.assertEqual(limited.status_code, 429)
        self.assertIn('retry-after', limited.headers)
        with Session(self.engine) as database:
            attempts = database.scalars(select(LoginAttempt)).all()
            self.assertGreaterEqual(len(attempts), 5)
            self.assertTrue(all(self.alice.username not in repr(item.__dict__) and self.password not in repr(item.__dict__) for item in attempts), 'Rate-limit storage contains only digests')

    def test_csrf_login_requires_challenge_header_and_origin(self):
        client = self.client()
        no_challenge = client.post('/auth/login', json={'username': self.alice.username, 'password': self.password}, headers={'Origin': ORIGIN})
        self.assertEqual(no_challenge.status_code, 403)
        challenge = client.get('/auth/csrf').json()['csrf_token']
        for headers in [{'X-CSRF-Token': challenge}, {'Origin': 'http://example.invalid', 'X-CSRF-Token': challenge}, {'Origin': ORIGIN, 'X-CSRF-Token': 'incorrect'}]:
            result = client.post('/auth/login', json={'username': self.alice.username, 'password': self.password}, headers=headers)
            self.assertEqual(result.status_code, 403)

    def test_authenticated_mutations_require_session_csrf(self):
        client = self.client(self.alice)
        csrf = client.headers.pop('X-CSRF-Token')
        self.assertEqual(client.post('/auth/logout').status_code, 403)
        client.headers['X-CSRF-Token'] = csrf
        client.headers['Origin'] = 'http://example.invalid'
        self.assertEqual(client.post('/auth/logout').status_code, 403)
        client.headers['Origin'] = ORIGIN
        self.assertEqual(client.post('/auth/logout').status_code, 200)
        self.assertEqual(client.get('/auth/me').status_code, 401)

    def test_login_rotates_and_revokes_presented_session(self):
        client = self.client(self.alice)
        old = client.cookies.get('clipforge_session')
        response = self.attempt(client, self.alice.username, self.password)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(old != client.cookies.get('clipforge_session'), 'Login must rotate the session identifier')
        replay = self.client()
        replay.cookies.set('clipforge_session', old)
        self.assertEqual(replay.get('/auth/me').status_code, 401)

    def test_expired_and_revoked_sessions_are_rejected(self):
        expired = self.client(self.alice)
        with Session(self.engine) as database, database.begin():
            database.execute(update(AuthSession).where(AuthSession.user_id == self.alice.id).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        self.assertEqual(expired.get('/auth/me').status_code, 401)
        revoked = self.client(self.bob)
        with Session(self.engine) as database, database.begin():
            database.execute(update(AuthSession).where(AuthSession.user_id == self.bob.id).values(revoked_at=datetime.now(timezone.utc)))
        self.assertEqual(revoked.get('/auth/me').status_code, 401)

    def test_logout_revokes_only_current_session(self):
        first, second = self.client(self.alice), self.client(self.alice)
        self.assertEqual(first.post('/auth/logout').status_code, 200)
        self.assertEqual(first.get('/auth/me').status_code, 401)
        self.assertEqual(second.get('/auth/me').status_code, 200)

    def test_change_password_checks_current_and_revokes_all_sessions(self):
        first, second = self.client(self.alice), self.client(self.alice)
        replacement = secrets.token_urlsafe(24)
        bad = first.post('/auth/password', json={'current_password': 'wrong-current-password', 'new_password': replacement})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(second.get('/auth/me').status_code, 200)
        changed = first.post('/auth/password', json={'current_password': self.password, 'new_password': replacement})
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(first.get('/auth/me').status_code, 401)
        self.assertEqual(second.get('/auth/me').status_code, 401)
        self.assertEqual(self.attempt(self.client(), self.alice.username, self.password).status_code, 401)
        self.assertEqual(self.attempt(self.client(), self.alice.username, replacement).status_code, 200)

    def test_admin_creates_and_deactivates_user_with_session_revocation(self):
        admin = self.client(self.admin)
        password = secrets.token_urlsafe(24)
        created = admin.post('/auth/users', json={'username': 'created_by_admin', 'password': password})
        self.assertEqual(created.status_code, 201)
        public = created.json().get('user', created.json())
        user_id = public['id']
        first, second = self.client(), self.client()
        http_login(first, 'created_by_admin', password, ORIGIN)
        http_login(second, 'created_by_admin', password, ORIGIN)
        disabled = admin.post(f'/auth/users/{user_id}/deactivate')
        self.assertEqual(disabled.status_code, 200)
        self.assertEqual(first.get('/auth/me').status_code, 401)
        self.assertEqual(second.get('/auth/me').status_code, 401)
        rejected = self.attempt(self.client(), 'created_by_admin', password)
        missing = self.attempt(self.client(), 'missing_identity', password)
        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(rejected.json(), missing.json())

    def test_user_admin_permissions_and_extra_role_fields_rejected(self):
        alice = self.client(self.alice)
        self.assertEqual(alice.get('/auth/users').status_code, 403)
        self.assertEqual(alice.post('/auth/users', json={'username': 'unauthorized', 'password': secrets.token_urlsafe(24)}).status_code, 403)
        self.assertEqual(alice.post(f'/auth/users/{self.bob.id}/deactivate').status_code, 403)
        admin = self.client(self.admin)
        for field, value in [('is_admin', True), ('role', 'admin'), ('owner_id', self.admin.id), ('workspace_id', self.admin.workspace_id)]:
            response = admin.post('/auth/users', json={'username': 'role_injection', 'password': secrets.token_urlsafe(24), field: value})
            self.assertEqual(response.status_code, 422)
        self.assertEqual(alice.post('/auth/register', json={}).status_code, 404)

    def test_admin_has_no_implicit_private_content_access(self):
        job, _ = self.seed_project(self.alice)
        admin, alice = self.client(self.admin), self.client(self.alice)
        self.assertEqual(alice.get(f'/jobs/{job}').status_code, 200)
        self.assertEqual(admin.get(f'/jobs/{job}').status_code, 404)
        self.assertEqual(admin.get('/projects').json()['total'], 0)
        self.assertEqual(admin.get('/ops/summary').json()['projects'], [])

    def test_cross_user_all_artifacts_and_mutations_denied(self):
        job, export = self.seed_project(self.alice)
        alice, bob = self.client(self.alice), self.client(self.bob)
        reviewed = alice.put(f'/jobs/{job}/exports/{export}/review', json={'status': 'approved', 'revision': 0, 'title': 'Fixture', 'notes': ''})
        self.assertEqual(reviewed.status_code, 200)
        packaged = alice.post(f'/jobs/{job}/deliveries', json={'selections': [{'export_id': export, 'review_revision': 1}]})
        self.assertEqual(packaged.status_code, 201)
        delivery = packaged.json()['id']
        paths = [f'/jobs/{job}', f'/jobs/{job}/source', f'/jobs/{job}/workspace',
            f'/jobs/{job}/clips/clip_01.mp4', f'/jobs/{job}/clips/clip_01.mp4/editor',
            f'/jobs/{job}/clips/clip_01.mp4/subtitles/srt', f'/jobs/{job}/clips/clip_01.mp4/subtitles/vtt',
            f'/projects/{job}/thumbnail', f'/jobs/{job}/drafts', f'/jobs/{job}/drafts/{uuid.uuid4().hex}',
            f'/jobs/{job}/exports', f'/jobs/{job}/exports/{export}',
            f'/jobs/{job}/exports/{export}/review', f'/jobs/{job}/exports/{export}/files/clip.mp4',
            f'/jobs/{job}/exports/{export}/files/clip.srt', f'/jobs/{job}/exports/{export}/files/clip.vtt',
            f'/jobs/{job}/deliveries', f'/jobs/{job}/deliveries/{delivery}/file',
            f'/jobs/{job}/operations', f'/jobs/{job}/selections', f'/jobs/{job}/selections/context']
        for path in paths:
            with self.subTest(route=path):
                self.assertEqual(bob.get(path).status_code, 404)
                self.assertEqual(bob.get(path, headers={'Range': 'bytes=0-10'}).status_code, 404)
        partial = alice.get(f'/jobs/{job}/source', headers={'Range': 'bytes=0-10'})
        self.assertEqual(partial.status_code, 206)
        self.assertIn('no-store', partial.headers.get('cache-control', ''))
        self.assertIn('cookie', partial.headers.get('vary', '').lower())
        package = alice.get(f'/jobs/{job}/deliveries/{delivery}/file')
        self.assertEqual(package.status_code, 200)
        self.assertIn('no-store', package.headers.get('cache-control', ''))
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            self.assertTrue(archive.namelist())
        self.assertEqual(bob.patch(f'/projects/{job}', json={'title': 'intrusion'}).status_code, 404)
        self.assertEqual(bob.put(f'/jobs/{job}/exports/{export}/review', json={'revision': 1, 'status': 'rejected', 'title': 'intrusion', 'notes': ''}).status_code, 404)
        self.assertEqual(bob.post(f'/jobs/{job}/deliveries', json={'selections': [{'export_id': export, 'review_revision': 1}]}).status_code, 404)
        self.assertEqual(bob.get('/projects').json()['total'], 0)
        self.assertEqual(bob.get('/ops/summary').json()['projects'], [])

    def test_ownerless_legacy_project_remains_inaccessible_after_login(self):
        orphan = uuid.uuid4().hex
        write_json_atomic(self.root / orphan / 'job.json', {'id': orphan, 'status': 'completed', 'clips': []})
        before = (self.root / orphan / 'job.json').read_bytes()
        for user in [self.alice, self.bob, self.admin]:
            client = self.client(user)
            self.assertEqual(client.get(f'/jobs/{orphan}').status_code, 404)
            self.assertEqual(client.get('/projects').json()['total'], 0)
        with Session(self.engine) as database:
            self.assertIsNone(database.get(Project, orphan))
        self.assertEqual((self.root / orphan / 'job.json').read_bytes(), before)

    def test_upload_ownership_is_server_assigned_and_client_owner_fields_rejected(self):
        alice, bob = self.client(self.alice), self.client(self.bob)
        for field, value in [('owner_id', self.bob.id), ('workspace_id', self.bob.workspace_id), ('role', 'admin')]:
            with patch.object(main, 'process'):
                reply = alice.post('/jobs', files={'file': ('fixture.mp4', b'synthetic', 'video/mp4')}, data={field: value})
            self.assertEqual(reply.status_code, 422)
        with patch.object(main, 'process'):
            uploaded = alice.post('/jobs', files={'file': ('fixture.mp4', b'synthetic', 'video/mp4')}, data={'processing_mode': 'manual'})
        self.assertEqual(uploaded.status_code, 202)
        job = uploaded.json()['id']
        self.assertEqual(alice.get(f'/jobs/{job}').status_code, 200)
        self.assertEqual(bob.get(f'/jobs/{job}').status_code, 404)
        with Session(self.engine) as database:
            resource = database.get(Project, job)
            self.assertEqual(resource.owner_id, self.alice.id)
            self.assertEqual(resource.workspace_id, self.alice.workspace_id)

    def test_custom_templates_private_to_workspace(self):
        alice, bob, admin = self.client(self.alice), self.client(self.bob), self.client(self.admin)
        created = alice.post('/templates', json={'name': 'Private preset', 'options': Presentation().model_dump()})
        self.assertEqual(created.status_code, 201)
        template_id = created.json()['id']
        self.assertEqual(alice.get('/templates/' + template_id).status_code, 200)
        for client in [bob, admin]:
            self.assertEqual(client.get('/templates/' + template_id).status_code, 404)
            self.assertFalse(any(item['id'] == template_id for item in client.get('/templates').json()['templates']))

    def test_secure_cookie_profile_and_local_exception_explicit(self):
        local = self.client(self.alice)
        local_response = self.attempt(local, self.alice.username, self.password)
        local_cookie = next(value for value in local_response.headers.get_list('set-cookie') if value.startswith('clipforge_session='))
        self.assertIn('HttpOnly', local_cookie)
        self.assertIn('SameSite=', local_cookie)
        self.assertNotIn('; Secure', local_cookie)
        with patch.dict(os.environ, {'CLIPFORGE_AUTH_PROFILE': 'https', 'CLIPFORGE_AUTH_ORIGIN': 'https://localhost'}):
            secured = self.client(base_url='https://localhost')
            challenge = secured.get('/auth/csrf')
            response = secured.post('/auth/login', json={'username': self.alice.username, 'password': self.password},
                headers={'Origin': 'https://localhost', 'X-CSRF-Token': challenge.json()['csrf_token']})
            self.assertEqual(response.status_code, 200)
            cookie = next(value for value in response.headers.get_list('set-cookie') if value.startswith('clipforge_session='))
            self.assertIn('; Secure', cookie)
            self.assertIn('HttpOnly', cookie)

    def test_bootstrap_admin_is_explicit_and_cannot_be_repeated(self):
        with self.assertRaises(Exception) as raised:
            auth.bootstrap_admin('second_bootstrap', secrets.token_urlsafe(24))
        self.assertTrue(self.password not in str(raised.exception), 'Bootstrap failure must not disclose a password')
        with Session(self.engine) as database:
            self.assertEqual(len(database.scalars(select(User).where(User.is_admin.is_(True))).all()), 1)

    def test_users_persist_after_engine_and_application_restart(self):
        client = self.client(self.alice)
        before = client.get('/auth/me').json()['user']
        auth_db.reset_engine()
        # Re-enter the real app lifespan to exercise candidate startup against
        # persisted PostgreSQL; the browser acceptance also restarts Uvicorn.
        with TestClient(main.app, base_url=ORIGIN) as restarted:
            http_login(restarted, self.alice.username, self.password, ORIGIN)
            self.assertEqual(restarted.get('/auth/me').json()['user'], before)

    def test_migration_is_idempotent_and_reports_actual_revision(self):
        first = auth_migrations.upgrade(self.engine)
        second = auth_migrations.upgrade(self.engine)
        with Session(self.engine) as database:
            self.assertEqual(len(database.scalars(select(User)).all()), 3)
        self.assertEqual(first, {'status': 'current', 'revision': 'auth02_0002'})
        self.assertEqual(second, first)
        with self.engine.connect() as connection:
            names = set(connection.execute(text('SELECT tablename FROM pg_tables WHERE schemaname=:schema'), {'schema': self.schema}).scalars())
        self.assertEqual(names, {'auth_users', 'auth_workspaces', 'auth_memberships',
            'auth_projects', 'auth_sessions', 'auth_challenges', 'auth_login_attempts', 'auth_schema_migrations',
            'auth_recovery_codes', 'auth_audit_events', 'auth_security_attempts'})

    def test_unknown_migration_revision_fails_without_mutating_users(self):
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE auth_schema_migrations SET revision='future_auth_99' WHERE revision='auth02_0002'"))
        with self.assertRaises(auth_migrations.MigrationError):
            auth_migrations.upgrade(self.engine)
        with Session(self.engine) as database:
            self.assertEqual(len(database.scalars(select(User)).all()), 3)
            revisions = database.execute(text('SELECT revision FROM auth_schema_migrations ORDER BY revision')).scalars().all()
        self.assertEqual(revisions, ['auth01_0001', 'future_auth_99'])

    def test_database_failure_returns_controlled_response_and_no_credentials(self):
        client = self.client(self.alice)
        with patch.dict(os.environ, {'CLIPFORGE_DATABASE_SCHEMA': 'auth01_test_nonexistent_' + secrets.token_hex(4)}):
            unavailable = client.get('/projects')
        self.assertEqual(unavailable.status_code, 503)
        self.assertTrue(self.password not in unavailable.text and 'postgresql' not in unavailable.text.lower(), 'Storage error must not expose connection details')

    def test_anonymous_resource_access_rejected_before_file_reads(self):
        job, export = self.seed_project(self.alice)
        client = self.client()
        with patch.object(main, 'load_job', side_effect=AssertionError('Anonymous request must not inspect private project')):
            for path in ['/projects', '/ops/summary', '/auth/users', f'/jobs/{job}',
                         f'/jobs/{job}/source', f'/jobs/{job}/exports/{export}/files/clip.mp4']:
                with self.subTest(route=path):
                    self.assertEqual(client.get(path).status_code, 401)

    def test_session_csrf_from_another_user_is_rejected(self):
        alice, bob = self.client(self.alice), self.client(self.bob)
        result = alice.post('/auth/logout', headers={'X-CSRF-Token': bob.headers['X-CSRF-Token']})
        self.assertEqual(result.status_code, 403)
        self.assertEqual(alice.get('/auth/me').status_code, 200)

    def test_anonymous_upload_body_not_consumed_before_authentication(self):
        received, messages = [], []
        async def receive():
            received.append(True)
            return {'type': 'http.request', 'body': b'private multipart payload', 'more_body': False}
        async def send(message):
            messages.append(message)
        scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
            'method': 'POST', 'scheme': 'http', 'path': '/jobs', 'raw_path': b'/jobs',
            'query_string': b'', 'root_path': '', 'server': ('127.0.0.1', 80),
            'client': ('127.0.0.1', 12345),
            'headers': [(b'host', b'127.0.0.1'), (b'origin', ORIGIN.encode()),
                        (b'content-type', b'multipart/form-data; boundary=fixture')]}
        asyncio.run(main.app(scope, receive, send))
        self.assertEqual(next(item for item in messages if item['type'] == 'http.response.start')['status'], 401)
        self.assertEqual(received, [], 'Authentication must precede reading untrusted upload bodies')


if __name__ == '__main__':
    unittest.main()
