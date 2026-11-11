"""AUTH-02 contracts over real, explicitly disposable PostgreSQL schemas.

Secrets and recovery codes remain in memory and never appear in assertion
messages. Clock offsets, historical DDL and audit-trigger failures are authored
fixtures; authentication, transactions, row locks and HTTP routes remain real.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
from http.cookies import CookieError, SimpleCookie
import io
import json
import logging
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from auth_support import auth_environment, http_login, prepare_database

with tempfile.TemporaryDirectory(prefix='clipforge-auth02-import-') as bootstrap:
    with patch.dict(os.environ, {'CLIPFORGE_DATA_DIR': bootstrap}):
        from app import main
from app import auth, auth_db, auth_migrations
from app.auth_models import AuditEvent, AuthSession, Project, RecoveryCode, SecurityAttempt, User


ORIGIN = 'http://127.0.0.1'
AUDIT_FIELDS = {'actor_id', 'target_id', 'action', 'created_at', 'result', 'correlation_id'}
FROZEN_AUTH01_DDL_SHA256 = '523b1fa864b7e9814e00962fa046eb7f6094c3512eb98824f27757658e1e8c5e'


class RecoveryPostgresTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='clipforge-auth02-case-')
        self.root = Path(self.temporary.name)
        self.root_patch = patch.object(main, 'ROOT', self.root)
        self.root_patch.start()
        self.schema = 'auth01_test_' + secrets.token_hex(8)
        self.environment = patch.dict(os.environ, {**auth_environment(),
            'CLIPFORGE_DATABASE_SCHEMA': self.schema, 'CLIPFORGE_AUTH_PROFILE': 'local-http',
            'CLIPFORGE_AUTH_ORIGIN': ORIGIN})
        self.environment.start()
        auth_db.reset_engine()
        self.engine = prepare_database(ORIGIN)
        self.assertEqual(self.engine.dialect.name, 'postgresql')
        self.password = secrets.token_urlsafe(24)
        self.new_password = secrets.token_urlsafe(24)
        self.admin = auth.bootstrap_admin('recovery_admin', self.password)
        self.alice = auth.create_user('recovery_alice', self.password)
        self.bob = auth.create_user('recovery_bob', self.password)
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        if not re.fullmatch(r'auth01_test_[0-9a-f]{16}', self.schema):
            raise ValueError('Refusing cleanup of an unowned fixture schema')
        with self.engine.begin() as connection:
            connection.execute(text('DROP SCHEMA "' + self.schema + '" CASCADE'))
        auth_db.reset_engine()
        self.environment.stop()
        self.root_patch.stop()
        self.temporary.cleanup()
        main.JOBS.clear()

    def client(self, user=None, password=None):
        client = TestClient(main.app, base_url=ORIGIN, raise_server_exceptions=False)
        self.clients.append(client)
        if user is not None:
            csrf = http_login(client, user.username, password or self.password, ORIGIN)
            client.headers.update({'Origin': ORIGIN, 'X-CSRF-Token': csrf})
        return client

    def issue(self, *, admin=None, target=None):
        client = admin or self.client(self.admin)
        response = client.post('/auth/admin/users/' + (target or self.alice.id) + '/recovery',
                               json={'current_password': self.password})
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertTrue(set(body) == {'recovery_code', 'expires_at'}, 'Issuance exposes only its documented fields')
        code = body['recovery_code']
        self.assertTrue(isinstance(code, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', code) is not None,
                        'Recovery code must encode 32 random bytes')
        return code, body['expires_at']

    def recover(self, code, password=None, *, client=None):
        client = client or self.client()
        challenge = client.get('/auth/csrf')
        self.assertEqual(challenge.status_code, 200)
        return client.post('/auth/recover', json={'code': code, 'new_password': password or self.new_password},
                           headers={'Origin': ORIGIN, 'X-CSRF-Token': challenge.json()['csrf_token']})

    def events(self, action=None):
        with Session(self.engine) as database:
            query = select(AuditEvent)
            if action is not None:
                query = query.where(AuditEvent.action == action)
            return database.scalars(query).all()

    def code_row(self, code):
        with Session(self.engine) as database:
            return database.get(RecoveryCode, auth.token_hash(code))

    def assert_no_secrets(self, material, *values):
        self.assertTrue(all(value not in material for value in values), 'Sensitive fixture values must remain private')

    def seed_client_attempts(self, purpose, count):
        with Session(self.engine) as database, database.begin():
            database.add_all(SecurityAttempt(purpose=purpose, identity_hash=auth.token_hash('other:' + str(index)),
                client_hash=auth.token_hash('client:testclient'), attempted_at=auth.now_utc()) for index in range(count))

    def reject_audit_inserts(self, action):
        if action not in {'recovery.issued', 'recovery.consumed'}:
            raise ValueError('Only authored audit fault fixtures are supported')
        with self.engine.begin() as connection:
            connection.execute(text("CREATE FUNCTION qa_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic audit insert failure'; END; $$"))
            connection.execute(text("CREATE TRIGGER qa_audit_failure BEFORE INSERT ON auth_audit_events FOR EACH ROW WHEN (NEW.action = '" + action + "') EXECUTE FUNCTION qa_reject_audit()"))

    def remove_audit_failure(self):
        with self.engine.begin() as connection:
            connection.execute(text('DROP TRIGGER qa_audit_failure ON auth_audit_events'))
            connection.execute(text('DROP FUNCTION qa_reject_audit()'))

    def test_issuance_requires_authenticated_administrator(self):
        route = '/auth/admin/users/' + self.alice.id + '/recovery'
        self.assertEqual(self.client().post(route, json={'current_password': self.password}, headers={'Origin': ORIGIN}).status_code, 401)
        self.assertEqual(self.client(self.bob).post(route, json={'current_password': self.password}).status_code, 403)
        with Session(self.engine) as database:
            self.assertEqual(database.scalar(select(func.count()).select_from(RecoveryCode)), 0)

    def test_issuance_requires_origin_and_session_csrf(self):
        admin = self.client(self.admin)
        route = '/auth/admin/users/' + self.alice.id + '/recovery'
        token = admin.headers.pop('X-CSRF-Token')
        self.assertEqual(admin.post(route, json={'current_password': self.password}).status_code, 403)
        admin.headers['X-CSRF-Token'] = token
        for origin in ('http://example.invalid', None):
            if origin is None:
                admin.headers.pop('Origin')
            else:
                admin.headers['Origin'] = origin
            self.assertEqual(admin.post(route, json={'current_password': self.password}).status_code, 403)
        with Session(self.engine) as database:
            self.assertEqual(database.scalar(select(func.count()).select_from(RecoveryCode)), 0)

    def test_issuance_reauth_and_request_validation_fail_without_code(self):
        admin = self.client(self.admin)
        route = '/auth/admin/users/' + self.alice.id + '/recovery'
        wrong = admin.post(route, json={'current_password': 'authored-incorrect-current'})
        self.assertEqual(wrong.status_code, 400)
        for body in ({}, {'current_password': self.password, 'target_id': self.bob.id}, {'current_password': 17}):
            self.assertEqual(admin.post(route, json=body).status_code, 422)
        with Session(self.engine) as database:
            self.assertEqual(database.scalar(select(func.count()).select_from(RecoveryCode)), 0)
        failed = self.events('recovery.issued')
        self.assertTrue(any(item.result == 'failure' and item.actor_id == self.admin.id and item.target_id == self.alice.id for item in failed))

    def test_issuance_rejects_admin_inactive_missing_and_bad_targets(self):
        admin = self.client(self.admin)
        self.assertEqual(admin.post('/auth/users/' + self.bob.id + '/deactivate').status_code, 200)
        for target, status in ((self.admin.id, 409), (self.bob.id, 409), (uuid.uuid4().hex, 404), ('invalid', 404)):
            with self.subTest(expected_status=status):
                response = admin.post('/auth/admin/users/' + target + '/recovery', json={'current_password': self.password})
                self.assertEqual(response.status_code, status)
                self.assertTrue('recovery_code' not in response.text, 'Rejected issuance cannot expose a code')

    def test_issued_code_has_32_bytes_hash_only_and_exact_fifteen_minute_lifetime(self):
        admin = self.client(self.admin)
        clock = auth.now_utc().replace(microsecond=0)
        with patch.object(auth, 'now_utc', return_value=clock):
            code, expiry = self.issue(admin=admin)
        row = self.code_row(code)
        self.assertTrue(row is not None and row.token_hash == hashlib.sha256(code.encode()).hexdigest(), 'Only recovery-code digest persists')
        self.assertEqual(row.user_id, self.alice.id)
        self.assertEqual(row.issued_by_id, self.admin.id)
        self.assertEqual(row.created_at, clock)
        self.assertEqual(row.expires_at, clock + timedelta(minutes=15))
        self.assertTrue(isinstance(expiry, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', expiry) is not None,
                        'Expiry must be a UTC ISO timestamp')
        self.assertEqual(datetime.fromisoformat(expiry.replace('Z', '+00:00')), row.expires_at)
        self.assertIsNone(row.consumed_at)
        self.assertIsNone(row.revoked_at)
        self.assert_no_secrets(repr(row.__dict__), code, self.password, self.new_password)

    def test_second_issue_revokes_preceding_code_without_changing_password_or_sessions(self):
        admin, existing = self.client(self.admin), self.client(self.alice)
        first, _ = self.issue(admin=admin)
        second, _ = self.issue(admin=admin)
        self.assertTrue(first != second, 'Replacement code must be newly generated')
        self.assertIsNotNone(self.code_row(first).revoked_at)
        self.assertIsNone(self.code_row(second).revoked_at)
        self.assertEqual(existing.get('/auth/me').status_code, 200)
        self.assertEqual(self.recover(first).status_code, 400)
        self.assertEqual(self.recover(second).status_code, 200)

    def test_issue_limit_persists_across_admin_clients_and_engine_restart(self):
        admin = self.client(self.admin)
        for _ in range(5):
            self.issue(admin=admin)
        auth_db.reset_engine()
        limited = self.client(self.admin).post('/auth/admin/users/' + self.alice.id + '/recovery', json={'current_password': self.password})
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers.get('retry-after'), '900')
        with Session(self.engine) as database:
            self.assertEqual(database.scalar(select(func.count()).select_from(RecoveryCode)), 5)
        self.assertTrue(any(item.result == 'failure' for item in self.events('recovery.issued')))

    def test_issue_client_limit_counts_distinct_identities_at_exact_boundary(self):
        self.seed_client_attempts('recovery_issue', 29)
        admin = self.client(self.admin)
        self.issue(admin=admin)
        blocked = admin.post('/auth/admin/users/' + self.alice.id + '/recovery', json={'current_password': self.password})
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers.get('retry-after'), '900')

    def test_valid_recovery_changes_argon2_password_revokes_every_session_and_requires_login(self):
        first, second = self.client(self.alice), self.client(self.alice)
        code, _ = self.issue()
        anonymous = self.client()
        result = self.recover(code, client=anonymous)
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json() == {'status': 'password_recovered', 'login_required': True}, 'Recovery response contains only status and login requirement')
        session_cookies = []
        for header in result.headers.get_list('set-cookie'):
            cookie = SimpleCookie()
            try:
                cookie.load(header)
            except CookieError:
                raise AssertionError('Recovery cookie headers must be valid') from None
            if auth.SESSION_COOKIE in cookie:
                session_cookies.append(cookie[auth.SESSION_COOKIE])
        self.assertTrue(bool(session_cookies), 'Recovery must explicitly clear the session cookie')
        for cookie in session_cookies:
            self.assertTrue(cookie.value == '' and cookie['max-age'] == '0', 'Only an empty, zero-age session deletion cookie is permitted')
            try:
                expiration = parsedate_to_datetime(cookie['expires'])
            except (TypeError, ValueError, OverflowError):
                raise AssertionError('Session deletion must carry a valid expiration') from None
            self.assertTrue(isinstance(expiration, datetime) and expiration.tzinfo is not None and expiration <= datetime.now(timezone.utc),
                            'Session deletion expiration must not preserve a future session')
        for client in (anonymous, first, second):
            self.assertEqual(client.get('/auth/me').status_code, 401)
        with Session(self.engine) as database:
            user = database.get(User, self.alice.id)
            self.assertTrue(user.password_hash.startswith('$argon2id$') and PasswordHasher().verify(user.password_hash, self.new_password), 'Recovered password uses Argon2id')
            self.assertTrue(all(row.revoked_at is not None for row in database.scalars(select(AuthSession).where(AuthSession.user_id == self.alice.id))))
        self.assertEqual(self.client(self.alice, self.new_password).get('/auth/me').status_code, 200)
        row = self.code_row(code)
        self.assertIsNotNone(row.consumed_at)

    def test_existing_session_csrf_recovers_another_user_without_impersonation(self):
        caller, old_target = self.client(self.bob), self.client(self.alice)
        code, _ = self.issue()
        response = caller.post('/auth/recover', json={'code': code, 'new_password': self.new_password})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json() == {'status': 'password_recovered', 'login_required': True}, 'Recovery requires a fresh login')
        self.assertEqual(caller.get('/auth/me').status_code, 401)
        self.assertEqual(old_target.get('/auth/me').status_code, 401)
        self.assertEqual(self.client(self.bob).get('/auth/me').json()['user']['id'], self.bob.id)
        target = self.client(self.alice, self.new_password).get('/auth/me').json()['user']
        self.assertEqual((target['id'], target['workspace_id']), (self.alice.id, self.alice.workspace_id))
        events = [item for item in self.events('recovery.consumed') if item.result == 'success']
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0].actor_id, events[0].target_id), (self.bob.id, self.alice.id))

    def test_recovery_requires_preauth_challenge_csrf_and_exact_origin(self):
        code, _ = self.issue()
        client = self.client()
        body = {'code': code, 'new_password': self.new_password}
        self.assertEqual(client.post('/auth/recover', json=body, headers={'Origin': ORIGIN}).status_code, 403)
        csrf = client.get('/auth/csrf').json()['csrf_token']
        for headers in ({'X-CSRF-Token': csrf}, {'Origin': 'http://example.invalid', 'X-CSRF-Token': csrf},
                        {'Origin': ORIGIN, 'X-CSRF-Token': 'incorrect'}):
            self.assertEqual(client.post('/auth/recover', json=body, headers=headers).status_code, 403)
        self.assertIsNone(self.code_row(code).consumed_at)

    def test_malformed_code_and_new_password_validation_are_generic_and_bounded(self):
        code, _ = self.issue()
        client = self.client()
        csrf = client.get('/auth/csrf').json()['csrf_token']
        headers = {'Origin': ORIGIN, 'X-CSRF-Token': csrf}
        invalid = [{'code': value, 'new_password': self.new_password} for value in ('', 'X' * 129, 3, None)]
        invalid += [{'code': code, 'new_password': value} for value in ('short', 'X' * 129, ' ' * 12, 8)]
        invalid += [{'code': code, 'new_password': self.new_password, 'user_id': self.bob.id}]
        for body in invalid:
            response = client.post('/auth/recover', json=body, headers=headers)
            self.assertEqual(response.status_code, 422)
            self.assert_no_secrets(response.text, code, self.password, self.new_password)
        self.assertIsNone(self.code_row(code).consumed_at)

    def test_unknown_and_short_codes_return_identical_generic_errors(self):
        unknown, short = self.recover(secrets.token_urlsafe(32)), self.recover('short')
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(short.status_code, 400)
        self.assertTrue(unknown.json() == short.json(), 'Invalid code responses must not enumerate state')
        self.assertTrue(all(item.target_id is None and item.actor_id is None for item in self.events('recovery.consumed')))

    def test_expiry_boundary_rejects_equal_timestamp_and_accepts_prior_microsecond(self):
        admin = self.client(self.admin)
        clock = auth.now_utc()
        with patch.object(auth, 'now_utc', return_value=clock):
            first, _ = self.issue(admin=admin)
        with patch.object(auth, 'now_utc', return_value=clock + timedelta(minutes=15) - timedelta(microseconds=1)):
            self.assertEqual(self.recover(first).status_code, 200)
        with patch.object(auth, 'now_utc', return_value=clock):
            second, _ = self.issue(admin=admin)
        with patch.object(auth, 'now_utc', return_value=clock + timedelta(minutes=15)):
            self.assertEqual(self.recover(second).status_code, 400)
        self.assertIsNone(self.code_row(second).consumed_at)

    def test_expired_code_is_not_consumed_and_its_failure_is_audited(self):
        code, _ = self.issue()
        with Session(self.engine) as database, database.begin():
            database.execute(update(RecoveryCode).where(RecoveryCode.token_hash == auth.token_hash(code)).values(expires_at=auth.now_utc() - timedelta(seconds=1)))
        response = self.recover(code)
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(self.code_row(code).consumed_at)
        self.assertTrue(any(item.target_id == self.alice.id and item.result == 'failure' for item in self.events('recovery.consumed')))

    def test_code_expiring_during_real_user_row_lock_wait_is_rejected(self):
        code, _ = self.issue()
        clock = {'value': auth.now_utc()}
        expiry = clock['value'] + timedelta(seconds=1)
        with Session(self.engine) as database, database.begin():
            database.execute(update(RecoveryCode).where(RecoveryCode.token_hash == auth.token_hash(code)).values(expires_at=expiry))
        lock_requested = threading.Event()
        original_lock = auth._lock_users

        def observed_lock(database, *user_ids):
            if self.alice.id in user_ids:
                lock_requested.set()
            return original_lock(database, *user_ids)

        with self.engine.connect() as locker:
            transaction = locker.begin()
            locker.execute(select(User).where(User.id == self.alice.id).with_for_update())
            with patch.object(auth, 'now_utc', side_effect=lambda: clock['value']), \
                    patch.object(auth, '_lock_users', side_effect=observed_lock), ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.recover, code)
                try:
                    self.assertTrue(lock_requested.wait(timeout=10), 'Recovery must reach real PostgreSQL user lock')
                    self.assertFalse(future.done(), 'Recovery cannot finish while the fixture owns its target row lock')
                    clock['value'] = expiry
                finally:
                    transaction.rollback()
                response = future.result(timeout=20)
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(self.code_row(code).consumed_at)

    def test_revoked_code_returns_same_error_as_unknown(self):
        code, _ = self.issue()
        with Session(self.engine) as database, database.begin():
            database.execute(update(RecoveryCode).where(RecoveryCode.token_hash == auth.token_hash(code)).values(revoked_at=auth.now_utc()))
        revoked, unknown = self.recover(code), self.recover(secrets.token_urlsafe(32))
        self.assertEqual(revoked.status_code, 400)
        self.assertTrue(revoked.json() == unknown.json(), 'Revoked and unknown failures must be indistinguishable')

    def test_consumed_code_is_single_use(self):
        code, _ = self.issue()
        self.assertEqual(self.recover(code).status_code, 200)
        replay = self.recover(code, secrets.token_urlsafe(24))
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(len([item for item in self.events('recovery.consumed') if item.result == 'success']), 1)
        self.assertEqual(self.client(self.alice, self.new_password).get('/auth/me').status_code, 200)

    def test_code_for_newly_inactive_user_fails_without_password_change(self):
        code, _ = self.issue()
        self.assertEqual(self.client(self.admin).post('/auth/users/' + self.alice.id + '/deactivate').status_code, 200)
        self.assertEqual(self.recover(code).status_code, 400)
        with Session(self.engine) as database:
            self.assertTrue(PasswordHasher().verify(database.get(User, self.alice.id).password_hash, self.password), 'Rejected code cannot replace stored password')

    def test_code_for_user_promoted_to_admin_cannot_be_consumed(self):
        code, _ = self.issue()
        with Session(self.engine) as database, database.begin():
            database.execute(update(User).where(User.id == self.alice.id).values(is_admin=True))
        self.assertEqual(self.recover(code).status_code, 400)
        self.assertIsNone(self.code_row(code).consumed_at)

    def test_concurrent_recovery_accepts_exactly_one_transaction(self):
        code, _ = self.issue()
        clients = [self.client(), self.client()]
        passwords = [secrets.token_urlsafe(24), secrets.token_urlsafe(24)]
        tokens = [client.get('/auth/csrf').json()['csrf_token'] for client in clients]
        barrier = threading.Barrier(2)

        def consume(index):
            barrier.wait(timeout=10)
            return clients[index].post('/auth/recover', json={'code': code, 'new_password': passwords[index]},
                headers={'Origin': ORIGIN, 'X-CSRF-Token': tokens[index]}).status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(consume, (0, 1)))
        self.assertEqual(sorted(statuses), [200, 400])
        winner = statuses.index(200)
        with Session(self.engine) as database:
            self.assertTrue(PasswordHasher().verify(database.get(User, self.alice.id).password_hash, passwords[winner]), 'Only winning transaction sets the password')
        self.assertEqual(len([item for item in self.events('recovery.consumed') if item.result == 'success']), 1)

    def test_consume_limit_is_persistent_and_separate_from_issue(self):
        code, _ = self.issue()
        unknown = secrets.token_urlsafe(32)
        for _ in range(5):
            self.assertEqual(self.recover(unknown).status_code, 400)
        auth_db.reset_engine()
        limited = self.recover(unknown)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers.get('retry-after'), '900')
        self.assertEqual(self.recover(code).status_code, 200)
        with Session(self.engine) as database:
            self.assertEqual(database.scalar(select(func.count()).select_from(SecurityAttempt).where(SecurityAttempt.purpose == 'recovery_consume')), 6)

    def test_consume_client_rate_limit_keeps_password_and_code_on_rejection(self):
        code, _ = self.issue()
        self.seed_client_attempts('recovery_consume', 29)
        self.assertEqual(self.recover(secrets.token_urlsafe(32)).status_code, 400)
        rejected = self.recover(code)
        self.assertEqual(rejected.status_code, 429)
        self.assertEqual(rejected.headers.get('retry-after'), '900')
        self.assertIsNone(self.code_row(code).consumed_at)
        with Session(self.engine) as database:
            self.assertTrue(PasswordHasher().verify(database.get(User, self.alice.id).password_hash, self.password), 'Rate rejection leaves the password unchanged')

    def test_password_change_limits_persist_without_session_revocation_on_failure(self):
        alice = self.client(self.alice)
        for _ in range(5):
            self.assertEqual(alice.post('/auth/password', json={'current_password': 'authored-incorrect', 'new_password': self.new_password}).status_code, 400)
        auth_db.reset_engine()
        limited = alice.post('/auth/password', json={'current_password': self.password, 'new_password': self.new_password})
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers.get('retry-after'), '900')
        self.assertEqual(alice.get('/auth/me').status_code, 200)

    def test_rate_limit_storage_and_audit_do_not_persist_raw_credentials(self):
        code, _ = self.issue()
        self.assertEqual(self.recover(code).status_code, 200)
        with Session(self.engine) as database:
            material = repr([item.__dict__ for item in database.scalars(select(SecurityAttempt))])
            material += repr([item.__dict__ for item in database.scalars(select(AuditEvent))])
            self.assert_no_secrets(material, code, self.password, self.new_password)
            self.assertTrue(all(re.fullmatch(r'[0-9a-f]{64}', item.identity_hash) and re.fullmatch(r'[0-9a-f]{64}', item.client_hash)
                                for item in database.scalars(select(SecurityAttempt))), 'Attempt identifiers are digests')

    def test_issuance_audit_failure_rolls_back_code_and_attempt(self):
        admin = self.client(self.admin)
        self.reject_audit_inserts('recovery.issued')
        failed = admin.post('/auth/admin/users/' + self.alice.id + '/recovery', json={'current_password': self.password})
        self.assertEqual(failed.status_code, 503)
        with Session(self.engine) as database:
            self.assertEqual(database.scalar(select(func.count()).select_from(RecoveryCode)), 0)
            self.assertEqual(database.scalar(select(func.count()).select_from(SecurityAttempt).where(SecurityAttempt.purpose == 'recovery_issue')), 0)
        self.remove_audit_failure()
        self.issue(admin=admin)

    def test_consumption_audit_failure_rolls_back_password_sessions_and_code(self):
        first, second = self.client(self.alice), self.client(self.alice)
        code, _ = self.issue()
        self.reject_audit_inserts('recovery.consumed')
        self.assertEqual(self.recover(code).status_code, 503)
        self.assertIsNone(self.code_row(code).consumed_at)
        for client in (first, second):
            self.assertEqual(client.get('/auth/me').status_code, 200)
        with Session(self.engine) as database:
            self.assertTrue(PasswordHasher().verify(database.get(User, self.alice.id).password_hash, self.password), 'Audit failure rolls back password replacement')
            self.assertEqual(database.scalar(select(func.count()).select_from(SecurityAttempt).where(SecurityAttempt.purpose == 'recovery_consume')), 0)
        self.remove_audit_failure()
        self.assertEqual(self.recover(code).status_code, 200)

    def test_audit_is_admin_only_read_only_paginated_and_strictly_filtered(self):
        self.assertEqual(self.client().get('/auth/admin/audit').status_code, 401)
        self.assertEqual(self.client(self.alice).get('/auth/admin/audit').status_code, 403)
        admin = self.client(self.admin)
        self.issue(admin=admin)
        self.assertEqual(admin.post('/auth/admin/audit', json={}).status_code, 405)
        filtered = admin.get('/auth/admin/audit', params={'page': 1, 'page_size': 1, 'action': 'recovery.issued', 'target_id': self.alice.id, 'result': 'success'})
        self.assertEqual(filtered.status_code, 200)
        body = filtered.json()
        self.assertEqual(len(body['items']), 1)
        item = body['items'][0]
        self.assertTrue(set(item) == AUDIT_FIELDS, 'Audit item fields are fixed and public')
        self.assertEqual(item['action'], 'recovery.issued')
        self.assertEqual(item['target_id'], self.alice.id)
        self.assertEqual(item['actor_id'], self.admin.id)
        self.assertEqual(item['result'], 'success')
        next_page = admin.get('/auth/admin/audit', params={'page': 2, 'page_size': 1, 'action': 'recovery.issued', 'target_id': self.alice.id, 'result': 'success'})
        self.assertEqual(next_page.status_code, 200)
        self.assertTrue(next_page.json()['items'] == [], 'A filtered page past the end must be empty')
        for params in ({'page': 0}, {'page_size': 0}, {'page_size': 101}, {'action': 'unknown'}, {'result': 'unknown'}, {'target_id': 'bad'}):
            self.assertEqual(admin.get('/auth/admin/audit', params=params).status_code, 422)

    def test_audit_schema_has_no_secrets_or_private_content_and_valid_uuid_correlations(self):
        code, _ = self.issue()
        self.assertEqual(self.recover(code).status_code, 200)
        admin = self.client(self.admin)
        response = admin.get('/auth/admin/audit', params={'page_size': 100}, headers={'X-Correlation-ID': code})
        self.assertEqual(response.status_code, 200)
        self.assert_no_secrets(response.text, code, self.password, self.new_password)
        items = response.json()['items']
        for item in items:
            self.assertTrue(set(item) == AUDIT_FIELDS, 'Audit item fields are fixed and public')
            self.assertTrue(isinstance(item['correlation_id'], str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', item['correlation_id']) is not None,
                            'Audit correlation must have UUID syntax')
            self.assertEqual(uuid.UUID(item['correlation_id']).version, 4)
            self.assertTrue(isinstance(item['created_at'], str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', item['created_at']) is not None,
                            'Audit time must be UTC ISO syntax')
            self.assertIsNotNone(datetime.fromisoformat(item['created_at'].replace('Z', '+00:00')).tzinfo)
        consumed = [item for item in items if item['action'] == 'recovery.consumed' and item['result'] == 'success']
        self.assertEqual(len(consumed), 1)
        self.assertIsNone(consumed[0]['actor_id'])
        self.assertEqual(consumed[0]['target_id'], self.alice.id)
        self.assertTrue(all('password' not in name and 'token' not in name and 'code' not in name for name in AUDIT_FIELDS))

    def test_audit_records_account_password_and_recovery_success_and_failure(self):
        admin, alice = self.client(self.admin), self.client(self.alice)
        self.assertEqual(alice.post('/auth/password', json={'current_password': self.password, 'new_password': self.new_password}).status_code, 200)
        self.assertEqual(admin.post('/auth/admin/users/' + self.alice.id + '/recovery', json={'current_password': 'authored-incorrect'}).status_code, 400)
        code, _ = self.issue(admin=admin)
        self.assertEqual(self.recover(secrets.token_urlsafe(32)).status_code, 400)
        self.assertEqual(self.recover(code, secrets.token_urlsafe(24)).status_code, 200)
        self.assertEqual(admin.post('/auth/users/' + self.bob.id + '/deactivate').status_code, 200)
        events = self.events()
        self.assertEqual({item.action for item in events}, {'user.created', 'user.deactivated', 'password.changed', 'recovery.issued', 'recovery.consumed'})
        for action in ('recovery.issued', 'recovery.consumed'):
            self.assertEqual({item.result for item in events if item.action == action}, {'success', 'failure'})

    def test_recovery_persists_across_real_engine_and_lifespan_recreation(self):
        code, _ = self.issue()
        auth_db.reset_engine()
        with TestClient(main.app, base_url=ORIGIN, raise_server_exceptions=False) as restarted:
            self.assertEqual(self.recover(code, client=restarted).status_code, 200)
        auth_db.reset_engine()
        self.assertEqual(self.client(self.alice, self.new_password).get('/auth/me').status_code, 200)
        self.assertEqual(self.recover(code).status_code, 400)

    def test_recovery_does_not_transfer_private_workspace_or_project_access(self):
        project_id = uuid.uuid4().hex
        auth.register_project(project_id, self.alice)
        code, _ = self.issue()
        self.assertEqual(self.recover(code).status_code, 200)
        with Session(self.engine) as database:
            project = database.get(Project, project_id)
            self.assertEqual((project.owner_id, project.workspace_id), (self.alice.id, self.alice.workspace_id))
        for user in (self.admin, self.bob):
            self.assertEqual(self.client(user).get('/jobs/' + project_id).status_code, 404)
        self.assertEqual(self.client(self.bob).get('/auth/admin/audit').status_code, 403)

    def test_no_secret_in_response_errors_or_emitted_logs(self):
        code, _ = self.issue()
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        logger = logging.getLogger()
        logger.addHandler(handler)
        try:
            response = self.recover(code, 'short')
            self.assertEqual(response.status_code, 422)
            self.assertEqual(self.recover(code).status_code, 200)
        finally:
            logger.removeHandler(handler)
            handler.close()
        self.assert_no_secrets(output.getvalue() + response.text, code, self.password, self.new_password)

    def rebuild_auth01(self):
        """Seed old frozen DDL directly; future ORM/bootstrap cannot shape it."""
        clock = auth.now_utc()
        user_id, workspace_id, project_id = uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex
        session_token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        encoded = auth.PASSWORDS.hash(self.password)
        with self.engine.begin() as connection:
            connection.execute(text('DROP SCHEMA "' + self.schema + '" CASCADE'))
            connection.execute(text('CREATE SCHEMA "' + self.schema + '"'))
            connection.execute(text('CREATE TABLE auth_schema_migrations (revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)'))
            for statement in auth_migrations.DDL_0001:
                connection.execute(text(statement))
            connection.execute(text('INSERT INTO auth_schema_migrations VALUES (:revision,:time)'), {'revision': 'auth01_0001', 'time': clock})
            connection.execute(text('INSERT INTO auth_users VALUES (:id,:name,:password,false,true,:time)'), {'id': user_id, 'name': 'legacy_recovery_user', 'password': encoded, 'time': clock})
            connection.execute(text('INSERT INTO auth_workspaces VALUES (:id,:owner,:time)'), {'id': workspace_id, 'owner': user_id, 'time': clock})
            connection.execute(text("INSERT INTO auth_memberships VALUES (:workspace,:owner,'owner')"), {'workspace': workspace_id, 'owner': user_id})
            connection.execute(text('INSERT INTO auth_projects VALUES (:id,:workspace,:owner,:time)'), {'id': project_id, 'workspace': workspace_id, 'owner': user_id, 'time': clock})
            connection.execute(text('INSERT INTO auth_sessions VALUES (:token,:owner,:csrf,:time,:expiry,NULL)'),
                {'token': auth.token_hash(session_token), 'owner': user_id, 'csrf': auth.token_hash(csrf), 'time': clock, 'expiry': clock + timedelta(hours=12)})
        return {'user_id': user_id, 'workspace_id': workspace_id, 'project_id': project_id, 'password_hash': encoded, 'session': session_token}

    def test_auth01_sql_is_frozen_and_latest_migration_is_incremental(self):
        value = hashlib.sha256('\n'.join(auth_migrations.DDL_0001).encode()).hexdigest()
        self.assertEqual(value, FROZEN_AUTH01_DDL_SHA256)
        self.assertEqual([revision for revision, _ in auth_migrations.MIGRATIONS], ['auth01_0001', 'auth02_0002'])

    def test_auth01_upgrade_preserves_password_sessions_ownership_and_applies_once(self):
        old = self.rebuild_auth01()
        self.assertEqual(auth_migrations.upgrade(self.engine), {'status': 'applied', 'revision': 'auth02_0002'})
        self.assertEqual(auth_migrations.upgrade(self.engine), {'status': 'current', 'revision': 'auth02_0002'})
        with Session(self.engine) as database:
            self.assertTrue(database.get(User, old['user_id']).password_hash == old['password_hash'], 'Migration must preserve existing password encoding')
            project = database.get(Project, old['project_id'])
            self.assertEqual((project.owner_id, project.workspace_id), (old['user_id'], old['workspace_id']))
            self.assertEqual(database.execute(text('SELECT revision FROM auth_schema_migrations ORDER BY revision')).scalars().all(), ['auth01_0001', 'auth02_0002'])
            self.assertEqual(database.scalar(select(func.count()).select_from(RecoveryCode)), 0)
        client = self.client()
        client.cookies.set(auth.SESSION_COOKIE, old['session'])
        self.assertEqual(client.get('/auth/me').status_code, 200)

    def test_auth02_ddl_failure_rolls_back_history_and_old_data(self):
        old = self.rebuild_auth01()
        broken = (('auth01_0001', auth_migrations.DDL_0001), ('auth02_0002', (*auth_migrations.DDL_0002, 'SELECT 1 / 0')))
        with patch.object(auth_migrations, 'MIGRATIONS', broken):
            with self.assertRaises(auth_migrations.MigrationError):
                auth_migrations.upgrade(self.engine)
        with self.engine.connect() as connection:
            revisions = connection.execute(text('SELECT revision FROM auth_schema_migrations ORDER BY revision')).scalars().all()
            names = set(connection.execute(text('SELECT tablename FROM pg_tables WHERE schemaname=:schema'), {'schema': self.schema}).scalars())
            stored = connection.execute(text('SELECT password_hash FROM auth_users WHERE id=:id'), {'id': old['user_id']}).scalar_one()
        self.assertEqual(revisions, ['auth01_0001'])
        self.assertTrue(not {'auth_recovery_codes', 'auth_audit_events', 'auth_security_attempts'} & names, 'Failed migration must roll back its tables')
        self.assertTrue(stored == old['password_hash'], 'Migration fault must preserve old user data')

    def test_revision_gaps_or_unknown_states_are_rejected_without_mutation(self):
        for revisions in (['auth02_0002'], ['future_auth_99'], ['auth01_0001', 'future_auth_99']):
            old = self.rebuild_auth01()
            with self.engine.begin() as connection:
                connection.execute(text('DELETE FROM auth_schema_migrations'))
                for revision in revisions:
                    connection.execute(text('INSERT INTO auth_schema_migrations VALUES (:revision,:time)'), {'revision': revision, 'time': auth.now_utc()})
            with self.assertRaises(auth_migrations.MigrationError):
                auth_migrations.upgrade(self.engine)
            with self.engine.connect() as connection:
                self.assertEqual(connection.execute(text('SELECT revision FROM auth_schema_migrations ORDER BY revision')).scalars().all(), sorted(revisions))
                stored = connection.execute(text('SELECT password_hash FROM auth_users WHERE id=:id'), {'id': old['user_id']}).scalar_one()
            self.assertTrue(stored == old['password_hash'], 'Rejected history must preserve old user data')


if __name__ == '__main__':
    unittest.main()
