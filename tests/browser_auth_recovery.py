"""AUTH-02 real UI/PostgreSQL acceptance; emit only public step statuses.

Recovery codes/passwords stay in memory, request bodies and password inputs.
No screenshots, HAR, tracing, storage state, access log or server log is saved.
"""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'test-output/browser-auth-recovery-summary.json'
STEP_IDS = ('recovery_admin_reauthentication', 'recovery_issue', 'recovery_replace',
            'recovery_process_restart', 'recovery_consume', 'recovery_session_revocation',
            'recovery_single_use', 'recovery_audit_privacy')
AUDIT_FIELDS = {'actor_id', 'target_id', 'action', 'created_at', 'result', 'correlation_id'}


def ensure(condition, message):
    if not condition:
        raise RuntimeError(message)


def public_error(error_type, error, traceback):
    # Playwright exception text can include fill() arguments: never emit it.
    print('AUTH-02 browser stopped: ' + error_type.__name__, file=sys.stderr)


sys.excepthook = public_error


def login(page, origin, username, password):
    page.bring_to_front()
    page.goto(origin + '/login', wait_until='networkidle')
    page.locator('#username').fill(username)
    page.locator('#password').fill(password)
    with page.expect_response(lambda response: response.url == origin + '/auth/login' and response.request.method == 'POST') as response:
        page.locator('#login-form button[type=submit]').click()
    ensure(response.value.status == 200, 'Fixture login must succeed')
    page.wait_for_url(origin + '/', wait_until='networkidle')


def main():
    if os.environ.get('CLIPFORGE_AUTH_TEST_DATABASE') != '1':
        raise RuntimeError('Explicit isolated PostgreSQL test profile required')
    sys.path.insert(0, str(ROOT))
    from auth_support import prepare_browser_fixture
    from playwright.sync_api import sync_playwright

    details = []
    report = {'schema_version': 1, 'status': 'failed', 'exit_code': 1,
              'script': 'browser_auth_recovery.py', 'steps': 0, 'details': details,
              'timed_out': False, 'transport': 'direct_http', 'postgresql': 'real',
              'process_restart': False, 'auth_mocked': False, 'external_network': False}

    def record(step):
        ensure(step == STEP_IDS[len(details)], 'Unexpected recovery acceptance step order')
        details.append({'id': step, 'status': 'passed'})

    try:
        with tempfile.TemporaryDirectory(prefix='clipforge-browser-auth02-') as temporary:
            data = Path(temporary) / 'fixture-data'
            data.mkdir()
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            origin = 'http://127.0.0.1:' + str(port)
            admin = prepare_browser_fixture(origin, str(data) + '-admin', (), admin=True)
            user = prepare_browser_fixture(origin, str(data) + '-normal', ())
            target_id = user['principal'].id
            replacement = secrets.token_urlsafe(24)
            environment = {**os.environ, 'CLIPFORGE_DATA_DIR': str(data), 'CLIPFORGE_AI_PROVIDER': 'disabled'}

            def stop(process):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

            def start():
                process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1',
                    '--port', str(port), '--no-access-log', '--log-level', 'critical'], cwd=ROOT, env=environment,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(origin + '/health', timeout=1) as response:
                            if response.status == 200:
                                return process
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError('Isolated recovery server stopped')
                        time.sleep(.1)
                stop(process)
                raise TimeoutError('Isolated recovery server did not become ready')

            process = start()
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=os.getenv('CHROMIUM_EXECUTABLE') or shutil.which('chromium'),
                        headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
                    try:
                        admin_context = browser.new_context(viewport={'width': 1280, 'height': 960})
                        user_context, second_context = browser.new_context(), browser.new_context()
                        anonymous_context = browser.new_context(viewport={'width': 390, 'height': 844})
                        replay_context = browser.new_context()
                        admin_page, user_page = admin_context.new_page(), user_context.new_page()
                        second_page, public_page = second_context.new_page(), anonymous_context.new_page()
                        replay_page = replay_context.new_page()
                        errors = []
                        for page in (admin_page, user_page, second_page, public_page, replay_page):
                            page.on('pageerror', lambda error: errors.append(type(error).__name__))
                        login(admin_page, origin, admin['username'], admin['password'])
                        login(user_page, origin, user['username'], user['password'])
                        login(second_page, origin, user['username'], user['password'])
                        admin_page.bring_to_front()
                        admin_page.goto(origin + '/account', wait_until='networkidle')
                        admin_page.locator('#recovery-panel').wait_for(state='visible')
                        admin_page.locator('#recovery-target').select_option(target_id)
                        issue_route = origin + '/auth/admin/users/' + target_id + '/recovery'
                        admin_page.locator('#recovery-admin-password').fill('authored-incorrect-current')
                        with admin_page.expect_response(lambda response: response.url == issue_route and response.request.method == 'POST') as response:
                            admin_page.locator('#issue-recovery-form button[type=submit]').click()
                        ensure(response.value.status == 400, 'Recovery issuance requires current administrator password')
                        admin_page.wait_for_function("document.getElementById('recovery-admin-password').value === ''")
                        ensure(admin_page.locator('#recovery-admin-password').input_value() == '', 'Reauthentication input must clear')
                        ensure(not admin_page.locator('#recovery-issued').is_visible(), 'Incorrect reauthentication cannot expose a code')
                        record('recovery_admin_reauthentication')

                        def issue_ui():
                            admin_page.bring_to_front()
                            admin_page.locator('#recovery-admin-password').fill(admin['password'])
                            with admin_page.expect_response(lambda response: response.url == issue_route and response.request.method == 'POST') as issued:
                                admin_page.locator('#issue-recovery-form button[type=submit]').click()
                            ensure(issued.value.status == 201, 'Recovery issuance must succeed')
                            admin_page.locator('#recovery-issued').wait_for(state='visible')
                            field = admin_page.locator('#issued-recovery-code')
                            ensure(field.get_attribute('type') == 'password', 'Issued code must initially be masked')
                            value = field.input_value()
                            ensure(re.fullmatch(r'[A-Za-z0-9_-]{43}', value) is not None, 'Issued code format is invalid')
                            ensure(user['username'] in admin_page.locator('#recovery-recipient').inner_text(), 'Issued code must identify its captured recipient')
                            ensure(bool(admin_page.locator('#recovery-expiry').inner_text().strip()), 'Expiry must be visible')
                            admin_page.wait_for_function("document.getElementById('recovery-admin-password').value === ''")
                            ensure(admin_page.locator('#recovery-admin-password').input_value() == '', 'Successful reauthentication input must clear')
                            return value

                        first = issue_ui()
                        admin_page.locator('#show-recovery-code').click()
                        ensure(admin_page.locator('#issued-recovery-code').get_attribute('type') == 'text', 'Explicit reveal must show the code once')
                        ensure(admin_page.locator('#show-recovery-code').is_disabled(), 'Explicit reveal cannot be repeated')
                        admin_page.locator('#dismiss-recovery-code').click()
                        ensure(admin_page.locator('#issued-recovery-code').input_value() == '', 'Dismiss must erase displayed recovery code')
                        record('recovery_issue')
                        second = issue_ui()
                        ensure(first != second, 'Replacement must use a fresh code')
                        admin_page.locator('#dismiss-recovery-code').click()
                        public_page.bring_to_front()
                        public_page.goto(origin + '/recover', wait_until='networkidle')
                        public_page.locator('#recovery-code').fill(first)
                        public_page.locator('#recovery-new-password').fill(replacement)
                        public_page.locator('#recovery-confirm-password').fill(replacement)
                        with public_page.expect_response(lambda response: response.url == origin + '/auth/recover' and response.request.method == 'POST') as rejected:
                            public_page.locator('#recovery-form button[type=submit]').click()
                        ensure(rejected.value.status == 400, 'Preceding recovery code must be revoked')
                        ensure(anonymous_context.request.get(origin + '/auth/me').status == 401, 'Rejected recovery cannot authenticate')
                        record('recovery_replace')

                        stop(process)
                        process = start()
                        ensure(user_context.request.get(origin + '/auth/me').status == 200, 'Existing sessions must persist before recovery')
                        ensure(admin_context.request.get(origin + '/auth/me').status == 200, 'Administrator session must persist across restart')
                        report['process_restart'] = True
                        record('recovery_process_restart')
                        public_page.bring_to_front()
                        public_page.goto(origin + '/recover', wait_until='networkidle')
                        ensure(public_page.locator('#recovery-code').get_attribute('type') == 'password', 'Recovery input must mask the code')
                        public_page.locator('#recovery-code').fill(second)
                        public_page.locator('#recovery-new-password').fill(replacement)
                        public_page.locator('#recovery-confirm-password').fill(replacement)
                        with public_page.expect_response(lambda response: response.url == origin + '/auth/recover' and response.request.method == 'POST') as consumed:
                            public_page.locator('#recovery-form button[type=submit]').click()
                        ensure(consumed.value.status == 200, 'Current recovery code must succeed after restart')
                        public_page.locator('#recovery-form').wait_for(state='hidden')
                        public_page.locator('#recovery-login-link').wait_for(state='visible')
                        public_page.wait_for_function("['recovery-code','recovery-new-password','recovery-confirm-password'].every(id => document.getElementById(id).value === '')")
                        ensure(all(public_page.locator(selector).input_value() == '' for selector in
                                   ('#recovery-code', '#recovery-new-password', '#recovery-confirm-password')), 'Recovery success must erase all credential inputs')
                        ensure(anonymous_context.request.get(origin + '/auth/me').status == 401, 'Recovery must require explicit login')
                        ensure(public_page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Recovery page must fit mobile viewport')
                        record('recovery_consume')

                        ensure(user_context.request.get(origin + '/auth/me').status == 401, 'First old session must be revoked')
                        ensure(second_context.request.get(origin + '/auth/me').status == 401, 'Second old session must be revoked')
                        user_page.goto(origin + '/login', wait_until='networkidle')
                        user_page.locator('#username').fill(user['username'])
                        user_page.locator('#password').fill(user['password'])
                        with user_page.expect_response(lambda response: response.url == origin + '/auth/login' and response.request.method == 'POST') as old_password:
                            user_page.locator('#login-form button[type=submit]').click()
                        ensure(old_password.value.status == 401, 'Previous password must fail after recovery')
                        login(user_page, origin, user['username'], replacement)
                        record('recovery_session_revocation')
                        replay_page.bring_to_front()
                        replay_page.goto(origin + '/recover', wait_until='networkidle')
                        replay_page.locator('#recovery-code').fill(second)
                        replay_page.locator('#recovery-new-password').fill(secrets.token_urlsafe(24))
                        # Confirmation matches only in-memory input; never emit it.
                        replay_page.locator('#recovery-confirm-password').fill(replay_page.locator('#recovery-new-password').input_value())
                        with replay_page.expect_response(lambda response: response.url == origin + '/auth/recover' and response.request.method == 'POST') as replay:
                            replay_page.locator('#recovery-form button[type=submit]').click()
                        ensure(replay.value.status == 400, 'Consumed code must not be reusable')
                        ensure(replay_context.request.get(origin + '/auth/me').status == 401, 'Code reuse cannot authenticate')
                        record('recovery_single_use')

                        admin_page.bring_to_front()
                        admin_page.goto(origin + '/account', wait_until='networkidle')
                        admin_page.locator('#audit-panel').wait_for(state='visible')
                        admin_page.locator('#audit-filter-action').select_option('recovery.consumed')
                        admin_page.locator('#audit-filter-result').select_option('success')
                        admin_page.locator('#audit-filter-target').select_option(target_id)
                        with admin_page.expect_response(lambda response: response.url.startswith(origin + '/auth/admin/audit?') and response.request.method == 'GET') as audit:
                            admin_page.locator('#audit-filter-form button[type=submit]').click()
                        ensure(audit.value.status == 200, 'Administrator audit filter must succeed')
                        admin_page.wait_for_function("target => { const rows = [...document.querySelectorAll('#audit-list tr')]; return rows.length === 1 && rows[0].textContent.includes(target) && rows[0].textContent.includes('Recuperación completada'); }", arg=target_id)
                        items = audit.value.json()['items']
                        ensure(len(items) == 1 and all(set(item) == AUDIT_FIELDS for item in items), 'Audit exposes only fixed public fields')
                        ensure(items[0]['target_id'] == target_id and items[0]['action'] == 'recovery.consumed' and items[0]['result'] == 'success', 'Audit must identify the successful target action')
                        private_values = (first, second, replacement, user['password'], admin['password'])
                        material = json.dumps(items) + admin_page.locator('body').inner_text()
                        ensure(all(value not in material for value in private_values), 'Audit must not expose credentials or recovery codes')
                        user_page.bring_to_front()
                        user_page.goto(origin + '/account', wait_until='networkidle')
                        ensure(not user_page.locator('#audit-panel').is_visible(), 'Ordinary user cannot see audit controls')
                        ensure(not user_page.locator('#recovery-panel').is_visible(), 'Ordinary user cannot issue recovery')
                        ensure(user_context.request.get(origin + '/auth/admin/audit').status == 403, 'Audit API requires administrator')
                        ensure(not errors, 'Unexpected browser JavaScript error')
                        record('recovery_audit_privacy')
                    finally:
                        browser.close()
            finally:
                stop(process)
        ensure(len(details) == len(STEP_IDS), 'Recovery acceptance must complete every step')
        report.update(status='passed', exit_code=0)
    except Exception:
        # Failure evidence is the completed step IDs only, never exception text.
        report.update(status='failed', exit_code=1)
    report['steps'] = len(details)
    OUTPUT.parent.mkdir(exist_ok=True)
    with OUTPUT.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return report['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
