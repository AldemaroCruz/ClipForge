"""AUTH-01 real browser login/account/admin acceptance against isolated PostgreSQL.

Separate from the six historical media scenarios. No mocks for authentication,
no external providers, no secret values or request headers in emitted evidence.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from auth_support import prepare_browser_fixture
from playwright.sync_api import sync_playwright, expect

OUTPUT = ROOT / 'test-output'
OUTPUT.mkdir(exist_ok=True)
results = []
STEP_IDS = ('login', 'admin_create_user', 'independent_sessions', 'process_restart',
            'password_revocation', 'admin_deactivation', 'logout_mobile')


def report_failure(error_type, error, traceback):
    # Playwright errors can include fill() arguments. Never publish their text.
    print('AUTH browser failed after ' + str(len(results)) + ' steps: ' + error_type.__name__, file=sys.stderr)


sys.excepthook = report_failure


def record(message):
    results.append({'id': STEP_IDS[len(results)], 'status': 'passed', 'detail': message})
    print('PASS: ' + message, flush=True)


def login(page, origin, username, password):
    page.goto(origin + '/login', wait_until='networkidle')
    page.locator('#username').fill(username)
    page.locator('#password').fill(password)
    page.locator('#login-form button[type=submit]').click()
    page.wait_for_url(origin + '/', wait_until='networkidle')
    expect(page.locator('[data-auth-user]')).to_have_text(username)


with tempfile.TemporaryDirectory(prefix='clipforge-browser-auth-') as temporary:
    data = Path(temporary) / 'auth-fixture-data'
    data.mkdir()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    fixture = prepare_browser_fixture(origin, str(data), (), admin=True)
    username, password = 'browser_user_' + secrets.token_hex(5), secrets.token_urlsafe(24)
    replacement = secrets.token_urlsafe(24)
    server_log = (OUTPUT / 'browser-auth-server.log').open('x', encoding='utf-8')
    environment = {**os.environ, 'CLIPFORGE_DATA_DIR': str(data), 'CLIPFORGE_AI_PROVIDER': 'disabled'}

    def start():
        process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(port), '--no-access-log'],
            cwd=ROOT, env=environment, stdout=server_log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                with urllib.request.urlopen(origin + '/health', timeout=1) as response:
                    if response.status == 200:
                        return process
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError('Isolated AUTH-01 fixture server stopped')
                time.sleep(.1)
        process.terminate()
        process.wait(timeout=10)
        raise TimeoutError('Isolated AUTH-01 fixture did not become ready')

    def stop(process):
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    process = start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv('CHROMIUM_EXECUTABLE') or shutil.which('chromium'),
                headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
            admin_context = browser.new_context(viewport={'width': 1280, 'height': 960})
            user_context = browser.new_context(viewport={'width': 1280, 'height': 960})
            second_context = browser.new_context()
            admin_page, user_page, second_page = admin_context.new_page(), user_context.new_page(), second_context.new_page()
            errors = []
            for page in [admin_page, user_page, second_page]:
                page.on('pageerror', lambda error: errors.append(type(error).__name__))
            admin_page.goto(origin + '/login')
            admin_page.locator('#username').fill(fixture['username'])
            admin_page.locator('#password').fill('incorrect-authored-fixture')
            admin_page.locator('#login-form button').click()
            expect(admin_page.locator('#login-status')).to_contain_text('Usuario o contraseña incorrectos')
            expect(admin_page.locator('#password')).to_have_value('')
            record('Login UI rejects incorrect credentials and clears the password field.')
            login(admin_page, origin, fixture['username'], fixture['password'])
            admin_page.goto(origin + '/account', wait_until='networkidle')
            expect(admin_page.locator('#users-panel')).to_be_visible()
            admin_page.locator('#new-username').fill(username)
            admin_page.locator('#user-password').fill(password)
            admin_page.locator('#create-user-form button').click()
            expect(admin_page.locator('#users-status')).to_have_text('Cuenta creada.')
            expect(admin_page.locator('#user-password')).to_have_value('')
            expect(admin_page.locator('#user-list')).to_contain_text(username)
            record('Administrator creates a PostgreSQL-backed user through the real account UI.')
            login(user_page, origin, username, password)
            login(second_page, origin, username, password)
            user_page.goto(origin + '/account', wait_until='networkidle')
            expect(user_page.locator('#users-panel')).to_be_hidden()
            assert admin_context.request.get(origin + '/auth/me').json()['user']['id'] != user_context.request.get(origin + '/auth/me').json()['user']['id'], 'Separate browser identities'
            record('Independent admin/user browser contexts hold separate sessions; ordinary user has no administration panel.')
            stop(process)
            process = start()
            user_page.reload(wait_until='networkidle')
            expect(user_page.locator('[data-auth-user]')).to_have_text(username)
            admin_page.reload(wait_until='networkidle')
            expect(admin_page.locator('#user-list')).to_contain_text(username)
            record('Users and active sessions persist across an actual isolated Uvicorn process restart.')
            user_page.locator('#current-password').fill(password)
            user_page.locator('#new-password').fill(replacement)
            user_page.locator('#password-form button').click()
            user_page.wait_for_url(origin + '/login')
            assert second_context.request.get(origin + '/auth/me').status == 401, 'Previous second session revoked'
            login(user_page, origin, username, replacement)
            record('Password change via UI requires current password and revokes the other browser session; new password signs in.')
            admin_page.on('dialog', lambda dialog: dialog.accept())
            admin_page.get_by_role('button', name='Desactivar a ' + username, exact=True).click()
            expect(admin_page.locator('#user-list')).to_contain_text(username + ' · Desactivada')
            assert user_context.request.get(origin + '/auth/me').status == 401, 'Disabled user session revoked'
            user_page.goto(origin + '/login')
            user_page.locator('#username').fill(username)
            user_page.locator('#password').fill(replacement)
            user_page.locator('#login-form button').click()
            expect(user_page.locator('#login-status')).to_contain_text('Usuario o contraseña incorrectos')
            record('Administrator deactivation revokes active access and disabled account login fails without enumeration.')
            admin_page.locator('[data-auth-logout]').click()
            admin_page.wait_for_url(origin + '/login')
            assert admin_context.request.get(origin + '/auth/me').status == 401, 'Logout revoked server session'
            admin_page.set_viewport_size({'width': 390, 'height': 844})
            assert admin_page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile login overflow'
            assert not errors, 'Unexpected browser JavaScript error'
            record('Logout removes authenticated access; login remains usable on mobile without JavaScript errors.')
            browser.close()
    finally:
        stop(process)
        server_log.close()
with (OUTPUT / 'browser-auth-summary.json').open('x', encoding='utf-8') as stream:
    json.dump({'schema_version': 1, 'status': 'passed', 'exit_code': 0,
               'script': 'browser_auth.py', 'timed_out': False, 'details': results, 'steps': len(results), 'transport': 'direct_http', 'postgresql': 'real',
               'process_restart': True, 'auth_mocked': False, 'external_network': False,
               'scope': 'Separate AUTH-01 UI acceptance; no real ASR/LLM, no release approval'}, stream, indent=2)
    stream.write('\n')
