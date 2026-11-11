"""Local-launcher boundary fixtures; no daemon, service or credential access."""
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
from scripts import dev_local as dev


class DevelopmentBoundaryTests(unittest.TestCase):
    def test_http_requires_explicit_profile_before_git_or_filesystem(self):
        with patch.object(dev.subprocess, 'check_output') as git, patch.object(dev.tempfile, 'mkdtemp') as temporary:
            with self.assertRaises(dev.DevelopmentError):
                dev.prepare(None, 0, False)
        git.assert_not_called()
        temporary.assert_not_called()

    def test_reserved_and_invalid_port_values_rejected(self):
        for port in [-1, 65536, 8080]:
            with self.subTest(port=port), self.assertRaises(dev.DevelopmentError):
                dev.choose_port(port)

    def test_port_zero_selects_actual_loopback_port_and_busy_port_is_rejected(self):
        port = dev.choose_port(0)
        self.assertTrue(0 < port <= 65535 and port != 8080)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            with self.assertRaises(OSError):
                dev.choose_port(listener.getsockname()[1])

    def test_variables_reject_newlines_and_quotes(self):
        for value in ["broken'value", 'broken\nvalue', 'broken\rvalue', 'broken\0value']:
            with self.subTest(value=repr(value)), self.assertRaises(dev.DevelopmentError):
                dev.dotenv(value)
        self.assertEqual(dev.dotenv('C:/safe path/state'), "'C:/safe path/state'")

    def test_state_inside_checkout_rejected_before_reading(self):
        with patch.object(Path, 'read_text') as reader:
            with self.assertRaises(dev.DevelopmentError):
                dev.load_state(dev.ROOT / 'auth01-untrusted-state')
        reader.assert_not_called()

    def test_state_identity_and_public_binding_tampering_rejected(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-state-fixture-') as tmp:
            state = Path(tmp)
            valid = {'schema': dev.SCHEMA, 'project': 'clipforge-auth01-' + 'a'*12,
                     'image': 'clipforge-auth01-' + 'a'*12 + '-app:local', 'port': 49153,
                     'origin': 'http://127.0.0.1:49153', 'profile': 'local-http', 'source': str(dev.ROOT)}
            for change in [{'project': 'clipforge-mvp'}, {'image': 'clipforge/mvp:operational'},
                           {'port': 8080}, {'origin': 'http://0.0.0.0:49153'}, {'profile': 'https'},
                           {'source': str(dev.ROOT.parent)}]:
                (state / 'development.json').write_text(json.dumps({**valid, **change}))
                with self.subTest(change=change), patch.object(dev.context, 'verify_context') as verify:
                    with self.assertRaises(dev.DevelopmentError):
                        dev.load_state(state)
                    verify.assert_not_called()

    def test_compose_uses_explicit_external_project_and_vars(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-command-fixture-') as tmp:
            state = Path(tmp)
            with patch.object(dev, 'host_executable', return_value=str(state / 'docker')):
                command = dev.compose(state, {'project': 'clipforge-auth01-' + 'b'*12})
            self.assertEqual(command[command.index('--env-file') + 1], str(state / 'runtime.vars'))
            self.assertEqual(command[command.index('--project-directory') + 1], str(state))
            self.assertEqual(command[command.index('-f') + 1], str(state / 'context/compose.dev.yaml'))

    def test_host_resolver_rejects_unknown_relative_and_missing_reviewed_tools(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-tool-fixture-') as tmp:
            missing = str(Path(tmp) / 'missing-docker')
            with patch.dict(dev.HOST_EXECUTABLES, {os.name: {'git': 'relative/git', 'docker': missing}}, clear=True):
                with self.assertRaises(dev.DevelopmentError):
                    dev.host_executable('unreviewed')
                with self.assertRaises(dev.DevelopmentError):
                    dev.host_executable('git')
                with self.assertRaises(FileNotFoundError):
                    dev.host_executable('docker')

    def test_host_resolver_returns_only_explicit_reviewed_path_despite_path_entry(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-tool-fixture-') as tmp:
            reviewed = Path(tmp) / 'reviewed-tool'
            reviewed.write_text('fixture; never executed', encoding='utf-8')
            reviewed.chmod(0o755)
            checked_stat = dev.context._checked_stat

            def metadata(path):
                actual = checked_stat(path)
                if Path(path) == reviewed:
                    return SimpleNamespace(st_mode=actual.st_mode, st_uid=0)
                return actual

            with patch.dict(dev.HOST_EXECUTABLES, {os.name: {'docker': str(reviewed)}}, clear=True), \
                 patch.dict(os.environ, {'PATH': str(Path(tmp) / 'untrusted')}), \
                 patch.object(dev.context, '_checked_stat', side_effect=metadata), \
                 patch.object(dev.os, 'access', return_value=True):
                self.assertEqual(dev.host_executable('docker'), str(reviewed))

    def test_host_resolver_rejects_link_and_reparse_metadata_before_access(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-tool-fixture-') as tmp:
            reviewed = Path(tmp) / 'reviewed-tool'
            real_lstat = os.lstat
            for mode, attributes in [(stat.S_IFLNK | 0o755, 0), (stat.S_IFREG | 0o755, 0x400)]:
                def metadata(path, *args, **kwargs):
                    if Path(path) == reviewed:
                        return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                    return real_lstat(path, *args, **kwargs)

                with self.subTest(kind='link' if mode & stat.S_IFLNK == stat.S_IFLNK else 'reparse'), \
                     patch.dict(dev.HOST_EXECUTABLES, {os.name: {'docker': str(reviewed)}}, clear=True), \
                     patch.object(dev.context.os, 'lstat', side_effect=metadata), \
                     patch.object(dev.os, 'access') as access:
                    with self.assertRaises(dev.context.ContextError):
                        dev.host_executable('docker')
                    access.assert_not_called()

    def test_host_resolver_rejects_nonregular_or_nonexecutable_reviewed_paths(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-tool-fixture-') as tmp:
            reviewed = Path(tmp) / 'reviewed-tool'
            reviewed.write_text('fixture; never executed', encoding='utf-8')
            with patch.dict(dev.HOST_EXECUTABLES, {os.name: {'docker': tmp}}, clear=True):
                with self.assertRaises(dev.DevelopmentError):
                    dev.host_executable('docker')
            with patch.dict(dev.HOST_EXECUTABLES, {os.name: {'docker': str(reviewed)}}, clear=True), \
                 patch.object(dev.context, '_checked_stat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)), \
                 patch.object(dev.os, 'access', return_value=False):
                with self.assertRaises(dev.DevelopmentError):
                    dev.host_executable('docker')

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership contract runs in the Linux CI candidate')
    def test_host_resolver_rejects_untrusted_posix_ownership_and_write_modes(self):
        for owner, mode in [(1000, 0o755), (0, 0o775), (0, 0o757)]:
            with self.subTest(owner=owner, mode=oct(mode)), \
                 patch.dict(dev.HOST_EXECUTABLES, {'posix': {'docker': '/reviewed/tool'}}, clear=True), \
                 patch.object(dev.context, '_checked_stat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=owner)), \
                 patch.object(dev.os, 'access') as access:
                with self.assertRaises(dev.DevelopmentError):
                    dev.host_executable('docker')
                access.assert_not_called()

    def test_dev_compose_preserves_private_network_and_storage_boundaries(self):
        recipe = yaml.safe_load((dev.ROOT / 'compose.dev.yaml').read_text(encoding='utf-8'))
        self.assertTrue(recipe['networks']['private']['internal'])
        self.assertFalse(recipe['networks']['frontend']['internal'])
        self.assertEqual(recipe['networks']['frontend']['driver'], 'bridge')
        self.assertEqual(recipe['networks']['frontend']['driver_opts']['com.docker.network.bridge.host_binding_ipv4'], '127.0.0.1')
        postgres, app = recipe['services']['postgres'], recipe['services']['app']
        self.assertEqual(postgres['networks'], ['private'])
        self.assertEqual(app['networks'], ['private', 'frontend'])
        self.assertNotIn('ports', postgres)
        self.assertEqual(app['ports'][0]['host_ip'], '127.0.0.1')
        self.assertEqual(app['environment']['CLIPFORGE_AUTH_PROFILE'], 'local-http')
        self.assertEqual(app['environment']['CLIPFORGE_AI_PROVIDER'], 'disabled')
        self.assertEqual(app['volumes'], ['app_data:/srv/clipforge'])
        for service in [postgres, app]:
            self.assertEqual(service['cap_drop'], ['ALL'])
            self.assertTrue(service['read_only'])
            self.assertIn('healthcheck', service)
            self.assertTrue(all('docker.sock' not in str(value) for value in service.get('volumes', [])))

    def test_down_never_removes_volumes_or_runs_global_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-dev-down-fixture-') as tmp:
            with patch.object(dev, 'run', return_value='') as execute, \
                 patch.object(dev, 'host_executable', return_value=str(Path(tmp) / 'docker')):
                dev.execute('down', Path(tmp), {'project': 'clipforge-auth01-' + 'c'*12})
            self.assertEqual(execute.call_count, 1)
            argv = execute.call_args.args[2]
            self.assertIn('down', argv)
            self.assertNotIn('--volumes', argv)
            self.assertNotIn('prune', argv)


if __name__ == '__main__':
    unittest.main()
