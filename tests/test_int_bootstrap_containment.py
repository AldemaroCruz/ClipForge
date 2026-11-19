"""Synthetic containment authority only; never guest access or actual stop."""
import copy
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import int_bootstrap_containment as c
BOOT = "12345678-1234-1234-1234-123456789abc"
UNIT_BYTES = b"synthetic public unit fixture; not the native unit's preimage\n"


def fixture():
    at = datetime.now(timezone.utc)
    proposal = {"status": "authorized_single_guest_initialization", "execution_authorized": True,
        "cloud_writes_authorized": True, "VM_operations_authorized": True, "SQL_on_INT_authorized": True,
        "target": {"instance_id": "1670495097211408131", "disk_id": "6427691858848206684",
            "project_id": "clipforgebeta2", "project_number": "816643438938", "zone": "us-central1-a"},
        "containment": c.containment_policy("a" * 64, "b" * 64, authorized=True)}
    proposal_raw = json.dumps(proposal)
    decision = {"schema": "clipforge-db01-activation-decision-1", "status": "authorized_single_guest_initialization",
        "owner": "admin@ixbalam.studio", "repository": "AldemaroCruz/ClipForge", "branch": "ci/bootstrap-sec03",
        "approved_commit": "c" * 40, "operation_id": "d" * 32, "proposal_sha256": c.sha(proposal_raw.encode()),
        "host_evidence_sha256": "e" * 64, "baseline_evidence_sha256": "f" * 64,
        "baseline_run_id": "1", "baseline_artifact_id": "2", "confirmation": "INITIALIZE_NEW_DISK_6427691858848206684",
        "issued_utc": (at - timedelta(minutes=1)).isoformat(), "expires_utc": (at + timedelta(minutes=20)).isoformat()}
    journal = c.guest.Operator({}, "b" * 64).receipt
    journal.pop("journal_sha256")
    journal.update({"journal_path": c.JOURNAL.as_posix(), "operation_id": decision["operation_id"],
        "approved_commit": decision["approved_commit"], "proposal_sha256": decision["proposal_sha256"],
        "operator_sha256": "b" * 64, "disk_id": "6427691858848206684", "filesystem_uuid": "12345678-1234-1234-1234-123456789abc",
        "effective_config_sha256": "1" * 64, "status": "partial_preserved", "exit_code": 3,
        "guest_boot_id": BOOT, "phase": "postchecks", "error_code": "synthetic_postcheck_failure",
        "started_utc": (at-timedelta(seconds=30)).isoformat(), "finished_utc": (at-timedelta(seconds=1)).isoformat(),
        "native_operations": [{"operation": "start", "status": "ok", "exit_code": 0, "duration_ms": 1,
            "stdout_bytes": 0, "stderr_bytes": 0, "messages": [], "unclassified_stderr_lines": 0}]})
    journal["checks"]["mount_verified"] = True
    journal_raw = json.dumps(journal).encode()
    decision_raw = json.dumps(decision)
    payload = {"schema": "clipforge-db01-containment-input-1", "owner_decision_json": decision_raw,
        "owner_decision_sha256": c.sha(decision_raw.encode()), "proposal_json": proposal_raw,
        "journal_sha256": c.sha(journal_raw)}
    return payload, decision, journal_raw


def show(active):
    return ("ActiveState=" + ("active" if active else "inactive") + "\nSubState=" + ("running" if active else "dead")
        + "\nLoadState=loaded\nMainPID=" + ("1234" if active else "0")
        + "\nFragmentPath=/usr/lib/systemd/system/postgresql@.service\nDropInPaths=\nNeedDaemonReload=no\n"
        + "ExecStop={ path=/usr/bin/pg_ctlcluster ; argv[]=" + " ".join(c.EXEC_STOP)
        + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n").encode()


class ContainmentTests(unittest.TestCase):
    def test_current_unapproved_policy_blocks_before_guest_reads_or_stop(self):
        payload, _, _ = fixture();proposal = json.loads(payload["proposal_json"]);proposal["containment"]["authorized"] = False
        payload["proposal_json"] = json.dumps(proposal)
        decision = json.loads(payload["owner_decision_json"]);decision["proposal_sha256"] = c.sha(payload["proposal_json"].encode())
        payload["owner_decision_json"] = json.dumps(decision);payload["owner_decision_sha256"] = c.sha(payload["owner_decision_json"].encode())
        reader = mock.Mock(side_effect=AssertionError("guest access before authority"))
        result = c.Containment(payload, own_sha="a" * 64, bootstrap_sha="b" * 64, read=reader).run()
        self.assertEqual(result["status"], "blocked_before_stop");reader.assert_not_called()

    def test_policy_digests_boolean_types_expiry_target_and_extra_fields_fail(self):
        payload, _, _ = fixture()
        c.authorize(payload, "a" * 64, "b" * 64)
        mutations = [lambda p:p.update(execution_authorized=False),
            lambda p:p["containment"].update(authorized=1),lambda p:p["containment"].update(automatic_retry=0),
            lambda p:p["containment"].update(argv=["/usr/bin/systemctl", "restart", c.UNIT]),
            lambda p:p["containment"].update(source_sha256="f" * 64),lambda p:p["target"].update(disk_id="1")]
        for mutate in mutations:
            changed=copy.deepcopy(payload);proposal=json.loads(changed["proposal_json"]);mutate(proposal)
            changed["proposal_json"]=json.dumps(proposal);d=json.loads(changed["owner_decision_json"])
            d["proposal_sha256"]=c.sha(changed["proposal_json"].encode());changed["owner_decision_json"]=json.dumps(d)
            changed["owner_decision_sha256"]=c.sha(changed["owner_decision_json"].encode())
            with self.subTest(mutate=mutate),self.assertRaises(c.guest.Blocked):c.authorize(changed,"a"*64,"b"*64)
        for key,value in [("expires_utc",(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()),("unexpected","value")]:
            changed=copy.deepcopy(payload);d=json.loads(changed["owner_decision_json"]);d[key]=value
            changed["owner_decision_json"]=json.dumps(d);changed["owner_decision_sha256"]=c.sha(changed["owner_decision_json"].encode())
            with self.assertRaises(c.guest.Blocked):c.authorize(changed,"a"*64,"b"*64)

    def test_foreign_journal_uuid_hash_or_missing_start_blocks(self):
        payload,decision,raw=fixture();c.owned_journal(raw,decision,c.sha(raw),"b"*64,guest_boot_id=BOOT)
        for key,value in [("operation_id","a"*32),("filesystem_uuid","not_uuid"),("disk_id","1"),("native_operations",[])]:
            j=json.loads(raw);j[key]=value;changed=json.dumps(j).encode()
            with self.assertRaises(c.guest.Blocked):c.owned_journal(changed,decision,c.sha(changed),"b"*64,guest_boot_id=BOOT)
        with self.assertRaises(c.guest.Blocked):c.owned_journal(raw,decision,"0"*64,"b"*64,guest_boot_id=BOOT)

    def orchestrate(self, *, interrupted=False, bad_after=False, foreign=False, intent_error=None, process_changed=False, writer=None):
        payload, _, raw = fixture();calls=[]
        def runner(op,argv,stdin,timeout):
            calls.append((op,argv));self.assertIsNone(stdin);self.assertLessEqual(timeout,20)
            row={"operation":op,"status":"ok","exit_code":0,"duration_ms":1,"stdout_bytes":0,"stderr_bytes":0,"messages":[],"unclassified_stderr_lines":0}
            if op=="containment_stop" and interrupted:
                row.update(status="interrupted",exit_code=-9)
                raise c.guest.NativeInterruption(c.guest.Blocked("signal_interruption"),row)
            data=show(sum(x[0]=="unit_state" for x in calls)<=2) if op=="unit_state" else b""
            return data,row
        def reader(path,**kwargs):
            if path==c.UNIT_FRAGMENT:return UNIT_BYTES
            if path==Path('/proc/sys/kernel/random/boot_id'):return (BOOT+'\n').encode()
            return raw
        intent=writer or mock.Mock(side_effect=intent_error,return_value='2'*64)
        obj=c.Containment(payload,own_sha="a"*64,bootstrap_sha="b"*64,runner=runner,read=reader,intent_writer=intent,
            identity=lambda:{"instance_id":"1670495097211408131","project_id":"clipforgebeta2","project_number":"816643438938","zone":"us-central1-a"})
        before={"public_file_sha256":{"public":"hash"},"uuid":"uuid","major_minor":"8:16","cluster":["17","main","5432","online","postgres","data"]}
        after=copy.deepcopy(before);after["cluster"][3]="down"
        if bad_after:after["public_file_sha256"]={"foreign":"edited"}
        process={'pid':1234,'start_ticks':'333','uid':999,'PGDATA':c.PGDATA.as_posix()}
        sequence=[process,process,{**process,'start_ticks':'334'} if process_changed else process]
        with mock.patch.object(c.sys,"platform","linux"),mock.patch.object(c.os,"geteuid",return_value=0,create=True),mock.patch.object(c,'UNIT_FRAGMENT_SHA256',c.sha(UNIT_BYTES)),mock.patch.object(c,"created_postmaster",side_effect=c.guest.Blocked("foreign_pid") if foreign else sequence),mock.patch.object(obj,"snapshot",side_effect=[before,before,after]):
            result=obj.run()
        return result,calls

    def test_one_stop_preserves_configuration_and_never_runs_other_mutators(self):
        result,calls=self.orchestrate();self.assertEqual(result["status"],"created_cluster_stopped_preserved")
        self.assertEqual([args for op,args in calls if op=="containment_stop"],[c.STOP])
        self.assertTrue(result["configuration_and_journal_preserved"])
        self.assertTrue(result['intent_created'])
        self.assertEqual([op for op,_ in calls],["unit_state","unit_state","containment_stop","unit_state","tcp","unix"])

    def test_interrupted_stop_retains_native_exit_and_is_never_repeated(self):
        result,calls=self.orchestrate(interrupted=True)
        self.assertEqual(result["status"],"stop_outcome_unknown_preserve_and_review")
        self.assertEqual(result["native_operations"][-1]["exit_code"],-9)
        self.assertEqual(sum(op=="containment_stop" for op,_ in calls),1)

    def test_foreign_process_blocks_and_post_stop_drift_never_restores(self):
        result,calls=self.orchestrate(foreign=True);self.assertFalse(result["stop_attempted"])
        self.assertFalse(any(op=="containment_stop" for op,_ in calls))
        result,calls=self.orchestrate(bad_after=True);self.assertEqual(result["status"],"stop_outcome_unknown_preserve_and_review")
        self.assertFalse(result["configuration_restored"]);self.assertFalse(result["data_reinitialized"])

    def test_public_loader_is_small_hash_bound_and_has_no_transport_or_credentials(self):
        first=b"PUBLIC_BOOTSTRAP = 1\n";second=b"PUBLIC_CONTAINMENT = 2\n"
        bundle=c.public_payload(first,second,c.sha(first),c.sha(second))
        self.assertLess(len(bundle),65536)
        with mock.patch.dict(sys.modules):
            namespace={"__name__":"synthetic_read_only_compile"};exec(compile(bundle,"<test-public-loader>","exec"),namespace)
            self.assertEqual(namespace["PUBLIC_CONTAINMENT"],2)
        with self.assertRaises(c.guest.Blocked):c.public_payload(first,second,"0"*64,c.sha(second))

    def test_snapshot_rejects_wrong_mount_uuid_device_options_and_configuration(self):
        payload,_,_=fixture()
        files={str(path):b"public configuration\n" for path in c.PUBLIC_FILES}
        expected=c.sha(c.guest.canonical({"postgresql_conf":c.sha(files[str(c.CONFIG/'postgresql.conf')]),
            "pg_hba_conf":c.sha(files[str(c.CONFIG/'pg_hba.conf')])}))
        journal={"effective_config_sha256":expected,"fstab_after_sha256":c.sha(files[str(c.PUBLIC_FILES[0])]),
            "filesystem_uuid":"12345678-1234-1234-1234-123456789abc"}
        row={"uuid":journal['filesystem_uuid'],"source":"/dev/sdb","target":str(c.guest.MOUNT),
            "fstype":"ext4","maj:min":"8:16","options":"rw,nodev,nosuid,noexec"}
        def file_stat(path):
            return SimpleNamespace(st_dev=1) if str(path)==str(Path('/')) else SimpleNamespace(st_mode=stat.S_IFBLK|0o600,st_rdev=16)
        def exercise(selected):
            obj=c.Containment(payload,own_sha="a"*64,bootstrap_sha="b"*64,read=lambda p,**k:files[str(p)])
            obj.call=mock.Mock(side_effect=[json.dumps({"filesystems":[selected]}).encode(),b"17 main 5432 online postgres "+str(c.guest.MOUNT/'pgdata').encode('ascii')+b" log\n"])
            with mock.patch.object(c.Path,'stat',file_stat),mock.patch.object(c.guest,'postgres_account',return_value=SimpleNamespace(pw_uid=999)),mock.patch.object(c.os,'major',return_value=8,create=True),mock.patch.object(c.os,'minor',return_value=16,create=True):
                return obj.snapshot(journal)
        self.assertEqual(exercise(row)['major_minor'],'8:16')
        for key,value in [('uuid','foreign'),('fstype','xfs'),('maj:min','8:1'),('options','rw'),('target','/foreign')]:
            changed={**row,key:value}
            with self.subTest(key=key),self.assertRaises(c.guest.Blocked):exercise(changed)
        journal['effective_config_sha256']='f'*64
        with self.assertRaises(c.guest.Blocked):exercise(row)

    def test_created_postmaster_requires_postgres_uid_and_exact_binary(self):
        def link(path):return '/usr/lib/postgresql/17/bin/postgres' if path.name=='exe' else c.PGDATA.as_posix()
        fields=['S']+['1']*18+['334']+['1']*8
        reader=mock.Mock(return_value=('1234 (postgres) '+' '.join(fields)+'\n').encode())
        with mock.patch.object(c.Path,'stat',return_value=SimpleNamespace(st_uid=999)),mock.patch.object(c.guest,'postgres_account',return_value=SimpleNamespace(pw_uid=999)),mock.patch.object(c.os,'readlink',side_effect=link),mock.patch.object(c,'postmaster_metadata') as metadata:
            self.assertEqual(c.created_postmaster(1234,reader=reader)['start_ticks'],'334')
            metadata.assert_called_once_with(1234,999)
            with mock.patch.object(c.os,'readlink',return_value='/usr/local/bin/foreign'):
                with self.assertRaises(c.guest.Blocked):c.created_postmaster(1234,reader=reader)
            with mock.patch.object(c.os,'readlink',side_effect=lambda path:'/usr/lib/postgresql/17/bin/postgres' if path.name=='exe' else '/foreign/data'):
                with self.assertRaises(c.guest.Blocked):c.created_postmaster(1234,reader=reader)
        with self.assertRaises(c.guest.Blocked):c.created_postmaster(0)

    def test_successful_unfinished_wrong_boot_and_future_journals_block(self):
        _,decision,raw=fixture()
        for key,value in [('status','configured_guest_verified_external_acceptance_pending'),('status','blocked'),('finished_utc',None),('guest_boot_id','a'*36),('error_code',None),('finished_utc',(datetime.now(timezone.utc)+timedelta(seconds=10)).isoformat())]:
            journal=json.loads(raw);journal[key]=value;changed=json.dumps(journal).encode()
            with self.subTest(key=key,value=value),self.assertRaises((ValueError,TypeError,AttributeError)):
                c.owned_journal(changed,decision,c.sha(changed),'b'*64,guest_boot_id=BOOT)

    def test_fully_valid_successful_bootstrap_receipt_cannot_authorize_stop(self):
        _,decision,raw=fixture();journal=json.loads(raw)
        journal.update(status='configured_guest_verified_external_acceptance_pending',exit_code=0,
            phase='guest_verified',error_code=None,checks={key:True for key in c.guest.CHECK_KEYS},
            disk_proof_sha256='a'*64,guest_read_receipt_sha256='b'*64,guest_read_source_sha256='c'*64,
            fstab_before_sha256='d'*64,fstab_after_sha256='e'*64,
            parent_permissions_before={'uid':0,'gid':0,'mode':'0700'},parent_permissions_after={'uid':0,'gid':999,'mode':'0710'})
        sample=journal['native_operations'][0]
        journal['native_operations']=[{**sample,'operation':op} for op in c.guest.SUCCESS_OPERATIONS]
        # Verify this is a genuinely valid complete success fixture, rather than
        # relying on a malformed receipt to make the negative assertion pass.
        c.guest.validate_receipt({**journal,'journal_sha256':'f'*64,'journal_path':str(c.guest.JOURNAL_DIR/'operation.json')})
        changed=json.dumps(journal).encode()
        with self.assertRaisesRegex(c.guest.Blocked,'containment_requires_finished_failed_same_boot'):
            c.owned_journal(changed,decision,c.sha(changed),'b'*64,guest_boot_id=BOOT)

    def test_effective_unit_overrides_reload_and_alternate_ExecStop_block(self):
        self.assertEqual(c.unit_state(show(True))['ExecStop'],c.EXEC_STOP)
        for before,after in [(b'DropInPaths=',b'DropInPaths=/etc/systemd/system/override.conf'),(b'NeedDaemonReload=no',b'NeedDaemonReload=yes'),(b'17-main stop',b'18-main stop'),(b'-m fast',b'-m immediate'),(b'ignore_errors=no',b'ignore_errors=yes'),(b' ; pid=0',b' ; extra=bad ; pid=0')]:
            with self.subTest(after=after),self.assertRaises(c.guest.Blocked):c.unit_state(show(True).replace(before,after))

    def test_intent_failure_or_existing_claim_never_sends_stop(self):
        for error in [OSError('synthetic fsync failure'),FileExistsError('existing own or foreign claim')]:
            result,calls=self.orchestrate(intent_error=error)
            self.assertEqual(result['status'],'blocked_before_stop')
            self.assertTrue(result['intent_creation_attempted']);self.assertFalse(result['stop_attempted'])
            self.assertFalse(any(op=='containment_stop' for op,_ in calls))

    def test_process_PID_reuse_after_intent_blocks_without_stop_and_claim_remains(self):
        result,calls=self.orchestrate(process_changed=True)
        self.assertTrue(result['intent_created']);self.assertFalse(result['stop_attempted'])
        self.assertFalse(any(op=='containment_stop' for op,_ in calls))
        self.assertEqual(result['error_code'],'containment_process_changed_after_intent')

    def test_two_callers_share_one_exclusive_claim_and_unknown_never_retries(self):
        claimed=[]
        def writer(value):
            if claimed:raise FileExistsError('already claimed')
            claimed.append(value);return '2'*64
        first,first_calls=self.orchestrate(interrupted=True,writer=writer)
        second,second_calls=self.orchestrate(writer=writer)
        self.assertEqual(first['status'],'stop_outcome_unknown_preserve_and_review')
        self.assertEqual(len(claimed),1)
        self.assertEqual(sum(op=='containment_stop' for op,_ in first_calls+second_calls),1)
        self.assertFalse(second['stop_attempted'])

    def test_policy_factory_defaults_false_and_uses_literal_POSIX_paths(self):
        policy=c.containment_policy('a'*64,'b'*64)
        self.assertIs(policy['authorized'],False);self.assertIs(policy['intent_creation_authorized'],False)
        self.assertEqual(policy['intent_path'],'/var/lib/clipforge-postgres/db01/containment-intent.json')
        self.assertNotIn('\\',policy['journal_path'])
        first=Path(c.guest.__file__).read_bytes();second=Path(c.__file__).read_bytes()
        bundle=c.public_payload(first,second,c.sha(first),c.sha(second))
        self.assertLessEqual(len(c.base64.b64encode(bundle)),65536)

    def test_pidfile_reads_only_two_metadata_lines_and_checks_opened_inode(self):
        info=SimpleNamespace(st_dev=1,st_ino=2)
        for lines,changed in [([b'1234\n',c.PGDATA.as_posix().encode()+b'\n'],False),
                              ([b'9999\n',c.PGDATA.as_posix().encode()+b'\n'],False),
                              ([b'1234\n',b'/foreign/pgdata\n'],False),
                              ([b'1234\n',c.PGDATA.as_posix().encode()+b'\n'],True)]:
            file=mock.MagicMock();file.fileno.return_value=66
            file.readline.side_effect=lines+[b'not_authorized_to_read_this_third_line\n']
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(c.guest,'_parents'))
                stack.enter_context(mock.patch.object(c.guest,'_regular',return_value=info))
                stack.enter_context(mock.patch.object(c.os,'open',return_value=66))
                stack.enter_context(mock.patch.object(c.os,'fdopen',return_value=mock.MagicMock(__enter__=mock.Mock(return_value=file))))
                stack.enter_context(mock.patch.object(c.os,'fstat',return_value=SimpleNamespace(st_dev=1,st_ino=3) if changed else info))
                stack.enter_context(mock.patch.object(c.os,'O_NOFOLLOW',getattr(c.os,'O_NOFOLLOW',0),create=True))
                if changed or lines[0]!=b'1234\n' or lines[1]!=c.PGDATA.as_posix().encode()+b'\n':
                    with self.assertRaises(c.guest.Blocked):c.postmaster_metadata(1234,999)
                else:
                    c.postmaster_metadata(1234,999)
                    self.assertEqual(file.readline.call_args_list,[mock.call(64),mock.call(512)])
                self.assertLessEqual(file.readline.call_count,2);file.read.assert_not_called()

    def test_real_private_fixture_claim_exclusive_flags_no_delete_after_fsync_error(self):
        # Filesystem is real and private; owner checks are explicitly synthetic
        # so this test needs neither root nor a real guest on either platform.
        real_open=c.os.open
        for fails in (False,True):
            with tempfile.TemporaryDirectory(prefix='db01-contained-intent-') as directory,ExitStack() as stack:
                target=Path(directory)/'containment-intent.json';opened=[]
                def open_file(path,flags,mode=0o777):
                    opened.append(flags);return real_open(path,flags,mode)
                stack.enter_context(mock.patch.object(c,'INTENT',target))
                stack.enter_context(mock.patch.object(c.guest,'_parents'))
                syncdir=stack.enter_context(mock.patch.object(c.guest,'_fsync_dir'))
                stack.enter_context(mock.patch.object(c.guest,'read_bytes',side_effect=lambda path,**kw:path.read_bytes()))
                stack.enter_context(mock.patch.object(c.os,'O_NOFOLLOW',getattr(c.os,'O_NOFOLLOW',0),create=True))
                stack.enter_context(mock.patch.object(c.os,'fstat',return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)))
                chmod=stack.enter_context(mock.patch.object(c.os,'fchmod',create=True))
                stack.enter_context(mock.patch.object(c.os,'open',side_effect=open_file))
                if fails:stack.enter_context(mock.patch.object(c.os,'fsync',side_effect=OSError('synthetic disk sync failure')))
                value={'schema':'synthetic_intent_fixture','operation_id':'a'*32}
                if fails:
                    with self.assertRaises(OSError):c.claim_stop_intent(value)
                    syncdir.assert_not_called()
                else:
                    digest=c.claim_stop_intent(value)
                    self.assertEqual(digest,c.sha(target.read_bytes()));syncdir.assert_called_once_with(target.parent)
                self.assertTrue(target.exists())
                with self.assertRaises(FileExistsError):c.claim_stop_intent(value)
                self.assertTrue(all(flags & c.os.O_EXCL and flags & c.os.O_CREAT for flags in opened))
                chmod.assert_called_once_with(mock.ANY,0o600)


if __name__ == "__main__":unittest.main()
