"""v0.4.2 backup, local metrics, locks, pinned model and read-only acceptance."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from fastapi.testclient import TestClient
from app import main, backup, model_source
from app.acceptance import inspect_project
from app.lease import data_lease, LeaseBusy
from app.operations import project_stats
from app.state import write_json_atomic
from app.telemetry import Recorder

J='a'*32; E='b'*32; D='c'*32; A='d'*32; Z='e'*32


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'data';self.root.mkdir()
        self.out=self.base/'backups'/'backup.zip'
        self.folder=self.root/J;self.folder.mkdir()
        write_json_atomic(self.folder/'job.json',{'id':J,'status':'completed','clips':[]})
        (self.folder/'input.mp4').write_bytes(b'not a real video; backup must preserve bytes')
        write_json_atomic(self.folder/'transcript.json',[{'start':0,'end':20,'text':'private test content'}])

    def make(self):return backup.create_backup(self.root,self.out)

    def mutate_zip(self,change):
        self.make()
        with zipfile.ZipFile(self.out) as z: content={i.filename:z.read(i) for i in z.infolist()}
        change(content)
        target=self.base/'bad.zip'
        with zipfile.ZipFile(target,'w') as z:
            for name,value in content.items():z.writestr(name,value)
        return target

    def test_roundtrip_all_bytes_and_nanosecond_mtimes(self):
        os.utime(self.folder/'input.mp4',ns=(1770000000123456700,1770000000123456700))
        expected={p.relative_to(self.root).as_posix():(p.read_bytes(),p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        r=self.make();self.assertEqual(r['files'],3)
        restored=self.base/'restored';backup.restore_backup(self.out,restored,r['sha256'])
        for name,(content,mtime) in expected.items():
            self.assertEqual((restored/name).read_bytes(),content)
            self.assertEqual((restored/name).stat().st_mtime_ns,mtime)

    def test_missing_data_directory_rejected(self):
        absent=self.base/'absent'
        with self.assertRaises(ValueError):backup.create_backup(absent,self.out)
        self.assertFalse(absent.exists())

    def test_manifest_and_external_checksum(self):
        r=self.make();self.assertEqual(r['sha256'],backup.digest_file(self.out))
        self.assertTrue(self.out.with_suffix('.zip.sha256').read_text().startswith(r['sha256']))
        self.assertEqual(backup.verify_backup(self.out,r['sha256'])['files'],3)

    def test_wrong_external_hash_rejected(self):
        self.make()
        with self.assertRaises(ValueError):backup.verify_backup(self.out,'0'*64)

    def test_known_credentials_excluded_without_reading_content(self):
        (self.root/'.env.ai').write_text('OPENAI_API_KEY=secret-fixture')
        (self.folder/'private.key').write_text('secret key')
        r=self.make();self.assertEqual(r['excluded_secret_files'],2)
        with zipfile.ZipFile(self.out) as z:self.assertNotIn(b'secret-fixture',b''.join(z.read(n) for n in z.namelist()))

    def test_unknown_file_rejected_not_silently_dropped(self):
        (self.folder/'unknown.json').write_text('{}')
        with self.assertRaises(ValueError):self.make()
        self.assertFalse(self.out.exists())

    def test_symlink_rejected(self):
        (self.folder/'clip_01.mp4').symlink_to(self.folder/'input.mp4')
        with self.assertRaises(ValueError):self.make()

    def test_symlink_directory_rejected(self):
        (self.root/'templates').symlink_to(self.folder,target_is_directory=True)
        with self.assertRaises(ValueError):self.make()

    def test_active_process_rejected(self):
        write_json_atomic(self.folder/'job.json',{'status':'transcribing'})
        with self.assertRaises(ValueError):self.make()

    def test_active_ai_rejected(self):
        write_json_atomic(self.folder/'selections'/A/'selection.json',{'status':'running'})
        with self.assertRaises(ValueError):self.make()

    def test_corrupt_state_preserved_not_repaired(self):
        (self.folder/'job.json').write_bytes(b'{broken')
        self.make();dest=self.base/'recovered';backup.restore_backup(self.out,dest)
        self.assertEqual((dest/J/'job.json').read_bytes(),b'{broken')

    def test_runtime_lease_blocks_backup(self):
        with data_lease(self.root):
            with self.assertRaises(LeaseBusy):self.make()
        self.make()

    def test_lease_blocks_separate_process(self):
        with data_lease(self.root):
            code='from pathlib import Path; from app.lease import data_lease;\nwith data_lease(Path('+repr(str(self.root))+')): pass'
            p=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0);self.assertIn('LeaseBusy',p.stderr)

    def test_never_backup_inside_data(self):
        with self.assertRaises(ValueError):backup.create_backup(self.root,self.root/'backup.zip')

    def test_existing_archive_and_destination_never_overwritten(self):
        self.make();before=self.out.read_bytes()
        with self.assertRaises(FileExistsError):self.make()
        destination=self.base/'live';destination.mkdir();(destination/'keep').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):backup.restore_backup(self.out,destination)
        self.assertEqual((destination/'keep').read_bytes(),b'keep');self.assertEqual(self.out.read_bytes(),before)

    def test_corrupt_payload_rejected_before_publish(self):
        def change(c):c['data/'+J+'/input.mp4']=b'changed'
        bad=self.mutate_zip(change)
        with self.assertRaises(ValueError):backup.restore_backup(bad,self.base/'restored')
        self.assertFalse((self.base/'restored').exists())

    def test_zip_slip_rejected(self):
        bad=self.mutate_zip(lambda c:c.update({'data/../../pwn':b'bad'}))
        with self.assertRaises(ValueError):backup.verify_backup(bad)
        self.assertFalse((self.base/'pwn').exists())

    def test_manifest_forged_path_rejected(self):
        def change(c):
            m=json.loads(c['manifest.json']);m['files'][0]['path']='../../pwn';c['manifest.json']=json.dumps(m).encode()
        with self.assertRaises(ValueError):backup.verify_backup(self.mutate_zip(change))

    def test_duplicate_zip_members_rejected(self):
        self.make()
        with zipfile.ZipFile(self.out,'a') as z:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore');z.writestr('manifest.json','{}')
        with self.assertRaises(ValueError):backup.verify_backup(self.out)

    def test_disk_full_rejected(self):
        with mock.patch('app.backup.shutil.disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaises(ValueError):self.make()
        self.assertFalse(self.out.exists())

    def test_changed_file_during_backup_aborts(self):
        real=backup.inventory;calls=0
        def changing(root):
            nonlocal calls
            calls+=1
            if calls==2:(self.folder/'input.mp4').write_bytes(b'changed')
            return real(root)
        with mock.patch('app.backup.inventory',side_effect=changing):
            with self.assertRaises(ValueError):self.make()
        self.assertFalse(self.out.exists());self.assertFalse(list(self.out.parent.glob('.backup-*')))

    def test_preserves_templates_reviews_proposals_and_deliveries(self):
        for rel in [f'templates/{D}.json',f'{J}/drafts/{D}.json',f'{J}/exports/{E}/review.json',
                    f'{J}/selections/{A}/selection.json',f'{J}/deliveries/{Z}/delivery.json',
                    f'{J}/metrics/process-{J}.json',f'{J}/review-time/{D}.json']:
            write_json_atomic(self.root/rel,{'status':'completed'})
        (self.root/J/'deliveries'/Z/'delivery.zip').write_bytes(b'inner zip opaque bytes')
        r=self.make();self.assertEqual(r['files'],11)


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.patch=mock.patch.object(main,'ROOT',self.root);self.patch.start();self.addCleanup(self.patch.stop)
        write_json_atomic(self.root/J/'job.json',{'id':J,'status':'completed','clips':[]})
        self.client=TestClient(main.app)

    def test_legacy_not_measured_is_null(self):
        r=project_stats(self.root,J);self.assertIsNone(r['stage_seconds']);self.assertIsNone(r['cost_usd'])

    def test_timing_stages_nonnegative_persisted(self):
        rec=Recorder(self.root,J,'process',J);rec.phase('validation');rec.phase('render');rec.finish('completed')
        r=project_stats(self.root,J);self.assertEqual(r['timed_runs'],1);self.assertGreaterEqual(r['stage_seconds']['render'],0)

    def test_metrics_io_failure_does_not_fail_pipeline(self):
        rec=Recorder(self.root,J,'process',J)
        with mock.patch('app.telemetry.write_json_atomic',side_effect=OSError('secret text should not log')):
            rec.phase('render');rec.finish('completed')

    def test_metrics_no_raw_exception_body(self):
        rec=Recorder(self.root,J,'process',J);rec.phase('validation');rec.finish('failed','secret api-key text')
        text=rec.path.read_text();self.assertNotIn('secret',text);self.assertIn('PROCESSING_FAILED',text)

    def test_review_minutes_idempotent(self):
        body={'id':D,'minutes':12.5}
        self.assertEqual(self.client.post(f'/jobs/{J}/review-time',json=body).status_code,201)
        self.assertEqual(self.client.post(f'/jobs/{J}/review-time',json=body).status_code,201)
        r=project_stats(self.root,J);self.assertEqual(r['review_minutes'],12.5);self.assertEqual(r['review_sessions'],1)

    def test_review_conflicting_duplicate_409(self):
        self.client.post(f'/jobs/{J}/review-time',json={'id':D,'minutes':10})
        self.assertEqual(self.client.post(f'/jobs/{J}/review-time',json={'id':D,'minutes':11}).status_code,409)

    def test_review_invalid_fields_422(self):
        for body in [{'id':D,'minutes':0},{'id':D,'minutes':-1},{'id':'../','minutes':1},
                     {'id':D,'minutes':1441},{'id':D,'minutes':5,'notes':'secret'}]:
            self.assertEqual(self.client.post(f'/jobs/{J}/review-time',json=body).status_code,422)

    def test_summary_no_transcript_or_names(self):
        write_json_atomic(self.root/J/'transcript.json',[{'text':'private words'}])
        write_json_atomic(self.root/J/'job.json',{'id':J,'status':'completed','clips':[],'source_filename':'private-title.mp4'})
        response=self.client.get('/ops/summary');self.assertEqual(response.status_code,200)
        self.assertNotIn('private',response.text);self.assertIn('no-store',response.headers['cache-control'])

    def test_usage_and_approved_counts(self):
        write_json_atomic(self.root/J/'selections'/A/'selection.json',{'mode':'llm','request_started_at':1,'usage':{'input_tokens':250,'output_tokens':40},'elapsed_seconds':8})
        write_json_atomic(self.root/J/'exports'/E/'export.json',{'status':'completed'})
        write_json_atomic(self.root/J/'exports'/E/'review.json',{'status':'approved'})
        r=project_stats(self.root,J);self.assertEqual(r['approved_exports'],1);self.assertEqual(r['tokens_reported']['input_tokens'],250)
        self.assertEqual(r['ai_requests_attempted'],1)

    def test_failed_attempt_without_usage_not_zero_cost(self):
        write_json_atomic(self.root/J/'selections'/A/'selection.json',{'mode':'llm','status':'failed','request_started_at':1,'usage':None})
        r=project_stats(self.root,J);self.assertEqual(r['ai_usage_missing'],1);self.assertIsNone(r['tokens_reported']);self.assertIsNone(r['cost_usd'])

    def test_running_ai_counts_as_active_work(self):
        write_json_atomic(self.root/J/'selections'/A/'selection.json',{'mode':'llm','status':'running'})
        self.assertEqual(project_stats(self.root,J)['active_work'],1)

    def test_no_review_sessions_not_assumed_free_labor(self):
        write_json_atomic(self.root/J/'exports'/E/'export.json',{'status':'completed'})
        write_json_atomic(self.root/J/'exports'/E/'review.json',{'status':'approved'})
        self.assertIsNone(project_stats(self.root,J)['review_minutes_per_approved'])

    def test_corrupt_export_visible_as_warning(self):
        p=self.root/J/'exports'/E/'export.json';p.parent.mkdir(parents=True);p.write_text('{bad')
        self.assertGreater(project_stats(self.root,J)['warnings_count'],0)

    def test_api_lifespan_blocks_offline_backup(self):
        with TestClient(main.app):
            with self.assertRaises(LeaseBusy):
                backup.create_backup(self.root,self.root.parent/('unique-'+J+'.zip'))

    def test_ops_page_and_version(self):
        r=self.client.get('/ops');self.assertEqual(r.status_code,200);self.assertIn('v0.4.2',r.text)
        self.assertEqual(self.client.get('/health').json()['version'],'0.4.2')


class ModelLockTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.home=self.root/'hf';self.revision='f'*40
        self.snapshot=self.home/'hub'/'models--Systran--faster-whisper-tiny'/'snapshots'/self.revision
        self.snapshot.mkdir(parents=True)
        files=[]
        for name in ('config.json','tokenizer.json','model.bin'):
            p=self.snapshot/name;p.write_bytes(b'fixture-'+name.encode());files.append({'name':name,'bytes':p.stat().st_size,'sha256':backup.digest_file(p)})
        self.lock=self.root/'lock.json';write_json_atomic(self.lock,{'schema':1,'model':'tiny','repo_id':'Systran/faster-whisper-tiny','revision':self.revision,'files':files})
        self.env=mock.patch.dict(os.environ,{'CLIPFORGE_MODEL_LOCK':str(self.lock),'HF_HOME':str(self.home),'WHISPER_MODEL':'tiny'})
        self.env.start();self.addCleanup(self.env.stop);model_source._VERIFIED.clear()

    def test_pinned_snapshot_returns_local_path_without_network(self):
        self.assertEqual(model_source.resolve_model(),str(self.snapshot))

    def test_tampered_model_fails(self):
        (self.snapshot/'model.bin').write_bytes(b'corrupted')
        with self.assertRaises(ValueError):model_source.resolve_model()

    def test_missing_snapshot_fails_no_download(self):
        shutil.rmtree(self.snapshot)
        with self.assertRaises(ValueError):model_source.resolve_model()

    def test_model_name_mismatch_fails(self):
        with mock.patch.dict(os.environ,{'WHISPER_MODEL':'small'}):
            with self.assertRaises(ValueError):model_source.resolve_model()

    def test_valid_cache_blob_symlinks_supported(self):
        p=self.snapshot/'model.bin';blob=self.home/'hub'/'blob';blob.write_bytes(p.read_bytes());p.unlink();p.symlink_to(blob)
        self.assertEqual(model_source.resolve_model(),str(self.snapshot))

    def test_symlink_escape_fails(self):
        p=self.snapshot/'model.bin';blob=self.root/'outside';blob.write_bytes(p.read_bytes());p.unlink();p.symlink_to(blob)
        with self.assertRaises(ValueError):model_source.resolve_model()

    def test_model_cli_verify_never_infers(self):
        self.assertEqual(model_source.main(['verify']),0)

    def test_model_cli_download_needs_explicit_permission(self):
        self.assertEqual(model_source.main(['fetch']),1)

    def test_unlocked_legacy_mode_preserved(self):
        with mock.patch.dict(os.environ,{'WHISPER_MODEL':'tiny'},clear=True):self.assertEqual(model_source.resolve_model(),'tiny')


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)/'data'
        self.folder=self.root/J;self.folder.mkdir(parents=True)
        (self.folder/'input.mp4').write_bytes(b'original synthetic fixture')
        write_json_atomic(self.folder/'job.json',{'status':'completed','clips':[]})
        write_json_atomic(self.folder/'transcript.json',[{'start':0,'end':22,'text':'test text not ASR'}])
        self.origin={'analysis_id':A,'candidate_id':'1','mode':'llm','provider':'fixture','model':'fixture-no-inference'}
        write_json_atomic(self.folder/'selections'/A/'selection.json',{'status':'completed','mode':'llm','candidates':[{'id':'1'}]})
        write_json_atomic(self.folder/'drafts'/f'{D}.json',{'revision':2,'selection_origin':self.origin})
        self.export=self.folder/'exports'/E
        write_json_atomic(self.export/'export.json',{'status':'completed','draft_id':D,'draft_revision':1,'selection_origin':self.origin})
        write_json_atomic(self.export/'review.json',{'status':'approved'})
        (self.export/'clip.mp4').write_bytes(b'synthetic bytes not decoded');(self.export/'clip.srt').write_bytes(b'text')
        self.delivery=self.folder/'deliveries'/Z;self.delivery.mkdir(parents=True)
        files=[]
        with zipfile.ZipFile(self.delivery/'delivery.zip','w') as z:
            for name in ['clip.mp4','clip.srt']:
                path=self.export/name;n='01/'+name;z.write(path,n);files.append({'path':n,'sha256':backup.digest_file(path),'bytes':path.stat().st_size})
            z.writestr('manifest.json',json.dumps({'clips':[{'export_id':E,'files':files}]}))

    def test_saved_artifact_integrity_not_real_inference(self):
        r=inspect_project(self.root,J);self.assertEqual(r['status'],'passed');self.assertFalse(r['acceptance_ready'])
        self.assertFalse(r['whisper_executed']);self.assertFalse(r['provider_contacted']);self.assertIsNone(r['checks']['delivered_video_decoded'])

    def test_content_attestation_does_not_replace_decode(self):
        self.assertFalse(inspect_project(self.root,J,reviewed_content=True)['acceptance_ready'])

    def test_decode_invalid_media_fails(self):
        with self.assertRaises(ValueError):inspect_project(self.root,J,decode=True)

    def test_pending_review_not_accepted(self):
        write_json_atomic(self.export/'review.json',{'status':'pending'})
        r=inspect_project(self.root,J);self.assertEqual(r['status'],'incomplete')

    def test_delivery_tamper_rejected(self):
        (self.export/'clip.mp4').write_bytes(b'modified')
        with self.assertRaises(ValueError):inspect_project(self.root,J)

    def test_missing_ai_provenance_incomplete(self):
        write_json_atomic(self.export/'export.json',{'status':'completed'})
        self.assertEqual(inspect_project(self.root,J)['status'],'incomplete')

    def test_backup_restore_preserves_acceptance(self):
        before=inspect_project(self.root,J);archive=self.root.parent/'backup.zip';backup.create_backup(self.root,archive)
        dest=self.root.parent/'restored';backup.restore_backup(archive,dest)
        after=inspect_project(dest,J)
        self.assertEqual(before['checks'],after['checks']);self.assertEqual(before['source_sha256'],after['source_sha256'])

    def test_invalid_id_rejected(self):
        with self.assertRaises(ValueError):inspect_project(self.root,'../../etc')
