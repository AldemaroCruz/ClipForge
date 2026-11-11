"""v0.3.0 editorial workflow. Real ffprobe/FFmpeg fixtures, no Whisper inference."""
import copy
import hashlib
import json
import math
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from auth_support import AuthenticatedTestClient as TestClient
from pydantic import ValidationError

from app import main
from app.check_presentation import make_source
from app.editorial import EditorialContent, RangeChange, retime_cues, validate_range
from app.presentation import Presentation
from app.state import write_json_atomic
from app.workspace import read_draft

ID = 'a' * 32


class RangeTests(unittest.TestCase):
    def test_range_boundaries(self):
        self.assertEqual(validate_range(0, 1, 30), (0, 1))
        self.assertEqual(validate_range(120, 180, 180), (120, 180))
        for args in [(-1, 1, 30), (0, .999, 30), (0, 60.01, 100), (5, 5, 30),
                     (5, 4, 30), (10, 31, 30), (float('nan'), 5, 10), (0, 5, math.inf)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                validate_range(*args)

    def test_schema_invalid_and_unknown_fields(self):
        for kwargs in [dict(start=math.nan, end=10), dict(start=0, end=5, shell='bad'),
                       dict(start=0, end=5, title='  '), dict(start=0, end=5, clip_file='../job.json')]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                EditorialContent(**kwargs)

    def test_shrink_preserves_corrected_text_and_rebases(self):
        cues=[{'start':0,'end':4,'text':'corregido A'}, {'start':4,'end':10,'text':'corregido B'}, {'start':10,'end':20,'text':'C'}]
        result, stats=retime_cues(cues, 100,120,103,110,[])
        self.assertEqual(result,[{'start':0,'end':1,'text':'corregido A'},{'start':1,'end':7,'text':'corregido B'}])
        self.assertEqual(stats,{'preserved':2,'trimmed':1,'removed':1,'added':0})

    def test_extend_only_adds_outside_previous_range(self):
        transcript=[{'start':0,'end':5,'text':'antes'},{'start':5,'end':10,'text':'no resucitar borrado'}, {'start':10,'end':15,'text':'despues'}]
        cues=[{'start':1,'end':3,'text':'mi correccion'}]
        result, stats=retime_cues(cues,5,10,0,15,transcript)
        self.assertEqual([c['text'] for c in result],['antes','mi correccion','despues'])
        self.assertEqual(result[1],{'start':6,'end':8,'text':'mi correccion'})
        self.assertEqual(stats['added'],2)

    def test_disjoint_range_uses_only_transcript(self):
        result, stats=retime_cues([{'start':0,'end':2,'text':'fuera'}],0,5,10,15,[{'start':11,'end':14,'text':'nuevo'}])
        self.assertEqual(result,[{'start':1,'end':4,'text':'nuevo'}])
        self.assertEqual(stats['removed'],1)

    def test_empty_previous_cues_preserves_deletions(self):
        result,_=retime_cues([],0,10,2,8,[{'start':0,'end':10,'text':'eliminado'}])
        self.assertEqual(result,[])

    def test_new_manual_uses_transcript_and_reports_added(self):
        result,stats=retime_cues([],None,None,5,10,[{'start':6,'end':8,'text':'hola'}])
        self.assertEqual(result,[{'start':1,'end':3,'text':'hola'}]);self.assertEqual(stats['added'],1)

    def test_partial_previous_range_rejected(self):
        with self.assertRaises(ValueError):retime_cues([],0,None,1,5,[])

    def test_millisecond_tiny_overlap_dropped(self):
        result,_=retime_cues([{'start':0,'end':1,'text':'a'}],0,2,.98,2,[])
        self.assertEqual(result,[])

    def test_many_shrinks_never_make_negative_or_out_of_range_times(self):
        cues=[{'start':i,'end':i+1,'text':str(i)} for i in range(30)]
        for start in [0,.001,1.001,10.05,20.123]:
            for end in [start+1,start+5,30]:
                if end>30:continue
                result,_=retime_cues(cues,0,30,start,end,[])
                self.assertTrue(all(0<=c['start']<c['end']<=round(end-start,3)+.001 for c in result))


class WorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures=tempfile.TemporaryDirectory(prefix='clipforge-source-030-')
        cls.source=Path(cls.fixtures.name)/'source.mp4'
        make_source(cls.source,12)
        cls.source_bytes=cls.source.read_bytes()

    @classmethod
    def tearDownClass(cls):cls.fixtures.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='clipforge-workspace-')
        self.root=Path(self.tmp.name);self.folder=self.root/ID;self.folder.mkdir()
        self.root_patch=patch.object(main,'ROOT',self.root);self.root_patch.start()
        self.delay=patch.object(main,'READ_DELAY_SECONDS',0);self.delay.start()
        self.client=TestClient(main.app, projects=(ID,))
        (self.folder/'input.mp4').write_bytes(self.source_bytes)
        (self.folder/'clip_01.mp4').write_bytes(self.source_bytes)
        write_json_atomic(self.folder/'job.json',{'id':ID,'status':'completed','clips':[{'file':'clip_01.mp4','start':2,'end':12}]})
        write_json_atomic(self.folder/'transcript.json',[{'start':i,'end':i+2,'text':f'frase {i}'} for i in range(0,12,2)])
        self.originals={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.folder.iterdir() if p.is_file()}

    def tearDown(self):
        self.client.close();self.root_patch.stop();self.delay.stop();main.JOBS.clear();self.tmp.cleanup()

    def payload(self,**kwargs):
        p={'title':'Clip de prueba','clip_file':'clip_01.mp4','start':3.25,'end':6.25,
           'options':Presentation(burn_subtitles=True,subtitle_color='#FFD54F',subtitle_font_size=72).model_dump(),
           'cues':[{'start':0,'end':2,'text':'Texto corregido'}]}
        p.update(kwargs);return p

    def create(self,**kwargs):
        response=self.client.post(f'/jobs/{ID}/drafts',json=self.payload(**kwargs))
        self.assertEqual(response.status_code,201,response.text);return response.json()

    def assert_originals(self):
        self.assertEqual(self.originals,{name:hashlib.sha256((self.folder/name).read_bytes()).hexdigest() for name in self.originals})

    def test_workspace_legacy_source_and_default_style(self):
        r=self.client.get(f'/jobs/{ID}/workspace');self.assertEqual(r.status_code,200,r.text)
        self.assertAlmostEqual(r.json()['source_duration'],12,delta=.15)
        self.assertEqual(r.json()['options']['subtitle_font_size'],52);self.assertTrue(r.json()['transcript_available']);self.assert_originals()

    def test_new_range_reads_cached_transcript_without_whisper(self):
        with patch.object(main,'process') as processor:
            r=self.client.post(f'/jobs/{ID}/editor/range',json={'start':2,'end':6})
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(len(r.json()['cues']),2);processor.assert_not_called();self.assert_originals()

    def test_range_preserves_current_edits_not_only_cache(self):
        r=self.client.post(f'/jobs/{ID}/editor/range',json={'start':3,'end':7,'previous_start':2,'previous_end':8,'cues':[{'start':0,'end':4,'text':'EDITADO'}]})
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()['cues'],[{'start':0,'end':3,'text':'EDITADO'}]);self.assert_originals()

    def test_range_outside_source_rejected(self):
        for body in [{'start':0,'end':15},{'start':6,'end':2},{'start':0,'end':.5},{'start':0,'end':5,'previous_start':0}]:
            with self.subTest(body=body):self.assertEqual(self.client.post(f'/jobs/{ID}/editor/range',json=body).status_code,422)

    def test_save_no_thread_no_render_preserves_files(self):
        with patch('app.workspace.Thread') as thread,patch.object(main,'render_clip') as render:
            d=self.create()
        thread.assert_not_called();render.assert_not_called();self.assertEqual(d['revision'],1);self.assert_originals()
        self.assertFalse((self.folder/'exports').exists())
        self.assertTrue((self.folder/'drafts'/f'{d["id"]}.json').is_file())

    def test_draft_get_list_pagination_and_update(self):
        d=self.create();p=self.payload(title='CorrecciÃ³n',revision=1)
        r=self.client.put(f'/jobs/{ID}/drafts/{d["id"]}',json=p)
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()['revision'],2)
        self.assertEqual(self.client.get(f'/jobs/{ID}/drafts/{d["id"]}').json()['title'],'CorrecciÃ³n')
        self.create(title='Otro');listing=self.client.get(f'/jobs/{ID}/drafts?limit=1').json()
        self.assertEqual(listing['total'],2);self.assertTrue(listing['has_more']);self.assertNotIn('cues',listing['drafts'][0])
        self.assertEqual(len(self.client.get(f'/jobs/{ID}/drafts?offset=1&limit=1').json()['drafts']),1);self.assert_originals()

    def test_revision_conflict_keeps_saved_version(self):
        d=self.create();url=f'/jobs/{ID}/drafts/{d["id"]}'
        self.assertEqual(self.client.put(url,json=self.payload(title='Primera',revision=1)).status_code,200)
        self.assertEqual(self.client.put(url,json=self.payload(title='Perdida',revision=1)).status_code,409)
        self.assertEqual(self.client.get(url).json()['title'],'Primera')

    def test_concurrent_updates_one_wins(self):
        d=self.create();url=f'/jobs/{ID}/drafts/{d["id"]}'
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda title:self.client.put(url,json=self.payload(title=title,revision=1)).status_code,['A','B']))
        self.assertEqual(sorted(responses),[200,409]);self.assertEqual(read_draft(ID,d['id'])['revision'],2)

    def test_save_empty_cues_allowed_but_burn_export_rejected(self):
        d=self.create(cues=[]);r=self.client.post(f'/jobs/{ID}/drafts/{d["id"]}/exports',json={'revision':1})
        self.assertEqual(r.status_code,422,r.text);self.assertEqual(read_draft(ID,d['id'])['cues'],[])
        self.assertFalse((self.folder/'exports').exists())

    def test_manual_draft_without_transcript(self):
        (self.folder/'transcript.json').unlink()
        r=self.client.post(f'/jobs/{ID}/editor/range',json={'start':1,'end':5})
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()['cues'],[]);self.assertTrue(r.json()['warning'])
        self.create(clip_file=None,cues=[],options=Presentation().model_dump())

    def test_corrupt_transcript_warned_not_destroyed(self):
        path=self.folder/'transcript.json';path.write_text('{oops')
        r=self.client.get(f'/jobs/{ID}/workspace');self.assertEqual(r.status_code,200);self.assertTrue(r.json()['warning'])
        self.assertEqual(path.read_text(),'{oops')

    def test_save_invalid_times_cues_and_fields_no_directory(self):
        for p in [self.payload(end=20),self.payload(start=6,end=4),self.payload(end=3.5),self.payload(cues=[{'start':0,'end':4,'text':'Fuera'}]),self.payload(clip_file='../../input.mp4'),self.payload(title=' '),{**self.payload(),'filter':'shell'}]:
            with self.subTest(p=p):self.assertEqual(self.client.post(f'/jobs/{ID}/drafts',json=p).status_code,422)
        self.assertFalse((self.folder/'drafts').exists())

    def test_missing_source_and_active_job_rejected(self):
        p=self.folder/'input.mp4';p.unlink();self.assertEqual(self.client.post(f'/jobs/{ID}/drafts',json=self.payload()).status_code,409)
        p.write_bytes(self.source_bytes);job=json.loads((self.folder/'job.json').read_text());job['status']='rendering';write_json_atomic(self.folder/'job.json',job)
        self.assertEqual(self.client.get(f'/jobs/{ID}/workspace').status_code,409)

    def test_corrupt_draft_not_overwritten_and_list_warning(self):
        d=self.create();path=self.folder/'drafts'/f'{d["id"]}.json';path.write_text('{bad')
        self.assertEqual(self.client.get(f'/jobs/{ID}/drafts/{d["id"]}').status_code,503)
        self.assertEqual(self.client.put(f'/jobs/{ID}/drafts/{d["id"]}',json=self.payload(revision=1)).status_code,503)
        r=self.client.get(f'/jobs/{ID}/drafts').json();self.assertEqual(r['unreadable'],1);self.assertEqual(path.read_text(),'{bad')

    def test_failed_atomic_save_keeps_previous_draft(self):
        d=self.create();path=self.folder/'drafts'/f'{d["id"]}.json';before=path.read_bytes()
        # Simulated IO failure propagates; old draft remains the source of truth.
        with patch('app.state.os.replace',side_effect=OSError('simulated disk error')):
            response=self.client.put(f'/jobs/{ID}/drafts/{d["id"]}',json=self.payload(revision=1))
            self.assertEqual(response.status_code,503)
        self.assertEqual(path.read_bytes(),before)

    def test_export_snapshot_frozen_before_later_edits(self):
        d=self.create()
        with patch('app.workspace.Thread') as thread:
            r=self.client.post(f'/jobs/{ID}/drafts/{d["id"]}/exports',json={'revision':1})
        self.assertEqual(r.status_code,202,r.text);thread.assert_called_once();snapshot=r.json()
        self.client.put(f'/jobs/{ID}/drafts/{d["id"]}',json=self.payload(title='despues',revision=1,start=6,end=9))
        saved=main.read_export(ID,snapshot['id'])
        self.assertEqual(saved['start'],3.25);self.assertEqual(saved['title'],'Clip de prueba');self.assertEqual(saved['draft_revision'],1)
        self.assert_originals()

    def test_stale_export_revision_rejected(self):
        d=self.create();self.assertEqual(self.client.post(f'/jobs/{ID}/drafts/{d["id"]}/exports',json={'revision':2}).status_code,409)
        self.assertFalse((self.folder/'exports').exists())

    def test_export_start_thread_failure_draft_survives(self):
        d=self.create()
        with patch('app.workspace.Thread') as thread:
            thread.return_value.start.side_effect=RuntimeError('thread fail')
            r=self.client.post(f'/jobs/{ID}/drafts/{d["id"]}/exports',json={'revision':1})
        self.assertEqual(r.status_code,503);self.assertEqual(read_draft(ID,d['id'])['revision'],1)
        exports=self.client.get(f'/jobs/{ID}/exports').json()['exports'];self.assertEqual(exports[0]['status'],'failed')

    def test_real_manual_export_duration_media_cues_and_hashes(self):
        d=self.create(clip_file=None)
        r=self.client.post(f'/jobs/{ID}/drafts/{d["id"]}/exports',json={'revision':1})
        self.assertEqual(r.status_code,202,r.text);eid=r.json()['id']
        for _ in range(300):
            item=self.client.get(f'/jobs/{ID}/exports/{eid}').json()
            if item['status'] in {'completed','failed'}:break
            time.sleep(.05)
        self.assertEqual(item['status'],'completed',item)
        output=self.folder/'exports'/eid/'clip.mp4'
        from app.media import inspect_media
        media=inspect_media(output,min_duration=0)
        # Source fixture is 5 fps: non-frame-aligned cuts can differ by one 0.2 s frame.
        self.assertAlmostEqual(media['duration_seconds'],3,delta=.21)
        self.assertEqual(media['audio_streams'],1)
        self.assertEqual((media['width'],media['height']),(1080,1920))
        srt=self.client.get(f'/jobs/{ID}/exports/{eid}/files/clip.srt')
        self.assertEqual(srt.status_code,200);self.assertIn('00:00:00,000 --> 00:00:02,000',srt.text);self.assertIn('Texto corregido',srt.text)
        partial=self.client.get(f'/jobs/{ID}/exports/{eid}/files/clip.mp4?inline=true',headers={'Range':'bytes=0-99'})
        self.assertEqual(partial.status_code,206);self.assertEqual(len(partial.content),100)
        self.assert_originals()

    def test_list_legacy_projects_and_rename_without_mutating_job(self):
        r=self.client.get('/projects').json();self.assertEqual(r['total'],1);self.assertEqual(r['projects'][0]['date_kind'],'legacy_file')
        self.assertEqual(r['projects'][0]['title'],f'Proyecto {ID[:8]}')
        rename=self.client.patch(f'/projects/{ID}',json={'title':'Entrevista inicial'})
        self.assertEqual(rename.status_code,200);self.assertEqual(self.client.get('/projects?q=entrevista').json()['total'],1)
        self.assertEqual(self.client.get('/projects?q=notfound').json()['total'],0);self.assert_originals()

    def test_library_pagination_and_unreadable_entry(self):
        self.client.own_projects(*[ch*32 for ch in ['b','c','d']])
        for ch in ['b','c','d']:
            folder=self.root/(ch*32);folder.mkdir();(folder/'job.json').write_text('{broken')
        r=self.client.get('/projects?limit=2').json();self.assertEqual(r['total'],4);self.assertEqual(len(r['projects']),2);self.assertTrue(r['has_more']);self.assertEqual(r['unreadable'],3)
        self.assertFalse(self.client.get('/projects?offset=2&limit=2').json()['has_more'])
        self.assertEqual(self.client.get('/projects?limit=0').status_code,422)

    def test_thumbnail_real_jpeg_cache_preserves_originals(self):
        r=self.client.get(f'/projects/{ID}/thumbnail');self.assertEqual(r.status_code,200,r.text[:100] if r.status_code!=200 else '')
        self.assertTrue(r.content.startswith(b'\xff\xd8'));self.assertEqual(r.headers['content-type'],'image/jpeg')
        with patch('app.workspace.subprocess.run') as run:
            cached=self.client.get(f'/projects/{ID}/thumbnail')
        run.assert_not_called();self.assertEqual(r.content,cached.content);self.assert_originals()

    def test_corrupt_project_metadata_preserved(self):
        path=self.folder/'project.json';path.write_text('{broken')
        self.assertEqual(self.client.patch(f'/projects/{ID}',json={'title':'X'}).status_code,409)
        self.assertTrue(self.client.get('/projects').json()['projects'][0]['metadata_warning']);self.assertEqual(path.read_text(),'{broken')

    def test_manual_upload_never_calls_whisper_and_saves_filename(self):
        with patch.object(main,'process') as process:
            r=self.client.post('/jobs',data={'processing_mode':'manual'},files={'file':('Demo.mp4',self.source_bytes,'video/mp4')})
        self.assertEqual(r.status_code,202,r.text);job=r.json();self.assertEqual(job['source_filename'],'Demo.mp4');self.assertIn('created_at',job)
        # No native ASR modules are present here: the manual path must succeed without importing them.
        main._process(job['id']);state=main.load_job(job['id'])
        self.assertEqual(state['status'],'completed',state);self.assertEqual(state['clips'],[])
        self.assertFalse((self.root/job['id']/'transcript.json').exists())

    def test_real_manual_api_upload_draft_export_without_asr(self):
        # Unmocked API -> upload thread -> ffprobe -> draft -> export thread -> FFmpeg.
        response=self.client.post('/jobs',data={'processing_mode':'manual'},files={'file':('Toma manual.mp4',self.source_bytes,'video/mp4')})
        self.assertEqual(response.status_code,202,response.text);job_id=response.json()['id']
        for _ in range(300):
            job=self.client.get(f'/jobs/{job_id}').json()
            if job['status'] in {'completed','failed'}:break
            time.sleep(.03)
        self.assertEqual(job['status'],'completed',job);self.assertEqual(job['clips'],[])
        body=self.payload(clip_file=None,start=0,end=2,cues=[],options=Presentation().model_dump())
        draft=self.client.post(f'/jobs/{job_id}/drafts',json=body)
        self.assertEqual(draft.status_code,201,draft.text)
        result=self.client.post(f'/jobs/{job_id}/drafts/{draft.json()["id"]}/exports',json={'revision':1})
        self.assertEqual(result.status_code,202,result.text);eid=result.json()['id']
        for _ in range(300):
            item=self.client.get(f'/jobs/{job_id}/exports/{eid}').json()
            if item['status'] in {'completed','failed'}:break
            time.sleep(.03)
        self.assertEqual(item['status'],'completed',item)
        self.assertEqual((self.root/job_id/'input.mp4').read_bytes(),self.source_bytes)
        self.assertFalse((self.root/job_id/'transcript.json').exists())
        self.assertEqual(self.client.get(f'/jobs/{job_id}/exports/{eid}/files/clip.mp4').status_code,200)

    def test_invalid_upload_mode_rejected(self):
        r=self.client.post('/jobs',data={'processing_mode':'unknown'},files={'file':('a.mp4',self.source_bytes,'video/mp4')})
        self.assertEqual(r.status_code,422)

    def test_library_survives_malformed_optional_metadata(self):
        path=self.folder/'job.json';job=json.loads(path.read_text())
        job.update(media=['bad'],source_filename=['bad'],created_at=True)
        write_json_atomic(path,job)
        response=self.client.get('/projects')
        self.assertEqual(response.status_code,200,response.text)
        item=response.json()['projects'][0]
        self.assertIsNone(item['duration']);self.assertEqual(item['date_kind'],'legacy_file')

    def test_bad_draft_metadata_is_reported_as_unreadable(self):
        d=self.create();path=self.folder/'drafts'/f'{d["id"]}.json'
        item=json.loads(path.read_text());item.pop('updated_at');write_json_atomic(path,item)
        response=self.client.get(f'/jobs/{ID}/drafts')
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['unreadable'],1)

    def test_cues_without_previous_range_are_not_silently_discarded(self):
        response=self.client.post(f'/jobs/{ID}/editor/range',json={'start':1,'end':5,'cues':[{'start':0,'end':1,'text':'corregido'}]})
        self.assertEqual(response.status_code,422,response.text)

    def test_wrong_ids_are_not_paths(self):
        for path in ['/jobs/invalid/workspace',f'/jobs/{ID}/drafts/invalid','/projects/invalid/thumbnail']:
            self.assertEqual(self.client.get(path).status_code,404,path)


if __name__=='__main__':unittest.main()
