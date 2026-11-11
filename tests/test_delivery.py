"""v0.3.1: real ZIP and persistence tests; fake bytes only where decode is irrelevant.
The final smoke test separately exports real MP4 through FFmpeg before approval.
"""
import copy
import hashlib
import io
import json
import math
import shutil
import tempfile
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from auth_support import AuthenticatedTestClient as TestClient
from pydantic import ValidationError
from app import main, delivery
from app.presentation import Presentation
from app.subtitles import to_ass
from app.state import write_json_atomic
from app.check_branding import check_branding, black_source
from app.render import render_clip

JOB='b'*32
ONE='c'*32
TWO='d'*32
CUES=[{'start':0,'end':1.8,'text':'Corrección conservada'}]


class BrandingSchemaTests(unittest.TestCase):
    def test_legacy_defaults(self):
        p=Presentation()
        self.assertEqual((p.subtitle_position,p.subtitle_margin_v,p.subtitle_outline,p.subtitle_outline_color,p.subtitle_shadow),('bottom',230,3,'#201510',1))

    def test_ranges_and_types_rejected(self):
        for key,values in [('subtitle_margin_v',[-1,651,2.5,True,'50',math.inf]),
                           ('subtitle_outline',[-1,13,False,'3',.5]),
                           ('subtitle_shadow',[-1,9,True,.1]),
                           ('subtitle_position',['../file','BOTTOM','top,1',None]),
                           ('subtitle_outline_color',['red','#fff','#FFFFFF\n','&H00FFFFFF'])]:
            for value in values:
                with self.subTest(key=key,value=value),self.assertRaises(ValidationError):
                    Presentation(**{key:value})

    def test_alignment_codes_and_margins_in_validated_ass(self):
        for pos,n in [('top',8),('center',5),('bottom',2)]:
            text=to_ass(CUES,position=pos,margin_v=400,outline=8,outline_color='#00ffff',shadow=0)
            self.assertIn(f',1,8,0,{n},95,95,400,1',text)
            self.assertIn('&H00FFFF00',text)

    def test_no_ass_injection_direct_calls(self):
        for kwargs in [{'position':'top\n[Events]'}, {'outline_color':'#ffffff,new'}, {'margin_v':'250,1'}, {'shadow':True}]:
            with self.assertRaises(ValidationError):to_ass(CUES,**kwargs)

    def test_style_never_mutates_cues(self):
        before=copy.deepcopy(CUES)
        to_ass(CUES,position='center',outline=12,margin_v=650)
        self.assertEqual(CUES,before)

    def test_real_render_position_margin_outline(self):
        report=check_branding()
        self.assertEqual(report['status'],'ok',report)
        self.assertEqual(len(report['checks']),6)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.patch=patch.object(main,'ROOT',self.root);self.patch.start()
        self.client=TestClient(main.app, projects=(JOB,));self.folder=self.root/JOB;self.folder.mkdir()
        write_json_atomic(self.folder/'job.json',{'id':JOB,'status':'completed','clips':[]})
        (self.folder/'input.mp4').write_bytes(b'PRIVATE SOURCE MUST NOT BE INCLUDED')
        write_json_atomic(self.folder/'transcript.json',CUES)
        self.seed(ONE);self.seed(TWO)
        self.before={str(p.relative_to(self.root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}

    def tearDown(self):
        self.client.close();self.patch.stop();main.JOBS.clear();self.tmp.cleanup()

    def seed(self,eid,status='completed'):
        p=main.export_path(JOB,eid);p.mkdir(parents=True,exist_ok=True)
        # Not a playable MP4: delivery routes only check availability, not re-render.
        (p/'clip.mp4').write_bytes(b'fixture-bytes-'+eid.encode())
        (p/'clip.srt').write_text('1\n00:00:00,000 --> 00:00:01,800\nCorrección conservada\n',encoding='utf-8')
        (p/'clip.vtt').write_text('WEBVTT\n',encoding='utf-8')
        main.persist_export(JOB,{'id':eid,'job_id':JOB,'status':status,'start':0,'end':2,'clip_file':'clip_01.mp4',
                                'title':'Mi clip','options':Presentation().model_dump(),'cues':CUES})

    def review(self,eid=ONE,**kw):
        payload={'revision':0,'status':'approved','title':'Título español','notes':'Entrega revisada\nSegunda línea'};payload.update(kw)
        return self.client.put(f'/jobs/{JOB}/exports/{eid}/review',json=payload)

    def package(self,ids=None,revisions=None):
        ids=ids or [ONE];revisions=revisions or [1]*len(ids)
        return self.client.post(f'/jobs/{JOB}/deliveries',json={'selections':[{'export_id':i,'review_revision':r} for i,r in zip(ids,revisions)]})

    def assert_preserved(self):
        for name,sha in self.before.items():self.assertEqual(hashlib.sha256((self.root/name).read_bytes()).hexdigest(),sha,name)

    def test_template_only_options_no_render(self):
        options=Presentation(framing='crop',burn_subtitles=True,subtitle_position='top',subtitle_outline=10).model_dump()
        with patch.object(main,'render_clip') as renderer,patch.object(main,'process') as asr:
            r=self.client.post('/templates',json={'name':'Cliente A','options':options})
        self.assertEqual(r.status_code,201,r.text);renderer.assert_not_called();asr.assert_not_called()
        self.assertEqual(r.json()['options'],options);self.assertNotIn('cues',r.json());self.assertNotIn('start',r.json())
        self.assertEqual(self.client.get('/templates').json()['templates'][0],r.json())
        self.assertEqual(self.client.get('/templates/'+r.json()['id']).status_code,200);self.assert_preserved()

    def test_template_defaults_legacy_options(self):
        r=self.client.post('/templates',json={'name':'Base','options':{'subtitle_font_size':60}})
        self.assertEqual(r.json()['options']['subtitle_position'],'bottom')

    def test_template_duplicate_name_no_overwrite(self):
        r=self.client.post('/templates',json={'name':' Cliente  A ','options':{}})
        dup=self.client.post('/templates',json={'name':'cliente a','options':{'subtitle_outline':12}})
        self.assertEqual(dup.status_code,409)
        self.assertEqual(self.client.get('/templates/'+r.json()['id']).json()['options']['subtitle_outline'],3)

    def test_template_extra_data_and_invalid_style_rejected(self):
        for p in [{'name':' ','options':{}},{'name':'x','options':{},'cues':CUES}, {'name':'x','options':{'subtitle_outline':999}}]:
            self.assertEqual(self.client.post('/templates',json=p).status_code,422)
        self.assertFalse(delivery.template_directory(self.client.fixture_principal.workspace_id).exists())

    def test_template_corruption_reported_preserved(self):
        path=delivery.template_path(ONE,self.client.fixture_principal.workspace_id);path.parent.mkdir(parents=True);path.write_bytes(b'{')
        r=self.client.get('/templates').json();self.assertEqual(r['unreadable'],1);self.assertEqual(r['templates'],[])
        self.assertEqual(self.client.get('/templates/'+ONE).status_code,503);self.assertEqual(path.read_bytes(),b'{')

    def test_template_disk_error_controlled(self):
        with patch('app.delivery.write_json_atomic',side_effect=OSError('disk full')):
            self.assertEqual(self.client.post('/templates',json={'name':'x','options':{}}).status_code,503)

    def test_review_legacy_pending_without_writing(self):
        r=self.client.get(f'/jobs/{JOB}/exports/{ONE}/review')
        self.assertEqual(r.status_code,200);self.assertEqual(r.json()['revision'],0);self.assertEqual(r.json()['status'],'pending')
        self.assertFalse((main.export_path(JOB,ONE)/'review.json').exists())
        self.assertEqual(self.client.get(f'/jobs/{JOB}/exports').json()['exports'][0]['review']['status'],'pending')

    def test_review_save_and_conflict(self):
        r=self.review();self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()['revision'],1)
        self.assertEqual(self.review(title='otra pestaña').status_code,409)
        self.assertEqual(self.review(revision=1,status='rejected').json()['revision'],2);self.assert_preserved()

    def test_review_concurrent_one_wins(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda name:self.review(title=name).status_code,['A','B']))
        self.assertEqual(sorted(responses),[200,409])

    def test_review_rejects_noncompleted_and_missing_mp4(self):
        self.seed(ONE,'rendering');self.assertEqual(self.review().status_code,409)
        self.seed(ONE);(main.export_path(JOB,ONE)/'clip.mp4').unlink();self.assertEqual(self.review().status_code,409)

    def test_review_unknown_fields_status_and_notes_limit(self):
        for kwargs in [{'status':'published'},{'revision':False},{'notes':'x'*2001},{'title':'x'*121},{'path':'../input.mp4'}]:
            self.assertEqual(self.review(**kwargs).status_code,422)

    def test_review_corrupt_fails_closed(self):
        p=main.export_path(JOB,ONE)/'review.json';p.write_text('{')
        self.assertEqual(self.review().status_code,503)
        self.assertEqual(self.package().status_code,503)
        listed=self.client.get(f'/jobs/{JOB}/exports').json()['exports'];item=next(i for i in listed if i['id']==ONE)
        self.assertEqual(item['review']['status'],'unreadable');self.assertEqual(p.read_text(),'{')

    def test_failed_review_write_preserves_old_state(self):
        self.review();p=main.export_path(JOB,ONE)/'review.json';before=p.read_bytes()
        with patch('app.delivery.write_json_atomic',side_effect=OSError('disk')):
            self.assertEqual(self.review(revision=1,status='rejected').status_code,503)
        self.assertEqual(p.read_bytes(),before)

    def test_zip_selected_only_sha_and_no_originals(self):
        self.review(ONE);self.review(TWO)
        response=self.package();self.assertEqual(response.status_code,201,response.text)
        result=response.json();self.assertEqual(len(result['clips']),1)
        raw=self.client.get(result['download_url']);self.assertEqual(raw.status_code,200)
        with zipfile.ZipFile(io.BytesIO(raw.content)) as z:
            self.assertIsNone(z.testzip());names=z.namelist()
            self.assertEqual(len(names),6);self.assertFalse(any('input.mp4' in n or 'transcript' in n or TWO[:8] in n for n in names))
            manifest=json.loads(z.read('manifest.json'))
            self.assertEqual(manifest['clips'][0]['title'],'Título español')
            self.assertEqual(manifest['clips'][0]['notes'],'Entrega revisada\nSegunda línea')
            for f in manifest['clips'][0]['files']:self.assertEqual(hashlib.sha256(z.read(f['path'])).hexdigest(),f['sha256'])
        self.assert_preserved()

    def test_multi_variant_delivery(self):
        self.review(ONE);self.review(TWO);r=self.package([ONE,TWO]);self.assertEqual(r.status_code,201,r.text)
        self.assertEqual(len(r.json()['clips']),2)

    def test_zip_without_optional_vtt(self):
        (main.export_path(JOB,ONE)/'clip.vtt').unlink();self.review()
        self.assertEqual(len(self.package().json()['clips'][0]['files']),2)

    def test_empty_srt_without_subtitles_allowed(self):
        (main.export_path(JOB,ONE)/'clip.srt').write_text('');self.review()
        self.assertEqual(self.package().status_code,201)

    def test_no_approval_no_zip(self):
        self.assertEqual(self.package().status_code,409)
        self.review(status='rejected');self.assertEqual(self.package().status_code,409)
        self.assertFalse((self.folder/'deliveries').exists())

    def test_stale_review_blocks_zip(self):
        self.review();self.review(revision=1,notes='Changed')
        self.assertEqual(self.package().status_code,409);self.assertEqual(self.package(revisions=[2]).status_code,201)

    def test_empty_duplicate_and_too_many_selections(self):
        for ids in [[],[ONE,ONE],[ONE]*31]:
            r=self.client.post(f'/jobs/{JOB}/deliveries',json={'selections':[{'export_id':i,'review_revision':1} for i in ids]})
            self.assertEqual(r.status_code,422)

    def test_missing_file_blocks_full_package(self):
        self.review(ONE);self.review(TWO);(main.export_path(JOB,TWO)/'clip.srt').unlink()
        self.assertEqual(self.package([ONE,TWO]).status_code,409)
        self.assertFalse((self.folder/'deliveries').exists())

    def test_symlink_refused(self):
        p=main.export_path(JOB,ONE)/'clip.mp4';p.unlink();p.symlink_to(self.folder/'input.mp4')
        self.assertEqual(self.review().status_code,409)

    def test_limit_and_disk_checks(self):
        self.review()
        with patch.object(delivery,'MAX_DELIVERY_BYTES',1):self.assertEqual(self.package().status_code,413)
        with patch('app.delivery.shutil.disk_usage',return_value=shutil._ntuple_diskusage(100,100,0)):
            self.assertEqual(self.package().status_code,507)

    def test_package_error_cleanup(self):
        self.review()
        with patch('app.delivery._zip_add_file',side_effect=OSError('test')):
            self.assertEqual(self.package().status_code,503)
        self.assertEqual(list((self.folder/'deliveries').iterdir()),[])

    def test_approval_change_during_creation_aborts(self):
        self.review();original=delivery._zip_add_file;changed=False
        def during(*args,**kwargs):
            nonlocal changed
            r=original(*args,**kwargs)
            if not changed:
                self.review(revision=1,status='rejected');changed=True
            return r
        with patch('app.delivery._zip_add_file',side_effect=during):self.assertEqual(self.package().status_code,409)
        self.assertEqual(list((self.folder/'deliveries').iterdir()),[])

    def test_serial_build_lock(self):
        self.review();delivery.DELIVERY_LOCK.acquire()
        try:self.assertEqual(self.package().status_code,409)
        finally:delivery.DELIVERY_LOCK.release()

    def test_old_package_is_snapshot_after_review_change(self):
        self.review();r=self.package().json();before=self.client.get(r['download_url']).content
        self.review(revision=1,status='rejected',notes='Revocada para futuras entregas')
        self.assertEqual(self.client.get(r['download_url']).content,before)
        self.assertEqual(self.package(revisions=[2]).status_code,409)

    def test_list_and_download_after_reload(self):
        self.review();r=self.package().json();self.client.close();self.client=TestClient(main.app, projects=(JOB,))
        listing=self.client.get(f'/jobs/{JOB}/deliveries').json()
        self.assertEqual(listing['deliveries'][0]['id'],r['id']);self.assertEqual(listing['deliveries'][0]['clips_count'],1)
        self.assertEqual(self.client.get(r['download_url']).status_code,200)

    def test_unreadable_delivery_reports_error(self):
        path=delivery.delivery_path(JOB,ONE);path.mkdir(parents=True);(path/'delivery.json').write_text('{')
        r=self.client.get(f'/jobs/{JOB}/deliveries').json();self.assertEqual(r['unreadable'],1)
        self.assertEqual(self.client.get(f'/jobs/{JOB}/deliveries/{ONE}/file').status_code,503)

    def test_path_traversal_ids_rejected(self):
        for route in ['/templates/not-id',f'/jobs/{JOB}/deliveries/not-id/file',f'/jobs/{JOB}/exports/not-id/review']:
            self.assertEqual(self.client.get(route).status_code,404)
        self.assertEqual(self.client.post(f'/jobs/{JOB}/deliveries',json={'selections':[{'export_id':'../input.mp4','review_revision':1}]}).status_code,422)

    def test_new_export_is_pending_even_if_source_approved(self):
        self.review(ONE);self.assertEqual(self.client.get(f'/jobs/{JOB}/exports/{TWO}/review').json()['status'],'pending')

    def test_extended_style_roundtrips_upload(self):
        with patch.object(main.threading,'Thread'):
            r=self.client.post('/jobs',files={'file':('video.mp4',b'fixture','video/mp4')},data={
                'subtitle_position':'top','subtitle_margin_v':'120','subtitle_outline':'8','subtitle_outline_color':'#00ffff','subtitle_shadow':'0'})
        self.assertEqual(r.status_code,202,r.text)
        o=r.json()['options'];self.assertEqual(o['subtitle_outline_color'],'#00FFFF');self.assertEqual(o['subtitle_margin_v'],120)

    def test_extended_upload_invalid_never_allocates(self):
        for data in [{'subtitle_position':'???'},{'subtitle_outline':'20'},{'subtitle_shadow':'-1'},{'subtitle_margin_v':'900'}]:
            with patch.object(main.threading,'Thread') as t:
                self.assertEqual(self.client.post('/jobs',files={'file':('v.mp4',b'fixture')},data=data).status_code,422);t.assert_not_called()

    def test_actual_render_then_review_delivery_decode(self):
        source=self.folder/'real-source.mp4';black_source(source)
        out=main.export_path(JOB,ONE)/'clip.mp4'
        render_clip(source,out,start=0,end=2,cues=CUES,options=Presentation(burn_subtitles=True,subtitle_position='top',subtitle_outline=7,subtitle_outline_color='#00FFFF'))
        self.assertEqual(self.review().status_code,200)
        r=self.package();self.assertEqual(r.status_code,201,r.text)
        raw=self.client.get(r.json()['download_url']).content
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            delivered=self.root/'delivered.mp4';delivered.write_bytes(z.read(f'01_{ONE[:8]}/clip.mp4'))
        import subprocess
        result=subprocess.run(['ffmpeg','-v','error','-i',str(delivered),'-f','null','-'],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
