"""Real FFmpeg delivery -> backup -> restore -> same AI candidate IDs.

AI output and transcript are authored fixtures. There is NO real inference here.
"""
import hashlib
import json
from pathlib import Path
import os
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from auth_support import AuthenticatedTestClient as TestClient, auth_environment
from app import main, ai_selection as ai
from app.acceptance import inspect_project
from app.backup import create_backup, restore_backup
from app.check_presentation import make_source
from app.presentation import Presentation
from app.state import write_json_atomic
import test_ai_selection as f


class RecoveryFlow(unittest.TestCase):
    def test_ai_fixture_to_real_delivery_restore_and_reaccept(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'data';folder=root/f.JOB;folder.mkdir(parents=True)
            make_source(folder/'input.mp4',61)
            write_json_atomic(folder/'job.json',{'id':f.JOB,'status':'completed','clips':[],
                                               'options':Presentation().model_dump()})
            write_json_atomic(folder/'transcript.json',f.SEGMENTS)
            original_hash=hashlib.sha256((folder/'input.mp4').read_bytes()).hexdigest()
            spec={'mode':'llm','brief':f.BRIEF,'max_clips':3,'min_seconds':20,'max_seconds':60,'window_start':0,'window_end':60}
            with patch.object(main,'ROOT',root),patch.dict(os.environ,{**f.ENV,**auth_environment()},clear=True):
                with TestClient(main.app, projects=(f.JOB,)) as client:
                    preview=client.post(f'/jobs/{f.JOB}/selections/preview',json=spec)
                    self.assertEqual(preview.status_code,200,preview.text)
                    consent={**spec,'preview_token':preview.json()['preview_token'],'consent':True,'request_id':uuid.uuid4().hex}
                    with patch.object(ai,'request_selection',return_value=(f.ANSWER,f.USAGE)):
                        start=client.post(f'/jobs/{f.JOB}/selections',json=consent)
                        self.assertEqual(start.status_code,202,start.text);rid=start.json()['id']
                        for _ in range(400):
                            run=client.get(f'/jobs/{f.JOB}/selections/{rid}').json()
                            if run['status']!='running':break
                            time.sleep(.025)
                        self.assertEqual(run['status'],'completed',run)
                    candidate=run['candidates'][0]['id']
                    draft_response=client.post(f'/jobs/{f.JOB}/selections/{rid}/candidates/{candidate}/draft')
                    self.assertEqual(draft_response.status_code,201,draft_response.text)
                    draft=draft_response.json()
                    exp=client.post(f'/jobs/{f.JOB}/drafts/{draft["id"]}/exports',json={'revision':draft['revision']})
                    self.assertEqual(exp.status_code,202,exp.text);eid=exp.json()['id']
                    for _ in range(1500):
                        item=client.get(f'/jobs/{f.JOB}/exports/{eid}').json()
                        if item['status'] in {'completed','failed'}:break
                        time.sleep(.025)
                    self.assertEqual(item['status'],'completed',item)
                    review=client.put(f'/jobs/{f.JOB}/exports/{eid}/review',json={'status':'approved','revision':0,'title':'Fixture. Not AI inference.','notes':''})
                    self.assertEqual(review.status_code,200,review.text)
                    pack=client.post(f'/jobs/{f.JOB}/deliveries',json={'selections':[{'export_id':eid,'review_revision':1}]})
                    self.assertEqual(pack.status_code,201,pack.text)
                    metrics=client.get(f'/jobs/{f.JOB}/operations').json()
                    self.assertGreater(metrics['stage_seconds']['render'],0)
                    self.assertEqual(metrics['approved_exports'],1)
                # All writers stopped and the filesystem lease released before backup.
                proof=inspect_project(root,f.JOB,decode=True,reviewed_content=False)
                self.assertEqual(proof['status'],'passed');self.assertTrue(proof['checks']['delivered_video_decoded'])
                self.assertFalse(proof['acceptance_ready'])  # No human editorial acceptance claimed.
                archive=Path(temp)/'backup.zip';result=create_backup(root,archive)
                restored=Path(temp)/'restored';restore_backup(archive,restored,result['sha256'])
                proof2=inspect_project(restored,f.JOB,decode=True)
                self.assertEqual(proof['checks'],proof2['checks'])
                self.assertEqual(proof2['source_sha256'],original_hash)
                # Accept a previously UNACCEPTED candidate after restore. mtime identity matters.
                with patch.object(main,'ROOT',restored):
                    with TestClient(main.app, projects=(f.JOB,), fixture_identity=str(root)) as recovered:
                        candidate2=run['candidates'][1]['id']
                        r=recovered.post(f'/jobs/{f.JOB}/selections/{rid}/candidates/{candidate2}/draft')
                        self.assertEqual(r.status_code,201,r.text)
                        opened=recovered.get(f'/jobs/{f.JOB}/drafts/{draft["id"]}')
                        self.assertEqual(opened.status_code,200)
                        data=recovered.get(f'/jobs/{f.JOB}/exports/{eid}/files/clip.mp4')
                        self.assertEqual(data.status_code,200)
