"""0.4.2 regression: bounded range catalogs and persistent rejection diagnostics.

No external provider/LLM calls. API fixtures use real local files and ffprobe.
"""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app import main, ai_selection as ai, ai_provider as provider
from app.check_presentation import make_source
from app.state import write_json_atomic
import test_ai_selection as fixtures


def prepared():
    return {'spec': ai.SelectionSpec().model_dump(),
            'content': copy.deepcopy(fixtures.CONTENT),
            'segments': copy.deepcopy(fixtures.CONTENT['segments'])}


class RangeCatalogTests(unittest.TestCase):
    def test_exhaustive_complete_segment_intervals(self):
        segs=fixtures.CONTENT['segments']; result=ai.eligible_ranges(segs,20,60)
        expected={(a['id'],b['id']) for i,a in enumerate(segs) for b in segs[i:]
                  if 20<=round(b['end']-a['start'],3)<=60}
        self.assertEqual({(r['start_segment'],r['end_segment']) for r in result},expected)
        self.assertEqual(len({r['range_id'] for r in result}),len(result))

    def test_exact_millisecond_boundaries(self):
        s=[{'id':1,'start':0.001,'end':20.001,'text':'x'},
           {'id':2,'start':20.001,'end':60.001,'text':'y'}]
        r=ai.eligible_ranges(s,20,60)
        self.assertEqual([v['duration_seconds'] for v in r],[20.,60.,40.])

    def test_gaps_are_included_in_duration_not_sum_of_speech(self):
        s=[{'id':1,'start':0.,'end':10.,'text':'x'},
           {'id':2,'start':100.,'end':110.,'text':'y'}]
        with self.assertRaises(HTTPException) as e:ai.eligible_ranges(s,20,60)
        self.assertIn('AI_NO_ELIGIBLE_RANGES',e.exception.detail)

    def test_missing_original_segment_ids_are_not_renumbered(self):
        s=[{'id':6,'start':30.,'end':40.,'text':'x'},
           {'id':9,'start':40.,'end':50.,'text':'y'}]
        self.assertEqual(ai.eligible_ranges(s,20,60)[0]['range_id'],'r6_9')

    def test_only_complete_segments_no_padding(self):
        s=[{'id':1,'start':0.,'end':19.999,'text':'x'}]
        with self.assertRaises(HTTPException):ai.eligible_ranges(s,20,60)
        s[0]['end']=60.001
        with self.assertRaises(HTTPException):ai.eligible_ranges(s,20,60)

    def test_catalog_cap_errors_no_silent_sampling(self):
        s=[{'id':i+1,'start':float(i),'end':float(i+1),'text':'x'} for i in range(100)]
        with self.assertRaises(HTTPException) as e:ai.eligible_ranges(s,20,60)
        self.assertEqual(e.exception.status_code,413)
        self.assertIn('AI_RANGE_CATALOG_TOO_LARGE',e.exception.detail)

    def test_contract_contains_actual_enum_and_requested_count(self):
        content=copy.deepcopy(fixtures.CONTENT);content['max_clips']=2
        schema=provider.output_schema(content)
        self.assertEqual(schema['properties']['candidates']['maxItems'],2)
        props=schema['properties']['candidates']['items']['properties']
        self.assertEqual(props['range_id']['enum'],[r['range_id'] for r in content['eligible_ranges']])
        self.assertNotIn('start_segment',props);self.assertNotIn('end_segment',props)
        self.assertEqual(props['hook']['enum'],[1,2,3,4,5])

    def test_output_schema_never_mutates_template(self):
        schema=provider.output_schema(fixtures.CONTENT)
        schema['properties']['candidates']['items']['properties']['range_id']['enum'].append('bad')
        self.assertNotIn('enum',provider.OUTPUT_SCHEMA['properties']['candidates']['items']['properties']['range_id'])
        self.assertNotIn('bad',provider.output_schema(fixtures.CONTENT)['properties']['candidates']['items']['properties']['range_id']['enum'])

    def test_invalid_contract_never_reaches_network(self):
        for content in [{},{'eligible_ranges':[]},dict(fixtures.CONTENT,selection_contract='old')]:
            with self.subTest(content=bool(content)),patch.object(provider,'_post_json') as call:
                with self.assertRaises(provider.AIError):provider.request_selection(provider.AIConfig('openai','test','https://api.openai.com/v1/responses','fake'),content)
                call.assert_not_called()

    def test_bad_duplicate_or_excessive_range_ids_rejected(self):
        for ranges in [[{'range_id':'bad'}],[{'range_id':'r1_4'}]*2,[{'range_id':f'r1_{i+1}'} for i in range(501)]]:
            with self.subTest(count=len(ranges)),self.assertRaises(provider.AIError):
                provider.output_schema(dict(fixtures.CONTENT,eligible_ranges=ranges))

    def test_accepted_proposals_resolve_to_original_timestamps(self):
        report={};_,out,warn=ai.validate_answer(fixtures.ANSWER,prepared(),report)
        self.assertEqual([(r['start'],r['end']) for r in out],[(0.,20.),(20.,40.)])
        self.assertEqual(report['accepted_count'],2);self.assertEqual(report['rejected_count'],0)
        self.assertFalse(warn)

    def test_all_rejections_keep_individual_reasons(self):
        data=copy.deepcopy(fixtures.ANSWER)
        for row in data['candidates']:row['range_id']='r999_999'
        with self.assertRaises(provider.AIError) as e:ai.validate_answer(data,prepared())
        self.assertEqual(e.exception.code,'AI_NO_VALID_CANDIDATES')
        self.assertEqual(len(e.exception.warnings),2)
        self.assertEqual(e.exception.diagnostics['rejection_counts'],{'UNKNOWN_RANGE':2})

    def test_duration_still_checked_even_if_catalog_is_incorrect(self):
        p=prepared();p['content']['eligible_ranges']=[{'range_id':'r1_2','start_segment':1,'end_segment':2,'duration_seconds':30.}]
        row=dict(fixtures.ANSWER['candidates'][0],range_id='r1_2')
        with self.assertRaises(provider.AIError) as e:ai.validate_answer({'summary':'x','candidates':[row]},p)
        self.assertEqual(e.exception.diagnostics['rejected'][0]['actual_seconds'],10.)
        self.assertIn('10.000',e.exception.warnings[0])

    def test_catalog_still_checked_against_authorized_segments(self):
        p=prepared();p['content']['eligible_ranges']=[{'range_id':'r1_999','start_segment':1,'end_segment':999,'duration_seconds':20.}]
        row=dict(fixtures.ANSWER['candidates'][0],range_id='r1_999')
        with self.assertRaises(provider.AIError) as e:ai.validate_answer({'summary':'x','candidates':[row]},p)
        self.assertEqual(e.exception.diagnostics['rejected'][0]['code'],'INVALID_SEGMENTS')

    def test_overlap_preserves_first_and_reports_second(self):
        data=copy.deepcopy(fixtures.ANSWER);data['candidates'][1]['range_id']='r3_6'
        report={};_,out,w=ai.validate_answer(data,prepared(),report)
        self.assertEqual(len(out),1);self.assertEqual(report['rejected'][0]['code'],'OVERLAP')
        self.assertEqual(report['rejected'][0]['overlaps_candidate'],'1');self.assertTrue(w)

    def test_empty_answer_is_not_a_failure_or_heuristic_fallback(self):
        report={};_,out,w=ai.validate_answer({'summary':'No hay ideas completas.','candidates':[]},prepared(),report)
        self.assertEqual((out,w),([],[]));self.assertEqual(report['proposed_count'],0)

    def test_old_pair_contract_is_not_silently_coerced(self):
        row=dict(fixtures.ANSWER['candidates'][0]);row.pop('range_id');row.update(start_segment=1,end_segment=4)
        with self.assertRaises(provider.AIError) as e:ai.validate_answer({'summary':'x','candidates':[row]},prepared())
        self.assertEqual(e.exception.code,'AI_SCHEMA_INVALID')

    def test_schema_diagnostic_redacts_inputs_and_unknown_field_names(self):
        secret='private-api-key-not-for-logs'
        row=dict(fixtures.ANSWER['candidates'][0],hook=secret);row[secret]=secret
        with self.assertRaises(provider.AIError) as e:ai.validate_answer({'summary':'x','candidates':[row]},prepared())
        encoded=json.dumps(e.exception.diagnostics)
        self.assertNotIn(secret,encoded);self.assertIn('unknown_field',encoded)

    def test_unsafe_range_id_not_echoed_in_diagnostics(self):
        row=dict(fixtures.ANSWER['candidates'][0],range_id='<script>alert(1)</script>')
        with self.assertRaises(provider.AIError) as e:ai.validate_answer({'summary':'x','candidates':[row]},prepared())
        self.assertNotIn('<script>',json.dumps(e.exception.diagnostics))
        self.assertEqual(e.exception.diagnostics['rejected'][0]['range_id'],'invalid_id')

    def test_requested_count_overflow_is_not_trimmed_silently(self):
        p=prepared();p['spec']['max_clips']=1
        with self.assertRaises(provider.AIError) as e:ai.validate_answer(fixtures.ANSWER,p)
        self.assertEqual(e.exception.code,'AI_SCHEMA_INVALID')
        self.assertEqual(e.exception.diagnostics['proposed_count'],2)


class RangeAPITests(unittest.TestCase):
    """Reuse setup/helpers only; do not count inherited test methods twice."""
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();p=Path(cls.temp.name)/'source.mp4'
        make_source(p,61);cls.source_bytes=p.read_bytes()
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    setUp=fixtures.SelectionTests.setUp
    tearDown=fixtures.SelectionTests.tearDown
    spec=fixtures.SelectionTests.spec
    preview=fixtures.SelectionTests.preview
    body=fixtures.SelectionTests.body
    start=fixtures.SelectionTests.start
    wait=fixtures.SelectionTests.wait
    run_fixture=fixtures.SelectionTests.run_fixture
    originals=fixtures.SelectionTests.originals

    def test_preview_advertises_catalog_and_does_not_consume_quota(self):
        with patch.object(ai,'request_selection') as call:p=self.preview()
        self.assertEqual(p['eligible_range_count'],len(p['payload_text']['eligible_ranges']))
        self.assertGreater(p['eligible_range_count'],0);self.assertEqual(ai.daily_calls_used(),0)
        call.assert_not_called();self.originals()

    def test_all_rejected_state_keeps_usage_diagnostics_and_can_be_reopened(self):
        row=dict(fixtures.ANSWER['candidates'][0],range_id='r999_999')
        item,_=self.run_fixture({'summary':'Fixture rejection','candidates':[row]})
        self.assertEqual(item['error_code'],'AI_NO_VALID_CANDIDATES')
        self.assertTrue(item['provider_response_received']);self.assertEqual(item['usage'],fixtures.USAGE)
        self.assertEqual(item['validation']['rejection_counts'],{'UNKNOWN_RANGE':1})
        self.assertEqual(len(item['warnings']),1)
        with patch.object(ai,'request_selection') as call:
            stored=self.client.get(f'/jobs/{fixtures.JOB}/selections/{item["id"]}').json()
            self.assertEqual(stored['validation'],item['validation'])
        call.assert_not_called();self.originals()

    def test_empty_catalog_preflight_stops_before_call_or_reservation(self):
        write_json_atomic(self.folder/'transcript.json',[{'start':0.,'end':5.,'text':'Short fixture'}])
        with patch.object(ai,'request_selection') as call:
            r=self.client.post(f'/jobs/{fixtures.JOB}/selections/preview',json=self.spec())
        self.assertEqual(r.status_code,422);self.assertIn('AI_NO_ELIGIBLE_RANGES',r.text)
        self.assertEqual(ai.daily_calls_used(),0);call.assert_not_called()

    def test_catalog_cap_preflight_no_truncation_or_call(self):
        write_json_atomic(self.folder/'transcript.json',[{'start':i*.5,'end':(i+1)*.5,'text':'x'} for i in range(120)])
        with patch.object(ai,'request_selection') as call:
            r=self.client.post(f'/jobs/{fixtures.JOB}/selections/preview',json=self.spec())
        self.assertEqual(r.status_code,413);self.assertIn('AI_RANGE_CATALOG_TOO_LARGE',r.text)
        self.assertFalse((self.folder/'selections').exists());call.assert_not_called()

    def test_failed_schema_keeps_numeric_diagnostics_but_no_secret_values(self):
        row=dict(fixtures.ANSWER['candidates'][0],hook='private-model-output')
        item,_=self.run_fixture({'summary':'x','candidates':[row]})
        self.assertEqual(item['error_code'],'AI_SCHEMA_INVALID');self.assertTrue(item['provider_response_received'])
        self.assertFalse(item['validation']['schema_valid'])
        self.assertNotIn('private-model-output',json.dumps(item));self.assertNotIn(fixtures.ENV['OPENAI_API_KEY'],json.dumps(item))

    def test_old_history_read_is_immutable_and_makes_no_call(self):
        run_id='a'*32
        old={'id':run_id,'job_id':fixtures.JOB,'version':'0.4.0','status':'failed','mode':'llm',
             'error_code':'AI_NO_VALID_CANDIDATES','error':'Old generic error','candidates':[],
             'baseline':[],'warnings':[],'usage':fixtures.USAGE}
        p=ai.run_path(fixtures.JOB,run_id);write_json_atomic(p,old);before=p.read_bytes()
        with patch.object(ai,'request_selection') as call:
            result=self.client.get(f'/jobs/{fixtures.JOB}/selections/{run_id}')
        self.assertEqual(result.status_code,200);self.assertNotIn('validation',result.json())
        self.assertEqual(p.read_bytes(),before);call.assert_not_called()

    def test_successful_reply_reported_without_claiming_editorial_quality(self):
        item,_=self.run_fixture()
        self.assertTrue(item['provider_response_received']);self.assertEqual(item['validation']['accepted_count'],2)
        self.assertEqual(item['eligible_range_count'],len(fixtures.CONTENT['eligible_ranges']))
        self.assertEqual(item['candidates'][0]['range_id'],'r1_4');self.originals()

    def test_http_failure_does_not_claim_parsed_model_response(self):
        body=self.body(self.preview())
        with patch.object(ai,'request_selection',side_effect=provider.AIError('AI_ACCESS_DENIED','Rejected')):
            item=self.wait(self.start(body).json()['id'])
        self.assertFalse(item['provider_response_received']);self.assertNotIn('validation',item)

if __name__=='__main__':unittest.main()
