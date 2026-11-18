"""Postverification contracts using authored bytes and simulated transports.

No test reads an operator state, policy, credential or receipt. Production raw
hash selectors, when needed, are explicitly replaced by hashes of own fixtures.
"""
import ast
from copy import deepcopy
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit
from types import SimpleNamespace

from scripts import check_tf_int as c, int_release as custody, int_foundation_close as close
from scripts import int_foundation_verify as verify
from tests.test_int_foundation_recovery import authored_partial, authored_plan
from tests.test_int_foundation_close import authored_iam
from tests import test_int_foundation_close as close_fixtures

PRIVATE = 'synthetic-private-postverification-sentinel'
NEW_COMMIT = 'f' * 40
OBSERVED = '2026-11-18T21:00:00+00:00'


def authored_inputs():
    state6_raw, _, parent = authored_partial(serial6=True)
    state = json.loads(state6_raw); state['serial'] = 7
    state['resources'].append({'mode':'managed','type':'google_iap_tunnel_instance_iam_member','name':'protected_bootstrap',
        'provider':'provider["registry.terraform.io/hashicorp/google"]','instances':[{'attributes':{
            'project':'816643438938','zone':'us-central1-a','instance':'1670495097211408131',
            'role':'roles/iap.tunnelResourceAccessor',
            'member':'serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com',
            'condition':[],'private_attribute':PRIVATE}}]})
    raw=custody.canonical(state)
    pin={'name':c.PREFIX+'/default.tfstate','generation':'1795030868572779','size':len(raw),'sha256':custody.sha256(raw),
         'lineage':'813c84a2-2ef1-ceb3-177e-3a2c3b815066','serial':7,'terraform_version':'1.15.8'}
    cfg={'schema':'clipforge-int-foundation-postverification-config-1',
        'operation':'read_only_postverification_with_optional_single_immutable_receipt','project_id':'clipforgebeta2','project_number':'816643438938',
        'backend':{'bucket':c.BUCKET,'prefix':c.PREFIX,'workspace':'default'},'state':pin,'parent_state':close.backend_fields(parent),
        'iam_package':authored_iam(),'managed_addresses':sorted(c.FOUNDATION_ADDRESSES),
        'critical_unchanged_addresses':['google_compute_instance.postgres','google_compute_disk.postgres','google_logging_project_sink.access'],
        'original_execution':{'run_id':'44382086626','run_attempt':'1','workflow':'.github/workflows/int-foundation-close.yml',
            'control_commit':'65057bbc51c6a3907d5529a3aae543f82583814e','workflow_conclusion':'failure',
            'native_completion_status':'native_close_apply_completed_postverification_failed_no_retry',
            'native_completion_observed_utc':'2026-11-18T19:47:28.901635+00:00'},
        'receipt':{'schema':'clipforge-int-foundation-postverification-receipt-1','prefix':'private-plans/int/',
            'original_run_component':'44382086626-1','filename':'foundation-state.json','if_generation_match':'0','maximum_bytes':65536},
        'runtime_authorized':False,'guest_authorized':False,'application_authorized':False}
    metadata={'name':pin['name'],'generation':pin['generation'],'size':str(pin['size'])}
    inventory={'items':[deepcopy(metadata)]}
    return cfg,state6_raw,raw,state,metadata,inventory


class FoundationPostverificationContract(unittest.TestCase):
    def setUp(self):
        self.cfg,self.state6_raw,self.raw,self.state,self.metadata,self.inventory=authored_inputs()
        self.management=next(row for row in self.cfg['iam_package']['bindings'] if row['key']=='iap_management')
        self.management['binding_id']='iap_management'
        self.policy={'version':3,'etag':'synthetic-private-etag','bindings':[
            {'role':close.FUNCTIONAL_ROLE,'members':[close.DEPLOY_MEMBER]},
            {'role':close.MANAGEMENT_ROLE,'members':[close.TF_MEMBER],
             'condition':{'title':'Historical expired binding kept','expression':'request.time < timestamp("2026-11-18T04:48:38Z")'}},
            {'role':'roles/viewer','members':['user:'+PRIVATE]}]}
        self.baseline={**deepcopy(self.policy),'bindings':deepcopy(self.policy['bindings'][1:])}
        selections={'STATE_PIN':deepcopy(self.cfg['state']),'BASELINE_SHA':custody.sha256(custody.canonical(self.baseline)),
                    'BASELINE_SIZE':len(custody.canonical(self.baseline))}
        for name,value in selections.items():
            patch=mock.patch.object(verify,name,value);patch.start();self.addCleanup(patch.stop)
        for name,value in {'EXPECTED_BINDINGS_SHA256':custody.sha256(custody.canonical(self.cfg['iam_package']['bindings'])),
                           'EXPECTED_IAM_SOURCE_SHA256':self.cfg['iam_package']['source_proposal_sha256'],
                           'EXPECTED_IAM_MANIFEST_SHA256':self.cfg['iam_package']['manifest_sha256']}.items():
            patch=mock.patch.object(close,name,value);patch.start();self.addCleanup(patch.stop)

    def metadata_contract(self):
        cfg,_=self.evidence_fixture()
        # Metadata-only parent selection; no synthetic bytes claim this real
        # production digest. Evidence tests instead retain their own parent hash.
        cfg['parent_state'].update(sha256='360a728e0e3dcb37050389b5bf936a4359107eeeb579794b96d35743a59a1f43',size=109542)
        names={'owner_decision':'close-owner-decision.authorized.json','administrative_authorization':'owner-administrative-authorization.json',
               'close_summary':'run-44382086626/close-summary.json','grant_index':'receipts/receipt-index.json',
               'withdrawal_index':'withdrawal-receipts/receipt-index.json','baseline_iap_policy':'iap-iam.json'}
        for key,name in names.items():cfg['local_evidence'][key]['name']=name
        return cfg

    def evidence_fixture(self, raw=None, cfg=None, metadata=None, inventory=None):
        cfg=deepcopy(cfg or self.cfg);raw=raw or self.raw
        metadata=deepcopy(metadata or self.metadata);inventory=deepcopy(inventory or self.inventory)
        _,_,contract=authored_partial(serial6=True)
        plan=authored_plan(contract);plan_raw=custody.canonical(plan)
        prefix='private-plans/int/24c753bd04cd3e530f08acee3768cb10545d1977/44360231461-1/'
        ref=lambda name,value,generation:{'name':prefix+name,'sha256':custody.sha256(value),'size':len(value),'generation':generation}
        cfg['plan']={'configuration_commit':verify.PRODUCER,'controls_commit':verify.PRODUCER,'run_id':'44360231461','run_attempt':'1',
            'configuration_sha256':'bf2a20357afc9ccd86edf34efd4a069ba7f43eb14b2853022ec031a9850fe0e1',
            'provider_lock_sha256':'89e2189a1b882ac5ad3ce74ad17a304e95cf7fa072b9ced86fce09e78b88b5fa',
            'terraform_version':'1.15.8','provider_version':'8.11.0','created_utc':'2026-11-18T17:36:00Z','expires_utc':'2026-11-19T17:36:00Z',
            'json':ref('int.json',plan_raw,'1002'),'binary':ref('int.tfplan',b'Authored binary; never executed','1001')}
        manifest={'configuration_commit':verify.PRODUCER,'run_id':'44360231461','binary':cfg['plan']['binary'],'json':cfg['plan']['json']}
        manifest_raw=custody.canonical(manifest);cfg['plan']['manifest']=ref('manifest.json',manifest_raw,'1003')
        cfg['historical_observations']={'grants_first_utc':'2026-11-18T19:31:27+00:00','grants_completed_utc':'2026-11-18T19:34:52+00:00',
            'owner_decision_checked_utc':'2026-11-18T19:35:51+00:00','withdrawal_first_utc':'2026-11-18T19:48:16+00:00','withdrawal_completed_utc':'2026-11-18T19:48:33+00:00'}
        cfg['local_evidence']={key:{'name':key+'.json','size':1,'sha256':digest} for key,digest in (
            ('owner_decision',verify.DECISION_SHA),('administrative_authorization','a'*64),('close_summary',verify.SUMMARY_SHA),
            ('grant_index',verify.GRANT_SHA),('withdrawal_index',verify.WITHDRAW_SHA))}
        baseline_raw=custody.canonical(self.baseline)
        cfg['local_evidence']['baseline_iap_policy']={'name':'authored-baseline.json','size':len(baseline_raw),'sha256':custody.sha256(baseline_raw)}
        history={'owner_decision_sha256':verify.DECISION_SHA,'grants':{'bindings_granted_and_verified':11,'existing_roles_verified':9,'receipt_files':97,
            'administrator_receipt_index_sha256':verify.GRANT_SHA},'grant_receipt_index_sha256':verify.GRANT_SHA,
            'withdrawal_receipt_index_sha256':verify.WITHDRAW_SHA,'withdrawal_receipt_files':9,'observed_utc':cfg['historical_observations'],
            'historical_window_only':close.WINDOW,'current_temporary_read_grants_required':False,'current_window_validity_not_required':True,
            'original_close_summary_sha256':verify.SUMMARY_SHA}
        return cfg,dict(new_commit=NEW_COMMIT,observed_utc=OBSERVED,history=history,manifest_raw=manifest_raw,plan_raw=plan_raw,
            state6_raw=self.state6_raw,state7_raw=raw,state_metadata=metadata,inventory=inventory,vm={},disks=[],sink={},
            iap_policy=deepcopy(self.policy),baseline_iap_policy_raw=baseline_raw,read_actor={
                'account':'admin@ixbalam.studio','source':'usual_admin_guard_external',
                'guard_source_sha256':'46e619f6a72fc1e20dce21f890749971328ba37c5cd206b17a8e031bfd753704'})

    def run_authored_evidence(self, cfg, kwargs):
        # Production immutable-reference selection cannot accept synthetic raw
        # parent bytes. Only that selection boundary is mocked; the full state,
        # plan/provenance, IAP and closed receipt validators execute normally.
        with mock.patch.object(verify,'validate_contract',side_effect=lambda value:value), \
                mock.patch.object(verify,'BASELINE_SHA',cfg['local_evidence']['baseline_iap_policy']['sha256']), \
                mock.patch.object(verify,'validate_vm',return_value={'instance_id':'1670495097211408131','configuration_sha256':'a'*64,
                    'startup_unchanged':True,'two_retained_disks':True,'guest_access_performed':False}), \
                mock.patch.object(verify,'validate_sink',return_value={'name':'clipforge-int-access','destination_sha256':'a'*64,
                    'filter_sha256':'b'*64,'stable_API_configuration_sha256':'c'*64,'enabled':True,'API_writer_identity_absent_or_empty':True,
                    'provider_8_11_read_unique_writer_identity':True,'representation_converged_without_second_plan':True,
                    'exclusive_writer_identity_not_inferred':True,'operational_audit_coverage_not_inferred':True}):
            return verify.verify_evidence(cfg,**kwargs)

    def test_current_state_requires_the_exact_generation_hash_header_and_all_42_untainted_addresses(self):
        proof=verify.validate_current_state(self.raw,self.metadata,self.inventory,self.cfg)
        self.assertNotIn(PRIVATE,json.dumps(proof));self.assertEqual(proof['serial'],7)
        for scenario in ('generation','sha','size','serial','serial-float','lineage','terraform','version','missing','duplicate','tainted','deposed','lock','other-workspace'):
            cfg=deepcopy(self.cfg);state=deepcopy(self.state);metadata=deepcopy(self.metadata);inventory=deepcopy(self.inventory)
            if scenario=='generation':metadata['generation']='1795030868572780'
            elif scenario=='sha':cfg['state']['sha256']='e'*64
            elif scenario=='size':cfg['state']['size']+=1
            elif scenario=='serial':state['serial']=8
            elif scenario=='serial-float':state['serial']=7.0
            elif scenario=='lineage':state['lineage']='unreviewed-lineage'
            elif scenario=='terraform':state['terraform_version']='1.15.7'
            elif scenario=='version':state['version']=3
            elif scenario=='missing':state['resources'].pop(0)
            elif scenario=='duplicate':state['resources'].append(deepcopy(state['resources'][0]))
            elif scenario=='tainted':state['resources'][0]['instances'][0]['status']='tainted'
            elif scenario=='deposed':state['resources'][0]['instances'][0]['deposed']='old'
            elif scenario=='lock':inventory['items'].append({'name':c.PREFIX+'/default.tflock','generation':'2002'})
            else:inventory['items'].append({'name':c.PREFIX+'/other.tfstate','generation':'2002'})
            raw=custody.canonical(state)
            if raw!=self.raw:
                cfg['state'].update(size=len(raw),sha256=custody.sha256(raw));metadata['size']=str(len(raw));inventory['items'][0]['size']=str(len(raw))
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):
                verify.validate_current_state(raw,metadata,inventory,cfg)

    def test_state_iap_accepts_only_short_or_exact_canonical_numeric_identity_and_empty_condition(self):
        for instance in ('1670495097211408131',close.IAP_RESOURCE):
            for condition in (None,[]):
                state=deepcopy(self.state);attributes=state['resources'][-1]['instances'][0]['attributes']
                attributes.update(instance=instance,condition=condition)
                raw=custody.canonical(state);cfg=deepcopy(self.cfg);metadata=deepcopy(self.metadata);inventory=deepcopy(self.inventory)
                cfg['state'].update(size=len(raw),sha256=custody.sha256(raw));metadata['size']=str(len(raw));inventory['items'][0]['size']=str(len(raw))
                evidence,kwargs=self.evidence_fixture(raw,cfg,metadata,inventory)
                self.run_authored_evidence(evidence,kwargs)
        for field,value in (('instance','projects/other/iap_tunnel/zones/us-central1-a/instances/1670495097211408131'),
                            ('instance','prefix/'+close.IAP_RESOURCE),('instance','clipforge-int-base-postgres'),
                            ('project','clipforgebeta2'),('zone','us-central1-b'),('role','roles/owner'),('member',close.TF_MEMBER),
                            ('condition',{}),('condition',[{'expression':'true'}])):
            state=deepcopy(self.state);state['resources'][-1]['instances'][0]['attributes'][field]=value
            raw=custody.canonical(state);cfg=deepcopy(self.cfg);metadata=deepcopy(self.metadata);inventory=deepcopy(self.inventory)
            cfg['state'].update(size=len(raw),sha256=custody.sha256(raw));metadata['size']=str(len(raw));inventory['items'][0]['size']=str(len(raw))
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                evidence,kwargs=self.evidence_fixture(raw,cfg,metadata,inventory)
                self.run_authored_evidence(evidence,kwargs)

    def test_iap_postwithdraw_requires_functional_member_and_only_the_reviewed_management_binding_absent(self):
        proof=verify.validate_iap_policy(self.policy,self.cfg)
        self.assertNotIn(PRIVATE,json.dumps(proof))
        for scenario in ('new-management-present','functional-missing','functional-conditional','functional-duplicate','wrong-functional-member'):
            value=deepcopy(self.policy)
            if scenario=='new-management-present':value['bindings'].append({'role':self.management['role'],'members':[self.management['member']],
                'condition':self.management['condition']})
            elif scenario=='functional-missing':value['bindings'].pop(0)
            elif scenario=='functional-conditional':value['bindings'][0]['condition']={'expression':'true'}
            elif scenario=='functional-duplicate':value['bindings'].append(deepcopy(value['bindings'][0]))
            else:value['bindings'][0]['members']=[close.TF_MEMBER]
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):verify.validate_iap_policy(value,self.cfg)

    def test_contract_preserves_failed_original_run_and_rejects_changed_scope_future_history_or_overwrite_target(self):
        cfg=self.metadata_contract();self.assertEqual(verify.validate_contract(cfg),cfg)
        for scenario in ('bucket','backend','state-generation','old-commit','workflow-success','future-completion','overwrite','runtime'):
            value=deepcopy(cfg)
            if scenario=='bucket':value['backend']['bucket']='other-bucket'
            elif scenario=='backend':value['backend']['prefix']='terraform/other'
            elif scenario=='state-generation':value['state']['generation']='1795030868572780'
            elif scenario=='old-commit':value['original_execution']['control_commit']=NEW_COMMIT
            elif scenario=='workflow-success':value['original_execution']['workflow_conclusion']='success'
            elif scenario=='future-completion':value['original_execution']['native_completion_observed_utc']='2030-01-01T00:00:00Z'
            elif scenario=='overwrite':value['receipt']['if_generation_match']='1795030868572779'
            else:value['runtime_authorized']=True
            token=mock.Mock(side_effect=AssertionError('Invalid contract must fail before token'))
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):verify.Client(value,token)
            token.assert_not_called()

    def test_transport_cannot_reach_unreviewed_endpoint_method_bucket_or_state_write_before_authentication(self):
        cfg=self.metadata_contract();token=mock.Mock(side_effect=AssertionError('Capability guard must run first'))
        client=verify.Client(cfg,token)
        bad=[('https://attacker.invalid/'+PRIVATE,'GET',None),
             ('https://iap.googleapis.com/v1/'+close.IAP_RESOURCE+':setIamPolicy','POST',{}),
             (verify.VM_URL,'DELETE',None),(verify.IAP_URL,'POST',{'policy':{'bindings':[]}}),
             (verify.metadata_url(cfg).replace(c.BUCKET,'other-bucket'),'GET',None),
             ('https://storage.googleapis.com/upload/storage/v1/b/'+c.BUCKET+'/o?uploadType=media&name='+c.PREFIX+'/default.tfstate&ifGenerationMatch=0','POST',{})]
        for url,method,payload in bad:
            with self.subTest(url=url,method=method),self.assertRaises(ValueError):client.read(url,method=method,payload=payload)
            with self.assertRaises(ValueError):client._send(url,method,custody.canonical(payload) if payload is not None else None)
        reference=deepcopy(cfg['state']);reference['name']='other/private-object'
        with self.assertRaises(ValueError):client.fetch(reference)
        token.assert_not_called()

    def test_transport_allows_only_fixed_reads_and_does_not_expose_http_error_body(self):
        cfg=self.metadata_contract();token=mock.Mock(return_value='synthetic-private-token-long-enough')
        client=verify.Client(cfg,token)
        response=mock.MagicMock();response.__enter__.return_value.read.return_value=b'{"authored":true}'
        opener=mock.Mock();opener.open.return_value=response
        with mock.patch.object(verify,'build_opener',return_value=opener):
            self.assertEqual(client.read(verify.VM_URL),{'authored':True})
            self.assertEqual(client.read(verify.IAP_URL,method='POST',payload=verify.IAP_BODY),{'authored':True})
        self.assertEqual([call.args[0].get_method() for call in opener.open.call_args_list],['GET','POST'])
        self.assertEqual(opener.open.call_args_list[1].args[0].data,custody.canonical({'options':{'requestedPolicyVersion':3}}))
        body=mock.Mock();body.read.side_effect=AssertionError('HTTP failure payload must not be read')
        opener.open.side_effect=verify.HTTPError(verify.VM_URL,403,PRIVATE,{'Authorization':'Bearer '+PRIVATE},body)
        with mock.patch.object(verify,'build_opener',return_value=opener),self.assertRaises(ValueError) as raised:client.read(verify.VM_URL)
        body.read.assert_not_called();self.assertNotIn(PRIVATE,str(raised.exception))

    def test_pure_receipt_keeps_four_distinct_facts_after_grants_expire_without_any_native_execution(self):
        cfg,kwargs=self.evidence_fixture()
        with mock.patch.object(close.driver,'run',side_effect=AssertionError('No native execution')) as native, \
                mock.patch.object(close.driver,'terraform_binary',side_effect=AssertionError('No Terraform lookup')) as binary, \
                mock.patch.object(close,'apply_reviewed',side_effect=AssertionError('No apply')) as apply, \
                mock.patch.object(close.recovery,'plan_recovery',side_effect=AssertionError('No plan')) as plan:
            receipt=self.run_authored_evidence(cfg,kwargs)
        for prohibited in (native,binary,apply,plan):prohibited.assert_not_called()
        self.assertEqual(set(receipt['facts']),{'historical_native_execution','observed_foundation','administrative_history_and_retirement','independent_postverification'})
        native_fact=receipt['facts']['historical_native_execution']
        self.assertEqual(native_fact['run_id'],'44382086626');self.assertEqual(native_fact['workflow_conclusion'],'failure')
        self.assertTrue(native_fact['native_apply_completed']);self.assertTrue(native_fact['workflow_failure_preserved'])
        self.assertEqual(receipt['issuer']['observed_utc'],OBSERVED)
        self.assertGreater(datetime.fromisoformat(OBSERVED),datetime(2026,11,18,20,15,tzinfo=timezone.utc))
        for flag in ('runtime_authorized','guest_authorized','application_authorized'):self.assertIs(receipt[flag],False)
        self.assertNotIn(PRIVATE,json.dumps(receipt));self.assertNotIn('attributes',json.dumps(receipt).replace('attributes_sha256','').replace('all_attributes_equal_to_serial6',''))

    def test_receipt_rejects_arbitrary_payload_changed_failure_fact_or_false_capability_claim(self):
        cfg,kwargs=self.evidence_fixture();receipt=self.run_authored_evidence(cfg,kwargs)
        for scenario in ('arbitrary','false-native','success','commit','state','credentials'):
            value=deepcopy(receipt)
            if scenario=='arbitrary':value['facts']['independent_postverification']['arbitrary_payload']=PRIVATE
            elif scenario=='false-native':value['facts']['independent_postverification']['no_native_execution']=False
            elif scenario=='success':value['facts']['historical_native_execution']['workflow_conclusion']='success'
            elif scenario=='commit':value['issuer']['control_commit']=cfg['original_execution']['control_commit']
            elif scenario=='state':value['facts']['observed_foundation']['state']['serial']=8
            else:value['facts']['observed_foundation']['credentials']=PRIVATE
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):verify.validate_receipt(value,cfg,NEW_COMMIT)

    def test_new_module_has_no_subprocess_or_dynamic_execution_or_native_apply_entry_point(self):
        tree=ast.parse(inspect.getsource(verify))
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):self.assertNotIn('subprocess',{alias.name for alias in node.names})
            elif isinstance(node,ast.ImportFrom):self.assertNotEqual(node.module,'subprocess')
            elif isinstance(node,ast.Call):
                if isinstance(node.func,ast.Name):self.assertNotIn(node.func.id,{'exec','eval','__import__'})
                elif isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,{'system','popen','terraform_binary','apply_reviewed','plan_recovery','apply_saved'})
        self.assertEqual(set(vars(verify.Client)) & {'run','apply','plan','import_state','set_iam_policy'},set())

    def test_receipt_bundle_rejects_path_traversal_before_opening_an_unlisted_file(self):
        with tempfile.TemporaryDirectory(prefix='clipforge-verify-receipt-path-') as temporary:
            root=Path(temporary);bundle=root/'bundle';bundle.mkdir()
            (root/'owned-synthetic.txt').write_text(PRIVATE)
            files=[{'name':f'{number:04d}.json','sha256':'a'*64} for number in range(1,98)]
            files[0]={'name':'../owned-synthetic.txt','sha256':custody.sha256(PRIVATE.encode())}
            index={'schema':'clipforge-int-read-admin-receipt-index-1','manifest_sha256':'a'*64,'source_proposal_sha256':'b'*64,'files':files}
            raw=custody.canonical(index);(bundle/'receipt-index.json').write_bytes(raw)
            reference={'name':'receipt-index.json','size':len(raw),'sha256':custody.sha256(raw)}
            original=Path.read_bytes
            def read(path):
                self.assertNotEqual(path.resolve(),(root/'owned-synthetic.txt').resolve())
                return original(path)
            with mock.patch.object(Path,'read_bytes',read),self.assertRaises(ValueError):verify._bundle(bundle,reference,97)

    def test_complete_baseline_policy_preserves_other_expired_bindings_and_rejects_unrelated_policy_changes(self):
        proof=verify.validate_iap_policy(self.policy,self.cfg,baseline=self.baseline)
        self.assertTrue(proof['all_other_policy_bindings_preserved'])
        for field in ('member','condition','role'):
            current=deepcopy(self.policy)
            if field=='member':current['bindings'][-1]['members']=['user:changed']
            elif field=='condition':current['bindings'][1]['condition']['expression']+=' || true'
            else:current['bindings'][-1]['role']='roles/owner'
            with self.subTest(field=field),self.assertRaises(ValueError):verify.validate_iap_policy(current,self.cfg,baseline=self.baseline)

    def test_publish_is_one_create_only_upload_with_fresh_state_check_and_exact_readback(self):
        data_cfg,kwargs=self.evidence_fixture();receipt=self.run_authored_evidence(data_cfg,kwargs)
        cfg=self.metadata_contract();token=mock.Mock(return_value='synthetic-private-token-long-enough')
        client=verify.Client(cfg,token,read_actor=verify.ADMIN_ACTOR);requests=[];written=[]
        def open_request(request,**_kwargs):
            requests.append(request);url=request.full_url
            if request.get_method()=='POST':
                query=parse_qs(urlsplit(url).query)
                self.assertEqual(query['ifGenerationMatch'],['0']);self.assertEqual(query['uploadType'],['media'])
                self.assertEqual(query['name'],['private-plans/int/'+NEW_COMMIT+'/44382086626-1/foundation-state.json'])
                self.assertEqual(urlsplit(url).path,'/upload/storage/v1/b/'+c.BUCKET+'/o')
                written.append(request.data)
                body=custody.canonical({'name':query['name'][0],'generation':'2001','size':str(len(request.data))})
            elif url==verify.bucket_url(cfg):body=custody.canonical({'name':c.BUCKET,'projectNumber':'816643438938',
                'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True},'publicAccessPrevention':'enforced'},'versioning':{'enabled':True}})
            elif url==verify.reference_url(cfg,cfg['state']):body=self.raw
            elif url==verify.metadata_url(cfg):body=custody.canonical(self.metadata)
            elif url==verify.inventory_url(cfg):body=custody.canonical(self.inventory)
            else:
                self.assertEqual(len(written),1);self.assertIn('generation=2001',url);self.assertIn('ifGenerationMatch=2001',url)
                body=written[0]
            response=mock.MagicMock();response.__enter__.return_value.read.return_value=body
            return response
        opener=mock.Mock();opener.open.side_effect=open_request
        with mock.patch.object(verify,'build_opener',return_value=opener):
            result=client.publish_receipt(receipt,NEW_COMMIT)
            count=token.call_count
            with self.assertRaises(ValueError):client.publish_receipt(receipt,NEW_COMMIT)
        self.assertEqual(token.call_count,count);self.assertEqual(len(written),1)
        self.assertEqual([request.get_method() for request in requests].count('POST'),1)
        self.assertEqual(result['sha256'],custody.sha256(written[0]));self.assertNotIn(PRIVATE,written[0].decode())

    def test_publish_rejects_wrong_commit_or_attempted_original_control_identity_before_authentication(self):
        cfg,kwargs=self.evidence_fixture();receipt=self.run_authored_evidence(cfg,kwargs)
        token=mock.Mock(side_effect=AssertionError('Invalid publication must fail before authentication'))
        client=verify.Client(self.metadata_contract(),token,read_actor=verify.ADMIN_ACTOR)
        for commit in ('bad',cfg['original_execution']['control_commit']):
            value=deepcopy(receipt);value['issuer']['control_commit']=commit
            with self.subTest(commit=commit),self.assertRaises(ValueError):client.publish_receipt(value,commit)
        token.assert_not_called()

    def test_all_historical_97_grants_and_nine_withdrawals_validate_at_their_observed_times_after_current_expiry(self):
        cfg=self.metadata_contract()
        proposal={'plan':deepcopy(cfg['plan']),'expected_review':{'counts':{'create':1,'no-op':41},'imports':[]},
                  'iam_package':deepcopy(self.cfg['iam_package'])}
        decision={'schema':close.DECISION_SCHEMA,'owner':'AldemaroCruz','apply_decision':'approve_exact_serial6_closure_binary_once',
            'apply_controls_commit':cfg['original_execution']['control_commit'],'plan':proposal['plan'],'expected_review':proposal['expected_review'],
            'runtime_authorized':False,'expires_utc':'2026-11-18T20:15:00Z','risk_expiry_utc':'2026-11-28T05:59:59Z',
            'iam_package':{'manifest_sha256':proposal['iam_package']['manifest_sha256'],'administrator_receipt_index_sha256':None}}
        grants=close_fixtures.FoundationCloseContract.receipt_bundle(SimpleNamespace(proposal=proposal),decision)
        cfg['historical_observations'].update(grants_first_utc='2026-11-18T18:30:00+00:00',grants_completed_utc='2026-11-18T18:30:00+00:00',
            withdrawal_first_utc='2026-11-18T19:48:16+00:00',withdrawal_completed_utc='2026-11-18T19:48:24+00:00')
        details={key:self.management[key] for key in ('binding_id','role','member','condition_sha256')}
        rows=[]
        for number in range(1,10):
            rows.append({'schema':'clipforge-int-read-admin-receipt-1','sequence':number,
                'utc':f'2026-11-18T19:48:{15+number:02d}+00:00','manifest_sha256':proposal['iam_package']['manifest_sha256'],
                'operation':('withdraw_preflight','withdraw_before','withdraw_management','verify_management_withdrawal')[(number-1)//2]
                    if number<9 else 'management_withdrawn','status':'attempted' if number<9 and number%2 else 'completed',
                'mutation_attempted':number==6,'http_status':200 if number<9 and number%2==0 else None,
                'key':'iap_management' if number<9 else '','resource':close.IAP_RESOURCE if number<9 else '',
                'details':deepcopy(details) if number in (6,8) else {'binding_id':'iap_management',
                    'functional_deploy_binding_preserved':True,'unrelated_bindings_preserved':True} if number==9 else {}})
        files={f'{number:04d}.json':custody.canonical(row).decode() for number,row in enumerate(rows,1)}
        index={'schema':'clipforge-int-read-admin-receipt-index-1','manifest_sha256':proposal['iam_package']['manifest_sha256'],
            'source_proposal_sha256':proposal['iam_package']['source_proposal_sha256'],
            'files':[{'name':name,'sha256':custody.sha256(raw.encode())} for name,raw in files.items()]}
        withdrawal={'index':custody.canonical(index).decode(),'files':files}
        summary=custody.canonical({'status':cfg['original_execution']['native_completion_status'],'runtime_authorized':False})
        def run(current_cfg,current_decision,current_grants,current_withdrawal):
            decision_raw=custody.canonical(current_decision)
            values={'DECISION_SHA':custody.sha256(decision_raw),'GRANT_SHA':custody.sha256(current_grants['index'].encode()),
                    'WITHDRAW_SHA':custody.sha256(current_withdrawal['index'].encode()),'SUMMARY_SHA':custody.sha256(summary)}
            current_cfg=deepcopy(current_cfg)
            current_cfg['local_evidence']['owner_decision'].update(sha256=values['DECISION_SHA'],size=len(decision_raw))
            current_cfg['local_evidence']['close_summary'].update(sha256=values['SUMMARY_SHA'],size=len(summary))
            class LateClock(datetime):
                @classmethod
                def now(cls,tz=None):return datetime(2026,11,21,tzinfo=timezone.utc)
            with mock.patch.multiple(verify,**values),mock.patch.object(verify,'datetime',LateClock):
                return verify.validate_history(decision_raw,current_grants,current_withdrawal,proposal,summary,current_cfg)
        history=run(cfg,decision,grants,withdrawal)
        self.assertEqual(history['grants']['receipt_files'],97);self.assertEqual(history['withdrawal_receipt_files'],9)
        self.assertFalse(history['current_temporary_read_grants_required']);self.assertTrue(history['current_window_validity_not_required'])
        for scenario in ('decision-expired-at-observation','native-after-expiry','withdraw-member','withdraw-failed','other-binding-not-preserved'):
            current_cfg=deepcopy(cfg);approval=deepcopy(decision);current=deepcopy(withdrawal)
            if scenario=='decision-expired-at-observation':approval['expires_utc']='2026-11-18T19:00:00Z'
            elif scenario=='native-after-expiry':current_cfg['original_execution']['native_completion_observed_utc']='2030-01-01T00:00:00Z'
            else:
                name='0006.json' if scenario!='other-binding-not-preserved' else '0009.json'
                row=json.loads(current['files'][name])
                if scenario=='withdraw-member':row['details']['member']='user:unreviewed'
                elif scenario=='withdraw-failed':row['status']='failed'
                else:row['details']['unrelated_bindings_preserved']=False
                current['files'][name]=custody.canonical(row).decode();idx=json.loads(current['index'])
                next(entry for entry in idx['files'] if entry['name']==name)['sha256']=custody.sha256(current['files'][name].encode())
                current['index']=custody.canonical(idx).decode()
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):run(current_cfg,approval,grants,current)


if __name__=='__main__':
    unittest.main()
