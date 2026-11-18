"""Authored closure fixtures; real guards, simulated CLI/cloud boundaries.

Synthetic source and lock hashes never claim preimages of production sources.
Tests do not load the checkout HCL, a real state, credentials or owner decisions.
"""
from copy import deepcopy
from datetime import datetime, timezone
import base64
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_tf_int as c, check_int_foundation as foundation, int_release as custody
from scripts import int_foundation_close as close, int_foundation_recovery as recovery
from scripts import classify_int_foundation_sast as sast
from tests.test_int_foundation_recovery import authored_partial, authored_manifest, authored_plan

NOW = datetime(2026,11,18,18,30,tzinfo=timezone.utc)
PRIVATE = 'synthetic-private-state-or-policy-sentinel'
PRODUCER = 'c'*40
CONTROLS = 'd'*40
# Exact nonsecret attribute projection from run 44382086626's sanitized serial-7
# observation. The surrounding state fixtures remain authored synthetic bytes;
# they do not claim the observed generation/hash or contain the real state.
OBSERVED_STATE7_IAP_ATTRIBUTES = {
    'project':'816643438938','zone':'us-central1-a',
    'instance':'projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131',
    'role':'roles/iap.tunnelResourceAccessor',
    'member':'serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com','condition':[]}


def authored_iam():
    condition={'title':'Authored temporary closure','expression':'request.time >= timestamp("2026-11-18T18:15:00Z") && request.time < timestamp("2026-11-18T20:15:00Z")'}
    secret=lambda name:'projects/clipforgebeta2/secrets/clipforge-int-'+name
    specs=[('logging_bucket_read','projects/clipforgebeta2','logging.buckets.get'),
           ('secret_metadata_read',secret('bootstrap-admin'),'secretmanager.secrets.get'),
           ('secret_metadata_read',secret('postgres-ca'),'secretmanager.secrets.get'),
           ('postgres_sa_policy_read','projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com','iam.serviceAccounts.getIamPolicy'),
           ('custom_role_metadata_read','projects/clipforgebeta2','iam.roles.get'),
           ('secret_policy_read',secret('bootstrap-admin'),'secretmanager.secrets.getIamPolicy'),
           ('secret_policy_read',secret('postgres-ca'),'secretmanager.secrets.getIamPolicy'),
           ('logging_sink_read','projects/clipforgebeta2','logging.sinks.get'),
           ('logging_view_read','projects/clipforgebeta2','logging.views.get'),
           ('logging_view_policy_read','projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access','logging.views.getIamPolicy'),
           ('iap_management',close.IAP_RESOURCE,None)]
    rows=[]
    for number,(key,resource,permission) in enumerate(specs,1):
        rows.append({'binding_id':'authored_'+str(number),'key':key,'resource':resource,'member':close.TF_MEMBER,
            'role':close.MANAGEMENT_ROLE if permission is None else 'projects/clipforgebeta2/roles/clipforgeIntSynthetic_'+key,
            'permissions':['iap.tunnelInstances.getIamPolicy','iap.tunnelInstances.setIamPolicy'] if permission is None else [permission],
            'condition':deepcopy(condition),'condition_sha256':custody.sha256(custody.canonical(condition))})
    return {'manifest_sha256':'a'*64,'source_proposal_sha256':'b'*64,'window':close.WINDOW,'bindings':rows}


class FoundationCloseContract(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='clipforge-foundation-close-authored-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.producer=self.root/'producer';self.producer.mkdir()
        raw,inventory,self.contract=authored_partial(serial6=True)
        self.raw,self.inventory=raw,inventory
        self.manifest,_=authored_manifest(self.contract)
        self.manifest.update(created_utc='2026-11-18T17:36:00+00:00',expires_utc='2026-11-19T17:36:00+00:00',
            recovery_contract_sha256='a'*64,plan_review_status='recovery_plan_requires_new_review',image={'id':'5913446147369107523','status':'READY'})
        self.plan=authored_plan(self.contract)
        for row in self.plan['resource_changes']:
            if row['address']==recovery.PENDING_IAP:row['change']['after'].update(project='816643438938',instance='1670495097211408131',zone='us-central1-a')
            if row['address']=='google_logging_project_sink.access':
                row['change']['after'].update(unique_writer_identity=True,writer_identity='')
                row['change']['before']=deepcopy(row['change']['after'])
        for row in self.plan['planned_values']['root_module']['resources']:
            row['values']=deepcopy(next(value['change']['after'] for value in self.plan['resource_changes'] if value['address']==row['address']))
        self.binary=b'Authored saved binary fixture; never executed.'
        for key,rawbytes in (('binary',self.binary),('json',custody.canonical(self.plan))):
            self.manifest[key].update(size=len(rawbytes),sha256=custody.sha256(rawbytes))
        for name in c.FILES:
            target=self.producer/'infra/gcp/int-base'/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(('synthetic source bytes '+name).encode())
        (self.producer/'config').mkdir()
        (self.producer/'config/int-foundation-recovery.json').write_bytes(custody.canonical(self.contract))
        source_contract={'schema':'clipforge-int-foundation-contract-1','scope':{'executed_python':[],'test_support_python':[],'tests':[],
            'workflows':[],'config':['config/int-foundation-recovery.json','config/int-foundation-contract.json'],'module_files':list(c.FILES)}}
        (self.producer/'config/int-foundation-contract.json').write_bytes(custody.canonical(source_contract))
        self.manifest['recovery_contract_sha256']=custody.sha256((self.producer/'config/int-foundation-recovery.json').read_bytes())
        self.manifest['control_sources_sha256']=foundation.fingerprint(self.producer,source_contract)[0]
        self.reference={'name':'private-plans/int/'+PRODUCER+'/50000000000-1/manifest.json','generation':'1003',
            'size':len(custody.canonical(self.manifest)),'sha256':custody.sha256(custody.canonical(self.manifest))}
        self.proposal={'schema':close.SCHEMA,'status':'proposed_not_authorized','repository':'AldemaroCruz/ClipForge',
            'branch':'ci/bootstrap-sec03','environment':'int','apply_authorized':False,'runtime_authorized':False,
            'administrative_iam_performed_by_workflow':False,'configuration_sha256':self.manifest['configuration_sha256'],
            'backend':close.backend_fields(self.contract),'plan':close.plan_selection(self.manifest,self.reference),
            'expected_review':recovery.verify_recovery_plan(self.plan,self.contract),'iam_package':authored_iam()}
        for key,value in (('EXPECTED_BINDINGS_SHA256',custody.sha256(custody.canonical(self.proposal['iam_package']['bindings']))),
                          ('EXPECTED_IAM_SOURCE_SHA256',self.proposal['iam_package']['source_proposal_sha256']),
                          ('EXPECTED_IAM_MANIFEST_SHA256',self.proposal['iam_package']['manifest_sha256'])):
            selection=mock.patch.object(close,key,value);selection.start();self.addCleanup(selection.stop)
        self.report={'control_commit':CONTROLS,'control_sources_sha256':'e'*64,'integrity_status':'passed',
            'source_files':{'scripts/tf_int_plan.py':foundation.EXECUTION_SOURCE_SHA256},
            'integrity':{key:{'status':'passed'} for key in foundation.REQUIRED_CHECKS},'sast':{'findings':[
                {'resource':'scripts/tf_int_plan.py','severity':'LOW','rule':rule,'line':line,'source_sha256':foundation.EXECUTION_SOURCE_SHA256,
                 'disposition':'risk_pending'} for rule,line in (('B404',16),('B603',169),('B603',180))]}}
        self.report['source_files'].update({name:custody.sha256(('authored source metadata '+name).encode()) for name in close.CLOSURE_SOURCES})
        self.report['control_sources_sha256']=custody.sha256(custody.canonical(self.report['source_files']))
        self.env={'GITHUB_SHA':CONTROLS,'INT_APPROVED_COMMIT':CONTROLS,'INT_STAGE':'foundation','TF_WORKSPACE':'default',
            'RUNTIME_IMAGE':self.contract['inputs']['runtime_image'],'MACHINE_TYPE':'e2-micro','SECRET_VERSIONS_JSON':'null'}
        class Clock(datetime):
            @classmethod
            def now(cls,tz=None):return NOW
        clock=mock.patch.object(close,'datetime',Clock);clock.start();self.addCleanup(clock.stop)
        recovery_clock=mock.patch.object(recovery,'datetime',Clock);recovery_clock.start();self.addCleanup(recovery_clock.stop)
        # Only the immutable production configuration selector is replaced by
        # our own ten-file hash. Every comparison of consumed bytes is real.
        selector=mock.patch.object(close,'ACTIVE_CONFIGURATION_SHA256',self.manifest['configuration_sha256'])
        selector.start();self.addCleanup(selector.stop)

    def approved(self):
        value=deepcopy(close.decision_template(self.report,self.proposal));value['apply_decision']='approve_exact_serial6_closure_binary_once'
        decisions={'F-SAST-EXEC':'approve_exact_new_closure_execution_route_for_this_binary_only',
            'F-VM-XML':'preserve_exact_image_inactive_database_conditions','F-AUDIT-0077':'preserve_alternative_pending_operational_validation'}
        for row in value['residual_decisions']:row['decision']=decisions[row['id']]
        value['iam_package']['administrator_receipt_index_sha256']='f'*64
        return value

    def verify_decision(self,value,**kwargs):
        return close.verify_owner_decision(value,custody.sha256(custody.canonical(value)),self.report,self.proposal,self.env,**kwargs)

    def test_proposal_is_one_create_41_noops_no_imports_and_no_implicit_authority(self):
        self.assertEqual(close.verify_proposal(self.proposal,self.contract),self.proposal)
        for scenario in ('pending-plan','legacy-run','17-create','imports','state5','runtime','grants','expiry','wrong-binary-name','producer'):
            value=deepcopy(self.proposal)
            if scenario=='pending-plan':value['plan']=None
            elif scenario=='legacy-run':value['plan']['run_id']='44219757502'
            elif scenario=='17-create':value['expected_review']['counts']={'create':17,'no-op':25}
            elif scenario=='imports':value['expected_review']['imports']=['unreviewed']
            elif scenario=='state5':value['plan']['backend']['serial']=5
            elif scenario=='runtime':value['runtime_authorized']=True
            elif scenario=='grants':value['administrative_iam_performed_by_workflow']=True
            elif scenario=='expiry':value['plan']['expires_utc']='2026-11-20T17:36:00+00:00'
            elif scenario=='wrong-binary-name':value['plan']['binary']['name']=value['plan']['binary']['name'].replace('int.tfplan','manifest.json')
            elif scenario=='producer':value['plan']['controls_commit']=CONTROLS
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):close.verify_proposal(value,self.contract)

    def test_public_plan_selection_excludes_the_full_manifest_and_arbitrary_private_fields(self):
        value=deepcopy(self.manifest);value['private_policy']={'secret':PRIVATE};value['configuration_files']['private_attribute']=PRIVATE
        selected=close.plan_selection(value,self.reference)
        self.assertNotIn(PRIVATE,json.dumps(selected));self.assertNotIn('configuration_files',selected)
        self.assertNotIn('refresh_metadata_classification',selected)

    def test_owner_decision_requires_fresh_controls_and_new_route_acceptance_with_fixed_window(self):
        self.assertEqual(close.decision_template(self.report,self.proposal)['apply_decision'],'pending')
        self.assertEqual(self.verify_decision(self.approved())['apply_controls_commit'],CONTROLS)
        for scenario in ('old-route','old-controls','missing-receipt','source-sha','higher-sast','missing-check','extended-window','risk-expiry','expired','not-yet-open'):
            value=self.approved();report=deepcopy(self.report);env=deepcopy(self.env);now=NOW
            if scenario=='old-route':value['residual_decisions'][0]['execution_route']='.github/workflows/int-foundation-recovery-apply.yml'
            elif scenario=='old-controls':env['GITHUB_SHA']=PRODUCER
            elif scenario=='missing-receipt':value['iam_package']['administrator_receipt_index_sha256']=None
            elif scenario=='source-sha':report['source_files']['scripts/tf_int_plan.py']='f'*64
            elif scenario=='higher-sast':report['sast']['findings'][0]['severity']='HIGH'
            elif scenario=='missing-check':report['integrity'].pop(next(iter(report['integrity'])))
            elif scenario=='extended-window':value['expires_utc']='2026-11-18T21:00:00Z'
            elif scenario=='risk-expiry':value['risk_expiry_utc']='2026-11-29T00:00:00Z'
            elif scenario=='expired':now=datetime(2026,11,18,20,15,tzinfo=timezone.utc)
            elif scenario=='not-yet-open':now=datetime(2026,11,18,18,14,59,tzinfo=timezone.utc)
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):
                close.verify_owner_decision(value,custody.sha256(custody.canonical(value)),report,self.proposal,env,now=now)

    def real_sast_report(self):
        # Only the native SAST evidence is real. Plan, receipts, decision,
        # control commit and clock remain authored test fixtures, never grants.
        fixtures=Path(__file__).parent/'fixtures/int_foundation_close'
        projection=json.loads((fixtures/'d67e581-sast-review.json').read_bytes())
        native_raw=(fixtures/'d67e581-bandit-native.json').read_bytes()
        self.assertEqual(custody.sha256(native_raw),projection['origin']['bandit_native_sha256'])
        self.assertEqual(projection['origin']['control_commit'],'d67e5819123b0c05502daff3e402c9adaee74ba1')
        # Reproduce this historical native report with its exact source bytes.
        # The only current checker delta is the new verification test command;
        # reversal must recover the historical proof hash, never a fabricated
        # source fingerprint. Current source/scanner coverage remains a separate
        # foundation gate and this fixture does not claim that newer evidence.
        historical=self.root/'historical-native-sast'
        source_names={row['resource'] for row in projection['sast']['findings']}
        self.assertEqual(source_names,{'scripts/check_int_foundation.py','scripts/check_tf_int.py',
                                       'scripts/int_release.py','scripts/tf_int_plan.py'})
        for name in source_names:
            raw=(foundation.ROOT/name).read_bytes()
            if name=='scripts/check_int_foundation.py':
                added=b', "tests.test_int_foundation_verify"'
                self.assertEqual(raw.count(added),1)
                raw=raw.replace(added,b'')
            hashes={row['source_sha256'] for row in projection['sast']['findings'] if row['resource']==name}
            self.assertEqual(hashes,{custody.sha256(raw)})
            target=historical/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        self.assertEqual(projection['sast'],sast.evaluate(historical,json.loads(native_raw)))
        report=deepcopy(self.report)
        report['sast']=deepcopy(projection['sast'])
        return report

    def synthetic_decision_for_report(self,report):
        with mock.patch.object(self,'report',report):
            return self.approved()

    def test_owner_decision_accepts_real_nine_findings_with_only_three_pending(self):
        report=self.real_sast_report()
        findings=report['sast']['findings']
        self.assertEqual(len(findings),9)
        self.assertEqual(sum(row['disposition']=='risk_pending' for row in findings),3)
        self.assertEqual(sum(row['disposition']=='false_positive_proven' for row in findings),5)
        self.assertEqual(sum(row['disposition']=='control_verified' for row in findings),1)
        decision=self.synthetic_decision_for_report(report)
        result=close.verify_owner_decision(decision,custody.sha256(custody.canonical(decision)),
                                         report,self.proposal,self.env,now=NOW)
        self.assertEqual(result['apply_controls_commit'],CONTROLS)
        self.assertEqual(decision['residual_decisions'][0]['native_review'],report['sast'])

    def test_real_sast_pending_delta_still_blocks_even_with_rebound_test_decision(self):
        for mutation in ('extra-pending','severity','source','rule','line','resource'):
            report=self.real_sast_report()
            pending=next(row for row in report['sast']['findings'] if row['disposition']=='risk_pending')
            if mutation=='extra-pending': report['sast']['findings'].append(deepcopy(pending))
            elif mutation=='severity': pending['severity']='HIGH'
            elif mutation=='source': pending['source_sha256']='f'*64
            elif mutation=='rule': pending['rule']='B999'
            elif mutation=='line': pending['line']=181
            else: pending['resource']='scripts/unreviewed.py'
            decision=self.synthetic_decision_for_report(report)
            with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,'Unknown or higher SAST'):
                close.verify_owner_decision(decision,custody.sha256(custody.canonical(decision)),
                                            report,self.proposal,self.env,now=NOW)

    def test_real_sast_decision_must_preserve_full_native_review_and_source_binding(self):
        report=self.real_sast_report()
        for mutation in ('omit-classified','classified-proof','acceptance','driver-source'):
            current=deepcopy(report);decision=self.synthetic_decision_for_report(current)
            if mutation=='omit-classified':
                decision['residual_decisions'][0]['native_review']['findings']=[
                    row for row in current['sast']['findings'] if row['disposition']=='risk_pending']
            elif mutation=='classified-proof': decision['residual_decisions'][0]['native_review']['proofs']=[]
            elif mutation=='acceptance': decision['residual_decisions'][0]['decision']='unreviewed_acceptance'
            else:
                current['source_files']['scripts/tf_int_plan.py']='f'*64
                current['control_sources_sha256']=custody.sha256(custody.canonical(current['source_files']))
                decision=self.synthetic_decision_for_report(current)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                close.verify_owner_decision(decision,custody.sha256(custody.canonical(decision)),
                                            current,self.proposal,self.env,now=NOW)

    def test_bridge_verifies_producer_control_hash_and_exact_ten_files_without_import_source(self):
        module=self.root/'module';shutil=__import__('shutil');shutil.copytree(self.producer/'infra/gcp/int-base',module)
        # The production source pin/static contract is a separate real gate;
        # this authored source cannot claim the frozen 709... preimage.
        with mock.patch.object(recovery,'static_contract'):
            close.verify_plan_bridge(self.manifest,self.proposal,module,self.producer,self.env)
            for name in ('main.tf','audit.tf','runtime.tf','.terraform.lock.hcl','postgres-install.sh'):
                target=module/name;original=target.read_bytes();target.write_bytes(original+b' changed')
                with self.subTest(name=name),self.assertRaises(ValueError):close.verify_plan_bridge(self.manifest,self.proposal,module,self.producer,self.env)
                target.write_bytes(original)
            (module/'recovery-imports.tf').write_text('Unreviewed import proposal')
            with self.assertRaises(ValueError):close.verify_plan_bridge(self.manifest,self.proposal,module,self.producer,self.env)

    def receipt_bundle(self,decision):
        rows=[];bindings=self.proposal['iam_package']['bindings']
        def emit(operation,status,key,resource,details=None,mutation=False):
            rows.append({'schema':'clipforge-int-read-admin-receipt-1','sequence':len(rows)+1,'utc':NOW.isoformat(),
                'manifest_sha256':'a'*64,'operation':operation,'status':status,'key':key,'resource':resource,
                'http_status':200 if status=='completed' and operation!='all_exact_grants' else None,'mutation_attempted':mutation,'details':details or {}})
        for role in sorted({row['role'] for row in bindings}):
            for status in ('attempted','completed'):emit('role_preflight',status,'role',role)
        for resource in sorted({row['resource'] for row in bindings}):
            for status in ('attempted','completed'):emit('policy_preflight',status,'policy',resource)
        for binding in bindings:
            details={key:binding[key] for key in ('binding_id','role','member','condition_sha256')}
            for operation in ('before_binding','grant_binding','verify_binding'):
                for status in ('attempted','completed'):
                    emit(operation,status,binding['key'],binding['resource'],details if status=='completed' else {},
                        mutation=operation=='grant_binding' and status=='completed')
        emit('all_exact_grants','completed',None,None,{'roles':9,'bindings':11,'role_definitions_created':0,**close.WINDOW})
        files={f'{number:04d}.json':custody.canonical(row).decode() for number,row in enumerate(rows,1)}
        index={'schema':'clipforge-int-read-admin-receipt-index-1','manifest_sha256':'a'*64,'source_proposal_sha256':'b'*64,
            'files':[{'name':name,'sha256':custody.sha256(raw.encode())} for name,raw in files.items()]}
        bundle={'index':custody.canonical(index).decode(),'files':files}
        decision['iam_package']['administrator_receipt_index_sha256']=custody.sha256(bundle['index'].encode())
        return bundle

    def test_administrative_receipts_keep_all_97_exact_raw_files_and_all_11_distinct_bindings(self):
        decision=self.approved();bundle=self.receipt_bundle(decision)
        self.assertEqual(close.verify_iam_receipts(json.dumps(bundle),decision,self.proposal)['receipt_files'],97)
        for scenario in ('raw-change','extra-file','missing-file','manifest','condition','withdrawal','failed','missing-http-success'):
            value=deepcopy(bundle);approval=deepcopy(decision)
            if scenario=='raw-change':value['files']['0001.json']+=' '
            elif scenario=='extra-file':value['files']['0098.json']='{}'
            elif scenario=='missing-file':value['files'].pop('0001.json')
            elif scenario=='manifest':index=json.loads(value['index']);index['manifest_sha256']='f'*64;value['index']=custody.canonical(index).decode();approval['iam_package']['administrator_receipt_index_sha256']=custody.sha256(value['index'].encode())
            else:
                name=next(name for name,raw in value['files'].items() if json.loads(raw)['operation']=='grant_binding' and json.loads(raw)['status']=='completed')
                row=json.loads(value['files'][name])
                if scenario=='condition':row['details']['condition_sha256']='f'*64
                elif scenario=='withdrawal':row['operation']='withdraw_binding'
                elif scenario=='missing-http-success':row['http_status']=None
                else:row['status']='failed'
                value['files'][name]=custody.canonical(row).decode();index=json.loads(value['index'])
                next(item for item in index['files'] if item['name']==name)['sha256']=custody.sha256(value['files'][name].encode())
                value['index']=custody.canonical(index).decode();approval['iam_package']['administrator_receipt_index_sha256']=custody.sha256(value['index'].encode())
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):close.verify_iam_receipts(json.dumps(value),approval,self.proposal)

    def test_receipt_compression_is_bounded_and_preserves_exact_raw_strings(self):
        decision=self.approved();raw=json.dumps(self.receipt_bundle(decision))
        encoded=base64.b64encode(gzip.compress(raw.encode())).decode()
        self.assertEqual(close.decode_receipts(encoded),raw)
        for value in ('!',base64.b64encode(b'not gzip').decode(),base64.b64encode(gzip.compress(b'x'*(close.MAX_RECEIPTS+1))).decode()):
            with self.assertRaises(ValueError):close.decode_receipts(value)

    def test_exact_administrative_schema_rejects_dangerous_role_permissions_resource_or_condition_deltas(self):
        for scenario in ('role','permission','resource','condition','extra-member','manifest'):
            value=deepcopy(self.proposal['iam_package']);row=value['bindings'][0]
            if scenario=='role':row['role']='projects/clipforgebeta2/roles/clipforgeIntUnreviewed'
            elif scenario=='permission':row['permissions']=['secretmanager.versions.get']
            elif scenario=='resource':row['resource']='projects/other'
            elif scenario=='condition':row['condition']['expression']+=' || true';row['condition_sha256']=custody.sha256(custody.canonical(row['condition']))
            elif scenario=='extra-member':row['member']='user:unreviewed'
            else:value['manifest_sha256']='f'*64
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):close.verify_iam_package(value)

    def test_receipts_cannot_replace_role_and_policy_preflights_with_unrelated_binding_reads(self):
        approval=self.approved();bundle=self.receipt_bundle(approval);index=json.loads(bundle['index'])
        for entry in index['files'][:30]:
            row=json.loads(bundle['files'][entry['name']]);row.update(operation='before_binding',key='unreviewed',resource='projects/unreviewed')
            bundle['files'][entry['name']]=custody.canonical(row).decode();entry['sha256']=custody.sha256(bundle['files'][entry['name']].encode())
        bundle['index']=custody.canonical(index).decode();approval['iam_package']['administrator_receipt_index_sha256']=custody.sha256(bundle['index'].encode())
        with self.assertRaises(ValueError):close.verify_iam_receipts(json.dumps(bundle),approval,self.proposal)

    def wif_fixture(self, root):
        adc=root/'gha-creds-authored.json'
        value={'type':'external_account','audience':'//iam.googleapis.com/projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github',
            'token_url':'https://sts.googleapis.com/v1/token',
            'service_account_impersonation_url':'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com:generateAccessToken',
            'credential_source':{'url':'https://synthetic.invalid/'+PRIVATE,'headers':{'Authorization':'Bearer '+PRIVATE}}}
        adc.write_bytes(custody.canonical(value))
        return adc,value

    def test_wif_checks_external_account_provider_target_and_all_selection_overrides_without_dumping_credentials(self):
        adc,document=self.wif_fixture(self.root)
        env={**self.env,'GCP_WIF_PROVIDER':'projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github',
             'GOOGLE_APPLICATION_CREDENTIALS':str(adc),'GOOGLE_GHA_CREDS_PATH':str(adc),'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE':str(adc)}
        result=close.verify_wif(env);self.assertIsNone(result['effective_identity']);self.assertNotIn(PRIVATE,json.dumps(result))
        self.assertNotIn(str(adc),json.dumps(result))
        for scenario in ('type','target','audience','token-url','private-key','executable','provider-override','file-alias','oversized'):
            value=deepcopy(document);current=deepcopy(env)
            if scenario=='type':value['type']='service_account'
            elif scenario=='target':value['service_account_impersonation_url']=value['service_account_impersonation_url'].replace('terraform-int','deploy-int')
            elif scenario=='audience':value['audience']='//iam.googleapis.com/projects/other'
            elif scenario=='token-url':value['token_url']='https://attacker.invalid/token'
            elif scenario=='private-key':value['private_key']=PRIVATE
            elif scenario=='executable':value['credential_source']={'executable':{'command':PRIVATE}}
            elif scenario=='provider-override':current['GOOGLE_CREDENTIALS']=PRIVATE
            elif scenario=='file-alias':current['GOOGLE_GHA_CREDS_PATH']=str(self.root/'other.json')
            adc.write_bytes(b'x'*65537 if scenario=='oversized' else custody.canonical(value))
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):close.verify_wif(current)

    def test_apply_trace_uses_only_init_and_saved_apply_and_never_retries_partial_or_postverification_failures(self):
        for scenario in ('success','state-race','withdrawn-iam','binary-race','source-race','native-failure','timeout','postverification-failure'):
            with tempfile.TemporaryDirectory(prefix='clipforge-close-native-trace-') as temporary,self.subTest(scenario=scenario):
                import shutil
                root=Path(temporary);shutil.copytree(self.producer,root/'plan-source')
                work=root/'work';reports=root/'reports';work.mkdir();reports.mkdir()
                adc,_=self.wif_fixture(root);decision=self.approved();bundle=self.receipt_bundle(decision)
                encoded=base64.b64encode(gzip.compress(json.dumps(bundle).encode())).decode()
                env={**self.env,'GITHUB_REPOSITORY':'AldemaroCruz/ClipForge','GITHUB_REF':'refs/heads/ci/bootstrap-sec03',
                    'GITHUB_EVENT_NAME':'workflow_dispatch','RUNNER_ENVIRONMENT':'github-hosted','GITHUB_RUN_ID':'50000000001','GITHUB_RUN_ATTEMPT':'1',
                    'GCP_ACCESS_TOKEN':'synthetic-private-token','GCP_PROJECT_ID':'clipforgebeta2','GCP_PROJECT_NUMBER':'816643438938','GCP_REGION':'us-central1',
                    'GCP_TERRAFORM_SA':'clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com',
                    'GCP_WIF_PROVIDER':'projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github',
                    'TF_STATE_BUCKET':c.BUCKET,'TF_STATE_PREFIX':'terraform/int','GOOGLE_APPLICATION_CREDENTIALS':str(adc),
                    'CLOSE_DECISION_JSON':json.dumps(decision),'CLOSE_DECISION_SHA256':custody.sha256(custody.canonical(decision)),
                    'CLOSE_IAM_RECEIPTS_GZIP_B64':encoded}
                objects={self.reference['name']:custody.canonical(self.manifest),self.manifest['json']['name']:custody.canonical(self.plan),self.manifest['binary']['name']:self.binary}
                def fetch(method,name,*,generation=None):
                    self.assertEqual(method,'GET');self.assertIn(generation,('1001','1002','1003'));return objects[name]
                native=[]
                def run(argv,operation,_work,**_kwargs):
                    native.append((argv,operation))
                    if operation=='foundation_close_init':
                        if scenario=='binary-race':(work/'int.tfplan').write_bytes(b'changed binary')
                        if scenario=='source-race':(work/'module/runtime.tf').write_bytes(b'changed source')
                    if operation=='foundation_close_apply_saved':
                        if scenario=='native-failure':raise close.driver.FailedOperation(operation,"403 Permission 'iap.tunnelInstances.setIamPolicy' denied")
                        if scenario=='timeout':raise close.driver.subprocess.TimeoutExpired('synthetic-terraform',1200,output=PRIVATE.encode())
                    return 0,b''
                proof={'classification':'recognized_serial6_foundation_state','state':{'serial':6}}
                after=deepcopy(proof)
                if scenario=='state-race':after['state']['serial']=7
                policy={'version':3,'bindings':[]};completed_policy={'version':3,'bindings':[{'role':close.FUNCTIONAL_ROLE,'members':[close.DEPLOY_MEMBER]}]}
                state={'generation':'2001','serial':7,'managed_addresses':sorted(c.FOUNDATION_ADDRESSES)}
                with mock.patch.object(close,'load_proposal',return_value=self.proposal),mock.patch.object(recovery,'static_contract'), \
                        mock.patch.object(foundation,'fetch_evidence',return_value=self.report),mock.patch.object(custody,'request',side_effect=fetch), \
                        mock.patch.object(close.driver,'metadata',return_value={'name':c.BUCKET}), \
                        mock.patch.object(recovery,'inspect_partial',side_effect=[proof,after]), \
                        mock.patch.object(close.image_review,'image_metadata',return_value=self.manifest['image']), \
                        mock.patch.object(close,'verify_live_iam',side_effect=[{'exact_bindings':11},
                            ValueError('Synthetic temporary binding withdrawn') if scenario=='withdrawn-iam' else {'exact_bindings':11},{'exact_bindings':11}]), \
                        mock.patch.object(close,'vm_proof',return_value={'configuration_sha256':'a'*64}), \
                        mock.patch.object(close,'sink_proof',return_value={'representation_converged_without_second_plan':True}), \
                        mock.patch.object(close,'read_policy',side_effect=[policy,policy,completed_policy]), \
                        mock.patch.object(close.driver,'terraform_binary',return_value='synthetic-terraform') as version, \
                        mock.patch.object(close.driver,'run',side_effect=run), \
                        mock.patch.object(close,'state_after_apply',side_effect=ValueError('Synthetic postverification failed') if scenario=='postverification-failure' else None,
                            return_value=state),mock.patch.object(custody,'upload',return_value={'name':'private-close-receipt'}) as upload:
                    if scenario=='success':
                        result=close.apply_reviewed(work,reports,env,root=root)
                        self.assertFalse(result['runtime_authorized']);self.assertFalse(result['guest_authorized']);upload.assert_called_once()
                        self.assertNotIn(PRIVATE,(reports/'close-summary.json').read_text())
                    else:
                        with self.assertRaises(close.driver.subprocess.TimeoutExpired if scenario=='timeout' else ValueError):
                            close.apply_reviewed(work,reports,env,root=root)
                        upload.assert_not_called()
                operations=[operation for _,operation in native]
                self.assertEqual(operations,['foundation_close_init'] if scenario in {'state-race','withdrawn-iam','binary-race','source-race'}
                    else ['foundation_close_init','foundation_close_apply_saved'])
                version.assert_called_once_with()
                self.assertEqual((work/'apply-attempted.json').exists(),len(native)==2)
                self.assertEqual((work/'apply-completed.json').exists(),scenario in {'success','postverification-failure'})
                if len(native)==2:self.assertEqual(native[-1][0],['synthetic-terraform','apply','-input=false','-no-color','-lock=true','-lock-timeout=120s',str(work/'int.tfplan')])

    def test_failure_summary_preserves_partial_metadata_for_timeout_and_distinguishes_completed_native_apply(self):
        for completed in (False,True):
            with tempfile.TemporaryDirectory(prefix='clipforge-close-partial-summary-') as temporary:
                root=Path(temporary);work=root/'work';reports=root/'reports';work.mkdir();reports.mkdir()
                def fail(*_args):
                    (work/'apply-attempted.json').write_bytes(b'{}')
                    if completed:(work/'apply-completed.json').write_bytes(b'{}')
                    raise close.driver.subprocess.TimeoutExpired('synthetic-terraform',1200,output=PRIVATE.encode())
                with mock.patch('sys.argv',['int_foundation_close','apply']),mock.patch.object(close.os,'umask'), \
                        mock.patch.object(close.driver,'private_paths',return_value=(work,reports)),mock.patch.object(close,'apply_reviewed',side_effect=fail) as execute, \
                        mock.patch.object(close,'load_proposal',return_value=self.proposal),mock.patch.object(close.driver,'metadata',return_value={'name':c.BUCKET}), \
                        mock.patch.object(close.state_reader,'private_current_state',return_value=(self.raw,{'generation':'2001'},{})), \
                        mock.patch.dict(close.os.environ,{},clear=True):self.assertEqual(close.main(),1)
                execute.assert_called_once();summary=json.loads((reports/'close-summary.json').read_bytes())
                self.assertEqual(summary['status'],'native_close_apply_completed_postverification_failed_no_retry' if completed else 'blocked_or_partial_foundation_close_preserve_state_no_retry')
                self.assertEqual(summary['partial_state']['generation'],'2001');self.assertNotIn(PRIVATE,json.dumps(summary))

    def test_main_keeps_successful_apply_distinct_from_postcheck_error_and_preserves_real_native_exit(self):
        cases=('native-exit-2','native-signal','native-timeout','postcheck-identity','postcheck-read-denied','preflight')
        for scenario in cases:
            with tempfile.TemporaryDirectory(prefix='clipforge-close-failure-phase-') as temporary:
                root=Path(temporary);work=root/'work';reports=root/'reports';work.mkdir();reports.mkdir()
                completed=scenario.startswith('postcheck-')
                def fail(*_args):
                    if scenario!='preflight':(work/'apply-attempted.json').write_bytes(b'{}')
                    if completed:
                        (work/'apply-completed.json').write_bytes(b'{}')
                        (work/'foundation_close_apply_saved.log').write_bytes(b'Apply complete! Resources: 1 added, 0 changed, 0 destroyed.\n')
                    if scenario in ('native-exit-2','native-signal'):
                        (work/'foundation_close_apply_saved.log').write_bytes(
                            b"Error: 403 Permission 'iap.tunnelInstances.setIamPolicy' denied\n"+PRIVATE.encode())
                        raise close.driver.FailedOperation('foundation_close_apply_saved',
                            "403 Permission 'iap.tunnelInstances.setIamPolicy' denied",2 if scenario=='native-exit-2' else -9)
                    if scenario=='native-timeout':raise close.driver.subprocess.TimeoutExpired('synthetic',1200,output=PRIVATE.encode())
                    if scenario=='postcheck-identity':raise ValueError('Final IAP state identity/role/member/condition differs')
                    if scenario=='postcheck-read-denied':raise close.driver.FailedOperation('read_unchanged_foundation_VM','HTTP 403 required read failed',403)
                    raise ValueError(PRIVATE)
                with mock.patch('sys.argv',['int_foundation_close','apply']),mock.patch.object(close.os,'umask'), \
                        mock.patch.object(close.driver,'private_paths',return_value=(work,reports)), \
                        mock.patch.object(close,'apply_reviewed',side_effect=fail) as execute, \
                        mock.patch.object(close,'load_proposal',return_value=self.proposal), \
                        mock.patch.object(close.driver,'metadata',return_value={'name':c.BUCKET}), \
                        mock.patch.object(close.state_reader,'private_current_state',return_value=(self.raw,{'generation':'2001'},{})), \
                        mock.patch.dict(close.os.environ,{},clear=True):self.assertEqual(close.main(),1)
                execute.assert_called_once();summary=json.loads((reports/'close-summary.json').read_bytes())
                self.assertFalse(summary['runtime_authorized']);self.assertFalse(summary['guest_authorized'])
                self.assertNotIn(PRIVATE,json.dumps(summary));self.assertNotEqual(summary['error']['operation'],'recovery_plan')
                if completed:
                    self.assertEqual(summary['status'],'native_close_apply_completed_postverification_failed_no_retry')
                    self.assertEqual(summary['failure_phase'],'postverification')
                    self.assertEqual(summary['native_apply'],{'attempted':True,'completed':True,'native_exit':0})
                    self.assertNotIn('original_private_log_sha256',summary['error'])
                    if scenario=='postcheck-identity':
                        self.assertEqual(summary['error']['operation'],'foundation_close_postverification')
                        self.assertEqual(summary['error']['message'],'Final IAP state identity/role/member/condition differs')
                    else:
                        self.assertEqual(summary['error']['operation'],'read_unchanged_foundation_VM')
                        self.assertEqual(summary['error']['status'],403)
                elif scenario in ('native-exit-2','native-signal'):
                    expected=2 if scenario=='native-exit-2' else -9
                    self.assertEqual(summary['failure_phase'],'native_apply')
                    self.assertEqual(summary['native_apply']['native_exit'],expected)
                    self.assertEqual(summary['error']['native_exit'],expected)
                    self.assertEqual(summary['error']['operation'],'foundation_close_apply_saved')
                    self.assertFalse(summary['error']['raw_log_published'])
                elif scenario=='native-timeout':
                    self.assertIsNone(summary['native_apply']['native_exit'])
                    self.assertEqual(summary['error']['error_type'],'TimeoutExpired')
                else:
                    self.assertEqual(summary['failure_phase'],'preflight')
                    self.assertEqual(summary['native_apply'],{'attempted':False,'completed':False,'native_exit':None})

    def test_live_iam_checks_all_11_bindings_and_nine_existing_definitions(self):
        bindings=self.proposal['iam_package']['bindings'];policies={}
        for row in bindings:policies.setdefault(row['resource'],{'version':3,'bindings':[]})['bindings'].append(
            {'role':row['role'],'members':[row['member']],'condition':row['condition']})
        roles={row['role']:{'name':row['role'],'stage':'GA','deleted':False,'includedPermissions':row['permissions']} for row in bindings}
        with mock.patch.object(close,'read_policy',side_effect=lambda resource:deepcopy(policies[resource])), \
                mock.patch.object(close,'read_json',side_effect=lambda _url,_op,resource:deepcopy(roles[resource])) as reads:
            self.assertEqual(close.verify_live_iam(self.proposal)['exact_bindings'],11);self.assertEqual(reads.call_count,9)
        for scenario in ('missing','condition','member','role-permissions','role-deleted','version'):
            ps=deepcopy(policies);rs=deepcopy(roles);target=bindings[0]
            if scenario=='missing':ps[target['resource']]['bindings'].pop(0)
            elif scenario=='condition':ps[target['resource']]['bindings'][0]['condition']={}
            elif scenario=='member':ps[target['resource']]['bindings'][0]['members']=['user:'+PRIVATE]
            elif scenario=='role-permissions':rs[target['role']]['includedPermissions'].append('resourcemanager.projects.setIamPolicy')
            elif scenario=='role-deleted':rs[target['role']]['deleted']=True
            else:ps[target['resource']]['version']=1
            with mock.patch.object(close,'read_policy',side_effect=lambda resource:ps[resource]), \
                    mock.patch.object(close,'read_json',side_effect=lambda _url,_op,resource:rs[resource]), \
                    self.subTest(scenario=scenario),self.assertRaises(ValueError):close.verify_live_iam(self.proposal)

    def test_read_transport_guards_credentials_before_unreviewed_urls_and_never_reads_error_bodies(self):
        for url in ('http://iam.googleapis.com/v1/projects/clipforgebeta2/roles/clipforgeIntSynthetic',
                    'https://attacker.invalid/'+PRIVATE,'https://iap.googleapis.com/v1/'+close.IAP_RESOURCE+':setIamPolicy'):
            with mock.patch.dict(close.os.environ,{},clear=True),mock.patch.object(close,'build_opener') as network,self.assertRaises(ValueError):
                close.read_json(url,'authored_read','projects/clipforgebeta2')
            network.assert_not_called()
        for resource in ('projects/clipforgebeta2',close.IAP_RESOURCE,
            'projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com'):
            method,url,payload=close.policy_endpoint(resource);body=mock.Mock();body.read.side_effect=AssertionError('No error body read')
            opener=mock.Mock();opener.open.side_effect=close.HTTPError(url,403,PRIVATE,{'Authorization':'Bearer '+PRIVATE},body)
            with mock.patch.dict(close.os.environ,{'GCP_ACCESS_TOKEN':'synthetic-private-token'},clear=True), \
                    mock.patch.object(close,'build_opener',return_value=opener):
                with self.assertRaises(close.driver.FailedOperation) as raised:close.read_policy(resource)
            body.read.assert_not_called();self.assertNotIn(PRIVATE,json.dumps(raised.exception.receipt))
            self.assertEqual(raised.exception.receipt['http_status'],403)
            request=opener.open.call_args.args[0];self.assertEqual(request.get_method(),method)
            self.assertEqual(request.data,custody.canonical(payload) if payload is not None else None)

    def test_sink_read_semantics_match_empty_writer_without_claiming_an_exclusive_identity(self):
        destination='logging.googleapis.com/projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access'
        planned={'unique_writer_identity':True,'writer_identity':'','destination':destination,'filter':'authored filter','disabled':False}
        value={'name':'clipforge-int-access','destination':destination,'filter':'authored filter'}
        with mock.patch.object(close,'read_json',return_value=value):
            proof=close.sink_proof(planned)
        with mock.patch.object(close,'read_json',side_effect=AssertionError('Injected reader must supply all metadata')) as default:
            calls=[]
            def reader(url,operation,resource):
                calls.append((url,operation,resource));return value
            self.assertEqual(close.sink_proof(planned,reader=reader),proof)
            default.assert_not_called()
            self.assertEqual(calls,[('https://logging.googleapis.com/v2/projects/clipforgebeta2/sinks/clipforge-int-access',
                                    'read_convergent_foundation_sink','projects/clipforgebeta2/sinks/clipforge-int-access')])
        self.assertTrue(proof['representation_converged_without_second_plan']);self.assertTrue(proof['exclusive_writer_identity_not_inferred'])
        for key,changed in (('writerIdentity','serviceAccount:unexpected'),('destination','other'),('filter','changed'),('disabled',True),
                            ('description','changed'),('interceptChildren',True),('exclusions',[{'name':'unreviewed'}])):
            with mock.patch.object(close,'read_json',return_value={**value,key:changed}),self.subTest(key=key),self.assertRaises(ValueError):
                close.sink_proof(planned)

    def test_vm_proof_binds_running_identity_retained_disks_startup_and_plan_values_and_detects_restart(self):
        base='https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/'
        startup='Authored fixture startup bytes; not the production a93... preimage.'
        metadata={'enable-oslogin':'TRUE','block-project-ssh-keys':'TRUE','startup-script':startup}
        boot=base+'disks/clipforge-int-base-postgres';data=base+'disks/clipforge-int-base-postgres-data'
        vm={'id':'1670495097211408131','name':'clipforge-int-base-postgres','machineType':'zones/us-central1-a/machineTypes/e2-micro',
            'status':'RUNNING','deletionProtection':True,'canIpForward':False,'lastStartTimestamp':'2026-11-18T01:00:00Z',
            'metadata':{'items':[{'key':key,'value':value} for key,value in metadata.items()]},
            'networkInterfaces':[{'networkIP':'10.80.1.2'}],'shieldedInstanceConfig':{'enableSecureBoot':True,'enableVtpm':True,'enableIntegrityMonitoring':True},
            'disks':[{'source':boot,'boot':True,'autoDelete':False},{'source':data,'boot':False,'autoDelete':False,'deviceName':'clipforge-pg-data'}]}
        disks={boot:{'id':'2158164599035219715','sourceImageId':'5913446147369107523'},
               data:{'id':'6427691858848206684','name':'clipforge-int-base-postgres-data','sizeGb':'20','type':'zones/us-central1-a/diskTypes/pd-standard'}}
        planned={'machine_type':'e2-micro','deletion_protection':True,'can_ip_forward':False,'network_interface':[{'network_ip':'10.80.1.2'}],
            'metadata':{key:value for key,value in metadata.items() if key!='startup-script'},'metadata_startup_script':startup,
            'attached_disk':[{'source':data,'device_name':'clipforge-pg-data'}]}
        planned_disk={'name':'clipforge-int-base-postgres-data','size':20,'type':'pd-standard'}
        def call(value,current_disks,current_plan=planned,*,injected=False):
            def reader(url,_operation,_resource):return value if '/instances/' in url else current_disks[url]
            with mock.patch.object(close,'STARTUP_SHA256',custody.sha256(startup.encode())), \
                    mock.patch.object(close,'read_json',side_effect=AssertionError('Injected reader must supply all metadata') if injected else reader) as default:
                proof=close.vm_proof(current_plan,planned_disk,reader=reader) if injected else close.vm_proof(current_plan,planned_disk)
                if injected:default.assert_not_called()
                return proof
        original=call(vm,disks)
        self.assertEqual(original,call(vm,disks,injected=True))
        changed=deepcopy(vm);changed['lastStartTimestamp']='2026-11-18T18:29:00Z'
        self.assertNotEqual(original,call(changed,disks))
        for scenario in ('status','public-IP','data-id','data-size','data-type','boot-id','image-id','planned-metadata'):
            value=deepcopy(vm);ds=deepcopy(disks);plan=deepcopy(planned)
            if scenario=='status':value['status']='TERMINATED'
            elif scenario=='public-IP':value['networkInterfaces'][0]['accessConfigs']=[{'natIP':'203.0.113.1'}]
            elif scenario=='data-id':ds[data]['id']='other'
            elif scenario=='data-size':ds[data]['sizeGb']='40'
            elif scenario=='data-type':ds[data]['type']='diskTypes/pd-balanced'
            elif scenario=='boot-id':ds[boot]['id']='other'
            elif scenario=='image-id':ds[boot]['sourceImageId']='other'
            else:plan['metadata']['enable-oslogin']='FALSE'
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):call(value,ds,plan)
        self.assertNotIn(startup,json.dumps(original))

    def test_functional_iap_postcheck_preserves_every_other_role_member_and_condition(self):
        before={'version':3,'etag':'before','bindings':[{'role':'roles/viewer','members':['user:'+PRIVATE]},
            {'role':close.MANAGEMENT_ROLE,'members':[close.TF_MEMBER],'condition':{'expression':'authored condition'}}]}
        after=deepcopy(before);after['etag']='after';after['bindings'].append({'role':close.FUNCTIONAL_ROLE,'members':[close.DEPLOY_MEMBER]})
        self.assertTrue(close.functional_iap_proof(before,after)['all_other_policy_bindings_preserved'])
        for scenario in ('missing','conditional','wrong-member','other-policy','duplicate'):
            value=deepcopy(after)
            if scenario=='missing':value['bindings'].pop()
            elif scenario=='conditional':value['bindings'][-1]['condition']={'expression':'unreviewed'}
            elif scenario=='wrong-member':value['bindings'][-1]['members']=['user:other']
            elif scenario=='other-policy':value['bindings'][0]['members']=['user:changed']
            else:value['bindings'].append(deepcopy(value['bindings'][-1]))
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):close.functional_iap_proof(before,value)

    def test_new_state_receipt_requires_42_untainted_descendant_addresses_and_exact_iap(self):
        state=json.loads(self.raw);state['serial']=7
        state['resources'].append({'mode':'managed','type':'google_iap_tunnel_instance_iam_member','name':'protected_bootstrap',
            'instances':[{'attributes':deepcopy(OBSERVED_STATE7_IAP_ATTRIBUTES)}]})
        for scenario in ('valid-full','valid-short','tainted','missing','wrong-project','wrong-zone','wrong-instance',
                         'wrong-uri-project','wrong-uri-zone','wrong-uri-prefix','wrong-uri-suffix','named-instance',
                         'wrong-role','wrong-member','condition','empty-dict-condition','same-generation','lock'):
            value=deepcopy(state);generation='2001'
            attributes=value['resources'][-1]['instances'][0]['attributes']
            if scenario=='valid-short':attributes.update(instance='1670495097211408131',condition=None)
            if scenario=='tainted':value['resources'][0]['instances'][0]['status']='tainted'
            elif scenario=='missing':value['resources'].pop(0)
            elif scenario=='wrong-project':attributes['project']='clipforgebeta2'
            elif scenario=='wrong-zone':attributes['zone']='us-central1-b'
            elif scenario=='wrong-instance':attributes['instance']='1670495097211408132'
            elif scenario=='wrong-uri-project':attributes['instance']=close.IAP_RESOURCE.replace('816643438938','816643438939')
            elif scenario=='wrong-uri-zone':attributes['instance']=close.IAP_RESOURCE.replace('us-central1-a','us-central1-b')
            elif scenario=='wrong-uri-prefix':attributes['instance']='https://iap.googleapis.com/v1/'+close.IAP_RESOURCE
            elif scenario=='wrong-uri-suffix':attributes['instance']=close.IAP_RESOURCE+'/'
            elif scenario=='named-instance':attributes['instance']=close.IAP_RESOURCE.replace('1670495097211408131','clipforge-int-base-postgres')
            elif scenario=='wrong-role':attributes['role']='roles/viewer'
            elif scenario=='wrong-member':attributes['member']='user:other'
            elif scenario=='condition':attributes['condition']=[{'expression':'request.time < timestamp("2030-01-01T00:00:00Z")'}]
            elif scenario=='empty-dict-condition':attributes['condition']={}
            elif scenario=='same-generation':generation=self.contract['backend']['generation']
            raw=custody.canonical(value);obj={'name':c.PREFIX+'/default.tfstate','generation':generation}
            live=[obj]+([{'name':c.PREFIX+'/default.tflock','generation':'2002'}] if scenario=='lock' else [])
            with mock.patch.object(close.state_reader,'private_current_state',return_value=(raw,obj,{})), \
                    mock.patch.object(close.driver,'backend_inventory',return_value={'live':live}),self.subTest(scenario=scenario):
                if scenario.startswith('valid-'):
                    result=close.state_after_apply({'name':c.BUCKET},self.proposal['plan'])
                    self.assertEqual(len(result['managed_addresses']),42);self.assertNotIn(PRIVATE,json.dumps(result))
                else:
                    with self.assertRaises(ValueError):close.state_after_apply({'name':c.BUCKET},self.proposal['plan'])


if __name__=='__main__':
    unittest.main()
