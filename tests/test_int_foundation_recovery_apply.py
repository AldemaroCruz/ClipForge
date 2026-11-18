"""Authored recovery-apply approval fixtures; no actual GCP, state or approval.

Source and artifact hashes below are computed from synthetic bytes. The tests
never load a repository config or claim preimages of production source/state.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_tf_int as c, int_release as custody
from scripts import int_foundation_recovery as recovery
from scripts import int_foundation_recovery_apply as apply_review
from scripts import check_int_foundation as foundation
from tests.test_int_foundation_recovery import authored_partial, authored_plan
from tests.test_tf_int import IMAGE_SOURCE_FIXTURE


PLAN_COMMIT = "264d1cfad6500e1abd60d3e7f966a3614a3a5831"
CONTROL_COMMIT = "c" * 40
DRIVER_SOURCE_SHA256 = "70982d2f5867d0101a181967d182058514e8c82a77423e5eceb09eb0cf89761b"
NOW = datetime(2026, 11, 18, 2, 30, tzinfo=timezone.utc)


def authored_artifacts(root):
    """Own source files and immutable custody for a synthetic recovery plan."""
    _, _, contract = authored_partial()
    contract["baseline"] = {"configuration_commit": "b" * 40}
    source_root = root / "producer-source"
    module = source_root / "infra/gcp/int-base"
    module.mkdir(parents=True)
    for name in c.FILES:
        target = module / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic reviewed source " + name)
    declarations = sorted({re.sub(r'\[.*', '', address) for address in c.ADDRESSES})
    main = IMAGE_SOURCE_FIXTURE + '\n'.join('resource "' + item.split('.')[0] + '" "' + item.split('.')[1] + '" {}' for item in declarations)
    main += '\n' + '\n'.join('data "' + kind + '" "synthetic" {}' for kind in sorted(c.DATA_TYPES - {"google_compute_image"}))
    main += '\n# Synthetic inventory text only, not a native Terraform plan.\n' + '\n'.join('lifecycle { prevent_destroy = true }' for _ in range(3))
    (module / 'main.tf').write_text(main)
    (module / 'variables.tf').write_text('\n'.join('variable "' + name + '" {}' for name in sorted(c.VARIABLES)))
    (module / 'versions.tf').write_text('terraform { required_version = "= 1.15.8"\n required_providers { google { version = "= 8.11.0" } } }')
    import_bytes = recovery.import_source(contract)
    (module / "recovery-imports.tf").write_bytes(import_bytes)
    base = {name: custody.sha256((module / name).read_bytes()) for name in c.FILES}
    files = {**base, "recovery-imports.tf": custody.sha256(import_bytes)}
    contract["source_bindings"] = {"base_configuration_sha256": custody.sha256(custody.canonical(base)),
                                   "provider_lock_sha256": files[".terraform.lock.hcl"], "imports_sha256": files["recovery-imports.tf"],
                                   "imports_source": "config/int-foundation-recovery-imports.tf"}
    (source_root / "config").mkdir()
    (source_root / "config/int-foundation-recovery.json").write_bytes(custody.canonical(contract))
    (source_root / "config/int-foundation-recovery-imports.tf").write_bytes(import_bytes)
    (source_root / 'scripts').mkdir()
    driver_fixture = b'# Synthetic producer-source identity; never executed.\n'
    (source_root / 'scripts/tf_int_plan.py').write_bytes(driver_fixture)
    contract['source_bindings']['execution_driver_sha256'] = custody.sha256(driver_fixture)
    (source_root / "config/int-foundation-recovery.json").write_bytes(custody.canonical(contract))
    foundation_contract = {'schema':'clipforge-int-foundation-contract-1', 'scope': {
        'executed_python':['scripts/tf_int_plan.py'], 'test_support_python':[], 'tests':[], 'workflows':[],
        'config':['config/int-foundation-contract.json', 'config/int-foundation-recovery.json'], 'module_files':list(c.FILES)}}
    (source_root / 'config/int-foundation-contract.json').write_bytes(custody.canonical(foundation_contract))
    plan = authored_plan(contract, with_imports=True)
    raw_json, binary = custody.canonical(plan), b"synthetic exact recovery saved binary"
    prefix = "private-plans/int/" + PLAN_COMMIT + "/44219757502-1/"
    reference = lambda name, generation, raw: {"name": prefix + name, "generation": generation,
                                               "sha256": custody.sha256(raw), "size": len(raw)}
    manifest = {"schema": "clipforge-int-foundation-recovery-private-plan-1", "configuration_commit": PLAN_COMMIT,
                "controls_commit": PLAN_COMMIT, "baseline_configuration_commit": "b" * 40,
                "configuration_files": files, "configuration_sha256": custody.sha256(custody.canonical(files)),
                "base_configuration_sha256": contract["source_bindings"]["base_configuration_sha256"],
                "provider_lock_sha256": files[".terraform.lock.hcl"], "terraform_version": "1.15.8", "provider_version": "8.11.0",
                "control_sources_sha256": foundation.fingerprint(source_root, foundation_contract)[0],
                "recovery_contract_sha256": custody.sha256(custody.canonical(contract)),
                "inputs": deepcopy(contract["inputs"]), "imports": deepcopy(contract["imports"]),
                "backend": {key: contract["backend"][key] for key in ("bucket", "prefix", "workspace", "name", "generation", "size", "sha256", "lineage", "serial", "terraform_version")},
                "created_utc": "2026-11-18T01:59:04.701513+00:00", "expires_utc": "2026-11-19T01:59:04.701513+00:00",
                "run_id": "44219757502", "run_attempt": "1", "apply_authorized": False,
                "risk_acceptance": deepcopy(contract["risk_acceptance"]),
                "image": {"project": "debian-cloud", "name": "debian-13-trixie-v20261116", "id": "5913446147369107523", "status": "READY"},
                "recovery_contract_sha256": custody.sha256((source_root / 'config/int-foundation-recovery.json').read_bytes()),
                "import_policies_sha256": "d" * 64, "plan_review_status": "recovery_plan_requires_new_review",
                "binary": reference("int.tfplan", "1001", binary), "json": reference("int.json", "1002", raw_json)}
    raw_manifest = custody.canonical(manifest)
    manifest_ref = reference("manifest.json", "1003", raw_manifest)
    return contract, manifest, manifest_ref, plan, binary, module, source_root


class RecoveryApplyContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='clipforge-recovery-apply-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.contract, self.manifest, self.reference, self.plan, self.binary,
         self.module, self.producer) = authored_artifacts(self.root)
        self.proposal = {'schema':'clipforge-int-foundation-recovery-apply-proposal-1', 'status':'proposed_not_authorized',
                         'apply_authorized':False, 'runtime_authorized':False, 'iam_grants_performed_by_apply_helper':False,
                         'repository':'AldemaroCruz/ClipForge', 'branch':'ci/bootstrap-sec03', 'environment':'int',
                         'plan':{**deepcopy(self.manifest), 'manifest':deepcopy(self.reference)},
                         'expected_review':recovery.verify_recovery_plan(self.plan,self.contract),
                         'iam_package':{'manifest_sha256':'d'*64,'expires_utc':(NOW+timedelta(hours=1)).isoformat(), 'bindings':{
                             key:{'resource':'projects/clipforgebeta2','role':'projects/clipforgebeta2/roles/clipforgeIntRecoverySynthetic_'+key,
                                  'member':'serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com',
                                  'condition':{'title':'Synthetic temporary grant','expression':'request.time < timestamp("2026-11-18T03:30:00Z")'},
                                  'permissions':['resourcemanager.projects.getIamPolicy'],
                                  'condition_sha256':custody.sha256(custody.canonical({'title':'Synthetic temporary grant','expression':'request.time < timestamp("2026-11-18T03:30:00Z")'}))}
                             for key in ('project_policy','logging_config','secret_create','secret_policies','iap_policy','postgres_sa_policy')}}}
        self.selection = deepcopy(self.proposal)
        prefix='private-plans/int/'+PLAN_COMMIT+'/44219757502-1/'
        for key,name,generation,digest,size in (
                ('manifest','manifest.json','1794967145187552','a6cd844f31900ab7d1c6012fa3a7b936a86698218551b2582a63266d88f4189e',6593),
                ('binary','int.tfplan','1794967144807369','c75860660cee6f3ac1c929963bac70f660e08d40767610e1895cd115f2462469',44420),
                ('json','int.json','1794967145021694','1ffeed1cfcd2b90e1df94dcdd23a77f78b3c5ba611255bc2eae11c2ff81ef194',293465)):
            self.selection['plan'][key]={'name':prefix+name,'generation':generation,'sha256':digest,'size':size}
        self.env={'GITHUB_SHA':CONTROL_COMMIT, 'INT_APPROVED_COMMIT':CONTROL_COMMIT,
                  'INT_STAGE':'foundation','TF_WORKSPACE':'default','RUNTIME_IMAGE':self.contract['inputs']['runtime_image'],
                  'MACHINE_TYPE':'e2-micro','SECRET_VERSIONS_JSON':'null'}
        self.report={'control_commit':CONTROL_COMMIT,'control_sources_sha256':'a'*64,'integrity_status':'passed',
                     'integrity':{name:{'status':'passed'} for name in foundation.REQUIRED_CHECKS},
                     'source_files':{'scripts/tf_int_plan.py':DRIVER_SOURCE_SHA256,'scripts/int_foundation_recovery_apply.py':'e'*64},
                     'sast':{'schema':'clipforge-int-foundation-sast-review-1','status':'blocked','proofs':[], 'findings':[
                         {'resource':'scripts/tf_int_plan.py','rule':rule,'line':line,'severity':'LOW',
                          'source_sha256':DRIVER_SOURCE_SHA256,'disposition':'risk_pending'}
                         for rule,line in (('B404',16),('B603',169),('B603',180))]}}
        fixed=NOW
        class Clock(datetime):
            @classmethod
            def now(cls,tz=None):
                return fixed.astimezone(tz) if tz else fixed.replace(tzinfo=None)
        for target in (apply_review,recovery):
            clock=mock.patch.object(target,'datetime',Clock)
            clock.start();self.addCleanup(clock.stop)

    def approved_fixture(self, report=None):
        """Future test input only; never writes or grants an owner decision."""
        value=deepcopy(apply_review.decision_template(report or self.report,self.proposal))
        value['apply_decision']='approve_exact_recovery_binary_once'
        for row in value['residual_decisions']:
            row['decision']={'F-SAST-EXEC':'approve_new_exact_recovery_execution_route_for_this_binary_only',
                             'F-VM-XML':'preserve_exact_image_inactive_database_conditions',
                             'F-AUDIT-0077':'preserve_alternative_pending_operational_validation'}[row['id']]
        value['iam_package']={'manifest_sha256':'d'*64,'administrator_receipt_sha256':'e'*64,
                              'expires_utc':(NOW+timedelta(hours=1)).isoformat()}
        self.receipt_bundle(value)
        return value

    def receipt_bundle(self, decision):
        rows=[]
        for key,binding in self.proposal['iam_package']['bindings'].items():
            for status in ('attempted','completed'):
                rows.append({'schema':'clipforge-int-foundation-iam-receipt-1','bundle_manifest_sha256':'d'*64,
                             'authorization_reference_sha256':'f'*64,'sequence':len(rows)+1,'utc':(NOW-timedelta(minutes=1)).isoformat(),
                             'mode':'Grant','operation':'grant_binding','status':status,'key':key,'mutation_attempted':True,
                             **{name:binding[name] for name in ('resource','role','member','condition_sha256')},
                             'http_status':200 if status=='completed' else None,
                             'native_exit_code':0 if status=='completed' else None,'error_category':None})
        index={'schema':'clipforge-int-foundation-iam-receipt-index-1','bundle_manifest_sha256':'d'*64,
               'authorization_reference_sha256':'f'*64,'mode':'Grant','files':[]}
        bundle={'index':'','files':{}}
        for sequence,row in enumerate(rows,1):
            name=f'{sequence:04d}.json';raw=custody.canonical(row).decode()
            bundle['files'][name]=raw;index['files'].append({'name':name,'sha256':custody.sha256(raw.encode())})
        bundle['index']=custody.canonical(index).decode()
        decision['iam_package']['administrator_receipt_sha256']=custody.sha256(bundle['index'].encode())
        return bundle

    @staticmethod
    def reseal_receipts(bundle,decision):
        index=json.loads(bundle['index'])
        for item in index['files']:
            item['sha256']=custody.sha256(bundle['files'][item['name']].encode())
        bundle['index']=custody.canonical(index).decode()
        decision['iam_package']['administrator_receipt_sha256']=custody.sha256(bundle['index'].encode())

    def verify_decision(self, decision, report=None, environ=None, now=NOW):
        return apply_review.verify_owner_decision(decision,custody.sha256(custody.canonical(decision)),
                   report or self.report,self.proposal,environ or self.env,now=now)

    def test_real_reference_selection_is_exact_metadata_and_grants_no_authority(self):
        original=deepcopy(self.selection)
        apply_review.verify_proposal(self.selection,self.contract,now=NOW)
        self.assertEqual(self.selection,original)
        self.assertFalse(self.selection['apply_authorized'])
        self.assertFalse(self.selection['runtime_authorized'])
        for reference in ('manifest','binary','json'):
            for field in ('name','generation','sha256','size'):
                changed=deepcopy(self.selection)
                changed['plan'][reference][field]=1 if field=='size' else 'different'
                with self.subTest(reference=reference,field=field),self.assertRaises(ValueError):
                    apply_review.verify_proposal(changed,self.contract,now=NOW)

    def test_changed_scope_actions_imports_origin_and_past_or_extended_plan_are_rejected(self):
        for field,value in (('configuration_commit','b'*40),('controls_commit',CONTROL_COMMIT),('run_id','44194990499'),
                            ('expires_utc',(NOW+timedelta(days=2)).isoformat())):
            changed=deepcopy(self.selection);changed['plan'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):apply_review.verify_proposal(changed,self.contract,now=NOW)
        for field,value in (('counts',{'create':42}),('imports',[]),('addresses',sorted(c.FOUNDATION_ADDRESSES)[:-1])):
            changed=deepcopy(self.selection);changed['expected_review'][field]=value
            with self.subTest(review=field),self.assertRaises(ValueError):apply_review.verify_proposal(changed,self.contract,now=NOW)
        with self.assertRaises(ValueError):
            apply_review.verify_proposal(self.selection,self.contract,now=datetime(2026,11,19,2,tzinfo=timezone.utc))

    def test_default_pending_decision_and_missing_iam_receipt_never_authorize(self):
        pending=apply_review.decision_template(self.report,self.proposal)
        self.assertEqual(pending['apply_decision'],'pending')
        self.assertTrue(all(row['decision']=='pending' for row in pending['residual_decisions']))
        with self.assertRaises(ValueError):self.verify_decision(pending)
        for field,value in (('manifest_sha256',None),('administrator_receipt_sha256',None),('expires_utc',NOW.isoformat())):
            decision=self.approved_fixture();decision['iam_package'][field]=value
            with self.subTest(package=field),self.assertRaises(ValueError):self.verify_decision(decision)

    def test_future_exact_decision_accepts_distinct_controls_without_rewriting_producer(self):
        original=deepcopy(self.proposal);decision=self.approved_fixture()
        result=self.verify_decision(decision)
        self.assertEqual(result['configuration_commit'],PLAN_COMMIT)
        self.assertEqual(result['apply_controls_commit'],CONTROL_COMMIT)
        self.assertEqual(self.proposal,original)
        self.assertEqual(self.proposal['plan']['controls_commit'],PLAN_COMMIT)
        same_report=deepcopy(self.report);same_report['control_commit']=PLAN_COMMIT
        same_env={**self.env,'GITHUB_SHA':PLAN_COMMIT,'INT_APPROVED_COMMIT':PLAN_COMMIT}
        self.verify_decision(self.approved_fixture(same_report),same_report,same_env)

    def test_old_decision_cannot_validate_fresh_controls_or_modified_evidence(self):
        decision=self.approved_fixture()
        for mutation in ('control','source-hash','failed-check','missing-check','high','unknown-site','changed-source','subset'):
            report=deepcopy(self.report)
            if mutation=='control':report['control_commit']='e'*40
            elif mutation=='source-hash':report['control_sources_sha256']='b'*64
            elif mutation=='failed-check':report['integrity']['fmt']['status']='failed'
            elif mutation=='missing-check':del report['integrity']['fmt']
            elif mutation=='high':report['sast']['findings'][0]['severity']='HIGH'
            elif mutation=='unknown-site':report['sast']['findings'][0]['line']=17
            elif mutation=='changed-source':report['sast']['findings'][0]['source_sha256']='0'*64
            else:report['sast']['findings'].pop()
            selected=decision if mutation in ('control','source-hash') else self.approved_fixture(report)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.verify_decision(selected,report)
        with self.assertRaises(ValueError):
            apply_review.verify_owner_decision(decision,'0'*64,self.report,self.proposal,self.env,now=NOW)

    def test_old_binary_risk_strings_altered_image_backend_and_expiry_never_transfer(self):
        for mutation in ('old-acceptance','image','backend','manifest','runtime','extended-risk','extended-plan'):
            decision=self.approved_fixture()
            if mutation=='old-acceptance':decision['residual_decisions'][0]['decision']='approve_exact_execution_sites_for_this_binary_only'
            elif mutation=='image':decision['residual_decisions'][1]['image']['id']='1'
            elif mutation=='backend':decision['plan']['backend']['serial']=1
            elif mutation=='manifest':decision['plan']['manifest']['sha256']='0'*64
            elif mutation=='runtime':decision['runtime_authorized']=True
            elif mutation=='extended-risk':decision['risk_expiry_utc']='2026-11-29T00:00:00+00:00'
            else:decision['expires_utc']='2026-11-20T01:59:04+00:00'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.verify_decision(decision)
        for when in (datetime(2026,11,18,1,tzinfo=timezone.utc),datetime(2026,11,19,2,tzinfo=timezone.utc)):
            with self.subTest(time=when),self.assertRaises(ValueError):self.verify_decision(self.approved_fixture(),now=when)

    def test_bridge_keeps_all_owned_source_bytes_and_producer_identity_exact(self):
        original=deepcopy(self.manifest)
        # Only the literal production-artifact selection is substituted: no
        # synthetic bytes pretend to have the real a6cd/c758 hashes. All source,
        # manifest, producer-fingerprint and environment checks execute normally.
        with mock.patch.object(apply_review,'verify_proposal') as selection:
            result=apply_review.verify_plan_bridge(self.manifest,self.proposal,self.module,self.producer,self.env)
        selection.assert_called_once()
        self.assertEqual(result,self.contract)
        self.assertEqual(self.manifest,original)
        for name in ('main.tf','postgres-install.sh','.terraform.lock.hcl','recovery-imports.tf'):
            target=self.module/name;raw=target.read_bytes();target.write_bytes(raw+b'\nchanged')
            with mock.patch.object(apply_review,'verify_proposal'),self.subTest(source=name),self.assertRaises(ValueError):
                apply_review.verify_plan_bridge(self.manifest,self.proposal,self.module,self.producer,self.env)
            target.write_bytes(raw)
        extra=self.module/'unexpected.tf';extra.write_text('# synthetic unexpected source')
        with mock.patch.object(apply_review,'verify_proposal'),self.assertRaises(ValueError):
            apply_review.verify_plan_bridge(self.manifest,self.proposal,self.module,self.producer,self.env)

    def test_six_iam_receipts_are_closed_ordered_and_bound_to_the_reviewed_package(self):
        decision=self.approved_fixture();bundle=self.receipt_bundle(decision)
        index=apply_review.verify_iam_receipts(json.dumps(bundle),decision,self.proposal)
        self.assertEqual(len(index['files']),12)
        for mutation in ('raw-byte','extra-file','failed','rollback','target','duplicate-attempt','no-attempt','http-failure','expired','private-field'):
            d=deepcopy(decision);b=deepcopy(bundle)
            if mutation=='raw-byte':b['files']['0001.json']+=' '
            elif mutation=='extra-file':b['files']['9999.json']='synthetic-private-sentinel'
            else:
                row=json.loads(b['files']['0002.json'])
                if mutation=='failed':row['status']='failed'
                elif mutation=='rollback':row['mode']='Rollback'
                elif mutation=='target':row['member']='allUsers'
                elif mutation=='duplicate-attempt':row['status']='attempted'
                elif mutation=='no-attempt':
                    first=json.loads(b['files']['0001.json']);first['status']='started';b['files']['0001.json']=custody.canonical(first).decode()
                elif mutation=='http-failure':row['http_status']=403
                elif mutation=='expired':row['utc']=self.proposal['iam_package']['expires_utc']
                else:row['private_response']='synthetic-private-sentinel'
                b['files']['0002.json']=custody.canonical(row).decode();self.reseal_receipts(b,d)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                apply_review.verify_iam_receipts(json.dumps(b),d,self.proposal)

    def test_native_trace_applies_only_the_verified_saved_file_and_stops_on_races_or_failure(self):
        for scenario in ('success','changed-backend','changed-binary','changed-config','withdrawn-iam','native-failure','wrong-json'):
            with tempfile.TemporaryDirectory(prefix='clipforge-recovery-apply-trace-') as temporary:
                root=Path(temporary);original=root/'plan-source'
                # Copy only this test's authored producer, not the real checkout.
                import shutil
                shutil.copytree(self.producer,original)
                work,reports=root/'work',root/'reports';work.mkdir();reports.mkdir()
                adc=root/'gha-creds-synthetic.json';adc.write_text('Synthetic filename marker; not credentials.')
                decision=self.approved_fixture();bundle=self.receipt_bundle(decision)
                env={**self.env,'GITHUB_REPOSITORY':'AldemaroCruz/ClipForge','GITHUB_REF':'refs/heads/ci/bootstrap-sec03',
                     'GITHUB_EVENT_NAME':'workflow_dispatch','RUNNER_ENVIRONMENT':'github-hosted','GCP_ACCESS_TOKEN':'synthetic-not-credentials',
                     'GCP_PROJECT_ID':'clipforgebeta2','GCP_PROJECT_NUMBER':'816643438938','GCP_REGION':'us-central1',
                     'GCP_TERRAFORM_SA':'clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com',
                     'GCP_WIF_PROVIDER':'projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github',
                     'TF_STATE_BUCKET':c.BUCKET,'TF_STATE_PREFIX':'terraform/int','GOOGLE_APPLICATION_CREDENTIALS':str(adc),
                     'RECOVERY_DECISION_JSON':json.dumps(decision),'RECOVERY_DECISION_SHA256':custody.sha256(custody.canonical(decision)),
                     'RECOVERY_IAM_RECEIPTS_JSON':json.dumps(bundle),'GITHUB_RUN_ID':'50000000000','GITHUB_RUN_ATTEMPT':'1'}
                objects={self.reference['name']:custody.canonical(self.manifest),
                         self.manifest['binary']['name']:self.binary,self.manifest['json']['name']:custody.canonical(self.plan)}
                if scenario=='wrong-json':objects[self.manifest['json']['name']]+=b' '
                def get(method,name,*,generation=None):
                    self.assertEqual(method,'GET');self.assertIn(generation,('1001','1002','1003'))
                    return objects[name]
                calls=[]
                def native(argv,operation,_work,**_kwargs):
                    calls.append((argv,operation))
                    if operation=='recovery_apply_init':
                        if scenario=='changed-binary':(work/'int.tfplan').write_bytes(b'changed synthetic binary')
                        if scenario=='changed-config':(work/'module/main.tf').write_text('# changed synthetic HCL')
                    if operation=='recovery_apply_saved' and scenario=='native-failure':
                        raise apply_review.driver.FailedOperation(operation,"403 Permission 'logging.buckets.create' denied on resource projects/clipforgebeta2")
                    return 0,b''
                proofs=[{'classification':'recognized_partial_foundation_state','state':{'serial':5}},
                        {'classification':'recognized_partial_foundation_state','state':{'serial':6 if scenario=='changed-backend' else 5}}]
                # Explicit external boundaries: live cloud/VM preconditions and
                # receipt publication are simulated. Every source, saved-byte,
                # owner-decision and import/action verifier runs normally.
                with mock.patch.object(apply_review,'load_proposal',return_value=self.proposal), \
                        mock.patch.object(apply_review,'verify_proposal'), \
                        mock.patch.object(foundation,'fetch_evidence',return_value=self.report), \
                        mock.patch.object(custody,'request',side_effect=get), \
                        mock.patch.object(apply_review.driver,'metadata',return_value={'name':c.BUCKET}), \
                        mock.patch.object(apply_review,'live_preflight',side_effect=proofs), \
                        mock.patch.object(apply_review,'verify_live_iam',side_effect=[{'bindings_present':6},
                            ValueError('Synthetic grant withdrawn after init') if scenario=='withdrawn-iam' else {'bindings_present':6}]) as iam, \
                        mock.patch.object(apply_review.driver,'terraform_binary',return_value='synthetic-terraform') as version_check, \
                        mock.patch.object(apply_review.driver,'run',side_effect=native), \
                        mock.patch.object(apply_review,'emit_receipt',return_value=({'name':'synthetic-private-receipt'}, {'state':{'serial':6}})) as emit, \
                        mock.patch.dict(apply_review.os.environ,{},clear=True),self.subTest(scenario=scenario):
                    if scenario=='success':
                        summary=apply_review.apply_reviewed(work,reports,env,root=root)
                        self.assertFalse(summary['runtime_authorized']);emit.assert_called_once()
                        self.assertEqual(emit.call_args.kwargs['bucket'],{'name':c.BUCKET})
                        self.assertEqual((work/'int.tfplan').read_bytes(),self.binary)
                    else:
                        with self.assertRaises(ValueError):apply_review.apply_reviewed(work,reports,env,root=root)
                        emit.assert_not_called()
                attempted=work/'apply-attempted.json';completed=work/'apply-completed.json'
                self.assertEqual(attempted.exists(),scenario in {'success','native-failure'})
                self.assertEqual(completed.exists(),scenario=='success')
                if attempted.exists():
                    self.assertEqual(json.loads(attempted.read_bytes()),{
                        'binary_sha256':self.proposal['plan']['binary']['sha256'],'controls_commit':CONTROL_COMMIT})
                operations=[operation for _,operation in calls]
                if scenario=='wrong-json':
                    self.assertEqual(operations,[]);version_check.assert_not_called();iam.assert_not_called()
                elif scenario in ('changed-backend','changed-binary','changed-config','withdrawn-iam'):
                    self.assertEqual(operations,['recovery_apply_init']);version_check.assert_called_once_with()
                    self.assertEqual(iam.call_count,1 if scenario=='changed-backend' else 2)
                else:
                    self.assertEqual(iam.call_count,2)
                    version_check.assert_called_once_with()
                    self.assertEqual(operations,['recovery_apply_init','recovery_apply_saved'])
                    self.assertEqual(calls[1][0],['synthetic-terraform','apply','-input=false','-no-color','-lock=true','-lock-timeout=120s',str(work/'int.tfplan')])

    def test_new_receipt_uses_real_bucket_metadata_and_final_state_descendant_without_payload(self):
        grouped={}
        for address in sorted(c.FOUNDATION_ADDRESSES):
            kind,rest=address.split('.',1);name,index=re.fullmatch(r'([^\[]+)(?:\["([^"\]]+)"\])?',rest).groups()
            row=grouped.setdefault((kind,name),{'mode':'managed','type':kind,'name':name,'instances':[]})
            instance={'attributes':{'synthetic_private_attribute':'synthetic-private-state-sentinel'}}
            if index is not None:instance['index_key']=index
            row['instances'].append(instance)
        env={**self.env,'GITHUB_RUN_ID':'50000000000','GITHUB_RUN_ATTEMPT':'1'}
        for mutation in ('valid','old-generation','old-serial','wrong-lineage','missing-resource','tainted','state-raced','current-lock'):
            value={'version':4,'terraform_version':'1.15.8','lineage':self.contract['backend']['lineage'],
                   'serial':6,'resources':deepcopy(list(grouped.values())),'outputs':{}}
            obj={'name':c.PREFIX+'/default.tfstate','generation':'2001'}
            if mutation=='old-generation':obj['generation']=self.contract['backend']['generation']
            elif mutation=='old-serial':value['serial']=5
            elif mutation=='wrong-lineage':value['lineage']='another-lineage'
            elif mutation=='missing-resource':value['resources'].pop()
            elif mutation=='tainted':value['resources'][0]['instances'][0]['status']='tainted'
            raw=custody.canonical(value);obj['size']=str(len(raw));bucket={'name':c.BUCKET}
            live=[deepcopy(obj)]
            if mutation=='state-raced':live[0]['generation']='2002'
            elif mutation=='current-lock':live.append({'name':c.PREFIX+'/default.tflock','generation':'2002'})
            with mock.patch.object(apply_review.state_reader,'private_current_state',return_value=(raw,obj,{})) as read, \
                    mock.patch.object(apply_review.driver,'backend_inventory',return_value={'live':live}) as inventory, \
                    mock.patch.object(custody,'upload',return_value={'name':'synthetic-private-receipt'}) as upload,self.subTest(mutation=mutation):
                if mutation=='valid':
                    _,receipt=apply_review.emit_receipt(self.root,self.proposal['plan'],{'decision_sha256':'d'*64},env,bucket=bucket)
                    self.assertEqual(receipt['schema'],'clipforge-int-foundation-recovery-apply-receipt-1')
                    self.assertEqual(receipt['producer_controls_commit'],PLAN_COMMIT)
                    self.assertEqual(receipt['issuer']['commit'],CONTROL_COMMIT)
                    self.assertEqual(receipt['issuer']['workflow'],'.github/workflows/int-foundation-recovery-apply.yml')
                    self.assertFalse(receipt['runtime_authorized'])
                    self.assertEqual(receipt['state']['managed_addresses'],sorted(c.FOUNDATION_ADDRESSES))
                    self.assertNotIn('synthetic-private-state-sentinel',json.dumps(receipt))
                    upload.assert_called_once()
                else:
                    with self.assertRaises(ValueError):apply_review.emit_receipt(self.root,self.proposal['plan'],{},env,bucket=bucket)
                    upload.assert_not_called()
            read.assert_called_once_with(bucket)
            if mutation in {'valid','state-raced','current-lock'}:inventory.assert_called_once_with(bucket)
            else:inventory.assert_not_called()

    def test_main_preserves_partial_state_after_attempt_and_distinguishes_completed_native_apply(self):
        for scenario in ('preflight','native-failure','timeout-without-log','receipt-failure','unknown-partial-lineage'):
            with tempfile.TemporaryDirectory(prefix='clipforge-recovery-apply-failure-') as temporary,self.subTest(scenario=scenario):
                root=Path(temporary);work=root/'work';reports=root/'reports';work.mkdir();reports.mkdir()
                value={'version':4,'terraform_version':'1.15.8','lineage':self.contract['backend']['lineage'],
                       'serial':6,'resources':[{'synthetic_private_attribute':'synthetic-private-state-sentinel'}]}
                if scenario=='unknown-partial-lineage':value['lineage']='unrecognized-lineage'
                raw=custody.canonical(value);bucket={'name':c.BUCKET}
                def fail(_work,_reports,_environ):
                    if scenario!='preflight':(work/'apply-attempted.json').write_bytes(b'{}')
                    if scenario=='receipt-failure':(work/'apply-completed.json').write_bytes(b'{}')
                    if scenario=='timeout-without-log':
                        raise apply_review.driver.subprocess.TimeoutExpired('synthetic-terraform',1200,output=b'synthetic-private-native-sentinel')
                    if scenario=='native-failure':
                        raise apply_review.driver.FailedOperation('recovery_apply_saved',"403 Permission 'logging.buckets.create' denied")
                    raise ValueError('synthetic-private-native-sentinel')
                with mock.patch('sys.argv',['int_foundation_recovery_apply','apply']), \
                        mock.patch.object(apply_review.os,'umask'),mock.patch.dict(apply_review.os.environ,{},clear=True), \
                        mock.patch.object(apply_review.driver,'private_paths',return_value=(work,reports)), \
                        mock.patch.object(apply_review,'apply_reviewed',side_effect=fail) as execute, \
                        mock.patch.object(apply_review.driver,'metadata',return_value=bucket) as metadata, \
                        mock.patch.object(apply_review.state_reader,'private_current_state',return_value=(raw,{'generation':'2001'},{})) as read, \
                        mock.patch.object(recovery,'load_contract',return_value=self.contract), \
                        mock.patch.object(apply_review.driver,'run') as native:
                    self.assertEqual(apply_review.main(),1)
                execute.assert_called_once_with(work,reports,apply_review.os.environ)
                native.assert_not_called()
                summary=json.loads((reports/'summary.json').read_bytes())
                expected='native_apply_completed_post_apply_verification_failed_no_retry' if scenario=='receipt-failure' else 'blocked_or_partial_recovery_preserve_state_no_retry'
                self.assertEqual(summary['status'],expected);self.assertFalse(summary['runtime_authorized'])
                for name in ('summary.json','summary.md'):
                    public=(reports/name).read_text()
                    self.assertNotIn('synthetic-private-state-sentinel',public)
                    self.assertNotIn('synthetic-private-native-sentinel',public)
                if scenario=='preflight':
                    metadata.assert_not_called();read.assert_not_called();self.assertNotIn('partial_state',summary)
                else:
                    metadata.assert_called_once();read.assert_called_once_with(bucket)
                    if scenario=='unknown-partial-lineage':
                        self.assertNotIn('partial_state',summary)
                        self.assertEqual(summary['partial_state_inspection'],{'error_type':'ValueError'})
                    else:
                        self.assertEqual(summary['partial_state'],{'name':apply_review.driver.STATE_NAME,'generation':'2001',
                            'size':len(raw),'sha256':custody.sha256(raw),'lineage':value['lineage'],'serial':6})

    def iam_observations(self):
        project='https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2:getIamPolicy'
        iap='https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131:getIamPolicy'
        sa='https://iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3'
        responses={project:{'bindings':[]},iap:{'bindings':[]},sa:{'bindings':[]}}
        for key,binding in self.proposal['iam_package']['bindings'].items():
            policy=iap if key=='iap_policy' else sa if key=='postgres_sa_policy' else project
            responses[policy]['bindings'].append({'role':binding['role'],'members':[binding['member']], 'condition':deepcopy(binding['condition'])})
            responses['https://iam.googleapis.com/v1/'+binding['role']]={'name':binding['role'],'stage':'GA','deleted':False,
                                                                         'includedPermissions':binding['permissions'][:]}
        return responses

    def test_live_iam_checks_all_six_current_bindings_and_role_definitions(self):
        responses=self.iam_observations()
        with mock.patch.object(apply_review,'iam_metadata',side_effect=lambda url:deepcopy(responses[url])) as reads:
            proof=apply_review.verify_live_iam(self.proposal)
        self.assertEqual(proof,{'bindings_present':6,'role_definitions_match':6,'effective_authorization_not_inferred':True})
        self.assertEqual(reads.call_count,9)
        self.assertEqual({call.args[0] for call in reads.call_args_list},set(responses))
        for mutation in ('missing','role','member','condition','duplicate','permissions','deleted','stage','role-name'):
            changed=deepcopy(responses);project=next(iter(changed))
            role_url='https://iam.googleapis.com/v1/'+self.proposal['iam_package']['bindings']['project_policy']['role']
            if mutation=='missing':changed[project]['bindings'].pop(0)
            elif mutation=='role':changed[project]['bindings'][0]['role']='roles/owner'
            elif mutation=='member':changed[project]['bindings'][0]['members']=['allUsers']
            elif mutation=='condition':changed[project]['bindings'][0]['condition']['expression']='true'
            elif mutation=='duplicate':changed[project]['bindings'].append(deepcopy(changed[project]['bindings'][0]))
            elif mutation=='permissions':changed[role_url]['includedPermissions'].append('iam.serviceAccountKeys.create')
            elif mutation=='deleted':changed[role_url]['deleted']=True
            elif mutation=='stage':changed[role_url]['stage']='ALPHA'
            else:changed[role_url]['name']='projects/clipforgebeta2/roles/anotherRole'
            with mock.patch.object(apply_review,'iam_metadata',side_effect=lambda url:deepcopy(changed[url])), self.subTest(mutation=mutation),self.assertRaises(ValueError):
                apply_review.verify_live_iam(self.proposal)

    def test_iam_endpoint_allowlist_rejects_before_token_lookup_or_transport(self):
        good='https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2:getIamPolicy'
        urls=(good.replace('https:','http:'),good.replace('clipforgebeta2','another-project'),good.replace(':getIamPolicy',':setIamPolicy'),
              good.replace('googleapis.com','googleapis.com.example.invalid'),good.replace('https://','https://user:synthetic-password@'),
              good.replace('.com/','.com:443/'),good+'#fragment',good+'?unreviewed=value',
              'https://iam.googleapis.com/v1/projects/clipforgebeta2/roles/notRecovery',
              'https://iam.googleapis.com/v1/projects/another-project/roles/clipforgeIntRecoverySynthetic')
        class NoCredentials(dict):
            def __getitem__(self,key):raise AssertionError('Unreviewed endpoint attempted credential lookup')
        for url in urls:
            with mock.patch.object(apply_review.os,'environ',NoCredentials()),mock.patch.object(apply_review,'build_opener') as network, \
                    self.subTest(url=url),self.assertRaises(ValueError):apply_review.iam_metadata(url)
            network.assert_not_called()

    def test_iam_transport_uses_only_fixed_readonly_post_or_get_requests(self):
        urls=list(self.iam_observations())
        for url in urls:
            opener,response=mock.Mock(),mock.MagicMock()
            response.__enter__.return_value.read.return_value=b'{"synthetic":true}'
            opener.open.return_value=response
            with mock.patch.dict(apply_review.os.environ,{'GCP_ACCESS_TOKEN':'synthetic-not-credentials'},clear=True), \
                    mock.patch.object(apply_review,'build_opener',return_value=opener),self.subTest(url=url):
                self.assertEqual(apply_review.iam_metadata(url),{'synthetic':True})
            request=opener.open.call_args.args[0]
            self.assertEqual(request.full_url,url)
            if url.startswith(('https://cloudresourcemanager.googleapis.com/','https://iap.googleapis.com/')):
                self.assertEqual(request.get_method(),'POST')
                self.assertEqual(json.loads(request.data),{'options':{'requestedPolicyVersion':3}})
            elif '/serviceAccounts/' in url:
                self.assertEqual(request.get_method(),'POST')
                self.assertEqual(request.full_url,'https://iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3')
                self.assertIn(request.data,(None,b''))
            else:
                self.assertEqual(request.get_method(),'GET');self.assertIsNone(request.data)

    def test_iam_http_error_receipt_identifies_only_the_allowlisted_read_and_status_without_reading_body(self):
        endpoints=(
            ('https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2:getIamPolicy',
             'read_project_iam_policy','projects/clipforgebeta2','POST'),
            ('https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131:getIamPolicy',
             'read_iap_instance_iam_policy','projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131','POST'),
            ('https://iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3',
             'read_postgres_service_account_iam_policy','projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com','POST'),
            ('https://iam.googleapis.com/v1/projects/clipforgebeta2/roles/clipforgeIntRecoverySynthetic_read',
             'read_recovery_role_definition','projects/clipforgebeta2/roles/clipforgeIntRecoverySynthetic_read','GET'))
        for url,operation,resource,method in endpoints:
            for status in (403,404,500):
                with self.subTest(operation=operation,status=status):
                    body=mock.Mock();body.read.side_effect=AssertionError('HTTP failure body must remain unread')
                    failure=apply_review.HTTPError(url,status,'synthetic-private-policy-reason',
                        {'Authorization':'Bearer synthetic-private-header','X-Policy':'synthetic-private-policy-header'},body)
                    opener=mock.Mock();opener.open.side_effect=failure
                    with mock.patch.dict(apply_review.os.environ,{'GCP_ACCESS_TOKEN':'synthetic-private-access-token'},clear=True), \
                            mock.patch.object(apply_review,'build_opener',return_value=opener):
                        with self.assertRaises(apply_review.driver.FailedOperation) as raised:
                            apply_review.iam_metadata(url)
                    body.read.assert_not_called();opener.open.assert_called_once()
                    receipt=raised.exception.receipt
                    self.assertEqual(set(receipt),{'operation','status','permissions','resources','messages','resource','http_status','method'})
                    self.assertEqual(receipt['operation'],operation)
                    self.assertEqual(receipt['resource'],resource);self.assertEqual(receipt['resources'],[resource])
                    self.assertEqual(receipt['status'],status);self.assertEqual(receipt['http_status'],status)
                    self.assertEqual(receipt['method'],method);self.assertEqual(receipt['permissions'],[])
                    self.assertEqual(opener.open.call_args.args[0].full_url,url)
                    public=json.dumps(receipt)+str(raised.exception)
                    for sentinel in ('synthetic-private-policy-reason','synthetic-private-header',
                                     'synthetic-private-policy-header','synthetic-private-access-token','Bearer','bindings'):
                        self.assertNotIn(sentinel,public)

    def test_bridge_rejects_parent_partial_inputs_manifest_and_workspaces_without_casts(self):
        for field,value in (('backend',{}),('controls_commit',CONTROL_COMMIT),('recovery_contract_sha256','0'*64)):
            manifest=deepcopy(self.manifest);manifest[field]=value
            with mock.patch.object(apply_review,'verify_proposal'),self.subTest(field=field),self.assertRaises(ValueError):
                apply_review.verify_plan_bridge(manifest,self.proposal,self.module,self.producer,self.env)
        for key,value in (('INT_STAGE','runtime'),('TF_WORKSPACE','other'),('MACHINE_TYPE','e2-small')):
            with mock.patch.object(apply_review,'verify_proposal'),self.subTest(variable=key),self.assertRaises(ValueError):
                apply_review.verify_plan_bridge(self.manifest,self.proposal,self.module,self.producer,{**self.env,key:value})


if __name__=='__main__':
    unittest.main()
