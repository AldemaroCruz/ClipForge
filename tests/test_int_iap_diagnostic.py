"""Read-diagnostic contracts with authored state/policies and mocked transports.

No fixture is an actual backend, credential or approval. Native execution is
represented by an argv spy; the real data-only and publication guards still run.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from scripts import check_tf_int as c, int_release as custody
from scripts import int_iap_diagnostic as diagnostic
from scripts import int_iap_provider_probe as native


NOW = datetime(2026, 11, 18, 17, 30, tzinfo=timezone.utc)
MEMBER = 'serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com'
SENTINEL = 'synthetic-private-policy-sentinel'
REASON = 'ClipForge IAP diagnostic run 50000000000 provider ADC numeric'
AUTHORED_LIVE_IDENTITY = {'verified':True,'project_id':'clipforgebeta2','project_number':'816643438938',
    'instance_id':'1670495097211408131','instance_name':'clipforge-int-base-postgres','zone':'us-central1-a'}
NUMERIC_RUNTIME = '''resource "google_iap_tunnel_instance_iam_member" "protected_bootstrap" {
  project = data.google_project.existing.number
  zone = local.zone
  instance = google_compute_instance.postgres.instance_id
  role = "roles/iap.tunnelResourceAccessor"
  member = "serviceAccount:authored-fixture@clipforgebeta2.iam.gserviceaccount.com"
}
'''


def authored_state():
    grouped = {}
    for address in sorted(c.FOUNDATION_ADDRESSES - {'google_iap_tunnel_instance_iam_member.protected_bootstrap'}):
        kind, rest = address.split('.', 1)
        name, index = re.fullmatch(r'([^\[]+)(?:\["([^"\]]+)"\])?', rest).groups()
        row = grouped.setdefault((kind, name), {'mode': 'managed', 'type': kind, 'name': name,
            'provider':'provider["registry.terraform.io/hashicorp/google"]','instances': []})
        instance = {'attributes': {'private_fixture': SENTINEL}}
        if (kind, name) == ('google_compute_instance', 'postgres'):
            instance['attributes'].update(instance_id='1670495097211408131',name='clipforge-int-base-postgres',
                                          project='clipforgebeta2',zone='us-central1-a')
        if index is not None:
            instance['index_key'] = index
        row['instances'].append(instance)
    resources = list(grouped.values()) + [{'mode':'data','type':'google_project','name':'existing',
                  'provider':'provider["registry.terraform.io/hashicorp/google"]',
                  'instances':[{'attributes':{'number':'816643438938','project_id':'clipforgebeta2'}}]}]
    return {'version': 4, 'terraform_version': '1.15.8', 'serial': 6,
            'lineage': 'author-authored-lineage-not-real-state', 'resources': resources, 'outputs': {}}


def authored_native_plan(policy):
    return {'terraform_version': '1.15.8', 'planned_values': {'root_module': {'resources': [
        {'address': 'data.google_iap_tunnel_instance_iam_policy.probe', 'mode': 'data',
         'type': 'google_iap_tunnel_instance_iam_policy', 'name': 'probe',
         'provider_name': 'registry.terraform.io/hashicorp/google', 'values': {'policy_data': json.dumps(policy)}},
        {'address': 'data.google_storage_bucket.identity', 'mode': 'data', 'type': 'google_storage_bucket',
         'name': 'identity', 'provider_name': 'registry.terraform.io/hashicorp/google',
         'values': {'name': 'clipforgebeta2-int-media'}}]}}}


class IapReadDiagnosticContract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='clipforge-iap-diagnostic-authored-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        (self.source / 'config').mkdir(parents=True)
        self.work = self.root / 'private-work'
        self.reports = self.root / 'public-reports'
        self.work.mkdir(); self.reports.mkdir()
        self.expected = {'role': 'projects/clipforgebeta2/roles/clipforgeIntRecoverySyntheticIapRead',
                         'member': MEMBER, 'condition': {'title': 'Synthetic grant',
                         'expression': 'request.time < timestamp("2026-11-18T05:00:00Z")'},
                         'expires_utc': '2026-11-18T05:00:00Z'}
        self.policy = {'version': 3, 'etag': 'synthetic-private-etag', 'bindings': [
            {'role': self.expected['role'], 'members': [MEMBER, 'serviceAccount:' + SENTINEL],
             'condition': deepcopy(self.expected['condition'])},
            {'role': 'roles/viewer', 'members': ['user:' + SENTINEL]}]}
        self.state = authored_state()
        self.raw = custody.canonical(self.state)
        self.obj = {'name': c.PREFIX + '/default.tfstate', 'generation': '1001', 'size': str(len(self.raw))}
        self.inventory = {'live': [deepcopy(self.obj)], 'versions': [deepcopy(self.obj),
            {'name': c.PREFIX + '/default.tflock', 'generation': '900'}], 'soft_deleted': []}
        self.contract = {'schema': 'clipforge-int-iap-read-diagnostic-1', 'grants_authorized': False,
            'apply_authorized': False, 'routes': deepcopy(diagnostic.ROUTES),
            'terraform_service_account': 'clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com',
            'historical_failure_utc': '2026-11-18T04:00:00Z', 'expired_binding': self.expected,
            'state_reference': {'generation': '1001', 'sha256': custody.sha256(self.raw), 'size': len(self.raw),
                                'lineage': self.state['lineage'], 'serial': 6}}
        self.provider_files = {}
        for name in c.FILES:
            target = self.source / 'infra/gcp/int-base' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((NUMERIC_RUNTIME if name=='runtime.tf' else 'Authored source fixture for ' + name + '\n').encode())
            self.provider_files[name] = custody.sha256(target.read_bytes())
        self.contract.update(foundation_configuration_sha256=custody.sha256(custody.canonical(self.provider_files)),
            provider_configuration_evidence={'provider_config_key':'google','provider_alias':None,'credential_expression_keys_present':[]})
        self.configure_route('numeric')
        self.contract['read_window']={'not_before_utc':'2026-11-18T17:00:00Z','expires_utc':'2026-11-18T18:00:00Z',
                                    'proposal_sha256':'b2fbaf3ba71e671601c7e803feb71cd89def33cad05cc47ea273d139ff897417','manifest_sha256':'a'*64}
        (self.source / 'config/int-iap-diagnostic.json').write_bytes(custody.canonical(self.contract))
        self.adc_document = {'type': 'external_account', 'audience': SENTINEL,
            'service_account_impersonation_url': 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com:generateAccessToken',
            'credential_source': {'url': 'https://synthetic.invalid/' + SENTINEL,
                                  'headers': {'Authorization': 'Bearer ' + SENTINEL}, 'format': {'type': 'json'}}}
        self.adc = self.root / 'gha-creds-authored.json'
        self.adc.write_bytes(custody.canonical(self.adc_document))
        self.env = {'GITHUB_SHA': 'c' * 40, 'INT_REVIEWED_CONTROLS_COMMIT': 'c' * 40,
            'GITHUB_REPOSITORY': 'AldemaroCruz/ClipForge', 'GITHUB_REF': 'refs/heads/ci/bootstrap-sec03',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_RUN_ID': '50000000000', 'GITHUB_RUN_ATTEMPT': '1',
            'GCP_PROJECT_ID': 'clipforgebeta2', 'GCP_PROJECT_NUMBER': '816643438938', 'GCP_REGION': 'us-central1',
            'GCP_TERRAFORM_SA': 'clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com',
            'GCP_WIF_PROVIDER': 'projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github',
            'TF_STATE_BUCKET': c.BUCKET, 'TF_STATE_PREFIX': 'terraform/int',
            'GCP_ACCESS_TOKEN': 'synthetic-private-access-token', 'GOOGLE_APPLICATION_CREDENTIALS': str(self.adc),
            'INT_READ_WINDOW_MANIFEST_SHA256':'a'*64,'INT_ADMIN_READ_RECEIPTS_SHA256':'b'*64,
            'UNRELATED_PRIVATE_VARIABLE': SENTINEL}
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return NOW if tz else NOW.replace(tzinfo=None)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(diagnostic, 'datetime', Clock).start()

    def configure_route(self, route):
        numeric=route=='numeric'
        expressions={'project':'data.google_project.existing.number' if numeric else 'var.project_id',
                     'zone':'local.zone','instance':'google_compute_instance.postgres.instance_id' if numeric else 'google_compute_instance.postgres.name'}
        text=NUMERIC_RUNTIME.replace('data.google_project.existing.number',expressions['project']).replace(
            'google_compute_instance.postgres.instance_id',expressions['instance'])
        (self.source/'infra/gcp/int-base/runtime.tf').write_text(text,encoding='utf-8',newline='\n')
        self.provider_files={name:custody.sha256((self.source/'infra/gcp/int-base'/name).read_bytes()) for name in c.FILES}
        fingerprint=custody.sha256(custody.canonical(self.provider_files))
        self.contract['foundation_configuration_sha256']=fingerprint
        self.contract['provider_route']={'required_route':route,'resource':diagnostic.ROUTES[route],
            'evaluated':{'project':'816643438938' if numeric else 'clipforgebeta2','zone':'us-central1-a',
                         'instance':'1670495097211408131' if numeric else 'clipforge-int-base-postgres'},
            'expressions':expressions,'address':'google_iap_tunnel_instance_iam_member.protected_bootstrap',
            'configuration_sha256':fingerprint}

    def authored_read_result(self):
        proof=diagnostic.provider_route_from_state(self.source,self.raw,self.contract)
        proof['live_identity']=deepcopy(AUTHORED_LIVE_IDENTITY)
        return {'provider_route':proof,
                'provider_source':diagnostic.verify_provider_reference(self.source,self.contract),
                'required_reads':[{'key':key,'method':method,'resource':resource,
                    'required_permission_for_operation':permission,'http_status':200}
                    for key,method,_url,_payload,permission,resource in diagnostic.READ_TARGETS],
                'probes':[{'route':route,'mode':mode,'resource':diagnostic.ROUTES[route],'http_status':200}
                          for route in ('numeric','named') for mode in ('explicit_http','provider_ADC')]}

    def test_credential_projection_is_closed_and_does_not_claim_effective_identity(self):
        document = deepcopy(self.adc_document)
        document['credential_source'][SENTINEL] = SENTINEL
        metadata = diagnostic.credential_metadata(self.env, document)
        self.assertEqual(metadata['configured_identity'], self.env['GCP_TERRAFORM_SA'])
        self.assertIsNone(metadata['effective_identity'])
        self.assertEqual(metadata['provider_expected_selection'], 'ADC')
        self.assertEqual(metadata['explicit_preflight_selection'], 'GCP_ACCESS_TOKEN_not_a_provider_auth_variable')
        self.assertTrue(metadata['ADC']['configured_target_matches'])
        self.assertEqual(metadata['ADC']['configured_impersonation_target'], self.env['GCP_TERRAFORM_SA'])
        self.assertTrue(all(type(value) is bool for value in metadata['environment_presence'].values()))
        self.assertEqual(set(metadata['environment_presence']), {
            'GOOGLE_CREDENTIALS', 'GOOGLE_CLOUD_KEYFILE_JSON', 'GCLOUD_KEYFILE_JSON', 'GOOGLE_OAUTH_ACCESS_TOKEN',
            'GOOGLE_IMPERSONATE_SERVICE_ACCOUNT', 'GOOGLE_IMPERSONATE_SERVICE_ACCOUNT_DELEGATES',
            'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_GHA_CREDS_PATH', 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE', 'GCP_ACCESS_TOKEN'})
        public = json.dumps(metadata)
        for private in (SENTINEL, str(self.adc), self.env['GCP_ACCESS_TOKEN'], 'Authorization'):
            self.assertNotIn(private, public)

    def test_credential_overrides_and_wrong_targets_never_prove_an_effective_principal(self):
        for name in ('GOOGLE_CREDENTIALS', 'GOOGLE_CLOUD_KEYFILE_JSON', 'GCLOUD_KEYFILE_JSON', 'GOOGLE_OAUTH_ACCESS_TOKEN',
                     'GOOGLE_IMPERSONATE_SERVICE_ACCOUNT', 'GOOGLE_IMPERSONATE_SERVICE_ACCOUNT_DELEGATES'):
            with self.subTest(name=name):
                result = diagnostic.credential_metadata({**self.env, name: SENTINEL}, self.adc_document)
                self.assertEqual(result['unexpected_overrides'], [name])
                self.assertEqual(result['provider_expected_selection'], 'override_present_not_reproduced')
                self.assertIsNone(result['effective_identity']); self.assertNotIn(SENTINEL, json.dumps(result))
        for field, value in (('type', 'service_account'), ('service_account_impersonation_url', 'https://attacker.invalid/' + SENTINEL)):
            document = {**self.adc_document, field: value}
            result = diagnostic.credential_metadata(self.env, document)
            self.assertFalse(result['ADC']['configured_target_matches']); self.assertIsNone(result['effective_identity'])
            self.assertNotIn(SENTINEL, json.dumps(result))

    def test_policy_semantic_comparison_normalizes_order_but_preserves_condition_bytes_and_etag(self):
        original = diagnostic.policy_metadata(self.policy, self.expected, now=NOW)
        reordered = deepcopy(self.policy); reordered['bindings'].reverse()
        for binding in reordered['bindings']: binding['members'].reverse()
        reordered['etag'] = 'different-private-etag'
        result = diagnostic.policy_metadata(reordered, self.expected, now=NOW)
        self.assertEqual(result['policy_semantic_sha256'], original['policy_semantic_sha256'])
        self.assertEqual(result['Terraform_direct_bindings'], original['Terraform_direct_bindings'])
        self.assertNotEqual(result['etag_sha256'], original['etag_sha256'])
        self.assertTrue(result['reviewed_binding_present_exactly'])
        self.assertTrue(result['reviewed_binding_expired_now'])
        self.assertFalse(diagnostic.policy_metadata(self.policy, self.expected,
            now=datetime(2026,11,18,4,59,tzinfo=timezone.utc))['reviewed_binding_expired_now'])
        for field in ('role', 'condition', 'duplicate'):
            policy = deepcopy(self.policy)
            if field == 'role': policy['bindings'][0]['role'] = 'roles/owner'
            elif field == 'condition': policy['bindings'][0]['condition']['expression'] += ' '
            else: policy['bindings'].append(deepcopy(policy['bindings'][0]))
            with self.subTest(field=field):
                changed = diagnostic.policy_metadata(policy, self.expected, now=NOW)
                self.assertNotEqual(changed['policy_semantic_sha256'], original['policy_semantic_sha256'])
                self.assertFalse(changed['reviewed_binding_present_exactly'])
                self.assertNotIn(SENTINEL, json.dumps(changed))

    def test_matrix_compares_contents_and_bindings_instead_of_equating_success_statuses(self):
        metadata = diagnostic.policy_metadata(self.policy, self.expected, now=NOW)
        rows = [{'route': route, 'mode': mode, 'http_status': 200, 'policy': deepcopy(metadata)}
                for route in ('numeric', 'named') for mode in ('explicit_http', 'provider_ADC')]
        self.assertTrue(all(row['policy_contents_equal'] for row in diagnostic.compare_matrix(rows)))
        rows[1]['policy']['policy_semantic_sha256'] = 'f' * 64
        rows[1]['policy']['Terraform_direct_bindings'] = []
        changed = diagnostic.compare_matrix(rows)
        self.assertFalse(changed[0]['policy_contents_equal']); self.assertFalse(changed[0]['Terraform_bindings_equal'])
        for left, right in ((200,403),(403,200),(403,403),(None,200)):
            values = deepcopy(rows); values[0]['http_status'] = left; values[1]['http_status'] = right
            if left != 200: values[0].pop('policy')
            if right != 200: values[1].pop('policy')
            comparison = diagnostic.compare_matrix(values)[0]
            self.assertFalse(comparison['policies_comparable'])
            for field in ('policy_contents_equal','Terraform_bindings_equal','etag_equal'):
                self.assertIsNone(comparison[field])

    def test_serial_six_reference_rejects_pins_current_locks_and_unrecognized_resources(self):
        proof = diagnostic.state_reference(self.raw,self.obj,self.inventory,self.contract)
        self.assertEqual(len(proof['managed_addresses']),41); self.assertEqual(proof['serial'],6)
        self.assertFalse(proof['current_lock']); self.assertNotIn(SENTINEL,json.dumps(proof))
        for scenario in ('generation','hash','size','lineage','serial','serial-float','version','version-float','terraform','tainted','deposed',
                         'missing','duplicate','module','secret-data','extra-output','current-lock','other-workspace'):
            state=deepcopy(self.state);obj=deepcopy(self.obj);inventory=deepcopy(self.inventory);contract=deepcopy(self.contract)
            if scenario=='generation':obj['generation']='1002'
            elif scenario=='hash':contract['state_reference']['sha256']='f'*64
            elif scenario=='size':contract['state_reference']['size']+=1
            elif scenario=='lineage':state['lineage']='unexpected-lineage'
            elif scenario=='serial':state['serial']=7
            elif scenario=='serial-float':state['serial']=6.0
            elif scenario=='version':state['version']=3
            elif scenario=='version-float':state['version']=4.0
            elif scenario=='terraform':state['terraform_version']='1.15.7'
            elif scenario=='tainted':state['resources'][0]['instances'][0]['status']='tainted'
            elif scenario=='deposed':state['resources'][0]['instances'][0]['deposed']='old'
            elif scenario=='missing':state['resources'].pop(0)
            elif scenario=='duplicate':state['resources'].append(deepcopy(state['resources'][0]))
            elif scenario=='module':state['resources'][0]['module']='module.unreviewed'
            elif scenario=='secret-data':state['resources'].append({'mode':'data','type':'google_secret_manager_secret_version'})
            elif scenario=='extra-output':state['outputs']['unreviewed']={'value':SENTINEL}
            elif scenario=='current-lock':inventory['live'].append({'name':c.PREFIX+'/default.tflock','generation':'1002'})
            elif scenario=='other-workspace':inventory['live'].append({'name':c.PREFIX+'/other.tfstate','generation':'1002'})
            raw=custody.canonical(state)
            if raw!=self.raw:
                contract['state_reference'].update(sha256=custody.sha256(raw),size=len(raw))
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):
                diagnostic.state_reference(raw,obj,inventory,contract)

    def test_direct_probe_limits_requests_to_two_read_routes_and_withholds_raw_failures(self):
        for route in ('numeric','named'):
            response=mock.MagicMock();response.__enter__.return_value.read.return_value=custody.canonical(self.policy)
            opener=mock.Mock();opener.open.return_value=response
            with mock.patch.object(diagnostic,'build_opener',return_value=opener):
                result=diagnostic.direct_probe(route,'synthetic-private-access-token',REASON)
            self.assertEqual(result['private_policy'],self.policy)
            request=opener.open.call_args.args[0]
            self.assertEqual(request.full_url,'https://iap.googleapis.com/v1/'+diagnostic.ROUTES[route]+':getIamPolicy?alt=json')
            self.assertEqual(request.get_method(),'POST');self.assertEqual(json.loads(request.data),{'options':{'requestedPolicyVersion':3}})
            self.assertEqual(request.get_header('X-goog-request-reason'),REASON)
            for status in (403,404,500):
                body=mock.Mock();body.read.return_value=custody.canonical({'error':{'status':'PERMISSION_DENIED','message':SENTINEL,
                    'details':[{'secret':SENTINEL}]}})
                error=diagnostic.HTTPError(request.full_url,status,SENTINEL,{'Authorization':'Bearer '+SENTINEL},body)
                opener.open.side_effect=error
                with mock.patch.object(diagnostic,'build_opener',return_value=opener):
                    failure=diagnostic.direct_probe(route,'synthetic-private-access-token',REASON)
                self.assertEqual(failure['http_status'],status);self.assertEqual(failure['resource'],diagnostic.ROUTES[route])
                self.assertEqual(failure['required_permission_for_operation'],'iap.tunnelInstances.getIamPolicy')
                self.assertNotIn('permission',failure)
                self.assertNotIn(SENTINEL,json.dumps(failure));self.assertNotIn('private_policy',failure)

    def test_direct_probe_rejects_unreviewed_route_or_reason_before_network(self):
        for route,reason in (('other',REASON),('numeric','Bearer '+SENTINEL),('numeric','bad\nheader'),('numeric','')):
            with mock.patch.object(diagnostic,'build_opener') as network,self.subTest(route=route,reason=reason),self.assertRaises(ValueError):
                diagnostic.direct_probe(route,'synthetic-private-token',reason)
            network.assert_not_called()

    def test_direct_identity_anchor_reads_only_bucket_metadata_with_matching_bearer_and_reason(self):
        token='synthetic-private-access-token'
        for status in (200,403):
            opener=mock.Mock();body=mock.Mock()
            if status==200:
                response=mock.MagicMock()
                response.__enter__.return_value.read.return_value=custody.canonical({'name':'clipforgebeta2-int-media','extra':SENTINEL})
                opener.open.return_value=response
            else:
                body.read.side_effect=AssertionError('Identity anchor error body must remain private and unread')
                opener.open.side_effect=diagnostic.HTTPError('https://storage.googleapis.com/storage/v1/b/clipforgebeta2-int-media?fields=name',
                    status,SENTINEL,{'Authorization':'Bearer '+SENTINEL},body)
            with mock.patch.object(diagnostic,'build_opener',return_value=opener),self.subTest(status=status):
                result=diagnostic.direct_identity_anchor(token,REASON)
            request=opener.open.call_args.args[0]
            self.assertEqual(request.full_url,'https://storage.googleapis.com/storage/v1/b/clipforgebeta2-int-media?fields=name')
            self.assertEqual(request.get_method(),'GET');self.assertIsNone(request.data)
            self.assertEqual(request.get_header('Authorization'),'Bearer '+token)
            self.assertEqual(request.get_header('X-goog-request-reason'),REASON)
            self.assertEqual(result,{'bucket':'clipforgebeta2-int-media','operation':'storage.buckets.get','http_status':status,
                'reason':REASON,'effective_identity':None,'proof':'requires_authenticated_server_audit_event'})
            self.assertNotIn(SENTINEL,json.dumps(result));self.assertNotIn(token,json.dumps(result))
            if status==403:body.read.assert_not_called()
        for payload in (b'{"name":"another-bucket"}',b'x'*65537):
            response=mock.MagicMock();response.__enter__.return_value.read.return_value=payload
            opener=mock.Mock();opener.open.return_value=response
            with mock.patch.object(diagnostic,'build_opener',return_value=opener),self.assertRaises(ValueError):
                diagnostic.direct_identity_anchor(token,REASON)
        with mock.patch.object(diagnostic,'build_opener') as network,self.assertRaises(ValueError):
            diagnostic.direct_identity_anchor(token,'bad\nheader')
        network.assert_not_called()

    def test_native_module_is_exactly_two_data_sources_without_auth_or_write_overrides(self):
        for route,project,instance in (('numeric','816643438938','1670495097211408131'),
                                       ('named','clipforgebeta2','clipforge-int-base-postgres')):
            module=native.native_module(route,REASON)
            self.assertEqual(module['data']['google_iap_tunnel_instance_iam_policy']['probe'],
                {'project':project,'instance':instance,'zone':'us-central1-a','depends_on':['data.google_storage_bucket.identity']})
            self.assertEqual(module['data']['google_storage_bucket']['identity'],{'project':'clipforgebeta2','name':'clipforgebeta2-int-media'})
            self.assertEqual(module['terraform']['required_providers']['google'],{'source':'hashicorp/google','version':'= 8.11.0'})
            self.assertEqual(module['provider']['google'],{'project':'clipforgebeta2','region':'us-central1','zone':'us-central1-a','request_reason':REASON})
            native.validate_native_module(module,route,REASON)
            for field,value in (('resource',{'google_storage_bucket':{'write':{}}}),('output',{'policy':{}}),('import',[]),
                                ('backend',{}),('variable',{})):
                changed=deepcopy(module);changed[field]=value
                with self.subTest(route=route,field=field),self.assertRaises(ValueError):native.validate_native_module(changed,route,REASON)
            changed=deepcopy(module);changed['provider']['google']['access_token']=SENTINEL
            with self.assertRaises(ValueError):native.validate_native_module(changed,route,REASON)
        for route,reason in (('other',REASON),('numeric',' leading'),('numeric','double  space'),('numeric','reason\nheader'),('numeric','x'*161)):
            with self.subTest(route=route,reason=reason),self.assertRaises(ValueError):native.native_module(route,reason)

    def test_provider_reference_hash_binds_all_ten_authored_files_and_rejects_credential_or_alias_drift(self):
        proof = diagnostic.verify_provider_reference(self.source,self.contract)
        self.assertEqual(len(proof['source_files']),10)
        self.assertEqual(proof['source_files'],self.provider_files)
        self.assertEqual(proof['configuration_sha256'],self.contract['foundation_configuration_sha256'])
        self.assertEqual(proof['provider_config_key'],'google');self.assertIsNone(proof['alias'])
        self.assertEqual(proof['credentials_expressions'],[])
        for name in c.FILES:
            target=self.source/'infra/gcp/int-base'/name;original=target.read_bytes()
            for delta in (b'\nprovider "google" { credentials = "synthetic-private-credential" }',
                          b'\nprovider "google" { alias = "unreviewed" }'):
                try:
                    target.write_bytes(original+delta)
                    with self.subTest(file=name,delta=delta),self.assertRaises(ValueError):
                        diagnostic.verify_provider_reference(self.source,self.contract)
                finally:
                    target.write_bytes(original)

    def test_provider_route_evaluates_actual_authored_hcl_and_state_for_both_supported_forms(self):
        for route in ('numeric','named'):
            self.configure_route(route)
            proof=diagnostic.provider_route_from_state(self.source,self.raw,self.contract)
            expected={key:value for key,value in self.contract['provider_route'].items() if key!='required_route'}
            expected['route']=route
            self.assertEqual(proof,expected)
            self.assertEqual(proof['resource'],diagnostic.ROUTES[route])
            self.assertEqual(proof['configuration_sha256'],self.contract['foundation_configuration_sha256'])
            self.assertNotIn(SENTINEL,json.dumps(proof))

    def test_provider_route_rejects_wrong_identity_unknown_expressions_and_discordant_configured_route(self):
        for scenario in ('project-number','instance-id','instance-name','instance-project','instance-zone','missing-project',
                         'duplicate-project','duplicate-instance','hash','declared-route','declared-resource','declared-hash',
                         'hybrid-expression','literal-instance','wrong-zone-expression'):
            self.configure_route('numeric')
            contract=deepcopy(self.contract);state=deepcopy(self.state)
            project=next(row for row in state['resources'] if row['type']=='google_project')['instances'][0]['attributes']
            vm_row=next(row for row in state['resources'] if row['type']=='google_compute_instance' and row['name']=='postgres')
            vm=vm_row['instances'][0]['attributes']
            if scenario=='project-number':project['number']='816643438939'
            elif scenario.startswith('instance-'):
                vm[{'instance-id':'instance_id','instance-name':'name','instance-project':'project','instance-zone':'zone'}[scenario]]='unreviewed'
            elif scenario=='missing-project':state['resources']=[row for row in state['resources'] if row['type']!='google_project']
            elif scenario=='duplicate-project':state['resources'].append(deepcopy(next(row for row in state['resources'] if row['type']=='google_project')))
            elif scenario=='duplicate-instance':vm_row['instances'].append(deepcopy(vm_row['instances'][0]))
            elif scenario=='hash':contract['foundation_configuration_sha256']='f'*64
            elif scenario=='declared-route':contract['provider_route']['required_route']='named'
            elif scenario=='declared-resource':contract['provider_route']['resource']=diagnostic.ROUTES['named']
            elif scenario=='declared-hash':contract['provider_route']['configuration_sha256']='f'*64
            else:
                path=self.source/'infra/gcp/int-base/runtime.tf'
                delta={'hybrid-expression':('data.google_project.existing.number','var.project_id'),
                       'literal-instance':('google_compute_instance.postgres.instance_id','"1670495097211408131"'),
                       'wrong-zone-expression':('local.zone','"us-central1-a"')}[scenario]
                path.write_text(NUMERIC_RUNTIME.replace(*delta),encoding='utf-8',newline='\n')
                files={name:custody.sha256((self.source/'infra/gcp/int-base'/name).read_bytes()) for name in c.FILES}
                fingerprint=custody.sha256(custody.canonical(files))
                contract['foundation_configuration_sha256']=fingerprint
                contract['provider_route']['configuration_sha256']=fingerprint
            raw=custody.canonical(state)
            contract['state_reference'].update(sha256=custody.sha256(raw),size=len(raw))
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):
                diagnostic.provider_route_from_state(self.source,raw,contract)

    def test_live_route_identity_uses_only_fixed_project_and_instance_gets_and_withholds_private_payloads(self):
        proof=diagnostic.provider_route_from_state(self.source,self.raw,self.contract)
        project_url='https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2?fields=projectId,projectNumber'
        instance_url='https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/instances/clipforge-int-base-postgres?fields=id,name,zone'
        values=[{'projectId':'clipforgebeta2','projectNumber':'816643438938','private':SENTINEL},
                {'id':'1670495097211408131','name':'clipforge-int-base-postgres',
                 'zone':'https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a','private':SENTINEL}]
        def response(value):
            result=mock.MagicMock();result.__enter__.return_value.read.return_value=custody.canonical(value)
            return result
        opener=mock.Mock();opener.open.side_effect=[response(value) for value in values]
        with mock.patch.object(diagnostic,'build_opener',return_value=opener):
            result=diagnostic.live_route_identity(proof,'synthetic-private-token')
        self.assertEqual(result['live_identity'],AUTHORED_LIVE_IDENTITY)
        self.assertEqual(result['evaluated'],proof['evaluated'])
        self.assertEqual([row['operation'] for row in result['live_operations']],['resourcemanager.projects.get','compute.instances.get'])
        self.assertTrue(all(row['http_status']==200 for row in result['live_operations']))
        self.assertNotIn(SENTINEL,json.dumps(result));self.assertNotIn('synthetic-private-token',json.dumps(result))
        for call,url in zip(opener.open.call_args_list,(project_url,instance_url)):
            request=call.args[0];self.assertEqual(request.full_url,url)
            self.assertEqual(request.get_method(),'GET');self.assertIsNone(request.data)
            self.assertEqual(request.get_header('Authorization'),'Bearer synthetic-private-token')
        for index,field,value in ((0,'projectId','other'),(0,'projectNumber','816643438939'),
                                  (1,'id','1670495097211408132'),(1,'name','other-instance'),(1,'zone','us-central1-b')):
            changed=deepcopy(values);changed[index][field]=value
            opener=mock.Mock();opener.open.side_effect=[response(row) for row in changed]
            with mock.patch.object(diagnostic,'build_opener',return_value=opener),self.subTest(field=field),self.assertRaises(ValueError):
                diagnostic.live_route_identity(proof,'synthetic-private-token')
        for index in (0,1):
            for status in (403,404,500):
                body=mock.Mock();body.read.side_effect=AssertionError('Identity error response must not be read')
                error=diagnostic.HTTPError((project_url,instance_url)[index],status,SENTINEL,{'Authorization':'Bearer '+SENTINEL},body)
                opener=mock.Mock();opener.open.side_effect=([response(values[0])] if index else [])+[error]
                with mock.patch.object(diagnostic,'build_opener',return_value=opener),self.subTest(index=index,status=status):
                    with self.assertRaises(diagnostic.RouteReadBlocked) as raised:
                        diagnostic.live_route_identity(proof,'synthetic-private-token')
                body.read.assert_not_called();self.assertEqual(opener.open.call_count,index+1)
                receipt=raised.exception.receipt
                self.assertEqual(receipt,{'operation':'verify_effective_IAP_'+('project' if index==0 else 'instance'),
                    'resource':'projects/clipforgebeta2' if index==0 else 'projects/clipforgebeta2/zones/us-central1-a/instances/1670495097211408131',
                    'required_permission_for_operation':'resourcemanager.projects.get' if index==0 else 'compute.instances.get',
                    'http_status':status,'response_payload_withheld':True})
                self.assertNotIn(SENTINEL,json.dumps(receipt)+str(raised.exception))

    def test_read_window_guard_enforces_inclusive_start_exclusive_end_and_exact_custody_references(self):
        for observed,allowed in ((datetime(2026,11,18,16,59,59,tzinfo=timezone.utc),False),
                                 (datetime(2026,11,18,17,tzinfo=timezone.utc),True),
                                 (datetime(2026,11,18,17,59,59,tzinfo=timezone.utc),True),
                                 (datetime(2026,11,18,18,tzinfo=timezone.utc),False)):
            class EdgeClock(datetime):
                @classmethod
                def now(cls,tz=None):return observed
            with mock.patch.object(diagnostic,'datetime',EdgeClock),self.subTest(observed=observed):
                if allowed:
                    result=diagnostic.read_window_guard(self.contract,self.env)
                    self.assertEqual(result['manifest_sha256'],self.env['INT_READ_WINDOW_MANIFEST_SHA256'])
                    self.assertEqual(result['administrator_receipt_index_sha256'],self.env['INT_ADMIN_READ_RECEIPTS_SHA256'])
                    self.assertEqual(result['not_before_utc'],'2026-11-18T17:00:00Z')
                    self.assertEqual(result['expires_utc'],'2026-11-18T18:00:00Z')
                    self.assertNotIn(SENTINEL,json.dumps(result))
                else:
                    with self.assertRaises(ValueError) as raised:diagnostic.read_window_guard(self.contract,self.env)
                    self.assertEqual(raised.exception.receipt['status'],'blocked_no_window_extension')
        for scenario in ('manifest','receipt-missing','receipt-invalid','proposal','earlier-start','later-expiry'):
            contract=deepcopy(self.contract);env=deepcopy(self.env)
            if scenario=='manifest':env['INT_READ_WINDOW_MANIFEST_SHA256']='f'*64
            elif scenario=='receipt-missing':env.pop('INT_ADMIN_READ_RECEIPTS_SHA256')
            elif scenario=='receipt-invalid':env['INT_ADMIN_READ_RECEIPTS_SHA256']=SENTINEL
            elif scenario=='proposal':contract['read_window']['proposal_sha256']='f'*64
            elif scenario=='earlier-start':contract['read_window']['not_before_utc']='2026-11-18T16:59:59Z'
            elif scenario=='later-expiry':contract['read_window']['expires_utc']='2026-11-18T18:00:01Z'
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):diagnostic.read_window_guard(contract,env)

    def test_native_policy_extraction_rejects_managed_changes_outputs_children_or_unreviewed_data(self):
        baseline=authored_native_plan(self.policy)
        self.assertEqual(native.extract_policy(baseline),self.policy)
        # Real Terraform 1.15.8 no-change data-only plans place the refreshed
        # values in prior_state and may have no planned_values root resources.
        for planned in ({}, {'root_module': {'resources': []}}):
            prior_only=deepcopy(baseline)
            prior_only['prior_state']={'values':deepcopy(prior_only['planned_values'])}
            prior_only['planned_values']=planned
            self.assertEqual(native.extract_policy(prior_only),self.policy)
            for scenario in ('missing','managed','output','child'):
                changed=deepcopy(prior_only);values=changed['prior_state']['values']
                if scenario=='missing':values['root_module']['resources'].pop()
                elif scenario=='managed':values['root_module']['resources'][0]['mode']='managed'
                elif scenario=='output':values['outputs']={'private':{'value':SENTINEL}}
                else:values['root_module']['child_modules']=[{}]
                with self.subTest(prior_only=scenario),self.assertRaises(ValueError):native.extract_policy(changed)
        for actions in (['read'],['no-op']):
            plan=deepcopy(baseline);plan['resource_changes']=deepcopy(plan['planned_values']['root_module']['resources'])
            for row in plan['resource_changes']:row['change']={'actions':actions}
            self.assertEqual(native.extract_policy(plan),self.policy)
        for scenario in ('terraform','missing','duplicate','managed','secret-data','provider','name','child','output','output-change',
                         'create','update','delete','replace','drift-managed','prior-managed','prior-output','policy-string','policy-list'):
            plan=deepcopy(baseline);rows=plan['planned_values']['root_module']['resources']
            if scenario=='terraform':plan['terraform_version']='1.15.7'
            elif scenario=='missing':rows.pop()
            elif scenario=='duplicate':rows.append(deepcopy(rows[0]))
            elif scenario=='managed':rows[0]['mode']='managed'
            elif scenario=='secret-data':rows[0]['type']='google_secret_manager_secret_version'
            elif scenario=='provider':rows[0]['provider_name']='registry.terraform.io/unreviewed/google'
            elif scenario=='name':rows[0]['name']='another'
            elif scenario=='child':plan['planned_values']['root_module']['child_modules']=[{}]
            elif scenario=='output':plan['planned_values']['outputs']={'private':{'value':SENTINEL}}
            elif scenario=='output-change':plan['output_changes']={'private':{'after':SENTINEL}}
            elif scenario in {'create','update','delete','replace'}:
                change=deepcopy(rows[0]);change['change']={'actions':['delete','create'] if scenario=='replace' else [scenario]}
                plan['resource_changes']=[change]
            elif scenario=='drift-managed':plan['resource_drift']=[{**deepcopy(rows[0]),'mode':'managed'}]
            elif scenario=='prior-managed':plan['prior_state']={'values':{'root_module':{'resources':[{**deepcopy(rows[0]),'mode':'managed'}]}}}
            elif scenario=='prior-output':plan['prior_state']={'values':{'outputs':{'private':SENTINEL}}}
            elif scenario=='policy-string':rows[0]['values']['policy_data']='unstructured-private-policy'
            elif scenario=='policy-list':rows[0]['values']['policy_data']='[]'
            with self.subTest(scenario=scenario),self.assertRaises(ValueError):native.extract_policy(plan)

    def test_native_trace_is_init_plan_show_only_with_locking_and_private_outputs(self):
        lock=b'Authored provider-lock fixture; no production preimage claim.'
        lock_file=self.source/'infra/gcp/int-base/.terraform.lock.hcl';lock_file.parent.mkdir(parents=True,exist_ok=True);lock_file.write_bytes(lock)
        for scenario in ('success-zero','success-two','init-failure','plan-failure','unexpected-state'):
            work=self.root/('native-'+scenario);calls=[]
            def run(argv,operation,path,**kwargs):
                calls.append((argv,operation,kwargs))
                if operation=='iap_diag_init' and scenario=='init-failure':
                    (path/'iap_diag_init.log').write_text('HTTP 403 '+SENTINEL)
                    return 1,b''
                if operation=='iap_diag_plan':
                    if scenario=='unexpected-state':(path/'module/terraform.tfstate').write_text(SENTINEL)
                    if scenario=='plan-failure':
                        (path/'iap_diag_plan.log').write_text("googleapi: Error 403: Permission 'iap.tunnelInstances.getIamPolicy' denied "+SENTINEL)
                        return 1,b''
                    return (2 if scenario=='success-two' else 0),b''
                if operation=='iap_diag_show':return 0,custody.canonical(authored_native_plan(self.policy))
                return 0,b''
            # Override only the immutable-lock selector with an authored hash;
            # do not pretend the synthetic lock is the production 89e218... file.
            with mock.patch.object(native,'PROVIDER_LOCK_SHA256',custody.sha256(lock)), \
                    mock.patch.object(native.driver,'terraform_binary',return_value='synthetic-terraform'), \
                    mock.patch.object(native.driver,'run',side_effect=run),mock.patch.dict(native.os.environ,{},clear=True):
                if scenario=='unexpected-state':
                    with self.assertRaises(ValueError):native.run_native(work,'numeric',REASON,source_root=self.source)
                else:
                    result=native.run_native(work,'numeric',REASON,source_root=self.source)
                    self.assertFalse(result['configured_identity_is_observed_identity'])
                    if scenario.startswith('success'):
                        self.assertEqual(result['policy'],self.policy);self.assertEqual(result['phase'],'complete')
                    else:
                        self.assertNotIn('policy',result);self.assertNotIn(SENTINEL,json.dumps(result))
            operations=[row[1] for row in calls]
            self.assertEqual(operations,['iap_diag_init'] if scenario=='init-failure' else
                ['iap_diag_init','iap_diag_plan','iap_diag_show'] if scenario.startswith('success') else ['iap_diag_init','iap_diag_plan'])
            if len(calls)>1:
                self.assertIn('-lock=true',calls[1][0]);self.assertIn('-lock-timeout=60s',calls[1][0])
                self.assertNotIn('-lock=false',calls[1][0]);self.assertIn('-detailed-exitcode',calls[1][0])
            self.assertTrue(all(argv[1] in {'init','plan','show'} for argv,_,_ in calls))
            self.assertFalse(any(path.suffix=='.tfstate' for path in self.reports.iterdir()))

    def test_orchestration_keeps_policies_private_and_historical_expiry_separate_from_current_reads(self):
        direct_calls=[];native_calls=[];anchor_calls=[];events=[]
        def anchor(token,reason):
            anchor_calls.append((token,reason));events.append(('anchor',token,reason))
            return {'bucket':'clipforgebeta2-int-media','http_status':200,'effective_identity':None,'reason':reason}
        def explicit(route,token,reason):
            direct_calls.append((route,token,reason));events.append(('iap',token,reason))
            return {'http_status':200,'private_policy':deepcopy(self.policy)}
        def provider(path,route,reason,**kwargs):
            native_calls.append((path,route,reason,kwargs))
            return {'native_exit':0,'policy':deepcopy(self.policy),'library':{'wrapper_is_managed_resource_read':False}}
        # The immutable production selector is the only source-selection mock;
        # verification below still hashes all ten authored files normally.
        with mock.patch.object(diagnostic,'load_contract',return_value=self.contract), \
                mock.patch.object(diagnostic,'live_route_identity',side_effect=lambda proof,_token:{**proof,'live_identity':deepcopy(AUTHORED_LIVE_IDENTITY)}) as live_identity, \
                mock.patch.object(diagnostic.driver,'metadata',return_value={'name':c.BUCKET}), \
                mock.patch.object(diagnostic.states,'private_current_state',return_value=(self.raw,self.obj,self.inventory)), \
                mock.patch.object(diagnostic.driver,'backend_inventory',return_value=self.inventory) as inventory, \
                mock.patch.object(diagnostic,'direct_identity_anchor',side_effect=anchor), \
                mock.patch.object(diagnostic,'required_reads',return_value=[]), \
                mock.patch.object(diagnostic,'direct_probe',side_effect=explicit),mock.patch.object(native,'run_native',side_effect=provider), \
                mock.patch.object(custody,'upload') as upload:
            result=diagnostic.run_diagnostic(self.work,self.reports,self.env,root=self.source)
        self.assertEqual(len(direct_calls),2);self.assertEqual(len(native_calls),2);self.assertEqual(inventory.call_count,2)
        live_identity.assert_called_once()
        self.assertEqual(live_identity.call_args.args[0]['route'],'numeric')
        self.assertEqual(live_identity.call_args.args[1],self.env['GCP_ACCESS_TOKEN'])
        self.assertEqual(len(anchor_calls),2)
        self.assertEqual([event[0] for event in events],['anchor','iap','anchor','iap'])
        self.assertEqual(anchor_calls,[(call[1],call[2]) for call in direct_calls])
        self.assertEqual([row[0] for row in direct_calls],['numeric','named'])
        self.assertEqual([row[1] for row in native_calls],['numeric','named'])
        self.assertTrue(result['historical_403_before_original_expiry']);self.assertTrue(result['original_binding_expired_now'])
        self.assertEqual(result['historical_cause'],'not_inferred_from_current_expired_grant_or_administrator_reads')
        self.assertFalse(result['new_apply_authorized']);self.assertFalse(result['new_grants_authorized'])
        self.assertEqual(result['provider_source']['source_files'],self.provider_files)
        self.assertTrue(all(row['policy_contents_equal'] for row in result['comparisons']))
        public=json.dumps(result)
        for private in (SENTINEL,str(self.adc),self.env['GCP_ACCESS_TOKEN'],'private_policy','synthetic-private-etag'):
            self.assertNotIn(private,public)
        for row in result['probes']:
            self.assertNotIn('bindings',row['policy']);self.assertIn('policy_semantic_sha256',row['policy'])
        upload.assert_not_called()
        self.assertEqual([path.name for path in self.reports.iterdir()],['iap-diagnostic.json'])
        partial=(self.reports/'iap-diagnostic.json').read_text()
        self.assertNotIn(SENTINEL,partial);self.assertNotIn(self.env['GCP_ACCESS_TOKEN'],partial)
        self.assertEqual(json.loads(partial)['status'],'partial_read_diagnostic')

    def test_native_bucket_denial_is_not_attributed_to_iap_and_unknown_private_fields_block_publication(self):
        for permission,status in (('storage.buckets.get',None),('iap.tunnelInstances.getIamPolicy',403),('unreviewed-private-field',None)):
            def provider(*_args,**_kwargs):
                result={'native_exit':1,'errors':[{'operation':'iap_diag_plan','status':403,'permissions':[permission]}]}
                if permission=='unreviewed-private-field':result[SENTINEL]=SENTINEL
                return result
            with mock.patch.object(diagnostic,'load_contract',return_value=self.contract), \
                    mock.patch.object(diagnostic,'live_route_identity',side_effect=lambda proof,_token:{**proof,'live_identity':deepcopy(AUTHORED_LIVE_IDENTITY)}), \
                    mock.patch.object(diagnostic.driver,'metadata',return_value={'name':c.BUCKET}), \
                    mock.patch.object(diagnostic.states,'private_current_state',return_value=(self.raw,self.obj,self.inventory)), \
                    mock.patch.object(diagnostic.driver,'backend_inventory',return_value=self.inventory), \
                    mock.patch.object(diagnostic,'direct_identity_anchor',return_value={'http_status':200,'effective_identity':None}), \
                    mock.patch.object(diagnostic,'required_reads',return_value=[]), \
                    mock.patch.object(diagnostic,'direct_probe',side_effect=lambda *_args:{'http_status':200,'private_policy':deepcopy(self.policy)}), \
                    mock.patch.object(native,'run_native',side_effect=provider),self.subTest(permission=permission):
                if permission=='unreviewed-private-field':
                    with self.assertRaises(ValueError):diagnostic.run_diagnostic(self.work,self.reports,self.env,root=self.source)
                    continue
                result=diagnostic.run_diagnostic(self.work,self.reports,self.env,root=self.source)
            rows=[row for row in result['probes'] if row['mode']=='provider_ADC']
            self.assertEqual([row['http_status'] for row in rows],[status,status])
            self.assertTrue(all('policy' not in row for row in rows))
            self.assertTrue(all(not row['policies_comparable'] for row in result['comparisons'] if row['dimension']=='authentication'))
            self.assertFalse(result['new_grants_authorized']);self.assertFalse(result['new_apply_authorized'])

    def test_orchestration_stops_before_probes_for_overrides_unreviewed_controls_or_state_race(self):
        for scenario in ('override','wrong-controls','state-race','credential-drift','alias-drift'):
            env=deepcopy(self.env)
            if scenario=='override':env['GOOGLE_OAUTH_ACCESS_TOKEN']=SENTINEL
            elif scenario=='wrong-controls':env['INT_REVIEWED_CONTROLS_COMMIT']='d'*40
            inventory=deepcopy(self.inventory)
            if scenario=='state-race':inventory['live'][0]['generation']='1002'
            main=self.source/'infra/gcp/int-base/main.tf';original=main.read_bytes()
            if scenario=='credential-drift':main.write_bytes(original+b'\nprovider "google" { credentials = "synthetic-private-credential" }')
            elif scenario=='alias-drift':main.write_bytes(original+b'\nprovider "google" { alias = "unreviewed" }')
            with mock.patch.object(diagnostic,'load_contract',return_value=self.contract), \
                    mock.patch.object(diagnostic,'live_route_identity',side_effect=lambda proof,_token:{**proof,'live_identity':deepcopy(AUTHORED_LIVE_IDENTITY)}), \
                    mock.patch.object(diagnostic.driver,'metadata',return_value={'name':c.BUCKET}), \
                    mock.patch.object(diagnostic.states,'private_current_state',return_value=(self.raw,self.obj,self.inventory)), \
                    mock.patch.object(diagnostic.driver,'backend_inventory',return_value=inventory), \
                    mock.patch.object(diagnostic,'direct_identity_anchor') as anchor, \
                    mock.patch.object(diagnostic,'direct_probe') as direct,mock.patch.object(native,'run_native') as provider, \
                    self.subTest(scenario=scenario),self.assertRaises(ValueError):
                diagnostic.run_diagnostic(self.work,self.reports,env,root=self.source)
            main.write_bytes(original)
            anchor.assert_not_called();direct.assert_not_called();provider.assert_not_called()

    def test_cli_has_no_apply_or_grant_and_failure_evidence_contains_no_raw_exception(self):
        with mock.patch('sys.argv',['int_iap_diagnostic','apply']),self.assertRaises(SystemExit), \
                mock.patch.object(diagnostic,'run_diagnostic') as execute,mock.patch('sys.stderr'):
            diagnostic.main()
        execute.assert_not_called()
        with mock.patch('sys.argv',['int_iap_diagnostic','diagnose']),mock.patch.object(diagnostic.os,'umask'), \
                mock.patch.object(diagnostic.driver,'private_paths',return_value=(self.work,self.reports)), \
                mock.patch.object(diagnostic,'run_diagnostic',side_effect=ValueError(SENTINEL)) as execute, \
                mock.patch.dict(diagnostic.os.environ,{},clear=True),mock.patch('builtins.print'):
            self.assertEqual(diagnostic.main(),1)
        execute.assert_called_once()
        public=(self.reports/'iap-diagnostic.json').read_text()+(self.reports/'iap-diagnostic.md').read_text()
        self.assertNotIn(SENTINEL,public)
        summary=json.loads((self.reports/'iap-diagnostic.json').read_text())
        self.assertFalse(summary['new_apply_authorized']);self.assertFalse(summary['new_grants_authorized'])

    def test_required_reads_use_only_exact_metadata_and_policy_methods_without_publishing_payloads(self):
        for status in (200,403):
            opener=mock.Mock();response=mock.MagicMock();body=mock.Mock()
            response.__enter__.return_value.read.return_value=custody.canonical({'private':SENTINEL})
            if status==200:opener.open.return_value=response
            else:
                body.read.side_effect=AssertionError('Error payload must not be read or published')
                opener.open.side_effect=diagnostic.HTTPError('https://logging.googleapis.com/v2/synthetic',403,SENTINEL,{},body)
            with mock.patch.object(diagnostic,'build_opener',return_value=opener):
                rows=diagnostic.required_reads('synthetic-private-token',REASON)
            self.assertEqual(len(rows),10);self.assertEqual(opener.open.call_count,10)
            for target,call,row in zip(diagnostic.READ_TARGETS,opener.open.call_args_list,rows):
                key,method,url,payload,permission,resource=target;request=call.args[0]
                self.assertEqual(request.full_url,url);self.assertEqual(request.get_method(),method)
                self.assertEqual(request.data,custody.canonical(payload) if payload is not None else None)
                self.assertEqual(row['http_status'],status);self.assertEqual(row['required_permission_for_operation'],permission)
                self.assertEqual(row['resource'],resource);self.assertEqual(row['key'],key)
                self.assertNotIn(':access',url);self.assertNotIn('/versions/',url)
            for key in ('grant_postgres_policy','secret_bootstrap_policy','secret_ca_policy'):
                target=next(x for x in diagnostic.READ_TARGETS if x[0]==key)
                self.assertTrue(target[2].endswith('?options.requestedPolicyVersion=3'));self.assertIsNone(target[3])
                self.assertEqual(target[1],'POST' if key=='grant_postgres_policy' else 'GET')
            self.assertNotIn(SENTINEL,json.dumps(rows));self.assertNotIn('synthetic-private-token',json.dumps(rows))
            if status==403:body.read.assert_not_called()
        with mock.patch.object(diagnostic,'build_opener') as network,self.assertRaises(ValueError):
            diagnostic.required_reads('synthetic','bad\nreason')
        network.assert_not_called()

    def test_required_reads_recheck_the_window_before_each_request_and_stop_when_it_closes(self):
        opener=mock.Mock();response=mock.MagicMock()
        response.__enter__.return_value.read.return_value=b'{}';opener.open.return_value=response
        guards=[]
        def before_read():
            guards.append(len(guards)+1)
            if len(guards)==3:raise ValueError('Synthetic read window expired')
        with mock.patch.object(diagnostic,'build_opener',return_value=opener),self.assertRaises(ValueError):
            diagnostic.required_reads('synthetic-private-token',REASON,before_read=before_read)
        self.assertEqual(guards,[1,2,3]);self.assertEqual(opener.open.call_count,2)

    def test_plan_requires_complete_successful_required_reads_and_same_four_iap_combinations(self):
        result=self.authored_read_result()
        self.assertTrue(diagnostic.reads_allow_plan(result,self.contract))
        for field in ('required_reads','probes'):
            for scenario in ('missing','duplicate','denied','unknown'):
                value=deepcopy(result)
                if scenario=='missing':value[field].pop()
                elif scenario=='duplicate':value[field][-1]=deepcopy(value[field][0])
                else:value[field][0]['http_status']=403 if scenario=='denied' else None
                with self.subTest(field=field,scenario=scenario):self.assertFalse(diagnostic.reads_allow_plan(value,self.contract))
        self.assertFalse(diagnostic.reads_allow_plan({},self.contract))

    def test_plan_uses_only_the_actual_hcl_route_without_losing_other_route_failures(self):
        for active in ('numeric','named'):
            self.configure_route(active)
            result=self.authored_read_result()
            for row in result['probes']:
                if row['route']=='named':row['http_status']=403
            self.assertEqual(diagnostic.reads_allow_plan(result,self.contract),active=='numeric')
            self.assertEqual([row['http_status'] for row in result['probes'] if row['route']=='named'],[403,403])
            if active=='numeric':
                for mode in ('explicit_http','provider_ADC'):
                    value=deepcopy(result)
                    next(row for row in value['probes'] if row['route']=='numeric' and row['mode']==mode)['http_status']=403
                    with self.subTest(active=active,mode=mode):self.assertFalse(diagnostic.reads_allow_plan(value,self.contract))

    def test_plan_rejects_wrong_read_resources_route_proofs_or_missing_diagnostic_combinations(self):
        result=self.authored_read_result()
        for scenario in ('read-resource','read-permission','read-method','probe-resource','proof-route','proof-resource',
                         'proof-evaluated','proof-hash','source-hash','missing-named','duplicate-named','live-missing','live-false','live-other-id'):
            value=deepcopy(result)
            if scenario=='read-resource':value['required_reads'][0]['resource']='projects/other'
            elif scenario=='read-permission':value['required_reads'][0]['required_permission_for_operation']='resourcemanager.projects.setIamPolicy'
            elif scenario=='read-method':value['required_reads'][0]['method']='DELETE'
            elif scenario=='probe-resource':value['probes'][-1]['resource']=diagnostic.ROUTES['numeric']
            elif scenario=='proof-route':value['provider_route']['route']='named'
            elif scenario=='proof-resource':value['provider_route']['resource']=diagnostic.ROUTES['named']
            elif scenario=='proof-evaluated':value['provider_route']['evaluated']['instance']='another-instance'
            elif scenario=='proof-hash':value['provider_route']['configuration_sha256']='f'*64
            elif scenario=='source-hash':value['provider_source']['configuration_sha256']='f'*64
            elif scenario=='missing-named':value['probes'].pop()
            elif scenario=='duplicate-named':value['probes'][-1]=deepcopy(value['probes'][-2])
            elif scenario=='live-missing':value['provider_route'].pop('live_identity')
            elif scenario=='live-false':value['provider_route']['live_identity']['verified']=False
            elif scenario=='live-other-id':value['provider_route']['live_identity']['instance_id']='different-instance'
            with self.subTest(scenario=scenario):self.assertFalse(diagnostic.reads_allow_plan(value,self.contract))

    def test_cli_preserves_grouped_missing_reads_and_never_starts_plan(self):
        from scripts import int_foundation_recovery as recovery
        result={'status':'read_comparison_completed_no_grants_no_apply','comparisons':[],
                'required_reads':[{'key':x[0],'resource':x[5],'required_permission_for_operation':x[4],
                                  'http_status':403 if 'policy' in x[0] else 200} for x in diagnostic.READ_TARGETS],
                'probes':[]}
        with mock.patch('sys.argv',['int_iap_diagnostic','diagnose']),mock.patch.object(diagnostic.os,'umask'), \
                mock.patch.object(diagnostic.driver,'private_paths',return_value=(self.work,self.reports)), \
                mock.patch.object(diagnostic,'run_diagnostic',return_value=result), \
                mock.patch.object(diagnostic,'load_contract',return_value=self.contract), \
                mock.patch.dict(diagnostic.os.environ,{'IAP_ATTEMPT_RECOVERY_PLAN':'true'},clear=True), \
                mock.patch.object(recovery,'load_contract',return_value={'recovery_phase':'serial6_no_imports'}), \
                mock.patch.object(recovery,'plan_recovery') as plan,mock.patch('builtins.print'):
            self.assertEqual(diagnostic.main(),1)
        plan.assert_not_called();self.assertFalse((self.work/'module').exists())
        saved=json.loads((self.reports/'recovery-summary.json').read_bytes())
        self.assertEqual(saved['status'],'blocked_required_reads_no_plan_no_apply')
        self.assertEqual(saved['required_reads'],result['required_reads']);self.assertFalse(saved['apply_authorized'])


class CurrentSinkDiagnosticProvenance(unittest.TestCase):
    def test_sink_candidate_keeps_numeric_identity_and_rejects_changed_history(self):
        root=diagnostic.ROOT
        actual=diagnostic.load_contract(root)
        self.assertEqual(actual['provider_route']['resource'],diagnostic.ROUTES['numeric'])
        self.assertEqual(actual['provider_route']['evaluated'],
                         {'project':'816643438938','zone':'us-central1-a','instance':'1670495097211408131'})
        native_read=Path.read_bytes
        for mutation in ('missing-alignment','alignment-hash','history-reference','history-bytes','named-route'):
            changed=deepcopy(actual)
            if mutation=='missing-alignment': del changed['configuration_change']['sink_alignment']
            elif mutation=='alignment-hash': changed['configuration_change']['sink_alignment']['configuration_sha256']='0'*64
            elif mutation=='history-reference': changed['configuration_change']['previous_diagnostic_contract']['sha256']='0'*64
            elif mutation=='named-route': changed['provider_route']['required_route']='named'
            def read(path):
                if path==root/diagnostic.CONFIG: return custody.canonical(changed)
                raw=native_read(path)
                return raw+b'\n' if mutation=='history-bytes' and path.name=='bbf7573-iap-diagnostic.json' else raw
            with self.subTest(mutation=mutation),mock.patch.object(Path,'read_bytes',read),self.assertRaises(ValueError):
                diagnostic.load_contract(root)


if __name__=='__main__':
    unittest.main()
