"""Import explicit historical reports, preserving observations without accepting risk.

Does not run scanners or read the application/operational data. Inputs are the
six named SEC-05 reports and SAST evidence; output must be a new file.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


ROLES = ('baseline_ci', 'baseline_browser', 'noble_ci', 'noble_browser',
         'noble_aptfix_ci', 'noble_aptfix_browser')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def import_register(evidence, output):
    evidence, output = Path(evidence), Path(output)
    final = json.loads((evidence / 'final-results.json').read_text(encoding='utf-8'))
    images = {item['role']: item for item in final['matrix']}
    database = json.loads((evidence / 'scanner-db-identity.json').read_text(encoding='utf-8'))
    defaults = {
        'state': 'registrado_no_aceptado', 'owner': 'por_designar_por_propietario',
        'next_review': '2026-11-24; o antes de proponer publicación, lo que ocurra primero',
        'acceptance': {'approved': False, 'approver': None, 'expires_at': None,
                       'reason': 'No existe aceptación; la expiración se exige antes de aprobar una.'},
        'mitigation': 'Desarrollo aislado, sin exposición pública ni datos operativos; no equivale a remediación. Release bloqueada.',
    }
    records, sources, counts = [], [], {}
    for role in ROLES:
        group = 'aptfix-all-severities' if role.startswith('noble_aptfix') else 'all-severities'
        directory = 'noble_browser-retry-timeout-1' if role == 'noble_browser' else role
        path = evidence / 'infra' / group / directory / 'trivy-all-severities.json'
        raw = json.loads(path.read_text(encoding='utf-8'))
        image = images[role]['image_id']
        if raw.get('Metadata', {}).get('ImageID') != image:
            raise ValueError('Historical image identity mismatch: ' + role)
        source_id = 'trivy-' + role
        sources.append({'id': source_id, 'path': path.as_posix(), 'sha256': digest(path),
                        'image_id': image, 'historical': True, 'scanner': 'Trivy 0.76.2',
                        'db_sha256': database['Sha256'], 'db_updated_at': database['Metadata']['UpdatedAt']})
        selected = []
        for target in raw.get('Results', []):
            for finding in target.get('Vulnerabilities') or []:
                selected.append(finding)
                records.append({
                    'id': f'AUTH01-HIST-{role}-{len(selected):04d}', 'kind': 'sca_observation',
                    'finding_id': finding['VulnerabilityID'], 'component': finding['PkgName'],
                    'installed_version': finding['InstalledVersion'], 'package_id': finding.get('PkgID'),
                    'package_path': finding.get('PkgPath'), 'source_package': finding.get('SrcName'),
                    'severity': finding['Severity'], 'severity_source': finding.get('SeveritySource'),
                    'severity_source_present': 'SeveritySource' in finding, 'data_source': finding.get('DataSource'),
                    'scanner_status': finding.get('Status'), 'fixed_version_catalogued': finding.get('FixedVersion'),
                    'target': target.get('Target'), 'target_type': target.get('Type'), 'image_id': image,
                    'historical_role': role, 'evidence_id': source_id,
                    'exposure': 'Observación de imagen histórica local. No acredita presencia/ausencia ni explotación en AUTH-01 o en la instalación operativa.',
                    **defaults,
                })
        if len(selected) != images[role]['all_findings']:
            raise ValueError('Historical finding count mismatch: ' + role)
        counts[role] = dict(Counter(item['Severity'] for item in selected))
    sast_path = evidence / 'security/sast-decisions.json'
    sast = json.loads(sast_path.read_text(encoding='utf-8'))
    if len(sast['locations']) != 28:
        raise ValueError('Expected complete historical SAST evidence')
    sources.append({'id':'sast-sec04-github', 'path':sast_path.as_posix(), 'sha256':digest(sast_path),
                    'historical':True, 'upstream_evidence':sast['source_evidence'],
                    'github_run':'https://github.com/AldemaroCruz/ClipForge/actions/runs/42884518893'})
    for finding in sast['locations']:
        records.append({'id':finding['id'], 'kind':'sast_observation', 'finding_id':finding['rule'],
            'component':finding['path'], 'component_version':finding['file_sha256'],
            'severity':finding['severity'], 'confidence':finding['confidence'], 'source':'Bandit historical GitHub/SEC-04',
            'file':finding['path'], 'line':finding['line'], 'span_start':finding['span_start'],
            'span_end':finding['span_end'], 'file_sha256':finding['file_sha256'],
            'span_sha256_utf8_lf':finding['span_sha256_utf8_lf'], 'evidence_id':'sast-sec04-github',
            'exposure':finding['scope'], 'previous_review_classification':finding['classification'],
            'required_decision':finding['decision_needed'], 'review_trigger':finding['review_trigger'],
            **defaults})
    result = {'schema':'clipforge-risk-register-1', 'recorded_date':'2026-11-10',
        'purpose':'Local development permitted by owner; no security risk acceptance or release approval',
        'sources':sources, 'counts':counts, 'sca_observations':sum(sum(v.values()) for v in counts.values()),
        'historical_sast_locations':28, 'records':records,
        'unscanned_candidates':[
            {'scope':'SEC-05 protected bootstrap', 'images':[
                'sha256:9e368a9c6d8b459d9635f271b1cfe2ce1ac1f2015308c9072771f0eb20be7fae',
                'sha256:1b3595fdca633e5801ff37ceb672a060e8a4586f42b0edb8eaf50c3436d6fe6a'],
             'historical_reports_apply':False},
            {'scope':'AUTH-01 new candidate', 'historical_reports_apply':False,
             'status':'New image/dependency identities and actual tests are recorded in AUTH-01 evidence; no historical scan attribution.'}],
        'policy_changes':False, 'acceptances_applied':False,
        'limits':['Rows are package/finding/image observations, not unique CVEs.',
                  'FixedVersion is a catalogued fix, not evidence that it is installed.',
                  'Missing SeveritySource remains null; it is never inferred from DataSource.',
                  'Source changes require fresh SAST; historical file hashes are retained, not relabelled.']}
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return {'records':len(records), 'sca':result['sca_observations'], 'sast':28, 'counts':counts}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(import_register(args.evidence, args.output), ensure_ascii=False))
