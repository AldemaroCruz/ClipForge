"""Actual UI -> actual API -> LOCAL provider STUB -> draft -> actual FFmpeg.

No real LLM or ASR inference. The standalone Ollama-shaped HTTP fixture returns
explicit authored output so validations, consent and persistence can be exercised.
CLIPFORGE_BROWSER_BRIDGE=1 uses the inherited explicit Python transport when
managed Chromium refuses localhost. It does not change browser security policy.
"""
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from app.check_presentation import make_source
from app.state import write_json_atomic
from auth_support import prepare_browser_fixture, browser_login
from test_ai_selection import SEGMENTS, ANSWER
from playwright.sync_api import sync_playwright,expect

OUT=ROOT/'test-output';OUT.mkdir(exist_ok=True)
BRIDGE=os.getenv('CLIPFORGE_BROWSER_BRIDGE')=='1'
JOB='e'*32
results=[]
def record(text):results.append('PASS: '+text);print(results[-1],flush=True)

with tempfile.TemporaryDirectory(prefix='clipforge-ai-browser-') as tmp:
    folder=Path(tmp)/'data'/JOB;folder.mkdir(parents=True)
    make_source(folder/'input.mp4',61)
    write_json_atomic(folder/'transcript.json',SEGMENTS)
    write_json_atomic(folder/'job.json',{'id':JOB,'status':'completed','clips':[],'source_filename':'Entrevista sintética · QA sin inferencia.mp4'})
    before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir() if p.is_file()}
    requests=[]
    answer_override=None
    class Stub(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append(body)
            reply={'done':True,'done_reason':'stop','model':'fixture-no-real-model','message':{'role':'assistant','content':json.dumps(answer_override if answer_override is not None else ANSWER)},'prompt_eval_count':420,'eval_count':150}
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(reply).encode())
    stub=ThreadingHTTPServer(('127.0.0.1',0),Stub);thread=threading.Thread(target=stub.serve_forever,daemon=True);thread.start()
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    url=f'http://127.0.0.1:{port}'
    auth_fixture = prepare_browser_fixture(url, str(folder.parent), (JOB,))
    env={**os.environ,'CLIPFORGE_DATA_DIR':str(folder.parent),'CLIPFORGE_AI_PROVIDER':'ollama',
         'CLIPFORGE_AI_MODEL':'fixture-no-real-model','CLIPFORGE_OLLAMA_URL':f'http://127.0.0.1:{stub.server_port}',
         'CLIPFORGE_OLLAMA_NUM_CTX':'16384'}
    serverlog=open(OUT/'browser-ai-server.log','w')
    process=None
    def start_server():
        proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],cwd=ROOT,env=env,stdout=serverlog,stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                with urllib.request.urlopen(url+'/health',timeout=1) as r:
                    assert json.load(r)['version']=='0.4.2'
                return proc
            except OSError:time.sleep(.1)
        proc.terminate();raise TimeoutError('API did not start')
    def stop_server(proc):
        proc.terminate()
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
    try:
        process=start_server()
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=os.getenv('CHROMIUM_EXECUTABLE') or shutil.which('chromium'),headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
            context=browser.new_context(viewport={'width':1440,'height':1100},accept_downloads=True)
            fixture_csrf = browser_login(context, url, auth_fixture)
            page=context.new_page();errors=[];page.on('pageerror',lambda exc:errors.append(str(exc)))
            if BRIDGE:
                def backend(_source,request):
                    path=request['url']
                    if not path.startswith('/') or path.startswith('//'):raise ValueError('Local API only')
                    body=request.get('body')
                    req=urllib.request.Request(url+path,data=body.encode() if body is not None else None,headers=request.get('headers',{}),method=request.get('method','GET'))
                    try:r=urllib.request.urlopen(req,timeout=20)
                    except urllib.error.HTTPError as e:r=e
                    with r:return {'status':r.status,'headers':dict(r.headers),'body':base64.b64encode(r.read()).decode()}
                page.expose_binding('backendRequest',backend)
                html=(ROOT/'app/static/index.html').read_text();html=re.sub(r'<script src="[^"]+" defer></script>','',html);page.set_content(html)
                page.add_script_tag(content=r'''
                  window.fetch=async (url,options={})=>{
                    const data=await window.backendRequest({url:String(url),method:options.method||'GET',headers:options.headers||{},body:options.body ?? null});
                    return new Response(Uint8Array.from(atob(data.body),c=>c.charCodeAt(0)),{status:data.status,headers:data.headers});
                  };
                  async function media(el) {
                    const src=el.getAttribute('src');if(!src || !src.startsWith('/') || el.dataset.bridgeSrc===src)return;
                    el.dataset.bridgeSrc=src;const data=await window.backendRequest({url:src});if(el.getAttribute('src')!==src)return;
                    el.src='data:'+(el.tagName==='IMG'?'image/jpeg':'video/mp4')+';base64,'+data.body;delete el.dataset.bridgeSrc;if(el.tagName==='VIDEO')el.load();
                  }
                  new MutationObserver(records=>{for(const r of records){if(r.type==='attributes' && ['VIDEO','IMG'].includes(r.target.tagName))media(r.target);for(const n of r.addedNodes||[]){if(n.nodeType===1){if(['VIDEO','IMG'].includes(n.tagName))media(n);n.querySelectorAll('video,img').forEach(media);}}}}).observe(document.body,{subtree:true,childList:true,attributes:true,attributeFilter:['src']});
                ''')
                page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
                record('Explicit browser/API bridge in use; direct HTTP/Range/cancellation not tested by this transport.')
            else:
                page.goto(url,wait_until='networkidle')
            expect(page.locator('#project-list .project-card')).to_have_count(1)
            page.locator('#project-list button').first.click()
            expect(page.locator('#ai-panel')).to_be_visible()
            expect(page.locator('#ai-config')).to_contain_text('fixture-no-real-model')
            expect(page.locator('#ai-mode')).to_have_value('llm')
            assert len(requests)==0
            record('Opening the existing project loads config/transcript metadata without contacting a provider.')
            page.locator('#ai-count').fill('2')
            page.locator('#ai-brief').fill('Busca  una idea completa y un consejo concreto.')
            page.locator('#ai-preview-button').click()
            expect(page.locator('#ai-preview')).to_be_visible()
            expect(page.locator('#ai-run')).to_be_disabled()
            expect(page.locator('#ai-preview-text')).to_contain_text(SEGMENTS[0]['text'])
            assert len(requests)==0
            page.locator('#ai-panel').screenshot(path=str(OUT/'ai-preview-040.png'))
            record('Local preview shows exact selected text/IDs/destination, normalizes whitespace, and requires explicit consent.')
            page.locator('#ai-consent').check();expect(page.locator('#ai-run')).to_be_enabled()
            page.locator('#ai-brief').fill('Busca ideas completas, útiles y comprensibles sin el video completo.')
            expect(page.locator('#ai-preview')).to_be_hidden()
            page.locator('#ai-preview-button').click();expect(page.locator('#ai-preview')).to_be_visible();expect(page.locator('#ai-consent')).not_to_be_checked()
            record('Editing the brief invalidates the preview and clears consent.')
            expect(page.locator('#ai-range-note')).to_contain_text('45 intervalos válidos')
            record('Preview shows the complete prevalidated range catalog before consent, with no model call.')
            page.locator('#ai-consent').check();page.locator('#ai-run').click()
            expect(page.locator('#ai-candidates .ai-candidate')).to_have_count(2,timeout=15000)
            expect(page.locator('#ai-result-warning')).to_be_hidden()
            assert len(requests)==1
            assert requests[0]['stream'] is False and 'format' in requests[0]
            assert 'images' not in json.dumps(requests[0])
            enum=requests[0]['format']['properties']['candidates']['items']['properties']['range_id']['enum']
            assert 'r1_4' in enum and 'r5_8' in enum and 'r1_2' not in enum
            expect(page.locator('#ai-result-stats')).to_contain_text('Respuesta JSON del proveedor recibida')
            expect(page.locator('#ai-diagnostics')).to_be_visible()
            page.locator('#ai-diagnostics summary').click()
            expect(page.locator('#ai-diagnostics-json')).to_contain_text('"accepted_count": 2')
            record('Actual HTTP request constrains range IDs; response receipt and accepted-count diagnostics display correctly.')
            expect(page.locator('#ai-baseline')).to_be_visible()
            expect(page.locator('#ai-candidates blockquote').first).to_have_text(' '.join(s['text'] for s in SEGMENTS[:4]))
            expect(page.locator('#ai-config')).to_contain_text('1/10')
            page.locator('#ai-panel').screenshot(path=str(OUT/'ai-results-041.png'))
            record('One actual HTTP call to the local Ollama-shaped STUB yields two validated proposals and a baseline; not real LLM inference.')
            page.locator('#ai-candidates button').first.click()
            expect(page.locator('#editor')).to_be_visible();expect(page.locator('#editor-name')).to_have_value(ANSWER['candidates'][0]['title'])
            expect(page.locator('#range-start')).to_have_value('0');expect(page.locator('#range-end')).to_have_value('20')
            assert len(list((folder/'drafts').glob('*.json')))==1
            assert not (folder/'exports').exists()
            record('Accepting a proposal creates a persistent draft with original transcript cues, without rendering or Whisper.')
            page.locator('#editor-name').fill('QA: borrador revisado')
            page.locator('#range-end').fill('2');page.locator('#apply-range').click()
            expect(page.locator('#range-duration')).to_contain_text('2.000')
            page.locator('#editor-burn').check();page.locator('#editor-subtitle-size').fill('72')
            page.locator('#editor-subtitle-hex').fill('#FFD54F')
            page.locator('#export-button').click()
            expect(page.locator('#export-status')).to_contain_text('Variante lista.',timeout=45000)
            expect(page.locator('#exports-list video')).to_have_count(1)
            page.wait_for_function("document.querySelector('#exports-list video').readyState>=2",timeout=15000)
            assert len(requests)==1
            export=json.loads(next((folder/'exports').glob('*/export.json')).read_text())
            assert export['selection_origin']['mode']=='llm'
            assert (folder/'exports'/export['id']/'clip.mp4').stat().st_size>1000
            record('Draft is shortened/edited and rendered with real FFmpeg, with provenance preserved and no second provider request.')
            page.locator('#close-editor').click()
            page.locator('#ai-candidates button').first.click()
            expect(page.locator('#editor-name')).to_have_value('QA: borrador revisado')
            assert len(list((folder/'drafts').glob('*.json')))==1
            page.locator('#close-editor').click()
            record('A second acceptance reopens the edited draft instead of duplicating or overwriting it.')
            stop_server(process);process=start_server()
            page.locator('#ai-refresh').click()
            expect(page.locator('#ai-candidates .ai-candidate')).to_have_count(2,timeout=15000)
            assert len(requests)==1
            record('Restarting the API and reopening saved analysis does not call the provider again.')
            assert before=={n:hashlib.sha256((folder/n).read_bytes()).hexdigest() for n in before}
            record('Original video, transcript and job.json retain their exact SHA-256 hashes.')
            page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(500)
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
            page.locator('#ai-panel').screenshot(path=str(OUT/'ai-mobile-041.png'))
            page.locator('#ai-mode').select_option('heuristic')
            page.locator('#ai-preview-button').click();expect(page.locator('#ai-preview')).to_be_visible()
            page.locator('#ai-consent').check();page.locator('#ai-run').click()
            expect(page.locator('#ai-result-title')).to_have_text('Comparación heurística local')
            expect(page.locator('#ai-candidates .ai-candidate')).to_have_count(1)
            assert len(requests)==1
            record('Local comparison works from the same panel without another provider call or presenting it as AI.')
            # Exercise all-rejected and legacy diagnostics against the real API.
            page.set_viewport_size({'width':1440,'height':1100})
            answer_override=copy.deepcopy(ANSWER)
            for candidate in answer_override['candidates']:candidate['range_id']='r999_999'
            page.locator('#ai-mode').select_option('llm')
            page.locator('#ai-preview-button').click();expect(page.locator('#ai-preview')).to_be_visible()
            page.locator('#ai-consent').check();page.locator('#ai-run').click()
            expect(page.locator('#ai-result-warning')).to_contain_text('UNKNOWN_RANGE',timeout=15000)
            expect(page.locator('#ai-result-stats')).to_contain_text('validación editorial local: rechazada')
            expect(page.locator('#ai-candidates .ai-candidate')).to_have_count(0)
            if not page.locator('#ai-diagnostics').evaluate('(e)=>e.open'):page.locator('#ai-diagnostics summary').click()
            expect(page.locator('#ai-diagnostics-json')).to_contain_text('"rejected_count": 2')
            assert len(requests)==2
            page.locator('#ai-panel').screenshot(path=str(OUT/'ai-diagnostic-041.png'))
            page.locator('#ai-refresh').click()
            expect(page.locator('#ai-result-warning')).to_contain_text('UNKNOWN_RANGE')
            assert len(requests)==2
            record('All-invalid response keeps individual reasons/usage, no fabricated clips, and refresh does not retry the provider.')
            legacy_id='c'*32
            legacy={'id':legacy_id,'job_id':JOB,'version':'0.4.0','status':'failed','mode':'llm',
                    'provider':'ollama','model':'fixture-legacy-no-real-model','segment_count':12,
                    'created_at':time.time()+10,'error_code':'AI_NO_VALID_CANDIDATES',
                    'error':'Old fixture error, not a real provider result.','candidates':[],
                    'baseline':[],'warnings':[],'usage':{'input_tokens':2801,'output_tokens':334}}
            write_json_atomic(folder/'selections'/legacy_id/'selection.json',legacy)
            page.locator('#ai-refresh').click()
            expect(page.locator('#ai-result-badge')).to_contain_text('fixture-legacy')
            if not page.locator('#ai-diagnostics').evaluate('(e)=>e.open'):page.locator('#ai-diagnostics summary').click()
            expect(page.locator('#ai-diagnostics-note')).to_contain_text('no conservó los motivos individuales')
            expect(page.locator('#ai-diagnostics-json')).to_be_hidden()
            assert len(requests)==2
            record('Legacy failed record stays readable; UI admits missing detail rather than reconstructing or retrying it.')
            page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(300)
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
            assert not errors,errors
            record('Mobile selection panel fits at 390px; no unhandled JavaScript errors.')
            context.close();browser.close()
    finally:
        if process:stop_server(process)
        serverlog.close();stub.shutdown();stub.server_close();thread.join(timeout=2)
(OUT/'browser-ai.log').write_text('\n'.join(results)+'\n')
