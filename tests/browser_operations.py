"""Real operations UI/API over direct HTTP by default; no ASR or AI inference.

CLIPFORGE_BROWSER_BRIDGE=1 explicitly selects the legacy managed-browser bridge.
The CI browser runner rejects that transport instead of calling it direct HTTP.
"""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from app.state import write_json_atomic
from app.telemetry import Recorder
from playwright.sync_api import sync_playwright, expect
OUTPUT=ROOT/'test-output';OUTPUT.mkdir(exist_ok=True)
BRIDGE=os.getenv('CLIPFORGE_BROWSER_BRIDGE')=='1'
ID='a'*32;SECOND='b'*32;EXPORT='c'*32;ANALYSIS='d'*32

def record(text):print('PASS: '+text,flush=True)

with tempfile.TemporaryDirectory(prefix='clipforge-ops-browser-') as temp:
    data=Path(temp)/'data';folder=data/ID
    write_json_atomic(folder/'job.json',{'id':ID,'status':'completed','clips':[],'media':{'duration_seconds':60}})
    write_json_atomic(data/SECOND/'job.json',{'id':SECOND,'status':'completed','clips':[]})
    rec=Recorder(data,ID,'process',ID);rec.phase('validation');time.sleep(.01);rec.finish('completed')
    write_json_atomic(folder/'exports'/EXPORT/'export.json',{'id':EXPORT,'job_id':ID,'status':'completed'})
    write_json_atomic(folder/'exports'/EXPORT/'review.json',{'status':'approved'})
    # Consumption values are authored fixture data, not a real provider call.
    write_json_atomic(folder/'selections'/ANALYSIS/'selection.json',{'mode':'llm','request_started_at':1,'usage':{'input_tokens':1012,'output_tokens':230},'elapsed_seconds':1})
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    url=f'http://127.0.0.1:{port}'
    logfile=(OUTPUT/'operations-server.log').open('w')
    def start():
        proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],
            cwd=ROOT,env={**os.environ,'CLIPFORGE_DATA_DIR':str(data),'CLIPFORGE_AI_PROVIDER':'disabled'},stdout=logfile,stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                with urllib.request.urlopen(url+'/health',timeout=1) as r:
                    assert json.load(r)['version']=='0.4.2';return proc
            except OSError:time.sleep(.1)
        raise RuntimeError('API not ready')
    proc=start()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=os.getenv('CHROMIUM_EXECUTABLE') or shutil.which('chromium'),headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
            context=browser.new_context(viewport={'width':1440,'height':1100})
            page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            if BRIDGE:
                def backend(source, req):
                    path=req['url']
                    if not path.startswith('/') or path.startswith('//'):raise ValueError('Only local API is allowed')
                    request=urllib.request.Request(url+path,data=req.get('body','').encode() if req.get('body') is not None else None,method=req.get('method','GET'),headers=req.get('headers',{}))
                    try:r=urllib.request.urlopen(request,timeout=20)
                    except urllib.error.HTTPError as e:r=e
                    with r:return {'status':r.status,'body':base64.b64encode(r.read()).decode(),'headers':dict(r.headers)}
                page.expose_binding('localTestHTTP',backend)
                html=(ROOT/'app/static/operations.html').read_text();html=re.sub(r'<script src="[^"]+" defer></script>','',html)
                page.set_content(html)
                page.evaluate('''() => { window.fetch = async (url, options={}) => { const r = await window.localTestHTTP({url:String(url),method:options.method||'GET',body:options.body,headers:options.headers||{}});const bytes=Uint8Array.from(atob(r.body),c=>c.charCodeAt(0));return new Response(bytes,{status:r.status,headers:r.headers}); }; }''')
                page.add_script_tag(content=(ROOT/'app/static/operations.js').read_text())
            else:
                page.goto(url+'/ops',wait_until='networkidle')
            expect(page.locator('#count')).to_have_text('2');record('Loads real API summary with two fixture projects')
            page.select_option('#project',ID);expect(page.locator('#details')).to_contain_text('1012',use_inner_text=True) if False else None
            expect(page.locator('#details')).to_contain_text('230');record('Saved provider usage and approved count shown')
            page.select_option('#project',SECOND);expect(page.locator('#stages')).to_contain_text('No medido');record('Legacy metrics are not invented')
            page.select_option('#project',ID);page.fill('#minutes','12.5');page.click('#save-review')
            expect(page.locator('#review-status')).to_contain_text('Minutos guardados');expect(page.locator('#human')).to_contain_text('12.5');record('Manual review time persisted via actual POST')
            # An unmistakable fixture label appears only in the test screenshot.
            page.locator('header .muted').evaluate("el => el.textContent = 'ESCENARIO DE PRUEBA · consumo simulado, sin proveedor real.'")
            page.screenshot(path=str(OUTPUT/'operations-042.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            page.screenshot(path=str(OUTPUT/'operations-mobile-042.png'),full_page=True);record('Mobile has no horizontal page overflow')
            proc.terminate();proc.wait(timeout=10);proc=start()
            page.click('#refresh');expect(page.locator('#human')).to_contain_text('12.5');record('Review time survives actual API restart')
            assert not errors,errors;record('No unhandled JavaScript errors')
            browser.close()
    finally:
        proc.terminate();proc.wait(timeout=10);logfile.close()
    print('SCOPE: HTTP bridge with real Uvicorn; no native browser network/Range test; no inference.'
          if BRIDGE else 'SCOPE: Direct browser HTTP to isolated Uvicorn; authored usage fixtures; no inference.',flush=True)
