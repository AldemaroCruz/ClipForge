"""Browser -> REAL HTTP API -> REAL FFmpeg -> rendered MP4/SRT.

Seeds a synthetic video and an existing v0.1.4-style job with explicit transcript
text. No Whisper inference or simulated successful inference occurs in this test.
Set CLIPFORGE_BROWSER_BRIDGE=1 only for environments with managed navigation
restrictions: HTTP then runs through an explicit Python bridge and video data URLs.
The bridge does not test native browser HTTP navigation, ranges or cancellation.
Requires Playwright and Chromium; see README. All job files use a temp directory.
"""
import base64
import re
import urllib.error
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.check_presentation import make_source
from app.presentation import Presentation
from app.render import render_clip
from app.state import write_json_atomic
from auth_support import prepare_browser_fixture, browser_login
import io
import zipfile
from playwright.sync_api import sync_playwright, expect

OUTPUT = ROOT / "test-output"
OUTPUT.mkdir(exist_ok=True)
ID = "f" * 32
logs = []
BRIDGE = os.getenv("CLIPFORGE_BROWSER_BRIDGE") == "1"

def record(message):
    logs.append("PASS: " + message)
    print(logs[-1], flush=True)

with tempfile.TemporaryDirectory(prefix="clipforge-browser-") as temporary:
    data = Path(temporary) / "data"
    folder = data / ID
    folder.mkdir(parents=True)
    source = folder / "input.mp4"
    make_source(source, 24)
    cues = [{"start": i * 2.75, "end": (i+1) * 2.75, "text": text} for i,text in enumerate([
        "Esta es una prueba local de edición.", "Partimos del video original.",
        "Seleccionamos un encuadre vertical.", "Y revisamos el texto antes de publicar.",
        "Los subtítulos conservan sus tiempos.", "El archivo base no se sobrescribe.",
        "Cada variante queda guardada.", "Ahora revisamos el resultado final."])]
    render_clip(source, folder / "clip_01.mp4", start=2, end=24, options=Presentation(), cues=[])
    write_json_atomic(folder / "transcript.json", [{**c,"start":c["start"]+2,"end":c["end"]+2} for c in cues])
    write_json_atomic(folder / "job.json", {"id":ID,"status":"completed","clips":[{"file":"clip_01.mp4","start":2,"end":24,"text":"Transcripción de prueba explícita."}]})
    originals = [folder / n for n in ("input.mp4", "clip_01.mp4", "transcript.json", "job.json")]
    before = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in originals}
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    auth_fixture = prepare_browser_fixture(url, str(data), (ID,))
    with (OUTPUT / "browser-delivery-server.log").open("w") as server_log:
        process = subprocess.Popen([sys.executable,"-m","uvicorn","app.main:app","--host","127.0.0.1","--port",str(port)],
                                   cwd=ROOT, env={**os.environ,"CLIPFORGE_DATA_DIR":str(data)},
                                   stdout=server_log,stderr=subprocess.STDOUT)
        try:
            for attempt in range(100):
                try:
                    with urllib.request.urlopen(url+"/health",timeout=1) as response:
                        assert json.load(response)["version"] == "0.4.2"
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError("Server stopped; inspect browser-delivery-server.log")
                    time.sleep(.1)
            else:
                raise TimeoutError("HTTP server did not become ready")
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path=os.getenv("CHROMIUM_EXECUTABLE") or shutil.which("chromium"),
                                           headless=True,args=["--no-sandbox","--disable-dev-shm-usage"])
                context = browser.new_context(viewport={"width":1440,"height":1100},accept_downloads=True)
                fixture_csrf = browser_login(context, url, auth_fixture)
                page = context.new_page()
                errors=[]
                page.on("pageerror",lambda e:errors.append(str(e)))
                if BRIDGE:
                    # Test-harness transport only: browser navigation to localhost may
                    # be blocked by managed browser policy. Keep the actual server,
                    # API code and renderer; do NOT alter browser security settings.
                    # Media arrives through this Python HTTP bridge as data URLs.
                    def backend(_source, request):
                        path = request["url"]
                        if not path.startswith("/") or path.startswith("//"):
                            raise ValueError("Only this local test server is allowed")
                        body = request.get("body")
                        req = urllib.request.Request(url + path, data=body.encode() if body is not None else None,
                                                     headers=request.get("headers", {}), method=request.get("method", "GET"))
                        try:
                            response = urllib.request.urlopen(req, timeout=20)
                        except urllib.error.HTTPError as exc:
                            response = exc
                        with response:
                            return {"status": response.status, "headers": dict(response.headers),
                                    "body": base64.b64encode(response.read()).decode()}
                    page.expose_binding("backendRequest", backend)
                    html=(ROOT / "app/static/index.html").read_text()
                    html=re.sub(r'<script src="[^"]+" defer></script>', '', html)
                    page.set_content(html)
                    page.add_script_tag(content=r"""
                      window.fetch=async (url,options={})=>{
                        const data=await window.backendRequest({url:String(url),method:options.method||'GET',headers:options.headers||{},body:options.body ?? null});
                        const bytes=Uint8Array.from(atob(data.body),c=>c.charCodeAt(0));
                        return new Response(bytes,{status:data.status,headers:data.headers});
                      };
                      async function media(video) {
                        const src=video.getAttribute('src');
                        if(!src || !src.startsWith('/') || video.dataset.bridgeSrc===src) return;
                        video.dataset.bridgeSrc=src;
                        const data=await window.backendRequest({url:src});
                        if(video.getAttribute('src')!==src) return;
                        video.src='data:video/mp4;base64,'+data.body;
                        delete video.dataset.bridgeSrc;
                        video.load();
                      }
                      new MutationObserver(records=>{
                        for(const r of records) {
                          if(r.type==='attributes' && r.target.tagName==='VIDEO') media(r.target);
                          for(const n of r.addedNodes || []) {if(n.nodeType===1) {if(n.tagName==='VIDEO') media(n); n.querySelectorAll('video').forEach(media);}}
                        }
                      }).observe(document.body,{subtree:true,childList:true,attributes:true,attributeFilter:['src']});
                      document.addEventListener('click',async event=>{
                        const a=event.target.closest('a');const href=a?.getAttribute('href');
                        if(!href || !href.startsWith('/')) return;
                        event.preventDefault();
                        const data=await window.backendRequest({url:href});
                        const bytes=Uint8Array.from(atob(data.body),c=>c.charCodeAt(0));
                        const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([bytes]));link.download='test-download.srt';link.click();
                      });
                    """)
                    page.add_script_tag(content=(ROOT / "app/static/app.js").read_text())
                    record("Transport is an explicit Python-to-HTTP test bridge; no direct browser HTTP navigation, fetch cancellation or video Range transport claimed.")
                else:
                    page.goto(url,wait_until="networkidle")
                expect(page.locator("h1")).to_have_text("ClipForge AI")
                page.locator("#job-details summary").click()
                page.locator("#job-id").fill(ID);page.locator("#job-form button").click()
                expect(page.locator("#status")).to_have_text("Procesamiento completado.")
                page.locator("#clips button").click()
                expect(page.locator('#editor')).to_be_visible()
                page.locator('#editor-burn').check()
                page.locator('#editor-framing').select_option('blur')
                page.locator('#editor-subtitle-size').fill('72')
                page.locator('#editor-subtitle-hex').fill('#FFD54F')
                page.locator('#editor-subtitle-position').select_option('top')
                page.locator('#editor-subtitle-margin').fill('140')
                page.locator('#editor-subtitle-outline').fill('5')
                page.locator('#editor-outline-hex').fill('#000000')
                page.locator('#editor-subtitle-shadow').fill('2')
                page.locator('#cue-list textarea').first.fill('Texto corregido que debe conservarse.')
                edited=page.evaluate('({cues:editorData.cues,start:editorData.start,end:editorData.end})')
                page.locator('#editor-template-name').fill('Podcast ámbar · prueba')
                page.locator('#editor-template-save').click()
                expect(page.locator('#editor-template-status')).to_contain_text('Plantilla guardada')
                assert not (folder/'exports').exists()
                assert not (folder/'drafts').exists()
                template_path=next((data/'workspaces'/auth_fixture['principal'].workspace_id/'templates').glob('*.json'))
                template=json.loads(template_path.read_text())
                assert 'cues' not in template and 'start' not in template
                assert template['options']['subtitle_position']=='top'
                record('Template persisted as visual options only, without cue/range data, render or draft creation.')
                page.locator('#editor-style-reset').click()
                expect(page.locator('#editor-subtitle-position')).to_have_value('bottom')
                expect(page.locator('#editor-subtitle-outline')).to_have_value('3')
                page.locator('#editor-template-apply').click()
                expect(page.locator('#editor-subtitle-position')).to_have_value('top')
                expect(page.locator('#editor-subtitle-outline')).to_have_value('5')
                expect(page.locator('#editor-subtitle-margin')).to_have_value('140')
                expect(page.locator('#editor-outline-hex')).to_have_value('#000000')
                assert edited==page.evaluate('({cues:editorData.cues,start:editorData.start,end:editorData.end})')
                page.locator('#editor-subtitle-position').select_option('center')
                expect(page.locator('#editor-subtitle-margin')).to_be_disabled()
                page.locator('#editor-template-apply').click()
                record('Template application restores framing/style, preserves corrected text and times; center disables the inapplicable margin.')
                page.wait_for_function("document.querySelector('#editor-source').readyState>=2")
                page.locator('#editor-source').evaluate('v=>{v.currentTime=3;v.pause();}')
                page.wait_for_timeout(300)
                page.locator('#editor').screenshot(path=str(OUTPUT/'branding-editor-031.png'))
                page.locator('#export-button').click()
                expect(page.locator('#export-status')).to_contain_text('Variante lista.',timeout=45000)
                expect(page.locator('#exports-list video')).to_have_count(1)
                item=json.loads(next((folder/'exports').glob('*/export.json')).read_text())
                eid=item['id']
                assert item['options']['subtitle_position']=='top' and item['options']['subtitle_outline']==5
                assert item['cues'][0]['text']=='Texto corregido que debe conservarse.'
                expect(page.locator('[data-delivery-id]')).to_be_disabled()
                record('Actual FFmpeg export saved the new style and corrected text; new variants default pending and are not selectable.')
                page.locator(f'#review-{eid}-title').fill('Un consejo útil para nuestro cliente')
                page.locator(f'#review-{eid}-notes').fill('Publicar después de revisión final.\nTexto de prueba, no contenido privado.')
                page.locator(f'#review-{eid}-status').select_option('approved')
                page.locator('#exports-list button').filter(has_text='Guardar revisión').click()
                expect(page.locator('.review-badge')).to_have_text('Aprobada')
                expect(page.locator('[data-delivery-id]')).to_be_enabled()
                review=json.loads((folder/'exports'/eid/'review.json').read_text())
                assert review['revision']==1 and review['status']=='approved'
                record('Explicit review persisted separately from export.json; approving enables selection without re-rendering.')
                # Simulate another tab through the real HTTP API; stale UI must reject overwrite.
                external={'revision':1,'status':'approved','title':'Título de otra pestaña','notes':'Cambio externo'}
                response=context.request.put(url+f'/jobs/{ID}/exports/{eid}/review',data=external,headers={'Origin':url,'X-CSRF-Token':fixture_csrf})
                assert response.status==200 and response.json()['revision']==2
                page.locator(f'#review-{eid}-notes').fill('Mis cambios todavía no guardados')
                page.locator('#exports-list button').filter(has_text='Guardar revisión').click()
                expect(page.locator('.review-message')).to_contain_text('otra pestaña')
                expect(page.locator(f'#review-{eid}-notes')).to_have_value('Mis cambios todavía no guardados')
                page.once('dialog',lambda dialog:dialog.accept())
                page.locator('#exports-list button').filter(has_text='Recargar revisión').click()
                expect(page.locator(f'#review-{eid}-notes')).to_have_value('Cambio externo')
                record('Stale review rejected with conflict, unsaved notes retained until explicit reload confirmation.')
                page.locator('[data-delivery-id]').check()
                expect(page.locator('#delivery-selection')).to_contain_text('1 variante(s)')
                page.locator('#create-delivery').click()
                expect(page.locator('#delivery-status')).to_contain_text('Entrega lista: 1',timeout=30000)
                expect(page.locator('#deliveries-list a')).to_have_count(1)
                with page.expect_download() as downloaded:
                    page.locator('#deliveries-list a').click()
                binary=Path(downloaded.value.path()).read_bytes()
                with zipfile.ZipFile(io.BytesIO(binary)) as archive:
                    assert archive.testzip() is None
                    manifest=json.loads(archive.read('manifest.json'))
                    assert manifest['clips'][0]['title']=='Título de otra pestaña'
                    assert manifest['clips'][0]['review_revision']==2
                    assert 'input.mp4' not in archive.namelist()
                    for file in manifest['clips'][0]['files']:
                        assert hashlib.sha256(archive.read(file['path'])).hexdigest()==file['sha256']
                record('UI selection produced and downloaded a real ZIP with approved revision, valid MP4/SRT/VTT hashes and no source video.')
                page.wait_for_function("document.querySelector('#exports-list video').readyState>=2")
                page.locator('#exports-list video').evaluate('v=>{v.currentTime=1;v.pause();}')
                page.wait_for_timeout(300)
                page.locator('#exports-panel').screenshot(path=str(OUTPUT/'review-delivery-031.png'))
                page.locator('#deliveries-panel').screenshot(path=str(OUTPUT/'packages-031.png'))
                # Revoke for future deliveries; already-created archive remains an explicit snapshot.
                page.locator(f'#review-{eid}-status').select_option('rejected')
                page.locator('#exports-list button').filter(has_text='Guardar revisión').click()
                expect(page.locator('.review-badge')).to_have_text('Descartada')
                expect(page.locator('[data-delivery-id]')).to_be_disabled()
                expect(page.locator('#create-delivery')).to_be_disabled()
                record('Discarding a variant removes future delivery eligibility; past ZIP remains accessible as a documented snapshot.')
                # Prove persisted templates and delivery survive a real server restart.
                process.terminate();process.wait(timeout=10)
                process=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],cwd=ROOT,env={**os.environ,'CLIPFORGE_DATA_DIR':str(data)},stdout=server_log,stderr=subprocess.STDOUT)
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(url+'/health',timeout=1) as response:assert response.status==200
                        break
                    except OSError:time.sleep(.1)
                page.evaluate('refreshTemplates()')
                expect(page.locator('#upload-template-select option')).to_have_count(2)
                page.locator('#exports-refresh').click()
                expect(page.locator('.review-badge')).to_have_text('Descartada')
                expect(page.locator('#deliveries-list a')).to_have_count(1)
                with page.expect_download() as again:page.locator('#deliveries-list a').click()
                assert Path(again.value.path()).read_bytes()==binary
                assert before=={q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in originals}
                record('API restart preserved templates, review and exact ZIP bytes; original video/clip/transcript/job hashes unchanged.')
                page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(250)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                page.locator('#editor .subtitle-style').screenshot(path=str(OUTPUT/'branding-mobile-031.png'))
                assert not errors,errors
                record('New controls, review and delivery workflow have no unhandled JavaScript errors or horizontal mobile overflow.')
                context.close();browser.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
(OUTPUT / "browser-delivery.log").write_text("\n".join(logs)+"\n",encoding="utf-8")
