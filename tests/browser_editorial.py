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
    with (OUTPUT / "browser-editorial-server.log").open("w") as server_log:
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
                        raise RuntimeError("Server stopped; inspect browser-editorial-server.log")
                    time.sleep(.1)
            else:
                raise TimeoutError("HTTP server did not become ready")
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path=os.getenv("CHROMIUM_EXECUTABLE") or shutil.which("chromium"),
                                           headless=True,args=["--no-sandbox","--disable-dev-shm-usage"])
                context = browser.new_context(viewport={"width":1440,"height":1100},accept_downloads=True)
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
                      const imageSrc=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');
                      Object.defineProperty(HTMLImageElement.prototype,'src',{configurable:true,get:imageSrc.get,set(value){
                        if(String(value).startsWith('/')) {
                          const image=this;
                          window.backendRequest({url:String(value)}).then(data=>imageSrc.set.call(image,'data:image/jpeg;base64,'+data.body));
                        } else imageSrc.set.call(this,value);
                      }});
                      async function media(video) {
                        const src=video.getAttribute('src');
                        if(!src || !src.startsWith('/') || video.dataset.bridgeSrc===src) return;
                        video.dataset.bridgeSrc=src;
                        const data=await window.backendRequest({url:src});
                        if(video.getAttribute('src')!==src) return;
                        video.src='data:'+(video.tagName==='IMG' ? 'image/jpeg' : 'video/mp4')+';base64,'+data.body;
                        delete video.dataset.bridgeSrc;
                        if(video.tagName==='VIDEO') video.load();
                      }
                      new MutationObserver(records=>{
                        for(const r of records) {
                          if(r.type==='attributes' && ['VIDEO','IMG'].includes(r.target.tagName)) media(r.target);
                          for(const n of r.addedNodes || []) {if(n.nodeType===1) {if(['VIDEO','IMG'].includes(n.tagName)) media(n); n.querySelectorAll('video,img').forEach(media);}}
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
                expect(page.locator("#project-list .project-card")).to_have_count(1)
                expect(page.locator("#library-status")).to_contain_text("1 proyecto")
                page.locator('#project-list button').filter(has_text='Abrir proyecto').click()
                expect(page.locator('#status')).to_have_text('Procesamiento completado.')
                expect(page.locator('#project-actions')).to_be_visible()
                page.once('dialog',lambda dialog:dialog.accept('Entrevista de prueba · local'))
                page.locator('#project-rename').click()
                expect(page.locator('#project-list h3')).to_have_text('Entrevista de prueba · local')
                page.locator('#library-query').fill('no existe')
                page.locator('#library-form button[type=submit]').click()
                expect(page.locator('#project-list .project-card')).to_have_count(0)
                page.locator('#library-query').fill('Entrevista')
                page.locator('#library-form button[type=submit]').click()
                expect(page.locator('#project-list .project-card')).to_have_count(1)
                page.locator('#library').scroll_into_view_if_needed()
                page.wait_for_function("document.querySelector('#project-list img')?.naturalWidth>0")
                record('Library discovers legacy project, renders a real thumbnail via '
                       + ('the explicit test bridge' if BRIDGE else 'direct browser HTTP')
                       + ', renames without changing job.json and filters by title over the real API.')
                page.locator('#clips button').click()
                expect(page.locator('#editor')).to_be_visible()
                page.wait_for_function("document.querySelector('#editor-source').readyState>=2")
                page.locator('#editor-name').fill('Idea principal · borrador')
                page.locator('#editor-burn').check()
                page.locator('#editor-framing').select_option('crop')
                page.locator('#editor-subtitle-size').fill('72')
                page.locator('#editor-subtitle-hex').fill('#FFD54F')
                page.locator('#cue-list textarea').first.fill('CORRECCIÓN conservada en el recorte.')
                # Base clip starts at 2 s; trim to 3–10 s, preserving first caption from 3 to 4.75.
                page.locator('#range-start').fill('3')
                page.locator('#range-end').fill('10')
                page.locator('#apply-range').click()
                expect(page.locator('#range-note')).to_contain_text('Rango aplicado.')
                expect(page.locator('#cue-list textarea').first).to_have_value('CORRECCIÓN conservada en el recorte.')
                expect(page.locator('input[aria-label="Inicio subtítulo 1"]')).to_have_value('0')
                expect(page.locator('input[aria-label="Fin subtítulo 1"]')).to_have_value('1.75')
                expect(page.locator('#editor-meta')).to_contain_text('3.000–10.000 s')
                record('Applying a smaller time range rebases subtitles and preserves the edited overlapping text.')
                page.locator('#range-end').fill('99')
                page.locator('#apply-range').click()
                expect(page.locator('#range-note')).to_contain_text('No se aplicó')
                expect(page.locator('#editor-meta')).to_contain_text('3.000–10.000 s')
                page.locator('#range-end').fill('10')
                record('Invalid source boundaries do not alter the active selection or corrected captions.')
                page.locator('#save-draft').click()
                expect(page.locator('#export-status')).to_contain_text('Borrador guardado · revisión 1')
                expect(page.locator('#draft-list .draft-card')).to_have_count(1)
                assert not (folder/'exports').exists()
                draft_path=next((folder/'drafts').glob('*.json'))
                saved=json.loads(draft_path.read_text())
                assert saved['start']==3 and saved['end']==10 and saved['revision']==1
                assert saved['cues'][0]['text'].startswith('CORRECCIÓN')
                record('Save draft persists title, absolute range, corrected cues and style WITHOUT an export or ASR.')
                page.locator('#close-editor').click()
                expect(page.locator('#editor')).to_be_hidden()
                page.locator('#draft-list button').first.click()
                expect(page.locator('#editor-name')).to_have_value('Idea principal · borrador')
                expect(page.locator('#range-start')).to_have_value('3')
                expect(page.locator('#range-end')).to_have_value('10')
                expect(page.locator('#editor-subtitle-size')).to_have_value('72')
                expect(page.locator('#editor-subtitle-hex')).to_have_value('#FFD54F')
                record('Closing and reopening a saved draft retrieves the complete state from disk.')
                # Dirty close must not discard without explicit acceptance.
                page.locator('#editor-name').fill('Cambio no guardado')
                page.once('dialog',lambda dialog:dialog.dismiss())
                page.locator('#close-editor').click()
                expect(page.locator('#editor')).to_be_visible()
                expect(page.locator('#editor-name')).to_have_value('Cambio no guardado')
                page.locator('#editor-name').fill('Idea principal · borrador')
                page.locator('#save-draft').click()
                expect(page.locator('#export-status')).to_contain_text('revisión 2')
                record('Unsaved-change confirmation prevents accidental dismissal; updates increment draft revisions.')
                # Simulate another tab saving a revision via real HTTP, then show conflict in the UI.
                current=json.loads(draft_path.read_text())
                payload={k:current[k] for k in ('title','clip_file','start','end','options','cues','revision')}
                payload['title']='Cambio desde otra pestaña'
                req=urllib.request.Request(url+f'/jobs/{ID}/drafts/{current["id"]}',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='PUT')
                with urllib.request.urlopen(req) as response:assert response.status==200
                page.locator('#editor-name').fill('Mi edición protegida')
                page.locator('#save-draft').click()
                expect(page.locator('#export-status')).to_contain_text('otra pestaña')
                expect(page.locator('#editor-name')).to_have_value('Mi edición protegida')
                page.locator('#copy-draft').click()
                expect(page.locator('#export-status')).to_contain_text('revisión 1')
                expect(page.locator('#draft-list .draft-card')).to_have_count(2)
                record('Stale revision produces a visible conflict without losing editor text; Save copy recovers an independent draft.')
                page.locator('#export-button').click()
                expect(page.locator('#export-status')).to_contain_text('Variante lista.',timeout=45000)
                expect(page.locator('#exports-list video')).to_have_count(1)
                page.wait_for_function("document.querySelector('#exports-list video').readyState>=2")
                exported=json.loads(next((folder/'exports').glob('*/export.json')).read_text())
                assert exported['start']==3 and exported['end']==10 and exported['draft_revision']==2
                page.locator('#exports-list video').evaluate('v=>v.play()')
                page.wait_for_function("document.querySelector('#exports-list video').currentTime>0.3")
                page.locator('#exports-list video').evaluate('v=>v.pause()')
                with page.expect_download() as download_info:
                    page.locator('#exports-list a').filter(has_text='SRT').click()
                srt=Path(download_info.value.path()).read_text(encoding='utf-8')
                assert '00:00:00,000 --> 00:00:01,750' in srt and 'CORRECCIÓN' in srt
                record('Real FFmpeg export uses the trimmed range and frozen draft revision; MP4 plays and SRT starts at clip-local zero.')
                page.locator('#exports-list').get_by_role('button',name='Usar estos ajustes',exact=True).click()
                expect(page.locator('#editor-title')).to_have_text('Editar una copia de la variante')
                expect(page.locator('#range-start')).to_have_value('3')
                expect(page.locator('#range-end')).to_have_value('10')
                expect(page.locator('#cue-list textarea').first).to_have_value('CORRECCIÓN conservada en el recorte.')
                assert page.evaluate('editorData.draft_id') is None
                record('Reusing an export retains its own edited bounds and opens a new unsaved copy, not the original clip range.')
                page.wait_for_function("document.querySelector('#editor-source').readyState>=2")
                page.locator('#editor-source').evaluate('v=>{v.currentTime=3.5;}')
                page.wait_for_function("!document.querySelector('#editor-source').seeking")
                page.wait_for_timeout(300)
                page.locator('#editor').screenshot(path=str(OUTPUT/'editorial-range-real.png'))
                page.locator('#library').screenshot(path=str(OUTPUT/'library-real.png'))
                page.locator('#drafts-panel').screenshot(path=str(OUTPUT/'drafts-real.png'))
                page.set_viewport_size({'width':390,'height':844})
                page.wait_for_timeout(300)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                page.locator('#editor').screenshot(path=str(OUTPUT/'editorial-mobile-real.png'))
                page.set_viewport_size({'width':1440,'height':1100})
                # Manual clip outside the suggested clip, starting at zero.
                page.locator('#close-editor').click()
                page.locator('#new-manual').click()
                expect(page.locator('#editor-title')).to_have_text('Crear clip manual')
                page.locator('#editor-name').fill('Clip creado a mano')
                page.locator('#range-start-slider').fill('0')
                page.locator('#range-end-slider').fill('2')
                page.locator('#save-draft').click()  # also applies any pending range
                expect(page.locator('#export-status')).to_contain_text('Borrador guardado')
                assert page.evaluate('editorData.clip_file') is None
                expect(page.locator('#range-end')).to_have_value('2')
                record('Manual clip creation can select outside suggested bounds; saving applies pending range without running Whisper.')
                # Extend then undo restores prior cue/range snapshot.
                page.locator('#range-end').fill('6')
                page.locator('#apply-range').click()
                expect(page.locator('#range-note')).to_contain_text('Rango aplicado.')
                page.once('dialog',lambda dialog:dialog.accept())
                page.locator('#undo-range').click()
                expect(page.locator('#range-end')).to_have_value('2')
                expect(page.locator('#range-note')).to_contain_text('deshecho')
                record('One-step range undo restores the earlier time selection and subtitle snapshot.')
                page.locator('#save-draft').click()
                expect(page.locator('#export-status')).to_contain_text('Borrador guardado')
                # Restart backend to confirm actual disk persistence of drafts (no queued renders).
                process.terminate();process.wait(timeout=10)
                process=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],cwd=ROOT,env={**os.environ,'CLIPFORGE_DATA_DIR':str(data)},stdout=server_log,stderr=subprocess.STDOUT)
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(url+'/health',timeout=1) as response:assert response.status==200
                        break
                    except OSError:time.sleep(.1)
                page.locator('#close-editor').click()
                page.locator('#drafts-refresh').click()
                expect(page.locator('#draft-list .draft-card')).to_have_count(3)
                page.locator('#draft-list .draft-card').filter(has_text='Clip creado a mano').locator('button').click()
                expect(page.locator('#range-end')).to_have_value('2')
                assert before=={q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in originals}
                assert not errors,errors
                record('Drafts reopen after an actual API restart; all four original files stay byte-identical. No unhandled JS errors, no mobile horizontal overflow.')
                page.wait_for_timeout(1200)
                context.close()
                browser.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
(OUTPUT / "browser-editorial.log").write_text("\n".join(logs)+"\n",encoding="utf-8")
