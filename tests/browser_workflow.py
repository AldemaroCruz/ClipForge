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
    with (OUTPUT / "browser-workflow-server.log").open("w") as server_log:
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
                        raise RuntimeError("Server stopped; inspect browser-workflow-server.log")
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
                page.locator("#job-id").fill(ID)
                page.locator("#job-form button").click()
                expect(page.locator("#status")).to_have_text("Procesamiento completado.")
                expect(page.locator("#clips video")).to_have_count(1)
                page.wait_for_function("document.querySelector('#clips video').readyState>=2",timeout=15000)
                page.locator("#clips video").evaluate("v=>v.play()")
                page.wait_for_function("document.querySelector('#clips video').currentTime>0.3",timeout=10000)
                page.locator("#clips video").evaluate("v=>v.pause()")
                record("Existing v0.1.4-schema job loaded over real HTTP; H.264 video decoded and played in Chromium.")
                page.locator("#clips button").click()
                expect(page.locator("#editor")).to_be_visible()
                expect(page.locator("#cue-list textarea")).to_have_count(8)
                page.wait_for_function("document.querySelector('#editor-source').readyState>=2",timeout=15000)
                page.locator("#editor-framing").select_option("crop")
                page.locator("#editor-x").fill("75")
                page.locator("#editor-zoom").fill("1.25")
                page.locator("#editor-burn").check()
                expect(page.locator("#editor-box")).to_be_visible()
                expect(page.locator("#editor-subtitle-size")).to_have_value("52")
                expect(page.locator("#editor-subtitle-hex")).to_have_value("#FFFFFF")
                page.locator("#editor-subtitle-size-range").fill("80")
                expect(page.locator("#editor-subtitle-size")).to_have_value("80")
                page.locator("#editor-subtitle-color").evaluate("e=>{e.value='#ffd54f';e.dispatchEvent(new Event('input',{bubbles:true}));}")
                expect(page.locator("#editor-subtitle-hex")).to_have_value("#FFD54F")
                expect(page.locator("#editor-style-sample")).to_have_css("color", "rgb(255, 213, 79)")
                expect(page.locator("#editor-style-sample")).to_have_css("font-size", "40px")
                page.locator("#editor-style-reset").click()
                expect(page.locator("#editor-subtitle-size")).to_have_value("52")
                expect(page.locator("#editor-subtitle-hex")).to_have_value("#FFFFFF")
                expect(page.locator("#editor-framing")).to_have_value("crop")
                expect(page.locator("#editor-burn")).to_be_checked()
                page.locator("#editor-subtitle-size").fill("80")
                page.locator("#editor-subtitle-hex").fill("#ffd54f")
                expect(page.locator("#editor-subtitle-size-range")).to_have_value("80")
                expect(page.locator("#editor-subtitle-color")).to_have_value("#ffd54f")
                record("Legacy defaults, slider/number and picker/hex synchronization, live style sample and style-only reset work.")
                # The export button is not in a form: it must explicitly validate fields.
                page.locator("#editor-subtitle-size").fill("121")
                page.locator("#export-button").click()
                expect(page.locator("#export-status")).to_contain_text("Revisa tamaño")
                assert not (folder / "exports").exists()
                page.locator("#editor-subtitle-size").fill("80")
                page.locator("#editor-subtitle-hex").fill("#zz0000")
                page.locator("#export-button").click()
                expect(page.locator("#export-status")).to_contain_text("Revisa tamaño")
                assert not (folder / "exports").exists()
                page.locator("#editor-subtitle-hex").fill("#FFD54F")
                record("Invalid size and color rejected in the editor without queueing a variant or discarding the draft.")
                page.locator("#cue-list textarea").first.fill("Texto corregido: edición local y subtítulos.")
                expect(page.locator("#dirty-note")).to_contain_text("Cambios sin guardar")
                page.locator("#play-range").click()
                page.wait_for_timeout(600)
                page.locator("#editor-source").evaluate("v=>v.pause()")
                page.locator("#editor").screenshot(path=str(OUTPUT / "editor-real.png"))
                record("Source video and crop preview rendered; editable cue text changed; fixed horizontal/zoom controls work.")
                # A malformed cue must fail visibly and allow correction, not queue a render.
                first_end=page.locator('input[aria-label="Fin subtítulo 1"]')
                first_end.fill("0")
                page.locator("#export-button").click()
                expect(page.locator("#export-status")).to_contain_text("No se pudo guardar:")
                expect(page.locator("#export-button")).to_be_enabled()
                first_end.fill("2.75")
                record("Invalid subtitle timing rejected by the real API; editor stays usable without losing the draft.")
                page.locator("#export-button").click()
                expect(page.locator("#export-status")).to_contain_text("Variante lista.",timeout=45000)
                expect(page.locator("#exports-list video")).to_have_count(1)
                page.wait_for_function("document.querySelector('#exports-list video').readyState>=2",timeout=15000)
                page.locator("#exports-list video").evaluate("v=>{v.currentTime=1;return v.play();}")
                page.wait_for_function("document.querySelector('#exports-list video').currentTime>1.2",timeout=10000)
                page.locator("#exports-list video").evaluate("v=>v.pause()")
                with page.expect_download() as download_info:
                    page.locator("#exports-list a").filter(has_text="SRT").click()
                download=download_info.value
                downloaded=Path(download.path()).read_text(encoding="utf-8")
                assert "Texto corregido" in downloaded
                assert "00:00:00,000 --> 00:00:02,750" in downloaded
                record("Real queued export completed via FFmpeg; resulting MP4 plays in Chromium; edited UTF-8 SRT downloads correctly.")
                assert before == {q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in originals}
                record("Original video, first clip, transcript and job.json preserved byte-for-byte after editing/export.")
                page.locator("#exports-list button").filter(has_text="Usar estos ajustes").click()
                expect(page.locator("#editor-framing")).to_have_value("crop")
                expect(page.locator("#cue-list textarea").first).to_have_value("Texto corregido: edición local y subtítulos.")
                record("Saved variant settings and corrected subtitles can be reopened in the editor.")
                expect(page.locator("#editor-subtitle-size")).to_have_value("80")
                expect(page.locator("#editor-subtitle-hex")).to_have_value("#FFD54F")
                saved = json.loads(next((folder / "exports").glob("*/export.json")).read_text())
                assert saved["options"]["subtitle_font_size"] == 80
                assert saved["options"]["subtitle_color"] == "#FFD54F"
                expect(page.locator("#exports-list .style-meta")).to_contain_text("80 · #FFD54F")
                record("Font size/color persisted in export.json and restored by 'Usar estos ajustes'; original job stays unchanged.")

                page.wait_for_function("document.querySelector('#editor-source').readyState>=2",timeout=15000)
                page.locator("#editor-source").evaluate("v=>{v.currentTime=3;}")
                page.wait_for_timeout(400)
                page.locator("#editor").screenshot(path=str(OUTPUT / "editor-real.png"))
                page.screenshot(path=str(OUTPUT / "ui-desktop-real.png"),full_page=True)
                page.set_viewport_size({"width":390,"height":844})
                page.wait_for_timeout(300)
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                page.locator("#editor").screenshot(path=str(OUTPUT / "ui-mobile-real.png"))
                assert not errors,errors
                record("Mobile layout has no horizontal document overflow; no unhandled JavaScript errors in this real workflow.")
                context.close()
                browser.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
(OUTPUT / "browser-workflow.log").write_text("\n".join(logs)+"\n",encoding="utf-8")
