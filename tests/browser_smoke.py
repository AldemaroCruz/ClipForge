"""Offline UI checks: actual HTML/JS with simulated fetch responses.

Optional local execution (not part of unittest discovery):
    python -m pip install playwright==1.57.0
    python -m playwright install chromium
    python tests/browser_smoke.py

Set CHROMIUM_EXECUTABLE to use an existing browser instead of Playwright's.
Reports go in test-output/. No real upload, ASR or API networking is tested here.
"""
import json
import os
import shutil
import re
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

project=Path(__file__).resolve().parents[1]
output=project/'test-output'
output.mkdir(exist_ok=True)
html=(project/'app/static/index.html').read_text()
html=re.sub(r'<script src="[^"]+" defer></script>', '', html)
script=(project/'app/static/app.js').read_text()
job_id='c'*32
results=[]
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=os.getenv('CHROMIUM_EXECUTABLE') or shutil.which('chromium'),headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
    def setup(scenario):
        ctx=browser.new_context(viewport={'width':1200,'height':1000})
        page=ctx.new_page()
        errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.set_content(html)
        page.evaluate('''(scenario) => {
          window.testScenario=scenario;
          window.getCalls=0;
          window.fetch=async (url, options={}) => {
            const id='cccccccccccccccccccccccccccccccc';
            const headers={'Content-Type':'application/json','Retry-After':'1'};
            if(url.endsWith('/exports')) return new Response(JSON.stringify({exports:[],has_more:false}),{status:200,headers});
            if(url==='/jobs') {window.lastUploadOptions=Object.fromEntries(Array.from(options.body.entries()).filter(([key])=>key!=='file'));return new Response(JSON.stringify({id,status:'queued',clips:[]}),{status:202,headers});}
            if(url.startsWith('/projects')) return new Response(JSON.stringify({projects:[],total:0,has_more:false,unreadable:0}),{status:200,headers});
            if(url.includes('/drafts?')) return new Response(JSON.stringify({drafts:[],total:0,has_more:false,unreadable:0}),{status:200,headers});
            if(url==='/templates') return new Response(JSON.stringify({templates:[],unreadable:0}),{status:200,headers});
            if(url.endsWith('/deliveries')) return new Response(JSON.stringify({deliveries:[],has_more:false,unreadable:0}),{status:200,headers});
            if(url==='/ai/config') return new Response(JSON.stringify({configured:false,provider:'disabled',reason:'IA desactivada',daily_used_utc:0}),{status:200,headers});
            if(url.endsWith('/selections/context')) return new Response(JSON.stringify({available:false,duration:22,note:'Sin transcripción en fixture'}),{status:200,headers});
            if(url.includes('/selections?')) return new Response(JSON.stringify({analyses:[],total:0,has_more:false,unreadable:0}),{status:200,headers});
            window.getCalls++;
            if(window.testScenario==='no_audio') return new Response(JSON.stringify({id,status:'failed',error_code:'NO_AUDIO_STREAM',error:'El MP4 no contiene una pista de audio reconocida. Sube un video con voz.',media:{duration_seconds:5,video_streams:1,audio_streams:0},clips:[]}),{status:200,headers});
            if(window.testScenario==='validating' && window.getCalls===1) return new Response(JSON.stringify({id,status:'validating',clips:[]}),{status:200,headers});
            if(window.testScenario==='validating') return new Response(JSON.stringify({id,status:'completed',clips:[],media:{duration_seconds:22,video_streams:1,audio_streams:1}}),{status:200,headers});
            if(window.testScenario==='missing') return new Response(JSON.stringify({detail:'Job no encontrado'}),{status:404,headers});
            if(window.testScenario==='unavailable' || window.getCalls<=2) return new Response(JSON.stringify({detail:'job.json unavailable'}),{status:503,headers});
            return new Response(JSON.stringify({id,status:'completed',clips:[{file:'clip_01.mp4',start:0,end:22}]}),{status:200,headers});
          };
        }''',scenario)
        page.add_script_tag(content=script)
        return ctx,page,errors
    def upload(page):
        page.locator('#file').set_input_files({'name':'sample.mp4','mimeType':'video/mp4','buffer':b'mock upload'})
        page.locator('#upload-button').click()

    ctx,page,errors=setup('ready')
    expect(page.locator('h1')).to_have_text('ClipForge AI')
    expect(page.locator('#status')).to_contain_text('Listo')
    assert not errors,errors
    results.append('PASS: offline HTML and actual app.js execute in Chromium without unhandled page errors.')
    ctx.close()

    ctx,page,errors=setup('recover')
    upload(page)
    expect(page.locator('#status')).to_contain_text('Procesamiento completado.',timeout=12000)
    assert page.evaluate('window.getCalls')==3
    expect(page.locator('#clips a')).to_have_count(2)
    expect(page.locator('#upload-button')).to_be_enabled()
    assert page.locator('#clips a').first.get_attribute('href')==f'/jobs/{job_id}/clips/clip_01.mp4'
    assert not errors,errors
    page.screenshot(path=str(output/'ui.png'),full_page=True)
    results.append('PASS: simulated upload -> two HTTP 503 responses -> retry -> completed status and download link.')
    ctx.close()

    ctx,page,errors=setup('unavailable')
    upload(page)
    expect(page.locator('#status')).to_contain_text('No se pudo consultar el estado:',timeout=12000)
    assert page.evaluate('window.getCalls')==6
    expect(page.locator('#upload-button')).to_be_enabled()
    page.wait_for_timeout(1500)
    assert page.evaluate('window.getCalls')==6
    assert 'undefined' not in page.locator('#status').inner_text()
    assert not errors,errors
    results.append('PASS: persistent simulated 503 stops after initial request plus five retries; controls re-enabled; no undefined state.')
    ctx.close()

    ctx,page,errors=setup('missing')
    page.locator('#job-details summary').click()
    page.locator('#job-id').fill('d'*32)
    page.locator('#job-form button').click()
    expect(page.locator('#status')).to_contain_text('Job no encontrado',timeout=5000)
    expect(page.locator('#upload-button')).to_be_enabled()
    assert page.evaluate('window.getCalls')==1
    assert not errors,errors
    results.append('PASS: simulated 404 is displayed clearly; polling stops immediately.')
    ctx.close()
    ctx,page,errors=setup('no_audio')
    upload(page)
    expect(page.locator('#status')).to_contain_text('NO_AUDIO_STREAM')
    expect(page.locator('#status')).to_contain_text('no contiene una pista de audio')
    expect(page.locator('#media-info')).to_contain_text('Pistas de audio: 0')
    expect(page.locator('#media-info')).to_be_visible()
    expect(page.locator('#upload-button')).to_be_enabled()
    expect(page.locator('#clips a')).to_have_count(0)
    page.wait_for_timeout(2800)
    assert page.evaluate('window.getCalls')==1
    assert not errors,errors
    page.screenshot(path=str(output/'ui-no-audio.png'),full_page=True)
    results.append('PASS: simulated NO_AUDIO_STREAM displays actionable error, duration and 0 audio streams; no further polls or downloads.')
    ctx.close()

    ctx,page,errors=setup('validating')
    upload(page)
    expect(page.locator('#status')).to_contain_text('Validando que el MP4')
    expect(page.locator('#status')).to_contain_text('Procesamiento completado.',timeout=6000)
    expect(page.locator('#media-info')).to_contain_text('22.00 s')
    expect(page.locator('#upload-button')).to_be_enabled()
    assert page.evaluate('window.getCalls')==2
    assert not errors,errors
    results.append('PASS: simulated validating state is recognized; polling continues to completed with media metadata.')
    ctx.close()
    ctx,page,errors=setup('no_audio')
    expect(page.locator('#upload-subtitle-size')).to_have_value('52')
    expect(page.locator('#upload-subtitle-hex')).to_have_value('#FFFFFF')
    page.locator('#upload-subtitle-size-range').fill('96')
    page.locator('#upload-subtitle-hex').fill('#80deea')
    page.locator('#upload-burn').check()
    expect(page.locator('#upload-subtitle-size')).to_have_value('96')
    expect(page.locator('#upload-subtitle-color')).to_have_value('#80deea')
    expect(page.locator('#upload-style-sample')).to_have_css('font-size','48px')
    expect(page.locator('#upload-style-sample')).to_have_css('color','rgb(128, 222, 234)')
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    upload(page)
    expect(page.locator('#status')).to_contain_text('NO_AUDIO_STREAM')
    fields=page.evaluate('window.lastUploadOptions')
    assert fields['subtitle_font_size']=='96',fields
    assert fields['subtitle_color']=='#80DEEA',fields
    assert fields['burn_subtitles']=='true',fields
    assert not errors,errors
    results.append('PASS: custom initial subtitle size/color preview and mobile controls; FormData carries normalized style to the simulated upload API.')
    ctx.close()
    browser.close()
(output/'browser-smoke.log').write_text('\n'.join(results)+'\n')
print('\n'.join(results))
