"""Offline visual regression for positioning, margins, and outline in actual MP4 pixels."""
import json
import subprocess
import tempfile
from pathlib import Path

from .presentation import Presentation
from .media_binaries import resolve_media_binary
from .render import render_clip


def black_source(path: Path):
    subprocess.run([resolve_media_binary('ffmpeg'),'-nostdin','-v','error','-y','-f','lavfi','-i',
                    'color=c=black:size=320x180:rate=5','-f','lavfi','-i',
                    'sine=frequency=440:sample_rate=16000','-t','2',
                    '-c:v','libx264','-threads','1','-pix_fmt','yuv420p',
                    '-c:a','aac',str(path)],check=True,capture_output=True,timeout=30)


def pixels(path: Path) -> dict:
    raw=subprocess.run([resolve_media_binary('ffmpeg'),'-nostdin','-v','error','-ss','0.8','-i',str(path),
                        '-frames:v','1','-vf','scale=270:480,format=rgb24',
                        '-f','rawvideo','-'],check=True,capture_output=True,timeout=30).stdout
    if len(raw)!=270*480*3:
        raise AssertionError('Invalid decoded frame')
    ys=[];cyan=0
    for i in range(0,len(raw),3):
        r,g,b=raw[i:i+3]
        if r>160 and g>160 and b>160:
            ys.append((i//3)//270)
        if g>100 and b>100 and r<80:
            cyan+=1
    if not ys:
        raise AssertionError('No caption pixels in output')
    return {'white_pixels':len(ys),'text_y_min':min(ys),'text_y_max':max(ys),'cyan_outline_pixels':cyan}


def check_branding():
    report={'status':'ok','scope':'real_ffmpeg_decoded_pixels_on_black_fixture','checks':{},
            'transcription_tested':False,'errors':[]}
    with tempfile.TemporaryDirectory(prefix='clipforge-branding-') as d:
        root=Path(d);source=root/'source.mp4'
        try:
            black_source(source)
            for name,position,margin,outline in [('top','top',200,0),('center','center',200,0),
                ('bottom','bottom',200,0),('top_margin400','top',400,0),
                ('center_margin400','center',400,0),('border10','top',200,10)]:
                target=root/(name+'.mp4')
                render_clip(source,target,start=0,end=2,cues=[{'start':.1,'end':1.9,'text':'Estilo aprobado'}],
                            options=Presentation(burn_subtitles=True,subtitle_font_size=96,
                                subtitle_position=position,subtitle_margin_v=margin,
                                subtitle_outline=outline,subtitle_outline_color='#00FFFF',subtitle_shadow=0))
                report['checks'][name]=pixels(target)
            c=report['checks']
            if not c['top']['text_y_max']<140:
                raise AssertionError(c['top'])
            if not 180<c['center']['text_y_min']<280:
                raise AssertionError(c['center'])
            if not c['bottom']['text_y_min']>350:
                raise AssertionError(c['bottom'])
            if not abs(c['top_margin400']['text_y_min']-c['top']['text_y_min']-50)<=3:
                raise AssertionError
            if not abs(c['center_margin400']['text_y_min']-c['center']['text_y_min'])<=1:
                raise AssertionError
            if not c['border10']['cyan_outline_pixels']>200:
                raise AssertionError(c['border10'])
            if not c['top']['cyan_outline_pixels']<10:
                raise AssertionError(c['top'])
        except Exception as exc:
            report.update(status='failed');report['errors'].append(f'{type(exc).__name__}: {exc}')
    return report


def main():
    report=check_branding();print(json.dumps(report,ensure_ascii=False,indent=2))
    if report['status']=='ok':
        print('Branding check OK (real rendered positions/margin/outline; no Whisper).');return 0
    return 1


if __name__=='__main__':raise SystemExit(main())
