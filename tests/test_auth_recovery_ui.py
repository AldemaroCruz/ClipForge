"""Synthetic DOM/promise regressions; not real browser or PostgreSQL evidence."""
import importlib.metadata
from pathlib import Path
import subprocess
import unittest


HARNESS = r'''
const fs=require('node:fs'),vm=require('node:vm');
const mode=process.argv[1],source=fs.readFileSync(process.argv[2],'utf8');
const check=(ok)=>{if(!ok)throw new Error('Recovery UI contract failed');};
class Element {
  constructor(id){this.id=id;this.value='';this.textContent='';this.hidden=true;this.disabled=false;this.options=[];this.listeners={};this.type='password';}
  addEventListener(name,callback){this.listeners[name]=callback;}
  querySelector(){return this.button||(this.button=new Element('button'));}
  replaceChildren(){this.options=[];}
  append(child){this.options.push(child);}
  get selectedOptions(){return this.options.filter(option=>option.value===this.value);}
  reset(){}
}
const elements=new Map(),get=id=>{if(id==='login-form')return null;if(!elements.has(id))elements.set(id,new Element(id));return elements.get(id);};
const document={hidden:false,listeners:{},getElementById:get,createElement:()=>new Element('new'),addEventListener(name,fn){this.listeners[name]=fn;}};
let complete,requested='',auditFailure=false;
const alice={id:'a'.repeat(32),username:'synthetic_alice',is_active:true,is_admin:false};
const bob={id:'b'.repeat(32),username:'synthetic_bob',is_active:true,is_admin:false};
const auth={ready:Promise.resolve({id:'c'.repeat(32),is_admin:true,permissions:['users:manage']}),
  payload:data=>({method:'POST',body:data}),
  json:async(url)=>{
    if(url==='/auth/users')return {users:[alice,bob]};
    if(url.startsWith('/auth/admin/audit')){if(auditFailure)throw new Error('Audit temporarily unavailable');return {items:[],page:1,page_size:25,total:0};}
    if(url.includes('/recovery')){requested=url;return await new Promise(resolve=>{complete=resolve;});}
    throw new Error('Unexpected synthetic request');
  }};
const window={ClipForgeAuth:auth,listeners:{},addEventListener(name,fn){this.listeners[name]=fn;}};
vm.runInNewContext(source,{window,document,URLSearchParams,confirm:()=>true,location:{replace(){}}});
const flush=()=>new Promise(setImmediate);
(async()=>{
  await flush();await flush();
  const target=get('recovery-target');target.value=alice.id;
  get('recovery-admin-password').value='synthetic-fixture-only';
  const work=get('issue-recovery-form').listeners.submit({preventDefault(){},currentTarget:get('issue-recovery-form')});
  check(target.disabled&&typeof complete==='function');
  if(mode==='recipient')target.value=bob.id;
  if(mode==='hidden'){document.hidden=true;document.listeners.visibilitychange();}
  if(mode==='audit_failure')auditFailure=true;
  complete({recovery_code:'opaque-synthetic-value-not-an-authorization',expires_at:'2099-01-01T00:00:00Z'});
  await work;
  check(requested.includes(alice.id)&&!target.disabled&&get('recovery-admin-password').value==='');
  if(mode==='recipient'){
    check(get('recovery-recipient').textContent.includes(alice.username));
    check(!get('recovery-issued').hidden);
    target.listeners.change();check(get('issued-recovery-code').value==='');
  }else if(mode==='hidden'){
    check(get('issued-recovery-code').value===''&&get('recovery-issued').hidden);
  }else if(mode==='audit_failure'){
    check(get('issued-recovery-code').value!==''&&!get('recovery-issued').hidden);
    check(get('audit-status').textContent!=='');
  }else throw new Error('Unknown synthetic case');
})().catch(()=>{process.stderr.write('Recovery UI contract failed\n');process.exitCode=1;});
'''


class RecoveryUIContractTests(unittest.TestCase):
    def exercise(self, case):
        node=importlib.metadata.distribution('playwright').locate_file('playwright/driver/node')
        if not Path(node).is_file():
            self.fail('Pinned Playwright Node runtime is required')
        source=Path(__file__).resolve().parents[1]/'app/static/account.js'
        outcome=subprocess.run([str(node),'-e',HARNESS,case,str(source)],capture_output=True,timeout=20)
        self.assertTrue(outcome.returncode==0,'Synthetic recovery UI contract must pass')
        self.assertTrue(not outcome.stdout,'Synthetic UI checks must not publish fixture values')

    def test_pending_issue_is_bound_to_captured_recipient_and_change_clears(self):
        self.exercise('recipient')

    def test_response_after_visibility_cleanup_cannot_reveal_code(self):
        self.exercise('hidden')

    def test_audit_refresh_error_preserves_single_authorized_response(self):
        self.exercise('audit_failure')


if __name__=='__main__':
    unittest.main()
