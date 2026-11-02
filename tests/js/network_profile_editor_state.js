// Executes shipped editor/receipt/guard against an in-memory DOM; no network or browser rendering.
module.exports = async function checkEditor(guardSource, receiptSource, editorSource) {
  const assert = (ok, message) => { if (!ok) throw new Error(message); };
  class Element {
    constructor(tag = 'div') { this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.events={};this.value='';this.name='';this.type='';this.checked=false;this.disabled=false;this.hidden=false;this._text=''; }
    append(...nodes) { for (const node of nodes) { node.parentElement=this;this.children.push(node); } }
    set textContent(value) { this._text=String(value);this.children=[]; } get textContent() { return this._text+this.children.map(x=>x.textContent).join(''); }
    get classList() { const update=(add,names)=>{const values=new Set((this.className||'').split(' ').filter(Boolean));for(const name of names)add?values.add(name):values.delete(name);this.className=[...values].join(' ');};return {add:(...names)=>update(true,names),remove:(...names)=>update(false,names)}; }
    get options() { return this.children.filter(x=>x.tagName==='OPTION'); }
    get form() { return this.closest('form'); }
    get elements() { const fields=this.querySelectorAll('input,select,textarea,button');for(const f of fields) if(f.name) fields[f.name]=f;return fields; }
    matches(selector) { return selector.split(',').some(part=>{
      part=part.trim();if(part===':scope > summary')return this.tagName==='SUMMARY';
      const tag=part.match(/^[\w-]+/);if(tag&&this.tagName!==tag[0].toUpperCase())return false;
      const id=part.match(/#([\w-]+)/);if(id&&this.id!==id[1])return false;
      for(const m of part.matchAll(/\.([\w-]+)/g)) if(!(this.className||'').split(' ').includes(m[1]))return false;
      for(const m of part.matchAll(/\[([^=\]]+)(?:=["']?([^\]"']+)["']?)?\]/g)){
        const key=m[1],value=key.startsWith('data-')?this.dataset[key.slice(5).replace(/-([a-z])/g,(_,x)=>x.toUpperCase())]:this[key];
        if(value===undefined||(m[2]!==undefined&&String(value)!==m[2]))return false;
      }return true;
    }); }
    querySelectorAll(selector) { const all=[];const visit=e=>{for(const child of e.children){all.push(child);visit(child);}};visit(this);
      const last=selector.includes(' ')?selector.slice(selector.lastIndexOf(' ')+1):selector;
      if(selector===':scope > summary')return this.children.filter(x=>x.tagName==='SUMMARY');
      const prefix=selector.includes(' ')?selector.slice(0,selector.lastIndexOf(' ')):'';
      return all.filter(x=>x.matches(last)&&(!prefix||x.parentElement?.closest(prefix))); }
    querySelector(selector) { return this.querySelectorAll(selector)[0]||null; }
    closest(selector) { for(let e=this;e;e=e.parentElement)if(e.matches(selector))return e;return null; }
    hasAttribute(name) { return name.startsWith('data-') ? Object.hasOwn(this.dataset,name.slice(5).replace(/-([a-z])/g,(_,x)=>x.toUpperCase())) : Object.hasOwn(this,name); }
    contains(node) { for(let n=node;n;n=n.parentElement)if(n===this)return true;return false; }
    addEventListener(name,fn) { (this.events[name]??=[]).push(fn); }
    async fire(name,event={}) { event.target??=this;event.defaultPrevented??=false;event.preventDefault??=()=>{event.defaultPrevented=true;};for(const fn of this.events[name]||[])await fn(event); }
    dispatchEvent(event) { for(const fn of this.events[event.type]||[])fn(event); } reportValidity(){return true;} focus(){} scrollIntoView(){} setAttribute(name,value){this[name]=value;}
  }
  class Form extends Element { constructor(){super('form');this.method='post';this.target='';} }
  class Data { constructor(form){this.values=new Map();if(form)for(const f of form.elements)if(f.name&&(!['checkbox','radio'].includes(f.type)||f.checked))this.values.set(f.name,f.value);}get(k){return this.values.get(k)??null;}has(k){return this.values.has(k);}set(k,v){this.values.set(k,v);} }
  class Option extends Element { constructor(text,value){super('option');this.textContent=text;this.value=value;} }
  const field=(name,type,value='')=>Object.assign(new Element('input'),{name,type,value});
  const tick=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};
  const reply=(payload,status=200)=>({ok:status<400,status,headers:{get:()=> 'application/json'},json:async()=>payload});
  const catalogue=(credentials=[])=>({credentials,hosts:[],oids:[]});
  function setup() {
    const root=new Element();root.dataset={networkProfiles:'snmp',profileChoicesUrl:'/choices'};
    const status=Object.assign(new Element('p'),{dataset:{profileChoiceStatus:''}}),refresh=Object.assign(new Element('button'),{dataset:{profileChoicesRefresh:''}});root.append(status,refresh);
    const forms=[];
    for(const existing of [false,true]){
      const card=new Element('details'),summary=new Element('summary'),form=new Form();form.dataset={kind:'credentials',unsavedForm:'',saveUrl:'/save',deleteUrl:'/delete'};form.className='snmp-profile-form';
      card.className=existing?'access-profile-card nested-profile-card saved-profile-record':'profile-create-details card-action-details saved-profile-create';
      const original=field('original_name','hidden',existing?'Existing':'');original.dataset.unsavedIgnore='';
      form.append(original,field('name','text',existing?'Existing':''),field('version','text','v2c'),field('community','password',''),Object.assign(new Element('button'),{type:'submit'}));
      if(existing){const dup=Object.assign(new Element('button'),{type:'button',dataset:{profileDuplicate:'/duplicate'}}),del=Object.assign(new Element('button'),{type:'button',className:'snmp-delete-profile'});form.append(dup,del);}
      card.append(summary,form);root.append(card);forms.push(form);
    }
    const run=new Form();run.dataset.unsavedForm='';run.id='snmp-test-form';const group=Object.assign(new Element('fieldset'),{dataset:{profileChoiceGroup:'hosts'}});run.append(group,field('draft','text','initial'));root.append(run);
    const select=Object.assign(new Element('select'),{name:'credential_name',dataset:{profileChoiceSelect:'credentials'}});select.append(new Option('Existing','Existing'));select.value='Existing';run.append(select);
    // Scope selectors accurately; the generic DOM deliberately has no style/layout emulation.
    const queryAll=root.querySelectorAll.bind(root);root.querySelectorAll=selector=>{
      const match=selector.match(/^\[data-profile-choice-(select|group)="([^"]+)"\](.*)$/);
      if(match){const nodes=queryAll(`[data-profile-choice-${match[1]}="${match[2]}"]`);return match[3].trim()?nodes.flatMap(n=>n.querySelectorAll(match[3].trim())):nodes;}
      return queryAll(selector);
    };
    const document={querySelector:s=>s==='[data-network-profiles]'?root:null,querySelectorAll:()=>[...forms,run],createElement:t=>new Element(t),getElementById:()=>({click(){},focus(){}})};
    const calls=[],queue=[];const fetch=(url,options={})=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});calls.push({url,options,resolve,reject});return promise;};
    const window={addEventListener(){},confirm:()=>true,TwnMso:{prepare:()=>true,saved(){},newProfile(){},deleteMessage:()=> 'Delete?' }};
    new Function('window','document','HTMLFormElement',guardSource)(window,document,Form);
    new Function('window',receiptSource)(window);
    new Function('window','document','HTMLFormElement','FormData','Option','fetch','AbortSignal','Event',editorSource)(window,document,Form,Data,Option,fetch,{timeout:()=>({})},class{constructor(type){this.type=type;}});
    return {root,status,refresh,forms,run,group,select,calls,window};
  }
  const results=[];async function check(name,fn){await fn();results.push(name);}
  const receipt=name=>({profile:{name,version:'v2c',has_community:true}});
  const button=(form,label)=>form.querySelectorAll('button').find(b=>b.textContent===label);
  await check('stale GET success/error cannot replace confirmed save choices or status',async()=>{
    for(const failure of [false,true]){
      const x=setup(),f=x.forms[0];f.elements.name.value='New';f.elements.community.value='submitted';const pending=f.fire('submit');await tick();x.calls[1].resolve(reply(receipt('New')));await pending;
      if(failure)x.calls[0].reject(new Error('stale GET failed'));else x.calls[0].resolve(reply(catalogue([])));await tick();
      assert(x.select.options.some(o=>o.value==='New'),'stale refresh removed saved choice');assert(x.select.value==='Existing','save changed selection');assert(!/failed|Refreshing/.test(x.status.textContent),'stale refresh replaced confirmed status');
    }
  });
  await check('confirmed save clears unchanged secret; newer pending secret and name remain dirty',async()=>{
    for(const newer of [false,true]){
      const x=setup();x.calls[0].resolve(reply(catalogue([{name:'Existing',version:'v2c'}])));await tick();const f=x.forms[0];f.elements.name.value='New';f.elements.community.value='submitted';const pending=f.fire('submit');await tick();if(newer){f.elements.community.value='newer-secret';f.elements.name.value='newer-name';}x.calls[1].resolve(reply(receipt('New')));await pending;
      assert(f.closest('details').matches('.saved-profile-record')&&!f.closest('details').matches('.card-action-details'),'saved card retained absolute-position create layout');
      assert(f.elements.community.value===(newer?'newer-secret':''),'secret clear erased newer text');assert(x.window.TwnUnsavedForms.hasChanges(f)===newer,'sanitized ACK dirty state wrong');
    }
  });
  await check('save fences same-editor duplicate/delete/new but leaves another editor usable',async()=>{
    const x=setup(),f=x.forms[1];x.calls[0].resolve(reply(catalogue([{name:'Existing',version:'v2c'}])));await tick();f.elements.community.value='secret';const pending=f.fire('submit');await tick();const before=x.calls.length;
    await f.fire('submit');await x.root.fire('click',{target:f.querySelector('[data-profile-duplicate]')});await button(f,'Create another credential').fire('click');assert(x.calls.length===before,'same editor admitted concurrent operation');assert(f.elements.original_name.value==='Existing','pending New reset editor');assert(!x.forms[0].querySelector('[type=submit]').disabled,'other editor locked');x.calls[1].resolve(reply(receipt('Existing')));await pending;
  });
  await check('MSO cancel performs no POST and creates no pending save',async()=>{
    const x=setup(),f=x.forms[0];x.window.TwnMso.prepare=()=>false;f.elements.name.value='draft';await f.fire('submit');assert(x.calls.length===1,'cancel sent POST');assert(!x.window.TwnUnsavedForms.isPending(f),'cancel left pending');assert(x.window.TwnUnsavedForms.hasChanges(f),'cancel erased draft');
  });
  await check('duplicate inserts canonical unselected choice and keeps source draft',async()=>{
    const x=setup(),f=x.forms[1];x.calls[0].resolve(reply(catalogue([{name:'Existing',version:'v2c'}])));await tick();f.elements.community.value='unsaved-secret';const p=x.root.fire('click',{target:f.querySelector('[data-profile-duplicate]')});await tick();await f.fire('submit');await button(f,'Create another credential').fire('click');await x.root.fire('click',{target:f.querySelector('.snmp-delete-profile')});assert(f.elements.original_name.value==='Existing','duplicate allowed New reset');assert(x.calls.length===2,'duplicate did not lock save/delete');x.calls[1].resolve(reply({source_name:'Existing',profile:{name:'Existing copy 2',version:'v2c'}}));await p;assert(x.select.options.some(o=>o.value==='Existing copy 2'),'copy missing');assert(x.select.value==='Existing','copy auto-selected');assert(f.elements.community.value==='unsaved-secret','copy erased source draft');
  });
  await check('delete locks operations, retains editor draft, requires New before another save',async()=>{
    const x=setup(),f=x.forms[1];x.calls[0].resolve(reply(catalogue([{name:'Existing',version:'v2c'}])));await tick();f.elements.community.value='draft';const p=x.root.fire('click',{target:f.querySelector('.snmp-delete-profile')});await tick();await f.fire('submit');await button(f,'Create another credential').fire('click');assert(f.elements.original_name.value==='Existing','delete allowed New reset');assert(x.calls.length===2,'delete allowed save');x.calls[1].resolve(reply({deleted:'Existing'}));await tick();x.calls[2].resolve(reply(catalogue([])));await p;assert(f.querySelector('[type=submit]').disabled,'deleted editor still save-enabled');assert(x.select.options[0].dataset.profileMissing==='true','deleted choice not unavailable');assert(f.elements.community.value==='draft','delete erased draft');await f.fire('submit');assert(x.calls.length===3,'deleted editor submitted');await button(f,'Create another credential').fire('click');assert(f.elements.original_name.value===''&&f.elements.community.value==='','New retained identity/secret');assert(!f.querySelector('[type=submit]').disabled,'New failed to re-enable editor');
  });
  await check('neutral new checkbox preserves clean baseline and existing dirty run',async()=>{
    for(const dirty of [false,true]){const x=setup();if(dirty)x.run.elements.draft.value='unsent';x.calls[0].resolve(reply({credentials:[{name:'Existing',version:'v2c'}],hosts:[{name:'host A',host:'192.0.2.1',port:161,credential_name:'Existing'},{name:'host B',host:'192.0.2.2',port:161,credential_name:'Existing'}],oids:[]}));await tick();assert(x.group.querySelectorAll('input').length===2,'checkbox projection failed');assert(x.window.TwnUnsavedForms.hasChanges(x.run)===dirty,'structural insertion reset/dirtied run');}
  });
  await check('canceling dirty Create another preserves identity, newer secret and other run draft',async()=>{
    const x=setup(),f=x.forms[1];x.calls[0].resolve(reply(catalogue([{name:'Existing',version:'v2c'}])));await tick();
    f.elements.name.value='Newer unsaved name';f.elements.community.value='Newer unsaved secret';x.run.elements.draft.value='Other unsent run';
    let prompts=0,resets=0;x.window.confirm=()=>{prompts++;return false;};x.window.TwnMso.newProfile=()=>{resets++;};
    const before=x.calls.length;await button(f,'Create another credential').fire('click');
    assert(prompts===1,'dirty New did not request confirmation');assert(resets===0,'cancel reset/adopted profile identity');
    assert(f.elements.original_name.value==='Existing'&&f.elements.name.value==='Newer unsaved name'&&f.elements.community.value==='Newer unsaved secret','cancel discarded own draft or saved identity');
    assert(x.run.elements.draft.value==='Other unsent run','cancel changed other run draft');assert(x.calls.length===before,'cancel sent a request');
    assert(x.window.TwnUnsavedForms.hasChanges(f)&&x.window.TwnUnsavedForms.hasChanges(x.run),'cancel cleaned a dirty baseline');
  });
  return results;
};
