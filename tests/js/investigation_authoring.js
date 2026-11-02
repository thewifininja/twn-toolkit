// In-memory form/protocol model of shipped clients; no browser/network/storage.
module.exports = async function checkAuthoring(guardSource, clientSource) {
  const assert=(ok,message)=>{if(!ok)throw new Error(message);};
  class Element {
    constructor(type='text',value='') { this.type=type;this.value=value;this.name='note';this.tagName='INPUT';this.dataset={};this.hidden=true;this.disabled=false;this.textContent='';this.events={}; }
    matches(){return !['submit','button'].includes(this.type);} hasAttribute(){return false;}
    addEventListener(name,fn){this.events[name]=fn;}
  }
  class Form {
    constructor(caseId) {
      this.dataset={journalUrl:'/investigations/'+caseId};this.action=this.dataset.journalUrl+'/notes';this.method='post';this.target='';
      this.note=new Element('textarea','Retained <note>');this.note.tagName='TEXTAREA';
      this.save=new Element('submit');this.cancel=new Element('button');this.elements=[this.note,this.save,this.cancel];
      this.status=new Element();this.check=new Element();this.confirmation=new Element();this.preview=new Element();this.link=new Element();this.events={};
    }
    reportValidity(){return true;} addEventListener(name,fn){this.events[name]=fn;}
    querySelector(selector){return ({'[name=note]':this.note,'[type=submit]':this.save,'[data-note-status]':this.status,'[data-note-check]':this.check,'[data-note-confirmation]':this.confirmation,'[data-note-saved-preview]':this.preview,'[data-note-saved-link]':this.link})[selector];}
  }
  class ModelURL {
    constructor(value,base){const origin=(value.match(/^https?:\/\/[^/]+/)||base.match(/^https?:\/\/[^/]+/))[0];this.origin=origin;const relative=value.replace(/^https?:\/\/[^/]+/,'');const [pathAndQuery,hash]=relative.split('#');const [path,query]=pathAndQuery.split('?');this.pathname=path;this.search=query?'?'+query:'';this.hash=hash?'#'+hash:'';this.href=origin+this.pathname+this.search+this.hash;}
  }
  const id='evt_'+'a'.repeat(24);
  const ack=(href='/investigations/case-a?include_event='+id+'#event-'+id)=>({ok:true,headers:{get:()=> 'application/json'},json:async()=>({event:{id,summary:'Retained <note>',href}})});
  const results=[];
  async function test(name,check){await check();results.push(name);}
  function setup() {
    const note=new Form('case-a'),other=new Form('case-b'),tool=new Form('tool');tool.note.value='Original tool settings';
    const document={querySelectorAll:selector=>selector==='form[data-investigation-note]'?[note,other]:[tool,note,other],querySelector:()=>null};
    const window={location:{href:'https://fixture.test/tools/dns-response'},addEventListener:()=>{}};
    new Function('document','window','HTMLFormElement',guardSource)(document,window,Form);
    tool.note.value='Unfinished tool draft';
    const queue=[],calls=[];const fetch=async(url,options)=>{calls.push({url,options});return await queue.shift()();};
    new Function('document','window','fetch','FormData','AbortSignal','URL',clientSource)(document,window,fetch,function(form){this.get=()=>form.note.value;},{timeout:()=>null},ModelURL);
    const submit=()=>note.events.submit({defaultPrevented:false,preventDefault(){this.defaultPrevented=true;}});
    return {note,other,tool,guard:window.TwnUnsavedForms,queue,calls,submit};
  }
  await test('one pending save preserves tool and scopes confirmed note',async()=>{
    const f=setup();let resolve;f.queue.push(()=>new Promise(done=>{resolve=done;}));const pending=f.submit();await f.submit();
    assert(f.calls.length===1 && f.note.elements.every(x=>x.disabled),'pending repeat submitted or controls not locked');
    assert(f.guard.isPending(f.note),'pending note unguarded');resolve(ack());await pending;
    assert(f.note.note.value==='' && !f.note.confirmation.hidden && f.note.preview.textContent==='Retained <note>','confirmed note not visible/cleared canonically');
    assert(f.note.link.href.includes('#event-'+id),'saved note has no canonical link');
    assert(f.other.confirmation.hidden,'note confirmation leaked into other case form');
    assert(f.tool.note.value==='Unfinished tool draft' && f.guard.hasChanges(f.tool),'underlying tool draft lost');
    assert(!f.guard.hasChanges(f.note) && !f.guard.isPending(f.note),'confirmed note remains dirty/pending');
  });
  await test('multipart multiline and Python whitespace canonical acknowledgement',async()=>{
    const f=setup();f.note.note.value='\u0085\u001cLine one\nLine two\u3000';
    f.queue.push(()=>{const reply=ack();reply.json=async()=>({event:{id,summary:'Line one\r\nLine two',href:'/investigations/case-a?include_event='+id+'#event-'+id}});return reply;});
    await f.submit();assert(f.note.note.value==='' && !f.note.confirmation.hidden,'valid multipart line endings/whitespace rejected');
    const bom=setup();bom.note.note.value='\ufeffKeep BOM';bom.queue.push(()=>{const reply=ack();reply.json=async()=>({event:{id,summary:'\ufeffKeep BOM',href:'/investigations/case-a?include_event='+id+'#event-'+id}});return reply;});
    await bom.submit();assert(bom.note.note.value==='' && !bom.note.confirmation.hidden,'Python-preserved BOM rejected');
  });
  await test('valid multiline emoji note uses server character bound',async()=>{
    const f=setup();f.note.note.value='😀'.repeat(1000)+'x\n'.repeat(700);
    const summary=f.note.note.value.trim().replace(/\n/g,'\r\n');
    f.queue.push(()=>{const reply=ack();reply.json=async()=>({event:{id,summary,href:'/investigations/case-a?include_event='+id+'#event-'+id}});return reply;});
    await f.submit();assert(f.note.note.value==='' && !f.note.confirmation.hidden,'valid UTF16/CRLF expansion falsely unconfirmed');
    assert(Array.from(f.note.preview.textContent).length===281,'bounded Unicode preview split incorrectly');
  });
  await test('validation keeps note and does not replay',async()=>{
    const f=setup();f.queue.push(()=>({ok:false,status:400,headers:{get:()=> 'application/json'},json:async()=>({error:'Correct this note'})}));await f.submit();
    assert(f.calls.length===1 && f.note.note.value==='Retained <note>' && f.note.status.textContent.includes('Correct this note'),'validation lost draft/actionable error');
    assert(f.note.check.hidden && f.guard.hasChanges(f.note),'definite failure state wrong');
  });
  for(const status of [401,403,404]) await test(status+' access response retains draft with action',async()=>{
    const f=setup();f.queue.push(()=>({ok:false,status,headers:{get:()=> 'text/html'}}));await f.submit();
    assert(f.note.note.value==='Retained <note>' && !f.note.check.hidden && f.note.confirmation.hidden,'access error discarded draft or claimed saved');
    assert(f.note.status.textContent.includes(status===401?'Sign in again':'case owner') && f.note.status.textContent.includes('may already have completed'),'access recovery misleading');
    assert(f.calls.length===1 && f.guard.hasChanges(f.tool),'access failure replayed/lost tool draft');
  });
  for(const kind of ['html','network','timeout','wrong-case','cross-origin','json500-after-write','wrong-summary','missing-event-query','mismatched-event-query']) await test(kind+' response stays uncertain without replay',async()=>{
    const f=setup();f.queue.push(()=>{
      if(kind==='network'||kind==='timeout')throw new Error(kind);
      if(kind==='html')return {ok:true,headers:{get:()=> 'text/html'}};
      if(kind==='json500-after-write')return {ok:false,status:500,headers:{get:()=> 'application/json'},json:async()=>({error:'Internal failure after write'})};
      if(kind==='missing-event-query')return ack('/investigations/case-a#event-'+id);
      if(kind==='mismatched-event-query')return ack('/investigations/case-a?include_event=evt_'+ 'b'.repeat(24)+'#event-'+id);
      if(kind==='wrong-summary'){const reply=ack();reply.json=async()=>({event:{id,summary:'Different note',href:'/investigations/case-a?include_event='+id+'#event-'+id}});return reply;}
      return ack(kind==='wrong-case'?'/investigations/case-b?include_event='+id+'#event-'+id:'https://outside.test/investigations/case-a?include_event='+id+'#event-'+id);
    });await f.submit();
    assert(f.calls.length===1 && f.note.note.value==='Retained <note>','uncertain save lost draft or replayed');
    assert(!f.note.check.hidden && f.note.confirmation.hidden && f.note.status.textContent.includes('may already have completed'),'uncertainty hidden');
    assert(f.note.elements.every(x=>!x.disabled) && !f.guard.isPending(f.note) && f.guard.hasChanges(f.tool),'failure did not restore safe editing');
  });
  return results;
};
