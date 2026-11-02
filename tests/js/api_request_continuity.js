// Executes the shipped client with a synthetic DOM/fetch; no browser rendering or HTTP.
module.exports = async function checkApiClient(source) {
  const assert = (ok, message) => { if (!ok) throw Error(message); };
  // Minimal URL interface for these fixed synthetic origins; browser URL parsing is not simulated broadly.
  class ModelURL {
    constructor(value, base='http://fixture.test/') {
      const full=/^https?:\/\//.test(value)?value:base.match(/^https?:\/\/[^/]+/)[0]+value;
      const parts=full.match(/^(https?:\/\/[^/]+)([^?#]*)(\?[^#]*)?/);
      if(!parts)throw Error('invalid fixture URL');this.origin=parts[1];this.pathname=parts[2]||'/';this.search=parts[3]||'';
      this.searchParams={get:name=>{const pairs=this.search.slice(1).split('&').map(x=>x.split('='));return pairs.find(x=>x[0]===name)?.[1]??null;},set:(name,value)=>{this.search='?'+name+'='+value;}};
    }
    get href(){return this.origin+this.pathname+this.search;}
  }
  const token = 'a'.repeat(64), next = 'b'.repeat(64);
  const tick = async () => { for (let i=0;i<10;i++) await Promise.resolve(); };
  class Element {
    constructor(tag='div') { this.tagName=tag.toUpperCase();this.children=[];this.events={};this.dataset={};this.hidden=false;this.disabled=false;this.value='';this.checked=false; }
    set textContent(value) { this.text=String(value??'');this.children=[]; }
    get textContent() { return (this.text||'')+this.children.map(x=>x.textContent).join(''); }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children=nodes; }
    addEventListener(type, handler) { (this.events[type]??=[]).push(handler); }
    async fire(type, event={}) { event.target??=this;event.preventDefault??=()=>{};for(const handler of this.events[type]||[])await handler(event); }
    querySelector(selector) { return this.lookup?.[selector]||null; }
  }
  function setup() {
    const form=new Element('form'), workspace=new Element(), anchor=new Element(), status=new Element(), submit=new Element('button'), refresh=new Element('button'), view=new Element('button'), row=new Element('label');
    form.action='http://fixture.test/tools/api-request';form.dataset.admissionUrl='http://fixture.test/tools/api-request/admission';
    form.elements={};for(const [name,value] of Object.entries({admission_token:token,method:'GET',url:'https://old.test/path?private',headers:'Authorization: Private',body:'Old body',timeout:'10',verify_tls:'on',write_consent:'yes'})) { const field=new Element('input');field.name=name;field.value=value;field.checked=['verify_tls','write_consent'].includes(name);form.elements[name]=field; }
    form.lookup={'[data-api-status]':status,'button[type=submit]':submit,'[data-api-consent]':row,'[data-api-new-admission]':refresh,'[data-api-view-result]':view};
    workspace.lookup={'[data-tool-results-anchor]':anchor};form.closest=()=>workspace;form.reportValidity=()=>true;
    const requests=[], states=[], histories=[], guard=[];let deadline;
    const window={location:{href:'http://fixture.test/tools/api-request'},history:{replaceState:(_,__,url)=>histories.push(url)},TwnToolWorkspace:{forElement:()=>({setState:(...args)=>states.push(args)})},TwnUnsavedForms:{capture:()=>{guard.push('capture');return 'snapshot';},acknowledge:()=>guard.push('ack'),failed:()=>guard.push('failed')}};
    class Data { constructor(f){this.values=new Map(Object.entries(f.elements).filter(([name,field])=>!['verify_tls','write_consent'].includes(name)||field.checked).map(([name,field])=>[name,field.value]));}get(name){return this.values.get(name)??null;} }
    const fetch=(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject}));
    class Abort { constructor(){this.signal={};}abort(){requests.at(-1).reject(Error('timeout'));} }
    new Function('document','window','fetch','FormData','URL','AbortController','setTimeout','clearTimeout',source)({querySelector:()=>form,createElement:tag=>new Element(tag)},window,fetch,Data,ModelURL,Abort,fn=>{deadline=fn;return 1;},()=>{});
    const reply=(extra={},statusCode=200,type='application/json')=>({status:statusCode,headers:{get:()=>type},json:async()=>({admission_token:token,next_token:next,dispatched:true,receipt_url:'/tools/api-request?receipt='+token,result:{status:200,reason:'<script>hostile</script>',elapsed_ms:2,bytes:3,truncated:false,redirect:'',resolved_addresses:['192.0.2.44'],response_headers:{'<b>header</b>':'<img onerror=bad>'},body:'<script>body</script>'},...extra})});
    return {form,workspace,anchor,status,submit,refresh,view,row,requests,states,histories,guard,reply,deadline:()=>deadline()};
  }
  const results=[];const check=async(name,fn)=>{await fn();results.push(name);};
  await check('one pending send, GET receipt history before acknowledgement, transient escaped result',async()=>{
    const x=setup(),pending=x.form.fire('submit');await tick();await x.form.fire('submit');assert(x.requests.length===1,'double send admitted');assert(x.histories[0].includes('receipt='+token),'pending receipt missing');assert(x.submit.disabled,'pending send enabled');x.requests[0].resolve(x.reply());await pending;assert(x.states.length===1,'unchanged composer did not show result');assert(x.anchor.textContent.includes('<script>body</script>'),'response text lost');assert(x.anchor.textContent.includes('192.0.2.44'),'resolved addresses lost');assert(!x.anchor.children.some(n=>n.tagName==='SCRIPT'),'response injected markup');assert(x.form.dataset.unsavedInitial==='true','transient composer lost leave guard');assert(x.form.elements.body.value==='Old body','response replaced composer');assert(!x.form.elements.write_consent.checked,'consent retained');
  });
  await check('newer pending edits preserve active layout and expose previous result identity',async()=>{
    const x=setup(),pending=x.form.fire('submit');await tick();x.form.elements.url.value='https://new.test/unsent';x.form.elements.body.value='New unsent body';x.requests[0].resolve(x.reply());await pending;assert(x.states.length===0,'newer composer hidden/focus stolen');assert(x.form.elements.body.value==='New unsent body','new draft overwritten');assert(x.anchor.textContent.includes('GET · https://old.test'),'result lost submitted identity');assert(x.status.textContent.includes('current edits are unsent'),'unsent context missing');assert(!x.view.hidden,'previous result action absent');await x.view.fire('click');assert(x.states.length===1,'explicit View result failed');
  });
  await check('uncertain HTML, wrong receipt, foreign receipt and network timeout never replay',async()=>{
    for(const mode of ['html','wrong-token','foreign-url','timeout']) {
      const x=setup(),pending=x.form.fire('submit');await tick();if(mode==='timeout')x.deadline();else x.requests[0].resolve(mode==='html'?x.reply({},500,'text/html'):mode==='wrong-token'?x.reply({admission_token:'c'.repeat(64)}):x.reply({receipt_url:'http://foreign.test/tools/api-request?receipt='+token}));await pending;assert(x.requests.length===1,'unknown response replayed');assert(x.form.elements.body.value==='Old body','unknown response lost draft');assert(x.submit.disabled&&!x.refresh.hidden,'unknown send not fenced');assert(x.guard.includes('failed')&&!x.guard.includes('ack'),'unknown response acknowledged');assert(x.states.length===0,'unknown response stole context');
    }
  });
  await check('read-only preparation does not send and requires fresh write consent',async()=>{
    const x=setup();let pending=x.form.fire('submit');await tick();x.requests[0].reject(Error('offline'));await pending;pending=x.refresh.fire('click');await tick();assert(!x.requests[1].options.method,'preparation used POST');x.requests[1].resolve({ok:true,headers:{get:()=> 'application/json'},json:async()=>({token:next})});await pending;assert(x.requests.length===2,'preparation auto sent');assert(x.form.elements.admission_token.value===next&&!x.submit.disabled,'new explicit send unavailable');assert(!x.form.elements.write_consent.checked,'fresh consent not required');
  });
  await check('local validation, access loss and capacity remain actionable without draft loss',async()=>{
    let x=setup();x.form.reportValidity=()=>false;await x.form.fire('submit');assert(x.requests.length===0,'invalid composer dispatched');
    x=setup();let pending=x.form.fire('submit');await tick();x.requests[0].resolve(x.reply({},403,'text/html'));await pending;assert(x.status.textContent.includes('check access'),'HTML403 lacks access guidance');
    x=setup();pending=x.form.fire('submit');await tick();x.requests[0].resolve(x.reply({next_token:''}));await pending;assert(x.anchor.textContent.includes('200'),'capacity discarded confirmed result');assert(x.submit.disabled&&!x.refresh.hidden,'capacity failed open');assert(x.status.textContent.includes('busy'),'capacity unclear');
  });
  await check('method and composer changes clear write consent without clearing fields',async()=>{
    const x=setup();x.form.elements.method.value='POST';await x.form.elements.method.fire('change');assert(x.form.elements.write_consent.required&&!x.row.hidden,'write consent absent');x.form.elements.write_consent.checked=true;await x.form.fire('input',{target:x.form.elements.body});assert(!x.form.elements.write_consent.checked,'changed write reused consent');assert(x.form.elements.body.value==='Old body','consent reset erased draft');
  });
  await check('malformed same-token result is never acknowledged or rendered as confirmed', async()=>{
    for(const invalid of [{status:9999},{elapsed_ms:undefined},{elapsed_ms:Infinity},{bytes:1048577},{truncated:'false'},{response_headers:[]},{resolved_addresses:['192.0.2.1',2]},{reason:null}]) {
      const x=setup(),pending=x.form.fire('submit');await tick();const response=x.reply();const payload=await response.json();Object.assign(payload.result,invalid);response.json=async()=>payload;x.requests[0].resolve(response);await pending;assert(!x.guard.includes('ack'),'malformed result acknowledged');assert(x.states.length===0&&!x.refresh.hidden&&x.submit.disabled,'malformed result failed open');assert(x.form.elements.body.value==='Old body','malformed result lost draft');
    }
  });
  await check('preparation GET timeout and history failure release locks without POST replay',async()=>{
    let x=setup(),pending=x.form.fire('submit');await tick();x.requests[0].reject(Error('offline'));await pending;pending=x.refresh.fire('click');await tick();x.deadline();await pending;assert(!x.refresh.disabled,'timed-out preparation stayed locked');assert(x.requests.length===2,'GET timeout sent a POST');assert(x.form.elements.body.value==='Old body','GET timeout lost draft');
    x=setup();x.form.action='not-a-url'; // ModelURL accepts path; force replaceState failure instead.
    // History APIs can fail in restricted contexts; source must settle the pending lock.
    x.histories.push = ()=>{throw Error('history denied');};await x.form.fire('submit');assert(x.requests.length===0,'history failure dispatched');assert(!x.refresh.disabled&&!x.refresh.hidden,'history failure left pending lock');
  });
  await check('confirmed HTTP error retains existing visual error state and diagnostics',async()=>{
    const x=setup(),pending=x.form.fire('submit');await tick();const response=x.reply();const payload=await response.json();payload.result.status=500;response.json=async()=>payload;x.requests[0].resolve(response);await pending;const all=[];const walk=n=>{all.push(n);n.children.forEach(walk);};walk(x.anchor);assert(all.some(n=>n.className==='pill error'&&n.textContent==='HTTP 500'),'HTTP error pill lost');assert(all.some(n=>n.tagName==='TABLE'),'bounded response-header table lost');assert(x.guard.includes('ack'),'received HTTP500 misclassified uncertain');
  });
  return results;
};
