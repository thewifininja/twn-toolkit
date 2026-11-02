// Executes the real shared guard against a fake DOM, not browser rendering.
module.exports = function checkRegistration(source) {
  const assert = (ok,message) => { if (!ok) throw new Error(message); };
  class Form {
    constructor(value='Initial') { this.dataset={}; this.method='post'; this.target=''; this.field={name:'draft',type:'text',tagName:'INPUT',value,matches:()=>true,hasAttribute:()=>false}; this.elements=[this.field]; }
  }
  let forms=[new Form(),new Form()];
  const calls={}; const window={addEventListener:(name,fn)=>{(calls[name]??=[]).push(fn);},confirm:()=>false};
  const document={querySelectorAll:()=>forms};
  const run=()=>new Function('document','window','HTMLFormElement',source)(document,window,Form);
  run(); const guard=window.TwnUnsavedForms;
  forms[0].field.value='Actual tool draft'; guard.capture(forms[1]);
  const note=new Form(''); forms.push(note); run();
  assert(window.TwnUnsavedForms===guard,'repeated loader replaced guard');
  assert(guard.hasChanges(forms[0]),'register erased prior dirty baseline');
  assert(guard.isPending(forms[1]),'register erased prior pending save');
  assert(!guard.hasChanges(note),'newly parsed note initially dirty');
  note.field.value='Quick note draft'; run();
  assert(guard.hasChanges(note),'repeated loader reset note draft');
  assert(guard.register(note)===false,'duplicate register accepted existing form');
  assert(Object.values(calls).every((listeners)=>listeners.length===1),'duplicate global navigation listeners');
  guard.reset(note);
  assert(guard.hasChanges(forms[0]) && guard.isPending(forms[1]),'note reset affected another editor');
  let blocked=false; calls.beforeunload[0]({preventDefault:()=>{blocked=true;}});
  assert(blocked,'underlying tool draft lost navigation protection');
  // A page with no original editor can initialize after quick-note is parsed.
  forms=[]; const emptyWindow={addEventListener:()=>{}};
  new Function('document','window','HTMLFormElement',source)(document,emptyWindow,Form);
  assert(!emptyWindow.TwnUnsavedForms,'empty pre-dialog load initialized unexpectedly');
  forms=[new Form('')]; new Function('document','window','HTMLFormElement',source)(document,emptyWindow,Form);
  assert(emptyWindow.TwnUnsavedForms && !emptyWindow.TwnUnsavedForms.hasChanges(forms[0]),'late-only quick-note registration failed');
  return ['repeat load preserves dirty/pending baselines','late note registers once','note reset preserves tool draft','navigation still guarded','late-only page initializes'];
};
