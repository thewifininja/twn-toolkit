// Fake DOM/guard regression model, not browser/layout coverage. Executes shipped clients.
module.exports = async function checkPrerequisites(guardSource, clientSource) {
  const assert = (ok, message) => { if (!ok) throw new Error(message); };
  class Element {
    constructor(tag = 'input') { this.tagName = tag.toUpperCase(); this.type = 'text'; this.value = ''; this.name = ''; this.dataset = {}; this.children = []; this.events = {}; this.checked = false; }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; }
    addEventListener(name, handler) { this.events[name] = handler; }
    matches() { return ['INPUT','SELECT','TEXTAREA'].includes(this.tagName); }
    hasAttribute() { return false; }
  }
  const descendants = (root) => root.children.flatMap((child) => [child, ...descendants(child)]);
  class Form extends Element {
    constructor() {
      super('form'); this.dataset.builderChoicesUrl = '/automations/builder/choices';
      this.nameField = Object.assign(new Element(), {name:'name', value:'Saved name'});
      this.mode = Object.assign(new Element('select'), {name:'run_mode', value:'manual'});
      this.schedule = Object.assign(new Element('select'), {name:'schedule_definition_id'});
      this.hidden = Object.assign(new Element(), {name:'action_stages_json', value:JSON.stringify([{id:'stage',name:'Retained stage',action_definition_ids:['a']}])});
      this.list = new Element('div'); this.refresh = new Element('button'); this.save = new Element('button');
      this.status = new Element('p'); this.readiness = new Element('p'); this.emptyConditions = new Element('p'); this.emptySchedules = new Element('p');
    }
    get elements() { return [this.nameField,this.mode,this.schedule,this.hidden,...descendants(this.list).filter((item) => item.tagName === 'INPUT')]; }
    querySelectorAll() { return descendants(this.list).filter((item) => item.tagName === 'INPUT' && item.checked); }
    querySelector(selector) { return ({'[name=run_mode]':this.mode,'[name=schedule_definition_id]':this.schedule,'[data-action-stages-json]':this.hidden,'[data-save-automation-paused]':this.save,'[data-builder-readiness]':this.readiness,'[data-builder-choice-status]':this.status,'[data-builder-condition-choices]':this.list,'[data-builder-empty-conditions]':this.emptyConditions,'[data-builder-empty-schedules]':this.emptySchedules,'[data-refresh-builder-choices]':this.refresh})[selector]; }
    dispatchEvent() { /* Stage integration is separately exercised by actual browser. */ }
  }
  const forms = [new Form(),new Form(),new Form()];
  const originalStages = forms.map((form) => form.hidden.value);
  const initial = {conditions:[],schedules:[],actions:[{id:'a',name:'Action',type:'email.send'}]};
  const updated = {...initial,conditions:[{id:'new',name:'New condition',type:'ping.multi'}]};
  const document = {
    querySelectorAll: (selector) => selector.includes('form[') ? forms : [],
    querySelector: () => ({textContent:JSON.stringify(initial)}),
    createElement: (tag) => new Element(tag),
  };
  const window = {addEventListener() {}};
  new Function('document','window','HTMLFormElement',guardSource)(document,window,Form);
  forms[1].nameField.value = 'Actual unfinished draft';
  window.TwnUnsavedForms.capture(forms[2]);
  const fetch = async () => ({ok:true,headers:{get:()=> 'application/json'},json:async()=>updated});
  function Option(label,value) { return Object.assign(new Element('option'),{textContent:label,value}); }
  function CustomEvent(type, options) { this.type=type; this.detail=options.detail; }
  new Function('document','window','fetch','Option','CustomEvent','AbortSignal',clientSource)(document,window,fetch,Option,CustomEvent,{timeout:()=>null});
  await forms[0].refresh.events.click({currentTarget:forms[0].refresh});
  assert(!window.TwnUnsavedForms.hasChanges(forms[0]), 'catalogue-only refresh falsely dirtied clean editor');
  assert(window.TwnUnsavedForms.hasChanges(forms[1]), 'refresh erased actual dirty editor baseline');
  assert(forms[1].nameField.value === 'Actual unfinished draft', 'refresh changed draft name');
  assert(window.TwnUnsavedForms.isPending(forms[2]), 'refresh settled another pending save');
  assert(window.TwnUnsavedForms.hasChanges(forms[2]), 'refresh hid pending save');
  assert(forms.every((form,index)=>form.hidden.value===originalStages[index]), 'refresh changed ordered stages');
  assert(forms.every((form)=>descendants(form.list).filter((item)=>item.tagName==='INPUT').length===1), 'refresh did not add new catalogue reference');
  return ['clean catalogue refresh remains clean','dirty draft stays dirty','pending save remains pending','stage draft unchanged'];
};
