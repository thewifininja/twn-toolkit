// Executes shipped clients against an in-memory DOM; not browser/layout coverage.
module.exports = function checkNetworkFailure(ntpSource,radiusSource,tabsSource) {
  const assert=(ok,message)=>{if(!ok)throw new Error(message);};
  class Element {
    constructor(value=''){this.value=value;this.events={};this.dataset={};this.attrs={};this.focused=false;}
    addEventListener(name,fn){this.events[name]=fn;} dispatchEvent(event){this.events[event.type]?.(event);}
    click(){this.events.click?.({currentTarget:this});} focus(){this.focused=true;}
    setAttribute(name,value){this.attrs[name]=value;}
  }
  const passed=[];
  const test=(name,fn)=>{fn();passed.push(name);};
  function ntp({get=true,hosts='',name='',selected='',saved='Remembered',blocked=false}={}) {
    const form=new Element();form.dataset.restoreRememberedProfile=get?'true':'false';
    const selector=new Element(selected);
    selector.options=[{value:'',dataset:{}},{value:'Remembered',dataset:{values:'remembered.test'}},{value:'Second',dataset:{values:'second.test'}}];
    Object.defineProperty(selector,'selectedOptions',{get:()=>selector.options.filter(option=>option.value===selector.value)});
    const targets=new Element(hosts),title=new Element(name),status=new Element(),save=new Element(),remove=new Element();
    const storage={getItem:()=>{if(blocked)throw new Error('Storage denied');return saved;},setItem:()=>{if(blocked)throw new Error('Storage denied');},removeItem:()=>{if(blocked)throw new Error('Storage denied');}};
    const document={getElementById:id=>({'ntp-form':form,'ntp-profile':selector,'ntp-hosts':targets,'ntp-profile-name':title,'ntp-status':status,'ntp-save-profile':save,'ntp-delete-profile':remove})[id]};
    let calls=0;const fetch=()=>{calls++;throw new Error('No automatic requests');};const window={location:{reload:()=>{throw new Error('No automatic reload');}}};
    new Function('document','window','sessionStorage','fetch','Event',ntpSource)(document,window,storage,fetch,function(type){this.type=type;});
    return {selector,targets,title,calls:()=>calls};
  }
  test('fresh empty GET restores remembered profile',()=>{const f=ntp();assert(f.targets.value==='remembered.test'&&f.title.value==='Remembered'&&f.selector.value==='Remembered','fresh restore missing');});
  test('edited POST keeps targets and draft profile identity',()=>{const f=ntp({get:false,hosts:'edited.test',name:'Draft rename',selected:'Remembered',saved:'Second'});assert(f.targets.value==='edited.test'&&f.title.value==='Draft rename'&&f.selector.value==='Remembered','POST overwritten');});
  test('empty POST and canceled blank naming stay empty',()=>{const f=ntp({get:false});assert(!f.targets.value&&!f.title.value&&!f.selector.value,'empty invalid request populated');});
  test('nonempty restored GET draft is not replaced',()=>{const f=ntp({hosts:'back-navigation.test'});assert(f.targets.value==='back-navigation.test'&&!f.selector.value,'GET draft overwritten');});
  test('draft profile name prevents automatic restore',()=>{const f=ntp({name:'Unfinished name'});assert(f.title.value==='Unfinished name'&&!f.targets.value,'name draft overwritten');});
  test('stale removed remembered selection stays unsaved',()=>{const f=ntp({saved:'Removed'});assert(!f.targets.value&&!f.selector.value,'stale option restored');});
  test('blocked storage keeps explicit profile selection working',()=>{const f=ntp({blocked:true});f.selector.value='Remembered';f.selector.dispatchEvent({type:'change'});assert(f.targets.value==='remembered.test'&&f.title.value==='Remembered','storage broke explicit selection');assert(f.calls()===0,'selection ran network');});
  test('explicit selection intentionally replaces edited targets',()=>{const f=ntp({get:false,hosts:'draft.test',name:'Draft'});f.selector.value='Second';f.selector.dispatchEvent({type:'change'});assert(f.targets.value==='second.test'&&f.title.value==='Second'&&f.calls()===0,'explicit profile selection broken/executed');});
  const workspace=new Element();workspace.dataset={initialTab:'workflows',forcedTab:'true',workspaceTabsKey:'radius'};
  const run=new Element(),profiles=new Element(),runPanel=new Element(),profilePanel=new Element(),repair=new Element();
  run.dataset.workspaceTab='workflows';profiles.dataset.workspaceTab='profiles';runPanel.dataset.workspacePanel='workflows';profilePanel.dataset.workspacePanel='profiles';
  workspace.querySelectorAll=selector=>selector==='[data-workspace-tab]'?[run,profiles]:[runPanel,profilePanel];
  const document={querySelectorAll:selector=>selector==='[data-workspace-tabs]'?[workspace]:selector==='[data-radius-show-profiles]'?[repair]:[],querySelector:()=>new Element(),getElementById:()=>profiles};
  const window={location:{pathname:'/tools/radius-test'},sessionStorage:{getItem:()=> 'profiles',setItem:()=>{}}};
  new Function('document','window',tabsSource)(document,window);
  test('RADIUS error tab wins over remembered Profiles',()=>{assert(!runPanel.hidden&&profilePanel.hidden&&run.attrs['aria-selected']==='true','error hidden by remembered tab');});
  new Function('document','window',radiusSource)(document,window);
  test('Open Profiles uses existing tab and keyboard focus',()=>{repair.click();assert(runPanel.hidden&&!profilePanel.hidden&&profiles.focused,'repair did not open/focus tab');run.click();assert(!runPanel.hidden&&profilePanel.hidden,'return to Run failed');});
  test('keyboard tab navigation remains available',()=>{run.events.keydown({key:'End',preventDefault(){}});assert(!profilePanel.hidden&&profiles.focused,'End did not open Profiles');profiles.events.keydown({key:'Home',preventDefault(){}});assert(!runPanel.hidden&&run.focused,'Home did not return Run');});
  return passed;
};
