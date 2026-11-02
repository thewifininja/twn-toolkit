/* Dependency editors: acknowledged saves update choices, never execute a tool or reload a draft. */
(() => {
  const root = document.querySelector('[data-network-profiles]');
  if (!root) return;
  const tool = root.dataset.networkProfiles;
  const groups = tool === 'snmp' ? ['credentials','hosts','oids'] : ['servers','credentials','attributes'];
  const forms = [...root.querySelectorAll('.snmp-profile-form,.radius-profile-form')];
  let catalog = Object.fromEntries(groups.map(kind => [kind,[]])), epoch = 0, catalogReady = false;
  const defaults = new Map();
  const strip = value => String(value || '').replace(/^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g,'');
  const valid = value => value && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 100;
  const label = (kind,item) => item.name + (item.host ? ` · ${item.host}${item.port ? ':'+item.port : ''}` : item.username ? ` · ${item.username}` : item.version ? ` · ${item.version}` : item.count !== undefined ? ` · ${item.count} entries` : '');
  const saveUrl = form => form.dataset.saveUrl || root.dataset.profileSaveTemplate.replace('__KIND__',form.dataset.kind);
  const statusFor = form => {
    let status = form.querySelector('.snmp-form-status,[data-profile-form-status]');
    if (!status) { status=document.createElement('p');status.className='tool-status';status.dataset.profileFormStatus='';status.setAttribute('role','status');form.append(status); }
    return status;
  };
  const checkboxName = kind => ({hosts:'host_names',oids:'oid_profile_names',servers:'server_names'})[kind];
  const apply = () => {
    groups.forEach(kind => {
      const items=catalog[kind];
      root.querySelectorAll(`[data-profile-choice-select="${kind}"]`).forEach(select => {
        const selected=select.value;
        items.forEach(item => {
          let option=[...select.options].find(option=>option.value===item.name);
          if (!option) { option=new Option('',item.name);select.append(option); }
          option.textContent=label(kind,item);delete option.dataset.profileMissing;
        });
        [...select.options].filter(option=>catalogReady && option.value && !items.some(item=>item.name===option.value)).forEach(option=>{option.textContent=`Unavailable saved profile: ${option.value}`;option.dataset.profileMissing='true';});
        select.value=selected;select.disabled=false;window.TwnSelectControls?.sync(select);
      });
      root.querySelectorAll(`[data-profile-choice-group="${kind}"]`).forEach(group => {
        const form=group.closest('form'),added=[];
        items.forEach(item => {
          let input=[...group.querySelectorAll('input[type=checkbox]')].find(input=>input.value===item.name);
          if (!input) {
            const row=document.createElement('label');row.className='check';input=document.createElement('input');input.type='checkbox';input.name=checkboxName(kind);input.value=item.name;
            const text=document.createElement('span');row.append(input,text);group.append(row);added.push(input);
          }
          input.parentElement.querySelector('span').textContent=label(kind,item);delete input.dataset.profileMissing;
        });
        group.querySelectorAll('input[type=checkbox]').forEach(input=>{
          if(catalogReady&&!items.some(item=>item.name===input.value)){input.dataset.profileMissing='true';input.parentElement.querySelector('span').textContent=`Unavailable saved profile: ${input.value}`;}
        });
        if(added.length)window.TwnUnsavedForms?.registerControls(form,added);
        group.querySelectorAll('[data-profile-empty]').forEach(empty=>{empty.hidden=items.length>0;});
      });
    });
    const availableHosts=[...root.querySelectorAll('[data-profile-choice-group="hosts"] input')].some(input=>!input.dataset.profileMissing);
    root.querySelectorAll('[data-profile-setup-empty]').forEach(node=>{node.hidden=availableHosts;});
    const run=root.querySelector('#snmp-test-form [type=submit]');if(run)run.disabled=!availableHosts;
    const discover=root.querySelector('.snmp-monitor-discover');if(discover)discover.disabled=!availableHosts;
  };
  const known = (kind,item,previous='') => {
    if(!valid(item))throw new Error('The saved profile could not be verified.');
    epoch++;
    if(previous && previous!==item.name){
      root.querySelectorAll(`[data-profile-choice-select="${kind}"]`).forEach(select=>{
        [...select.options].filter(option=>option.value===previous).forEach(option=>{option.value=item.name;});
        window.TwnUnsavedForms?.rebaseReference(select.form,select.name,previous,item.name);
      });
      root.querySelectorAll(`[data-profile-choice-group="${kind}"] input`).forEach(input=>{if(input.value===previous)input.value=item.name;});
      if(tool==='snmp'&&kind==='credentials')catalog.hosts.forEach(host=>{if(host.credential_name===previous)host.credential_name=item.name;});
    }
    catalog[kind]=[...catalog[kind].filter(current=>current.name!==previous&&current.name!==item.name),item];apply();
  };
  const refresh = async () => {
    const sequence=++epoch,status=root.querySelector('[data-profile-choice-status]');
    status.textContent='Refreshing saved choices; editors and selections stay here…';
    try {
      const response=await fetch(root.dataset.profileChoicesUrl,{headers:{Accept:'application/json'},cache:'no-store',signal:AbortSignal.timeout(10000)});
      if(!response.ok || !response.headers.get('content-type')?.includes('application/json'))throw new Error('Choices unavailable. Check your session/tool access, then try again.');
      const data=await response.json();
      if(!groups.every(kind=>Array.isArray(data[kind])&&data[kind].every(valid)))throw new Error('Saved choices were not recognized.');
      if(sequence!==epoch)return;
      catalog=data;catalogReady=true;apply();status.textContent='Choices refreshed. No editor was replaced or save retried; new choices are not selected automatically.';
    }catch(error){status.textContent=error.message+' Your drafts stay here.';}
  };
  root.querySelector('[data-profile-choices-refresh]').addEventListener('click',refresh);
  forms.forEach(form=>{
    if(!form.elements.original_name.value&&!defaults.has(form.dataset.kind))defaults.set(form.dataset.kind,[...form.elements].filter(field=>field.name).map(field=>({name:field.name,type:field.type,value:field.value,checked:field.checked})));
  });
  forms.forEach(form=>{
    const kind=form.dataset.kind,status=statusFor(form),submit=form.querySelector('[type=submit]');let pending=false;
    const returnButton=document.createElement('button');returnButton.type='button';returnButton.className='secondary';returnButton.hidden=true;returnButton.textContent=tool==='snmp'&&kind==='credentials'?'Continue host setup':'Return to Run tests';form.append(returnButton);
    returnButton.addEventListener('click',()=>{
      const toHosts=tool==='snmp'&&kind==='credentials';document.getElementById(toHosts?'snmp-profiles-tab':tool==='snmp'?'snmp-tests-tab':'radius-workflows-tab').click();
      const target=toHosts?root.querySelector('.snmp-profile-form[data-kind="hosts"] [name=credential_name]'):root.querySelector(tool==='snmp'?'#snmp-test-form':'#radius-test-form');
      if(target){for(let parent=target.parentElement;parent&&parent!==root;parent=parent.parentElement)if(parent.tagName==='DETAILS')parent.open=true;target.scrollIntoView({block:'center'});(target.matches('form')?target.querySelector('input,select'):target)?.focus();}
    });
    const newButton=document.createElement('button');newButton.type='button';newButton.className='secondary';newButton.textContent=`Create another ${kind==='credentials'?'credential':kind==='hosts'?'host':kind==='servers'?'server':'profile'}`;newButton.hidden=!form.elements.original_name.value;form.append(newButton);
    newButton.addEventListener('click',()=>{
      if(pending || (window.TwnUnsavedForms?.hasChanges(form)&&!window.confirm('Discard only this editor’s unsaved changes and start a new profile? Other drafts stay here.')))return;
      const initial=defaults.get(kind)||[];
      [...form.elements].filter(field=>field.name).forEach(field=>{const start=initial.find(item=>item.name===field.name&&item.type===field.type);if(start){field.value=start.value;field.checked=start.checked;}});
      form.elements.original_name.value='';window.TwnMso.newProfile(form);newButton.hidden=true;
      form.querySelectorAll('input[type=password]').forEach(field=>{field.value='';field.placeholder='';});
      form.querySelectorAll('.secret-note,.snmp-community-note').forEach(note=>{note.textContent='Enter required secrets for this new profile; no saved secret is carried over.';});
      form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile').forEach(button=>{button.hidden=true;});
      const summary=form.closest('details')?.querySelector(':scope > summary');if(summary)summary.textContent=`New ${kind==='credentials'?'credential':kind==='hosts'?'host':kind==='servers'?'server':'profile'}`;
      submit.textContent='Save new profile';form.elements.version?.dispatchEvent(new Event('change'));window.TwnUnsavedForms?.reset(form);
      status.textContent='New profile defaults are ready. Enter a new name and required secrets; other drafts are unchanged.';form.elements.name.focus();
    });
    form.addEventListener('submit',async event=>{
      if(event.defaultPrevented)return;event.preventDefault();if(pending||!form.reportValidity())return;
      const body=new FormData(form);
      if(!window.TwnMso?.prepare){status.textContent='Saved-list controls are still loading. Your draft is kept.';return;}
      if(!window.TwnMso.prepare(body,form)){status.textContent='Save canceled; draft kept.';return;}
      const snapshot=window.TwnUnsavedForms?.capture(form),previous=form.elements.original_name.value;
      const actionStates=[...form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile')].map(button=>[button,button.disabled]);actionStates.forEach(([button])=>{button.disabled=true;});
      pending=true;submit.disabled=true;newButton.disabled=true;status.textContent='Saving profile; no test is running…';
      try{
        const response=await fetch(saveUrl(form),{method:'POST',body,headers:{Accept:'application/json'},signal:AbortSignal.timeout(15000)});
        if(!response.headers.get('content-type')?.includes('application/json'))throw new Error('Save was not confirmed.');
        const payload=await response.json();
        if([401,403,404].includes(response.status)){const error=new Error('Your session or tool access is unavailable. Sign in or check access before trying again.');error.access=true;throw error;}
        if(!response.ok){const error=new Error(payload.error||'Profile could not be saved.');error.definite=response.status===400||response.status===409;throw error;}
        const profile=payload.profile;
        if(!valid(profile)||profile.name!==strip(body.get('name')))throw new Error('Save acknowledgment did not match this submitted name.');
        window.TwnMso.saved(form,profile);form.elements.original_name.value=profile.name;
        const savedValues={name:profile.name};
        if(form.elements.name.value===body.get('name'))form.elements.name.value=profile.name;
        form.querySelectorAll('input[type=password]').forEach(field=>{savedValues[field.name]='';if(field.value===body.get(field.name))field.value='';});
        window.TwnUnsavedForms?.acknowledge(form,snapshot,savedValues);
        known(kind,profile,previous);
        const summary=form.closest('details')?.querySelector(':scope > summary');if(summary)summary.textContent=`Editing ${profile.name}`;
        form.querySelectorAll('.secret-note,.snmp-community-note').forEach(note=>{note.textContent='Saved secrets are write-only. Leave blank to keep the saved value.';});
        form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile').forEach(button=>{button.hidden=false;button.dataset.profileName=profile.name;button.dataset.name=profile.name;});
        newButton.hidden=false;returnButton.hidden=false;submit.textContent='Update saved profile';status.textContent=`Saved ${profile.name}. It is available in the current choices; select it where needed. No test was run.`+(window.TwnUnsavedForms?.hasChanges(form)?' Newer edits in this editor are still unsaved.':'');
      }catch(error){window.TwnUnsavedForms?.failed(form);status.textContent=(error.access?error.message+' Save is unconfirmed; it may already have completed.':error.definite?error.message:'Save is unconfirmed. It may already have completed. Use Refresh saved choices or open the saved library before trying again.')+' Drafts are kept; no save is retried automatically.';}
      finally{pending=false;submit.disabled=false;newButton.disabled=false;actionStates.forEach(([button,disabled])=>{button.disabled=disabled;});window.TwnUnsavedForms?.settle(form);}
    });
    form.querySelectorAll('.snmp-delete-profile,.radius-delete-profile').forEach(button=>button.addEventListener('click',async()=>{
      if(pending)return;const name=form.elements.original_name.value;if(!name||!window.confirm(window.TwnMso.deleteMessage(form,name)))return;
      const body=new FormData();body.set('name',name);if(!window.TwnMso.prepare(body,form,'delete'))return;
      pending=true;button.disabled=true;
      try{const response=await fetch(form.dataset.deleteUrl||saveUrl(form)+'/delete',{method:'POST',body,signal:AbortSignal.timeout(15000)});const data=await response.json();if(!response.ok)throw new Error(data.error||'Delete unconfirmed.');status.textContent=`Deleted ${name}. Editors remain here; start a new profile to continue.`;await refresh();}
      catch(error){status.textContent=error.message+' Drafts are kept; no delete is retried.';}finally{pending=false;button.disabled=false;}
    }));
  });
  root.addEventListener('click',async event=>{
    const button=event.target.closest('[data-profile-duplicate]');if(!button||!root.contains(button)||button.disabled)return;
    const name=button.dataset.profileName||button.closest('form')?.elements.original_name.value;if(!name)return;
    const status=statusFor(button.closest('form'));button.disabled=true;
    try{const response=await fetch(button.dataset.profileDuplicate,{method:'POST',body:new URLSearchParams({name}),headers:{Accept:'application/json'},signal:AbortSignal.timeout(15000)});const data=await response.json();if(!response.ok||data.source_name!==name||!valid(data.profile)||data.profile.name===name)throw new Error(data.error||'Copy not confirmed.');known(button.closest('form').dataset.kind,data.profile);status.textContent=`Copied as ${data.profile.name}. The new choice is available but not selected; drafts are unchanged.`;}
    catch(error){status.textContent=error.message+' A copy may already exist. Refresh saved choices before retrying; no copy is retried automatically.';}finally{button.disabled=false;}
  });
  root.querySelectorAll('[data-network-setup]').forEach(button=>button.addEventListener('click',()=>{const tab=document.getElementById(tool==='snmp'?'snmp-profiles-tab':'radius-profiles-tab');tab.click();tab.focus();}));
  refresh();
})();
