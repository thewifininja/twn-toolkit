(() => {
  const builders = [...document.querySelectorAll("form[data-automation-builder]")];
  if (!builders.length) return;
  let choices;
  try { choices = JSON.parse(document.querySelector("[data-automation-builder-choices]").textContent); }
  catch (_) { return; }
  const validChoice = (item) => item && ["id", "name", "type"].every((key) => typeof item[key] === "string" && item[key].length);
  const validChoices = (value) => value && ["conditions", "schedules", "actions"].every((key) => Array.isArray(value[key]) && value[key].every(validChoice));
  if (!validChoices(choices)) return;
  const note = (form, message) => { form.querySelector("[data-builder-choice-status]").textContent = message; };
  const readiness = (form) => {
    const mode = form.querySelector("[name=run_mode]").value;
    const selected = [...form.querySelectorAll('[name="condition_definition_id"]:checked')].map((item) => item.value).filter(Boolean);
    const schedule = form.querySelector("[name=schedule_definition_id]").value;
    let stages = [];
    try { stages = JSON.parse(form.querySelector("[data-action-stages-json]").value); } catch (_) { /* Server validates malformed draft too. */ }
    const available = (group, id) => choices[group].some((item) => item.id === id);
    const conditionsReady = mode !== "condition" || (selected.length >= 1 && selected.length <= 10 && selected.every((id) => available("conditions", id)));
    const scheduleReady = mode !== "schedule" || available("schedules", schedule);
    const actionsReady = stages.length && stages.every((stage) => Array.isArray(stage.action_definition_ids) && stage.action_definition_ids.length && stage.action_definition_ids.every((id) => available("actions", id)));
    form.querySelector("[data-save-automation-paused]").disabled = !conditionsReady || !scheduleReady || !actionsReady;
    form.querySelector("[data-builder-readiness]").textContent = !conditionsReady ? "Select 1–10 available conditions, or create one here." : !scheduleReady ? "Choose a saved schedule, or create one here." : !actionsReady ? "Select at least one available action in every stage." : "Saved choices are selected. Review the settings, then save paused; nothing runs yet.";
  };
  const applyChoices = (catalogue, target = null, created = null, stageId = null) => {
    if (!validChoices(catalogue)) throw new Error("The saved choices could not be read. Your draft is unchanged.");
    choices = catalogue;
    builders.forEach((form) => {
      const selected = new Set([...form.querySelectorAll('[name="condition_definition_id"]:checked')].map((item) => item.value).filter(Boolean));
      if (form === target && created?.kind === "condition" && selected.size < 10) selected.add(created.id);
      const conditionList = form.querySelector("[data-builder-condition-choices]");
      const known = new Set(choices.conditions.map((item) => item.id));
      const rows = [...choices.conditions, ...[...selected].filter((id) => !known.has(id)).map((id) => ({id, name:"Unavailable saved condition", type:"Unselect before saving"}))];
      conditionList.replaceChildren();
      rows.forEach((item) => {
        const label = document.createElement("label"); label.className = "check";
        const input = document.createElement("input"); Object.assign(input, {type:"checkbox", name:"condition_definition_id", value:item.id, checked:selected.has(item.id)});
        const text = document.createElement("span"), title = document.createElement("strong"), detail = document.createElement("small");
        title.textContent = item.name; detail.textContent = item.type; text.append(title, detail); label.append(input, text); conditionList.append(label);
      });
      form.querySelector("[data-builder-empty-conditions]").hidden = choices.conditions.length > 0;
      const select = form.querySelector("[name=schedule_definition_id]");
      const selectedSchedule = form === target && created?.kind === "schedule" ? created.id : select.value;
      select.replaceChildren(new Option("Select a schedule", ""));
      choices.schedules.forEach((item) => select.append(new Option(item.name, item.id)));
      if (selectedSchedule && !choices.schedules.some((item) => item.id === selectedSchedule)) select.append(new Option("Unavailable saved schedule — choose another", selectedSchedule));
      select.value = selectedSchedule;
      window.TwnSelectControls?.sync(select);
      form.querySelector("[data-builder-empty-schedules]").hidden = choices.schedules.length > 0;
      form.dispatchEvent(new CustomEvent("automation:choices", {detail:{actions:choices.actions, useId:form === target && created?.kind === "action" ? created.id : null, stageId}}));
      readiness(form);
    });
  };
  builders.forEach((form) => {
    form.addEventListener("input", () => readiness(form));
    form.addEventListener("change", () => readiness(form));
    form.addEventListener("automation:stages-changed", () => readiness(form));
    form.querySelector("[data-refresh-builder-choices]").addEventListener("click", async (event) => {
      const button = event.currentTarget; button.disabled = true; note(form, "Refreshing saved choices; your draft stays here…");
      try {
        const response = await fetch(form.dataset.builderChoicesUrl, {headers:{Accept:"application/json"}, cache:"no-store", signal:AbortSignal.timeout(10000)});
        if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) throw new Error("Could not refresh choices. Check your session/access, then try again. Your draft is still here.");
        applyChoices(await response.json()); note(form, "Saved choices refreshed. Existing selections and stage order were kept.");
      } catch (error) { note(form, error.message); }
      finally { button.disabled = false; }
    });
    readiness(form);
  });

  document.querySelectorAll("[data-prerequisite-dialog]").forEach((dialog) => {
    const form = dialog.querySelector("form"), status = dialog.querySelector("[data-prerequisite-status]"), back = dialog.querySelector("[data-prerequisite-back]");
    const kind = dialog.dataset.prerequisiteDialog;
    let target, trigger, stageId, pending = false, saved = false;
    document.addEventListener("click", (event) => {
      const opener = event.target.closest(`[data-create-prerequisite="${kind}"]`);
      if (!opener || !opener.closest("form[data-automation-builder]") || typeof dialog.showModal !== "function") return;
      event.preventDefault(); target = opener.closest("form[data-automation-builder]"); trigger = opener; stageId = opener.dataset.prerequisiteStage || null;
      if (saved) {
        form.querySelector(`[name="${kind}_name"]`).value = ""; saved = false;
        status.textContent = "Previous settings are kept as a starting point. Give this new item a different name.";
        window.TwnUnsavedForms?.reset(form);
      }
      dialog.showModal(); form.querySelector("input:not([type=hidden])")?.focus();
    });
    back.addEventListener("click", () => { if (!pending) dialog.close(); });
    dialog.addEventListener("cancel", (event) => { if (pending) event.preventDefault(); });
    dialog.addEventListener("close", () => trigger?.focus());
    form.addEventListener("submit", async (event) => {
      if (event.defaultPrevented) return;
      event.preventDefault();
      if (pending || !form.reportValidity()) return;
      const body = new FormData(form);
      pending = true; window.TwnUnsavedForms?.capture(form);
      const controls = [...form.elements].map((field) => [field, field.disabled]); controls.forEach(([field]) => { field.disabled = true; }); back.disabled = true;
      status.textContent = "Saving this reusable item. No conditions or actions are running…";
      try {
        const response = await fetch(form.action, {method:"POST", body, headers:{Accept:"application/json"}, signal:AbortSignal.timeout(15000)});
        if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("Save was not confirmed. Your drafts remain; refresh saved choices before trying again.");
        const payload = await response.json();
        if (!response.ok) {
          const error = new Error(payload.error || "This item could not be saved."); error.definiteFailure = true; throw error;
        }
        const item = payload.definition;
        if (!validChoice(item) || item.kind !== kind) throw new Error("Save was not confirmed. Refresh saved choices before trying again.");
        const group = {condition:"conditions", schedule:"schedules", action:"actions"}[kind];
        const catalogue = {...choices, [group]:[...choices[group].filter((choice) => choice.id !== item.id), item]};
        applyChoices(catalogue, target, item, stageId);
        form.querySelectorAll('input[type="password"], [name="webhook_headers"]').forEach((field) => { field.value = ""; });
        window.TwnUnsavedForms?.settle(form); window.TwnUnsavedForms?.reset(form);
        saved = true; status.textContent = "";
        const selectedNewCondition = kind !== "condition" || [...target.querySelectorAll('[name="condition_definition_id"]:checked')].some((field) => field.value === item.id);
        note(target, selectedNewCondition ? `${kind[0].toUpperCase() + kind.slice(1)} saved. Review its selection, then save the automation paused.` : "Condition saved, but 10 conditions were already selected. Unselect one to use the new condition.");
        dialog.close();
      } catch (error) {
        window.TwnUnsavedForms?.failed(form);
        const message = error.definiteFailure ? error.message : "Save was not confirmed. Refresh saved choices before trying again.";
        status.textContent = message + " Your automation and this draft are still here. No save is retried automatically.";
      } finally {
        pending = false; controls.forEach(([field, disabled]) => { field.disabled = disabled; }); back.disabled = false;
        window.TwnUnsavedForms?.settle(form);
      }
    });
  });
})();
