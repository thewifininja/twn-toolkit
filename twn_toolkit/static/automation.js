(() => {
  const weekdayNames = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const ordinalNames = {"1":"first","2":"second","3":"third","4":"fourth","5":"fifth","-1":"last"};
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]));
  const displayTime = (value) => {
    const [hourText, minute = "00"] = String(value || "09:00").split(":");
    const hour = Number(hourText);
    return `${hour % 12 || 12}:${minute} ${hour >= 12 ? "PM" : "AM"}`;
  };
  const describeRule = (rule) => {
    const at = displayTime(rule.time);
    if (rule.type === "once") return `Once on ${rule.date || "select a date"} at ${at}`;
    if (rule.type === "daily") return `Every day at ${at}`;
    if (rule.type === "weekly") return `Every ${(rule.weekdays || []).map((day) => weekdayNames[day]).join(", ") || "selected weekday"} at ${at}`;
    if (rule.type === "interval_weeks") {
      const anchor = rule.anchor_date ? new Date(`${rule.anchor_date}T12:00:00`) : null;
      const weekday = anchor ? weekdayNames[(anchor.getDay() + 6) % 7] : "anchor weekday";
      return `Every ${rule.interval || 2} weeks on ${weekday} at ${at}, starting ${rule.anchor_date || "select a date"}`;
    }
    if (rule.type === "monthly_date") return `Day ${rule.day || 1} of every month at ${at}`;
    return `The ${ordinalNames[String(rule.ordinal || 1)]} ${weekdayNames[Number(rule.weekday || 0)]} of every month at ${at}`;
  };
  const newRuleId = () => globalThis.crypto?.randomUUID?.() || `rule-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  let sshCommandlets = [];
  try {
    sshCommandlets = JSON.parse(
      document.querySelector("[data-automation-ssh-commandlets]")?.textContent
      || "[]",
    );
  } catch (_error) {
    sshCommandlets = [];
  }

  document.querySelectorAll("[data-schedule-rule-editor]").forEach((editor) => {
    const form = editor.closest("form");
    const hidden = form?.querySelector("[data-schedule-rules-json]");
    const list = editor.querySelector("[data-schedule-rule-list]");
    const empty = editor.querySelector("[data-schedule-empty]");
    const add = editor.querySelector("[data-add-schedule-rule]");
    if (!form || !hidden || !list || !empty || !add) return;
    let rules = [];
    try { rules = JSON.parse(hidden.value || "[]"); } catch (_error) { rules = []; }

    const sync = () => { hidden.value = JSON.stringify(rules); };
    const render = (openId = "") => {
      list.replaceChildren();
      empty.hidden = rules.length > 0;
      rules.forEach((rule, index) => {
        const details = document.createElement("details");
        details.className = "schedule-rule-card";
        details.dataset.ruleId = rule.id;
        details.open = rule.id === openId;
        const weekdayChecks = weekdayNames.map((name, day) => `<label class="check"><input type="checkbox" data-field="weekdays" value="${day}" ${(rule.weekdays || []).includes(day) ? "checked" : ""}>${name.slice(0, 3)}</label>`).join("");
        details.innerHTML = `
          <summary><span><strong>Rule ${index + 1}</strong><small data-rule-description>${escapeHtml(describeRule(rule))}</small></span><span class="schedule-rule-toggle" data-rule-toggle-label>${details.open ? "Close editor" : "Edit rule"}</span></summary>
          <div class="schedule-rule-body">
            <div class="schedule-rule-core">
              <label>Rule type<select data-field="type">
                <option value="once" ${rule.type === "once" ? "selected" : ""}>One time</option>
                <option value="daily" ${rule.type === "daily" ? "selected" : ""}>Daily</option>
                <option value="weekly" ${rule.type === "weekly" ? "selected" : ""}>Weekly</option>
                <option value="interval_weeks" ${rule.type === "interval_weeks" ? "selected" : ""}>Every N weeks</option>
                <option value="monthly_date" ${rule.type === "monthly_date" ? "selected" : ""}>Monthly by date</option>
                <option value="monthly_weekday" ${rule.type === "monthly_weekday" ? "selected" : ""}>Monthly by weekday position</option>
              </select></label>
              <label>Time<input type="time" data-field="time" value="${escapeHtml(rule.time || "09:00")}" required></label>
            </div>
            <div data-rule-specific>
              ${rule.type === "once" ? `<label>Date<input type="date" data-field="date" value="${escapeHtml(rule.date || "")}" required></label>` : ""}
              ${rule.type === "weekly" ? `<fieldset class="schedule-weekdays"><legend>Weekdays</legend><div class="check-grid">${weekdayChecks}</div></fieldset>` : ""}
              ${rule.type === "interval_weeks" ? `<div class="schedule-rule-core"><label>Repeat every<input type="number" data-field="interval" min="1" max="52" value="${Number(rule.interval || 2)}" required></label><label>Starting date<input type="date" data-field="anchor_date" value="${escapeHtml(rule.anchor_date || "")}" required></label></div>` : ""}
              ${rule.type === "monthly_date" ? `<label>Day of month<input type="number" data-field="day" min="1" max="31" value="${Number(rule.day || 1)}" required></label>` : ""}
              ${rule.type === "monthly_weekday" ? `<div class="schedule-rule-core"><label>Week<select data-field="ordinal">${Object.entries(ordinalNames).map(([value,name]) => `<option value="${value}" ${Number(rule.ordinal || 1) === Number(value) ? "selected" : ""}>${name[0].toUpperCase()+name.slice(1)}</option>`).join("")}</select></label><label>Weekday<select data-field="weekday">${weekdayNames.map((name,day) => `<option value="${day}" ${Number(rule.weekday || 0) === day ? "selected" : ""}>${name}</option>`).join("")}</select></label></div>` : ""}
            </div>
            <div class="button-row schedule-rule-actions"><button class="secondary" type="button" data-duplicate-rule>Duplicate</button><button class="text-danger" type="button" data-delete-rule>Delete rule</button></div>
          </div>`;
        list.append(details);

        details.addEventListener("toggle", () => {
          const label = details.querySelector("[data-rule-toggle-label]");
          if (label) label.textContent = details.open ? "Close editor" : "Edit rule";
        });

        details.addEventListener("input", (event) => {
          const field = event.target.dataset.field;
          if (!field) return;
          if (field === "weekdays") {
            rule.weekdays = [...details.querySelectorAll('[data-field="weekdays"]:checked')].map((item) => Number(item.value));
          } else if (["interval", "day", "ordinal", "weekday"].includes(field)) {
            rule[field] = Number(event.target.value);
          } else {
            rule[field] = event.target.value;
          }
          sync();
          details.querySelector("[data-rule-description]").textContent = describeRule(rule);
        });
        details.querySelector('[data-field="type"]').addEventListener("change", () => render(rule.id));
        details.querySelector("[data-delete-rule]").addEventListener("click", () => { rules = rules.filter((item) => item.id !== rule.id); sync(); render(); });
        details.querySelector("[data-duplicate-rule]").addEventListener("click", () => {
          const duplicate = {...rule, id:newRuleId(), weekdays:[...(rule.weekdays || [])]};
          rules.splice(index + 1, 0, duplicate); sync(); render(duplicate.id);
        });
      });
      sync();
    };
    add.addEventListener("click", () => {
      const rule = {id:newRuleId(), type:"daily", time:"09:00"};
      rules.push(rule); render(rule.id);
    });
    render();

    const missedPolicy = form.querySelector('[name="schedule_missed_policy"]');
    const graceLabel = form.querySelector('[name="schedule_grace_minutes"]')?.closest("label");
    const syncGrace = () => { if (graceLabel) graceLabel.hidden = missedPolicy?.value !== "grace"; };
    missedPolicy?.addEventListener("change", syncGrace); syncGrace();
  });

  document.querySelectorAll("form.automation-form").forEach((form) => {
    const stageBuilder = form.querySelector("[data-action-stage-builder]");
    if (stageBuilder) {
      const hidden = form.querySelector("[data-action-stages-json]");
      const list = stageBuilder.querySelector("[data-action-stage-list]");
      const addStage = stageBuilder.querySelector("[data-add-action-stage]");
      let choices = [];
      let stages = [];
      try { choices = JSON.parse(stageBuilder.dataset.actionChoices || "[]"); } catch (_error) { choices = []; }
      try { stages = JSON.parse(hidden?.value || "[]"); } catch (_error) { stages = []; }
      const policyNotes = {
        all_completed: "The next stage runs after every action finishes, regardless of result.",
        success_or_partial: "The next stage runs when every action reports success or partial success; an error stops it.",
        all_success: "The next stage runs only when every action reports full success; partial results stop it.",
        any_failed: "Failure path: the next stage runs when one or more actions report an error.",
        all_failed: "Failure path: the next stage runs only when every action reports an error.",
      };
      const stageId = () => globalThis.crypto?.randomUUID?.() || `stage-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      if (!stages.length) stages = [{id:stageId(), name:"Stage 1", continue_policy:"all_completed", delay_seconds:0, action_definition_ids:[]}];
      const syncStages = () => { if (hidden) hidden.value = JSON.stringify(stages); };
      const renderStages = () => {
        list.replaceChildren();
        const assigned = new Set(stages.flatMap((stage) => stage.action_definition_ids || []));
        stages.forEach((stage, index) => {
          const card = document.createElement("section");
          card.className = "automation-stage-card";
          const stageName = stage.name || `Stage ${index + 1}`;
          const selectedActionIds = stage.action_definition_ids || [];
          const delaySeconds = Math.max(0, Number.parseInt(stage.delay_seconds || 0, 10) || 0);
          const delayUnit = delaySeconds > 0 && delaySeconds % 3600 === 0 ? "hours" : delaySeconds > 0 && delaySeconds % 60 === 0 ? "minutes" : "seconds";
          const delayDivisor = delayUnit === "hours" ? 3600 : delayUnit === "minutes" ? 60 : 1;
          const delayValue = delaySeconds / delayDivisor;
          const delayLabel = delayValue === 1 ? delayUnit.slice(0, -1) : delayUnit;
          const timingSummary = index === 0 ? "starts immediately" : delaySeconds ? `wait ${delayValue} ${delayLabel}` : "no delay";
          const delayControl = index === 0 ? `
            <div class="automation-stage-timing"><span>Delay before stage</span><strong>Immediate</strong><small>Begins as soon as the trigger fires.</small></div>` : `
            <label class="automation-stage-delay">Delay before stage
              <div class="automation-duration-input">
                <input data-stage-delay-value type="number" min="0" max="${delayUnit === "hours" ? 24 : delayUnit === "minutes" ? 1440 : 86400}" step="1" value="${delayValue}" required>
                <select data-stage-delay-unit aria-label="Stage delay unit">
                  <option value="seconds" ${delayUnit === "seconds" ? "selected" : ""}>seconds</option>
                  <option value="minutes" ${delayUnit === "minutes" ? "selected" : ""}>minutes</option>
                  <option value="hours" ${delayUnit === "hours" ? "selected" : ""}>hours</option>
                </select>
              </div>
              <small class="field-note">Runs in the background and survives restarts.</small>
            </label>`;
          const unavailableChoices = choices.filter((choice) => !selectedActionIds.includes(choice.id) && assigned.has(choice.id));
          const unavailableNames = unavailableChoices.slice(0, 3).map((choice) => escapeHtml(choice.name)).join(", ");
          const unavailableMore = unavailableChoices.length > 3 ? ` +${unavailableChoices.length - 3} more` : "";
          const actionRows = choices.filter((choice) => selectedActionIds.includes(choice.id) || !assigned.has(choice.id)).map((choice) => {
            const selected = selectedActionIds.includes(choice.id);
            return `<label class="check automation-stage-action"><input type="checkbox" value="${escapeHtml(choice.id)}" ${selected ? "checked" : ""}><span><strong>${escapeHtml(choice.name)}</strong><small>${escapeHtml(choice.type)}</small></span></label>`;
          }).join("");
          card.innerHTML = `
            <header class="automation-stage-toolbar">
              <div class="automation-stage-heading">
                <span class="automation-stage-index" aria-hidden="true">${index + 1}</span>
                <div><strong data-stage-title>${escapeHtml(stageName)}</strong><small>${selectedActionIds.length} action${selectedActionIds.length === 1 ? "" : "s"} · <span data-stage-timing-summary>${timingSummary}</span></small></div>
              </div>
              <div class="automation-stage-controls" aria-label="Stage ${index + 1} controls">
                <button class="secondary compact" type="button" data-stage-up aria-label="Move stage ${index + 1} up" title="Move up" ${index === 0 ? "disabled" : ""}>↑</button>
                <button class="secondary compact" type="button" data-stage-down aria-label="Move stage ${index + 1} down" title="Move down" ${index === stages.length - 1 ? "disabled" : ""}>↓</button>
                ${stages.length > 1 ? `<button class="text-danger compact" type="button" data-remove-stage aria-label="Remove stage ${index + 1}">Remove</button>` : ""}
              </div>
            </header>
            <div class="automation-stage-settings">
              <label>Name<input data-stage-name maxlength="100" value="${escapeHtml(stageName)}" required></label>
              <label>Continue when<select data-stage-policy>
                <optgroup label="Normal paths">
                  <option value="all_completed" ${stage.continue_policy === "all_completed" ? "selected" : ""}>Always — regardless of result</option>
                  <option value="success_or_partial" ${stage.continue_policy === "success_or_partial" ? "selected" : ""}>Success or partial — no action errors</option>
                  <option value="all_success" ${stage.continue_policy === "all_success" ? "selected" : ""}>Full success — every action succeeds</option>
                </optgroup>
                <optgroup label="Failure paths">
                  <option value="any_failed" ${stage.continue_policy === "any_failed" ? "selected" : ""}>One or more actions fail</option>
                  <option value="all_failed" ${stage.continue_policy === "all_failed" ? "selected" : ""}>Every action fails</option>
                </optgroup>
              </select><small class="field-note" data-stage-policy-note>${escapeHtml(policyNotes[stage.continue_policy] || policyNotes.all_completed)}</small></label>
              ${delayControl}
            </div>
            <section class="automation-stage-action-section">
              <header><div><strong>Actions</strong><small>Selected actions run in parallel.</small></div><span>${selectedActionIds.length} selected</span></header>
              <div class="automation-stage-actions">${actionRows || '<p class="automation-stage-empty">No actions are available for this stage.</p>'}</div>
              ${unavailableChoices.length ? `<small class="automation-stage-assigned-note"><strong>Assigned elsewhere:</strong> ${unavailableNames}${unavailableMore}</small>` : ""}
            </section>`;
          list.append(card);
          card.querySelector("[data-stage-name]").addEventListener("input", (event) => {
            stage.name = event.target.value;
            card.querySelector("[data-stage-title]").textContent = event.target.value.trim() || `Stage ${index + 1}`;
            syncStages();
          });
          card.querySelector("[data-stage-policy]").addEventListener("change", (event) => {
            stage.continue_policy = event.target.value;
            card.querySelector("[data-stage-policy-note]").textContent = policyNotes[stage.continue_policy] || "";
            syncStages();
          });
          const delayValueInput = card.querySelector("[data-stage-delay-value]");
          const delayUnitInput = card.querySelector("[data-stage-delay-unit]");
          const syncDelay = () => {
            if (!delayValueInput || !delayUnitInput) return;
            const factor = delayUnitInput.value === "hours" ? 3600 : delayUnitInput.value === "minutes" ? 60 : 1;
            const maximum = delayUnitInput.value === "hours" ? 24 : delayUnitInput.value === "minutes" ? 1440 : 86400;
            delayValueInput.max = String(maximum);
            stage.delay_seconds = Math.max(0, Number.parseInt(delayValueInput.value || "0", 10) || 0) * factor;
            const summaryValue = Number.parseInt(delayValueInput.value || "0", 10) || 0;
            const summaryUnit = summaryValue === 1 ? delayUnitInput.value.slice(0, -1) : delayUnitInput.value;
            card.querySelector("[data-stage-timing-summary]").textContent = stage.delay_seconds ? `wait ${summaryValue} ${summaryUnit}` : "no delay";
            syncStages();
          };
          delayValueInput?.addEventListener("input", syncDelay);
          delayUnitInput?.addEventListener("change", syncDelay);
          card.querySelectorAll(".automation-stage-action input").forEach((input) => input.addEventListener("change", () => {
            stage.action_definition_ids = [...card.querySelectorAll(".automation-stage-action input:checked")].map((item) => item.value);
            syncStages(); renderStages();
          }));
          card.querySelector("[data-stage-up]").addEventListener("click", () => { [stages[index - 1], stages[index]] = [stages[index], stages[index - 1]]; syncStages(); renderStages(); });
          card.querySelector("[data-stage-down]").addEventListener("click", () => { [stages[index + 1], stages[index]] = [stages[index], stages[index + 1]]; syncStages(); renderStages(); });
          card.querySelector("[data-remove-stage]")?.addEventListener("click", () => { stages.splice(index, 1); syncStages(); renderStages(); });
        });
        syncStages();
      };
      addStage?.addEventListener("click", () => { stages.push({id:stageId(), name:`Stage ${stages.length + 1}`, continue_policy:"all_completed", delay_seconds:0, action_definition_ids:[]}); renderStages(); });
      renderStages();
    }

    const conditionType = form.querySelector("select[name='condition_type']");
    if (conditionType) {
      const syncConditionFields = () => {
        form.querySelectorAll("[data-condition-fields]").forEach((group) => {
          const active = group.dataset.conditionFields === conditionType.value;
          group.hidden = !active;
          group.querySelectorAll("input, select, textarea").forEach((field) => {
            if (!field.dataset.originalRequired) {
              field.dataset.originalRequired = field.required ? "true" : "false";
            }
            field.required = active && field.dataset.originalRequired === "true";
          });
        });
      };
      conditionType.addEventListener("change", syncConditionFields);
      syncConditionFields();
    }

    const actionType = form.querySelector("select[name='action_type']");
    if (actionType) {
      const syncActionFields = () => {
        form.querySelectorAll("[data-action-fields]").forEach((group) => {
          const active = group.dataset.actionFields === actionType.value;
          group.hidden = !active;
          group.querySelectorAll("input, select, textarea").forEach((field) => {
            if (!field.dataset.originalRequired) {
              field.dataset.originalRequired = field.required ? "true" : "false";
            }
            field.required = active && field.dataset.originalRequired === "true";
          });
        });
      };
      actionType.addEventListener("change", syncActionFields);
      syncActionFields();

      const sshMatrixRoot = form.querySelector("[data-ssh-matrix-editor]");
      const sshCommands = form.querySelector("[data-automation-ssh-commands]");
      const sshVariablePicker = form.querySelector(
        "[data-automation-ssh-variable-picker]",
      );
      const sshMatrixEditor = globalThis.TwnSshMatrixEditor?.create(
        sshMatrixRoot,
        {
          commands: sshCommands,
          picker: sshVariablePicker,
        },
      );
      const commandletPicker = form.querySelector(
        "[data-automation-ssh-commandlet]",
      );
      commandletPicker?.addEventListener("change", () => {
        const commandlet = sshCommandlets.find(
          (item) => item.name === commandletPicker.value,
        );
        if (!commandlet) return;
        sshCommands.value = commandlet.commands || "";
        form.querySelector('[name="action_command_timeout"]').value = String(
          commandlet.command_timeout || 300,
        );
        if (commandlet.target_matrix) {
          sshMatrixEditor?.load(commandlet.target_matrix);
        }
        sshCommands.dispatchEvent(new Event("input", { bubbles: true }));
      });
      form.addEventListener("submit", (event) => {
        if (actionType.value !== "ssh.collect" || !sshMatrixEditor) return;
        const matrixInput = sshMatrixRoot.querySelector("[data-ssh-matrix]");
        if (sshMatrixEditor.mode === "grid") {
          sshMatrixEditor.sync();
          if (!sshMatrixEditor.validate({ focus: true, requireTargets: true })) {
            event.preventDefault();
          }
          return;
        }
        try {
          sshMatrixEditor.parse(matrixInput.value);
        } catch (error) {
          event.preventDefault();
          const message = sshMatrixRoot.querySelector("[data-ssh-matrix-error]");
          message.textContent = error.message;
          message.hidden = false;
          matrixInput.focus();
        }
      });

      const sftpOutput = form.querySelector("[data-sftp-action-output]");
      const sftpDatastore = form.querySelector("[data-sftp-action-datastore]");
      const syncSftpOutput = () => {
        const selected = sftpOutput?.querySelector("input:checked");
        if (sftpDatastore) sftpDatastore.hidden = selected?.value !== "datastore";
      };
      sftpOutput?.addEventListener("change", syncSftpOutput);
      syncSftpOutput();

      const captureOutput = form.querySelector("[data-capture-action-output]");
      const captureDatastore = form.querySelector("[data-capture-action-datastore]");
      const syncCaptureOutput = () => {
        const selected = captureOutput?.querySelector("input:checked");
        if (captureDatastore) captureDatastore.hidden = selected?.value !== "datastore";
      };
      captureOutput?.addEventListener("change", syncCaptureOutput);
      syncCaptureOutput();

      const transferProtocol = form.querySelector("[data-action-transfer-protocol]");
      const transferPort = form.querySelector("[data-action-transfer-port]");
      const sshOptions = form.querySelectorAll("[data-action-ssh-host-key-option]");
      let previousTransferProtocol = transferProtocol?.value;
      const syncTransferProtocol = () => {
        if (transferProtocol && transferPort) {
          const previousDefault = previousTransferProtocol === "ftp" ? "21" : "22";
          if (!transferPort.value || transferPort.value === previousDefault) transferPort.value = transferProtocol.value === "ftp" ? "21" : "22";
          previousTransferProtocol = transferProtocol.value;
        }
        if (transferProtocol) {
          for (const option of sshOptions) option.hidden = transferProtocol.value === "ftp";
        }
      };
      transferProtocol?.addEventListener("change", syncTransferProtocol);
      syncTransferProtocol();
    }

    const automationRunMode = form.querySelector("[data-automation-run-mode]");
    const scheduledPolicy = form.querySelector("[data-scheduled-policy]");
    if (automationRunMode && scheduledPolicy) {
      const syncAutomationPolicy = () => {
        const hidden = automationRunMode.value !== "condition";
        scheduledPolicy.hidden = hidden;
        scheduledPolicy.querySelectorAll("input, select, textarea").forEach((field) => {
          if (!field.dataset.originalRequired) field.dataset.originalRequired = field.required ? "true" : "false";
          field.required = !hidden && field.dataset.originalRequired === "true";
        });
        form.querySelectorAll("[data-automation-run-fields]").forEach((group) => {
          const active = group.dataset.automationRunFields === automationRunMode.value;
          group.hidden = !active;
          group.querySelectorAll("input, select, textarea").forEach((field) => {
            if (!field.dataset.originalRequired) field.dataset.originalRequired = field.required ? "true" : "false";
            field.required = active && field.dataset.originalRequired === "true";
          });
        });
      };
      automationRunMode.addEventListener("change", syncAutomationPolicy);
      syncAutomationPolicy();
    }
  });

  document.querySelectorAll("[data-automation-edit-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const editorId = button.getAttribute("aria-controls");
      const editor = editorId ? document.getElementById(editorId) : null;
      if (!editor) return;
      const opening = editor.hidden;
      editor.hidden = !opening;
      button.setAttribute("aria-expanded", String(opening));
      button.textContent = opening ? "Close editor" : "Edit";
      if (opening) {
        editor.querySelector("input:not([type='hidden']), select, textarea")?.focus();
      }
    });
  });
})();
