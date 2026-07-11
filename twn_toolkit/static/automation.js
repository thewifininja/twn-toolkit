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
    }

    const automationCondition = form.querySelector("[data-automation-condition-select]");
    const scheduledPolicy = form.querySelector("[data-scheduled-policy]");
    if (automationCondition && scheduledPolicy) {
      const syncAutomationPolicy = () => {
        const selected = automationCondition.selectedOptions[0];
        const hidden = ["manual.trigger", "schedule.calendar"].includes(selected?.dataset.conditionType);
        scheduledPolicy.hidden = hidden;
        scheduledPolicy.querySelectorAll("input, select, textarea").forEach((field) => {
          if (!field.dataset.originalRequired) field.dataset.originalRequired = field.required ? "true" : "false";
          field.required = !hidden && field.dataset.originalRequired === "true";
        });
      };
      automationCondition.addEventListener("change", syncAutomationPolicy);
      syncAutomationPolicy();
    }
  });

  document.querySelectorAll("details[data-automation-create]").forEach((details) => {
    const label = details.querySelector(":scope > summary span");
    if (!label) return;
    const closedLabel = label.textContent.trim();
    const syncLabel = () => {
      label.textContent = details.open ? "Cancel" : closedLabel;
    };
    details.addEventListener("toggle", syncLabel);
    syncLabel();
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
