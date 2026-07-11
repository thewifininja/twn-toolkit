(() => {
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

    const automationCondition = form.querySelector("[data-automation-condition-select]");
    const scheduledPolicy = form.querySelector("[data-scheduled-policy]");
    if (automationCondition && scheduledPolicy) {
      const syncAutomationPolicy = () => {
        const selected = automationCondition.selectedOptions[0];
        scheduledPolicy.hidden = selected?.dataset.conditionType === "manual.trigger";
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
