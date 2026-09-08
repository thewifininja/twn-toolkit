(() => {
  // Opt-in native and acknowledged asynchronous editors. Values stay in this page's memory; no drafts
  // or credentials are written to browser storage or sent to another endpoint.
  const forms = Array.from(document.querySelectorAll("form[data-unsaved-form]"));
  if (!forms.length) return;
  const signature = (form) => JSON.stringify(Array.from(form.elements)
    .filter((field) => field.matches("input, select, textarea") && !field.hasAttribute("data-unsaved-ignore")
      && !["submit", "reset", "button"].includes(field.type))
    .map((field) => [field.name, field.type, field.type === "file"
      ? Array.from(field.files || [], (file) => [file.name, file.size, file.lastModified])
      : field.tagName === "SELECT" && field.multiple
        ? Array.from(field.selectedOptions, (option) => option.value)
        : ["checkbox", "radio"].includes(field.type) ? field.checked : field.value]));
  const baselines = new Map(forms.map((form) => [form, signature(form)]));
  const dirty = (form) => form.dataset.unsavedInitial === "true"
    || signature(form) !== baselines.get(form);
  const pendingSaves = new Set();
  // Capture before issuing a save. Acknowledge that exact snapshot only after
  // success: edits made while the request is pending must remain dirty.
  window.TwnUnsavedForms = Object.freeze({
    capture: (form) => {
      if (!baselines.has(form)) return undefined;
      pendingSaves.add(form);
      return signature(form);
    },
    acknowledge: (form, snapshot) => {
      if (!baselines.has(form) || typeof snapshot !== "string") return;
      pendingSaves.delete(form);
      baselines.set(form, snapshot);
      delete form.dataset.unsavedInitial;
    },
    failed: (form) => {
      if (!baselines.has(form)) return;
      pendingSaves.delete(form);
      form.dataset.unsavedInitial = "true";
    },
    // A confirmed rename changes a reference's label, not the user's choice.
    rebaseReference: (form, name, previous, current) => {
      if (!baselines.has(form)) return;
      const baseline = JSON.parse(baselines.get(form));
      baseline.forEach((entry) => {
        if (entry[0] === name && entry[2] === previous) entry[2] = current;
      });
      baselines.set(form, JSON.stringify(baseline));
    },
    reset: (form) => {
      if (!baselines.has(form) || pendingSaves.has(form)) return false;
      baselines.set(form, signature(form));
      delete form.dataset.unsavedInitial;
      return true;
    },
    settle: (form) => pendingSaves.delete(form),
    isPending: (form) => pendingSaves.has(form),
    hasChanges: (form) => form
      ? baselines.has(form) && (pendingSaves.has(form) || dirty(form))
      : pendingSaves.size > 0 || forms.some(dirty),
  });
  let approvedSubmit = null;

  // Window bubbling runs after editor validation/serialization and document
  // loading handlers. Cancelling the event also suppresses their deferred UI.
  window.addEventListener("submit", (event) => {
    approvedSubmit = null;
    const form = event.target;
    if (event.defaultPrevented || !(form instanceof HTMLFormElement)
      || form.method === "dialog" || (form.target && form.target !== "_self")) return;
    if (forms.some((other) => other !== form && (dirty(other) || pendingSaves.has(other)))) {
      if (!window.confirm("Other editors on this page have unsaved changes or a save in progress. Continue and leave those editors?")) {
        event.preventDefault();
        return;
      }
    }
    approvedSubmit = event;
  });

  window.addEventListener("beforeunload", (event) => {
    const submission = approvedSubmit;
    approvedSubmit = null; // Exempt this departure only, never a later navigation.
    if (submission && !submission.defaultPrevented) return;
    if (!forms.some(dirty) && !pendingSaves.size) return;
    event.preventDefault();
    event.returnValue = "";
  });
  window.addEventListener("pageshow", () => { approvedSubmit = null; });
})();
