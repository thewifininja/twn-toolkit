(() => {
  // Opt-in native POST editors only. Values stay in this page's memory; no drafts
  // or credentials are written to browser storage or sent to another endpoint.
  const forms = Array.from(document.querySelectorAll("form[data-unsaved-form]"));
  if (!forms.length) return;
  const signature = (form) => JSON.stringify(Array.from(form.elements)
    .filter((field) => field.matches("input, select, textarea")
      && !["submit", "reset", "button"].includes(field.type))
    .map((field) => [field.name, field.type, field.type === "file"
      ? Array.from(field.files || [], (file) => [file.name, file.size, file.lastModified])
      : field.tagName === "SELECT" && field.multiple
        ? Array.from(field.selectedOptions, (option) => option.value)
        : ["checkbox", "radio"].includes(field.type) ? field.checked : field.value]));
  const baselines = new Map(forms.map((form) => [form, signature(form)]));
  const dirty = (form) => form.dataset.unsavedInitial === "true"
    || signature(form) !== baselines.get(form);
  let approvedSubmit = null;

  // Window bubbling runs after editor validation/serialization and document
  // loading handlers. Cancelling the event also suppresses their deferred UI.
  window.addEventListener("submit", (event) => {
    approvedSubmit = null;
    const form = event.target;
    if (event.defaultPrevented || !(form instanceof HTMLFormElement)
      || form.method === "dialog" || (form.target && form.target !== "_self")) return;
    if (forms.some((other) => other !== form && dirty(other))) {
      if (!window.confirm("Other editors on this page have unsaved changes. Continue and discard those changes?")) {
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
    if (!forms.some(dirty)) return;
    event.preventDefault();
    event.returnValue = "";
  });
  window.addEventListener("pageshow", () => { approvedSubmit = null; });
})();
