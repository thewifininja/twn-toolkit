(() => {
  const form = document.querySelector("[data-execution-context-form]");
  const select = form?.querySelector("[data-execution-context-select]");
  if (!form || !select) return;
  select.addEventListener("change", () => form.requestSubmit());
})();
