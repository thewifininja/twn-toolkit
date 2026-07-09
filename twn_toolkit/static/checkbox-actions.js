(() => {
  function checkboxContainer(button) {
    const selector = button.dataset.checkboxScope;
    if (selector) {
      return button.closest(selector);
    }
    return button.closest("form") || button.closest("section") || document;
  }

  function toggleCheckboxes(button) {
    const container = checkboxContainer(button);
    if (!container) return;
    const targetSelector = button.dataset.checkboxTarget || "input[type='checkbox']";
    const checked = button.dataset.checkboxAction === "select";
    container.querySelectorAll(targetSelector).forEach((checkbox) => {
      if (checkbox instanceof HTMLInputElement && checkbox.type === "checkbox" && !checkbox.disabled) {
        checkbox.checked = checked;
        checkbox.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const button = event.target.closest("[data-checkbox-action]");
    if (!button) return;
    event.preventDefault();
    toggleCheckboxes(button);
  });
})();
