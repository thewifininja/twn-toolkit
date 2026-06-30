(() => {
  const form = document.querySelector("#cleanup-selection-form");
  if (!form) return;

  const selectAll = form.querySelector("#cleanup-select-all");
  const targets = [...form.querySelectorAll(".cleanup-target")];
  const phrase = form.querySelector("#cleanup-confirmation-phrase");
  const confirmation = form.querySelector("#cleanup-confirmation-input");
  const selectedCount = form.querySelector("#cleanup-selected-count");
  const selectedNoun = form.querySelector("#cleanup-selected-noun");
  const submit = form.querySelector("#cleanup-submit");
  const verb = form.dataset.action === "remove_memberships" ? "REMOVE" : "DELETE";

  const updateSelection = () => {
    const count = targets.filter((target) => target.checked).length;
    const noun =
      form.dataset.action === "remove_memberships"
        ? count === 1
          ? "MEMBERSHIP"
          : "MEMBERSHIPS"
        : count === 1
          ? "DEVICE"
          : "DEVICES";
    const expected = `${verb} ${count} ${noun}`;
    phrase.textContent = expected;
    confirmation.placeholder = expected;
    confirmation.value = "";
    selectedCount.textContent = count;
    selectedNoun.textContent =
      form.dataset.action === "remove_memberships"
        ? count === 1
          ? "Membership"
          : "Memberships"
        : `${count === 1 ? "Device" : "Devices"} Globally`;
    submit.disabled = count === 0;
    selectAll.checked = count === targets.length;
    selectAll.indeterminate = count > 0 && count < targets.length;
  };

  selectAll.addEventListener("change", () => {
    targets.forEach((target) => {
      target.checked = selectAll.checked;
    });
    updateSelection();
  });
  targets.forEach((target) => target.addEventListener("change", updateSelection));
})();
