(() => {
  const form = document.querySelector("[data-mainframe-role-form]");
  const role = form?.querySelector("[data-mainframe-role]");
  if (!form || !role) return;

  const synchronizeFields = () => {
    form.querySelectorAll("[data-role-fields]").forEach((group) => {
      group.hidden = group.dataset.roleFields !== role.value;
    });
  };

  role.addEventListener("change", synchronizeFields);
  synchronizeFields();
})();
