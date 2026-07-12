(() => {
  const form = document.querySelector(".tftp-settings-form");
  if (!form) return;
  const modes = [...form.querySelectorAll("input[name='root_mode']")];
  const folder = form.querySelector("select[name='datastore_root']");
  const writes = form.querySelector("input[name='allow_write']");
  const overwrite = form.querySelector("input[name='allow_overwrite']");

  const applyMode = () => {
    const temporary = modes.some((input) => input.checked && input.value === "temporary");
    if (folder) folder.disabled = temporary;
    for (const input of [writes, overwrite]) {
      if (!input) continue;
      input.disabled = temporary;
      if (temporary) input.checked = false;
    }
  };

  for (const input of modes) input.addEventListener("change", applyMode);
  if (writes && overwrite) {
    writes.addEventListener("change", () => {
      if (!writes.checked) overwrite.checked = false;
      overwrite.disabled = !writes.checked;
    });
  }
  applyMode();
  if (writes && overwrite && !writes.checked) overwrite.disabled = true;
})();
