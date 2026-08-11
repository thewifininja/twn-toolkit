(() => {
  const managers = document.querySelectorAll("[data-saved-profile-manager]");

  managers.forEach((manager) => {
    const select = manager.querySelector("[data-saved-profile-select]");
    const name = manager.querySelector("[data-saved-profile-name]");
    const state = manager.querySelector("[data-saved-profile-state]");
    const save = manager.querySelector("[data-saved-profile-save]");
    const duplicate = manager.querySelector("[data-saved-profile-duplicate]");
    const remove = manager.querySelector("[data-saved-profile-delete]");

    if (!select) return;

    const sync = () => {
      const selectedName = select.value.trim();
      const enteredName = name?.value.trim() || "";
      const hasSavedProfile = Boolean(selectedName);
      const isRenaming = hasSavedProfile
        && Boolean(enteredName)
        && enteredName.toLocaleLowerCase() !== selectedName.toLocaleLowerCase();

      manager.dataset.profileState = isRenaming ? "renaming" : hasSavedProfile ? "saved" : "new";
      if (state) {
        state.textContent = isRenaming ? "Rename on save" : hasSavedProfile ? `Editing ${selectedName}` : "New profile";
      }
      if (save) {
        save.textContent = isRenaming ? "Rename profile" : hasSavedProfile ? "Save changes" : "Save profile";
      }
      if (duplicate) duplicate.disabled = !hasSavedProfile;
      if (remove) remove.disabled = !hasSavedProfile;
    };

    select.addEventListener("change", () => queueMicrotask(sync));
    name?.addEventListener("input", sync);
    sync();
  });
})();
