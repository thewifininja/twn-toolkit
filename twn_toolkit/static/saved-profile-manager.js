(() => {
  const managers = document.querySelectorAll("[data-saved-profile-manager]");

  managers.forEach((manager) => {
    const select = manager.querySelector("[data-saved-profile-select]");
    const name = manager.querySelector("[data-saved-profile-name]");
    const state = manager.querySelector("[data-saved-profile-state]");
    const count = manager.querySelector(".saved-profile-count");
    const save = manager.querySelector("[data-saved-profile-save]");
    const duplicate = manager.querySelector("[data-saved-profile-duplicate]");
    const remove = manager.querySelector("[data-saved-profile-delete]");
    const primary = manager.querySelector("[data-saved-profile-primary]");
    const more = manager.querySelector("[data-saved-profile-more]");
    const rename = manager.querySelector("[data-saved-profile-rename]");
    const naming = manager.querySelector("[data-saved-profile-naming]");
    const cancel = manager.querySelector("[data-saved-profile-cancel]");
    const compact = manager.classList.contains("compact-profile-manager");
    let namingMode = "";

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
        save.textContent = compact
          ? namingMode === "rename" ? "Rename" : hasSavedProfile ? "Save changes" : "Save"
          : isRenaming ? "Rename profile" : hasSavedProfile ? "Save changes" : "Save profile";
      }
      if (duplicate) duplicate.disabled = !hasSavedProfile;
      if (remove) remove.disabled = !hasSavedProfile;

      if (!compact) return;
      if (count) {
        const savedCount = [...select.options].filter((option) => option.value.trim()).length;
        count.textContent = `${savedCount} saved`;
      }
      if (primary) primary.textContent = hasSavedProfile ? "Save changes" : "Save current…";
      if (more) more.hidden = !hasSavedProfile;
    };

    const closeNaming = ({restoreName = true} = {}) => {
      namingMode = "";
      if (naming) naming.hidden = true;
      if (restoreName && name) name.value = select.value;
      sync();
    };

    const openNaming = (mode) => {
      if (!compact || !naming || !name) return;
      namingMode = mode;
      naming.hidden = false;
      name.value = mode === "rename" ? select.value : "";
      if (more) more.open = false;
      sync();
      queueMicrotask(() => name.focus());
    };

    select.addEventListener("change", () => queueMicrotask(() => {
      closeNaming({restoreName: false});
      sync();
    }));
    name?.addEventListener("input", sync);

    if (compact) {
      primary?.addEventListener("click", () => {
        if (!select.value) {
          openNaming("new");
          return;
        }
        if (name) name.value = select.value;
        save?.click();
      });
      rename?.addEventListener("click", () => openNaming("rename"));
      cancel?.addEventListener("click", closeNaming);
      manager.addEventListener("savedprofilesaved", () => closeNaming({restoreName: false}));
      document.addEventListener("click", (event) => {
        if (more?.open && !more.contains(event.target)) more.open = false;
      });
    }

    sync();
  });
})();
