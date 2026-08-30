(() => {
  const workspaces = document.querySelectorAll("[data-workspace-tabs]");

  workspaces.forEach((workspace, workspaceIndex) => {
    const tabs = Array.from(workspace.querySelectorAll("[data-workspace-tab]"));
    const panels = Array.from(workspace.querySelectorAll("[data-workspace-panel]"));
    if (!tabs.length || !panels.length) return;

    const storageKey = workspace.dataset.workspaceTabsKey
      || `twn.workspace-tabs.${window.location.pathname}.${workspaceIndex}`;
    const persistSelection = workspace.dataset.workspaceTabsPersist !== "false";

    const selectTab = (name, {focus = false, persist = true} = {}) => {
      const selected = tabs.find((tab) => tab.dataset.workspaceTab === name) || tabs[0];
      if (!selected) return;
      const selectedName = selected.dataset.workspaceTab;

      tabs.forEach((tab) => {
        const active = tab === selected;
        tab.setAttribute("aria-selected", active ? "true" : "false");
        tab.tabIndex = active ? 0 : -1;
      });
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.workspacePanel !== selectedName;
      });
      workspace.dataset.activeWorkspaceTab = selectedName;

      if (persist && persistSelection) {
        try { window.sessionStorage.setItem(storageKey, selectedName); } catch (_error) { /* Storage may be unavailable. */ }
      }
      if (focus) selected.focus();
    };

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => selectTab(tab.dataset.workspaceTab));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        let nextIndex = index;
        if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
        if (event.key === "Home") nextIndex = 0;
        if (event.key === "End") nextIndex = tabs.length - 1;
        selectTab(tabs[nextIndex].dataset.workspaceTab, {focus: true});
      });
    });

    let initial = workspace.dataset.initialTab || tabs[0].dataset.workspaceTab;
    if (persistSelection && workspace.dataset.forcedTab !== "true") {
      try {
        const saved = window.sessionStorage.getItem(storageKey);
        if (tabs.some((tab) => tab.dataset.workspaceTab === saved)) initial = saved;
      } catch (_error) { /* Use the server-selected tab. */ }
    }
    selectTab(initial, {persist: false});
  });
})();
