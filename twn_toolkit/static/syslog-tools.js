(() => {
  const switcher = document.querySelector("[data-syslog-task-switch]");
  const panelRoot = document.querySelector("[data-syslog-task-panels]");
  if (!switcher || !panelRoot) return;

  const tabs = Array.from(switcher.querySelectorAll("[data-syslog-task]"));
  const panels = Array.from(panelRoot.querySelectorAll("[data-syslog-task-panel]"));

  const selectTask = (task, {focus = false} = {}) => {
    const selected = tabs.find((tab) => tab.dataset.syslogTask === task) || tabs[0];
    if (!selected) return;
    const selectedTask = selected.dataset.syslogTask;

    tabs.forEach((tab) => {
      const active = tab === selected;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.tabIndex = active ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.syslogTaskPanel !== selectedTask;
    });
    panelRoot.dataset.activeSyslogTask = selectedTask;
    if (focus) selected.focus();
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTask(tab.dataset.syslogTask));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      let nextIndex = index;
      if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
      if (event.key === "Home") nextIndex = 0;
      if (event.key === "End") nextIndex = tabs.length - 1;
      selectTask(tabs[nextIndex].dataset.syslogTask, {focus: true});
    });
  });

  selectTask(panelRoot.dataset.initialSyslogTask || "send");
})();
