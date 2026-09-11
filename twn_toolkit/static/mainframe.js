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

(() => {
  const workspace = document.querySelector("[data-mainframe-workspace]");
  if (!workspace) return;
  // Preserve old section links and post-save anchors within the new tabs.
  const revealAnchor = () => {
    const target = document.getElementById(location.hash.slice(1));
    if (target?.matches("details")) target.open = true;
    const panel = target?.closest("[data-workspace-panel]");
    if (panel) workspace.querySelector(`[data-workspace-tab="${panel.dataset.workspacePanel}"]`)?.click();
  };
  window.addEventListener("load", revealAnchor);
  window.addEventListener("hashchange", revealAnchor);
  workspace.querySelectorAll("[data-capability-trigger]").forEach((trigger) => {
    const popup = document.getElementById(trigger.getAttribute("aria-controls"));
    let closing;
    let dismissing = false;
    const hide = () => {
      dismissing = true;
      clearTimeout(closing);
      if (popup.matches(":popover-open")) popup.hidePopover();
      popup.hidden = true;
      trigger.setAttribute("aria-expanded", "false");
      queueMicrotask(() => { dismissing = false; });
    };
    const show = () => {
      if (dismissing) return;
      clearTimeout(closing);
      popup.hidden = false;
      if (popup.showPopover && !popup.matches(":popover-open")) popup.showPopover();
      const rect = trigger.getBoundingClientRect();
      const below = innerHeight - rect.bottom - 14;
      const above = rect.top - 14;
      const useBelow = below >= Math.min(popup.scrollHeight + 32, 512) || below >= above;
      popup.style.maxHeight = `${Math.max(80, useBelow ? below : above)}px`;
      popup.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - popup.offsetWidth - 8))}px`;
      popup.style.top = `${Math.max(8, useBelow ? rect.bottom + 6 : rect.top - popup.offsetHeight - 6)}px`;
      trigger.setAttribute("aria-expanded", "true");
    };
    const delayHide = () => { closing = setTimeout(() => {
      if (!popup.matches(":hover") && !popup.contains(document.activeElement) && document.activeElement !== trigger) hide();
    }, 180); };
    trigger.addEventListener("pointerenter", (event) => { if (event.pointerType !== "touch") show(); });
    trigger.addEventListener("pointerleave", delayHide);
    trigger.addEventListener("focus", show);
    trigger.addEventListener("blur", delayHide);
    trigger.addEventListener("click", show);
    popup.addEventListener("pointerenter", () => clearTimeout(closing));
    popup.addEventListener("pointerleave", delayHide);
    popup.addEventListener("focusout", delayHide);
    popup.addEventListener("toggle", (event) => {
      if (event.newState === "closed" && !popup.matches(":popover-open")) { popup.hidden = true; trigger.setAttribute("aria-expanded", "false"); }
    });
    document.addEventListener("keydown", (event) => { if (event.key === "Escape") hide(); });
    document.addEventListener("pointerdown", (event) => {
      if (!trigger.contains(event.target) && !popup.contains(event.target)) hide();
    });
    window.addEventListener("resize", hide);
  });
})();
