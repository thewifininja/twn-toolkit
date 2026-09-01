(() => {
  const workspace = document.querySelector("[data-agent-workspace-pending]");
  if (!workspace) return;
  window.setTimeout(() => window.location.reload(), 1800);
})();
