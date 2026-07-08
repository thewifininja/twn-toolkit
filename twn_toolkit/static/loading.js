(() => {
  const overlay = document.getElementById("app-loading");
  const message = document.getElementById("app-loading-message");
  if (!overlay || !message) return;

  let depth = 0;

  function show(text = "Working on it…") {
    depth += 1;
    message.textContent = text;
    overlay.hidden = false;
    document.documentElement.classList.add("is-loading");
  }

  function hide() {
    depth = Math.max(0, depth - 1);
    if (depth > 0) return;
    overlay.hidden = true;
    document.documentElement.classList.remove("is-loading");
  }

  window.toolkitLoading = {show, hide};

  document.addEventListener("submit", (event) => {
    const form = event.target.closest("form[data-loading-message]");
    if (!form) return;
    window.setTimeout(() => {
      if (event.defaultPrevented) return;
      const submitterMessage = event.submitter?.dataset.loadingMessage;
      show(submitterMessage || form.dataset.loadingMessage);
    }, 0);
  });

  window.addEventListener("pageshow", () => {
    depth = 0;
    hide();
  });
})();
