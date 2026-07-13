(() => {
  const overlay = document.getElementById("app-loading");
  const message = document.getElementById("app-loading-message");
  const quip = document.getElementById("app-loading-quip");
  if (!overlay || !message) return;

  const quips = [
    "Tiny packets are doing tiny packet things.",
    "Asking the firewall politely about its current mood.",
    "Negotiating with APIs. Everyone is being professional.",
    "Shaking the logs gently to see what falls out.",
    "Checking under the routing table cushions.",
    "Waiting for the gear to finish its little monologue.",
    "Counting packets without making direct eye contact.",
    "Asking FortiThings a few FortiQuestions.",
  ];

  let depth = 0;
  let quipTimer = 0;
  let quipSwapTimer = 0;
  let quipIndex = -1;

  function nextQuip() {
    if (!quip) return;
    quip.classList.add("is-changing");
    window.clearTimeout(quipSwapTimer);
    quipSwapTimer = window.setTimeout(() => {
      quipIndex = (quipIndex + 1) % quips.length;
      quip.textContent = quips[quipIndex];
      quip.classList.remove("is-changing");
      quipSwapTimer = 0;
    }, 220);
  }

  function startQuips() {
    if (!quip || quipTimer || document.hidden) return;
    quipIndex = Math.floor(Math.random() * quips.length) - 1;
    quipIndex = (quipIndex + 1) % quips.length;
    quip.textContent = quips[quipIndex];
    quip.classList.remove("is-changing");
    quipTimer = window.setInterval(nextQuip, 8000);
  }

  function stopQuips() {
    if (quipTimer) window.clearInterval(quipTimer);
    if (quipSwapTimer) window.clearTimeout(quipSwapTimer);
    quipTimer = 0;
    quipSwapTimer = 0;
    quip?.classList.remove("is-changing");
  }

  function show(text = "Working on it…") {
    depth += 1;
    message.textContent = text;
    startQuips();
    overlay.hidden = false;
    document.documentElement.classList.add("is-loading");
  }

  function hide() {
    depth = Math.max(0, depth - 1);
    if (depth > 0) return;
    stopQuips();
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

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      stopQuips();
    } else if (depth > 0) {
      startQuips();
    }
  });
})();
