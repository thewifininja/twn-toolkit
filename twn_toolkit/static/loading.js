(() => {
  const overlay = document.getElementById("app-loading");
  const message = document.getElementById("app-loading-message");
  const quip = document.getElementById("app-loading-quip");
  if (!overlay || !message) return;

  const quips = [
    "The toolkit is talking to the gear. Tiny packets are doing tiny packet things.",
    "Asking the firewall politely. Results may depend on its mood.",
    "Packets have been dispatched. Clipboards have been warned.",
    "Consulting the network goblins. They prefer structured data.",
    "Negotiating with APIs. Everyone is being very professional about it.",
    "Tiny packets are forming an orderly queue.",
    "The gear is thinking. We are choosing to call that progress.",
    "Shaking the logs gently to see what falls out.",
    "Rounding up the bits. Some of them are being dramatic.",
    "Checking under the routing table cushions.",
    "The toolkit has put on its serious troubleshooting hat.",
    "Waiting on the gear to finish its little monologue.",
    "Counting packets without making direct eye contact.",
    "Asking FortiThings FortiQuestions.",
  ];

  let depth = 0;
  let quipTimer = 0;
  let quipIndex = -1;

  function nextQuip() {
    if (!quip) return;
    quipIndex = (quipIndex + 1) % quips.length;
    quip.textContent = quips[quipIndex];
  }

  function startQuips() {
    if (!quip || quipTimer) return;
    quipIndex = Math.floor(Math.random() * quips.length) - 1;
    nextQuip();
    quipTimer = window.setInterval(nextQuip, 4500);
  }

  function stopQuips() {
    if (!quipTimer) return;
    window.clearInterval(quipTimer);
    quipTimer = 0;
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
})();
