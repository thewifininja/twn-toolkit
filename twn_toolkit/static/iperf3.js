(() => {
  const protocol = document.querySelector("[data-iperf-protocol]");
  const udpField = document.querySelector("[data-iperf-udp-field]");
  const serverPort = document.querySelector("[name='server_port']");
  const serverCommand = document.querySelector(".iperf-server-callout code");
  const serverWorkspace = document.querySelector("[data-iperf-server-workspace]");
  const history = document.querySelector("[data-iperf-server-history]");
  const resultsContainer = document.querySelector("[data-iperf-server-results]");
  const clearHistory = document.querySelector("[data-iperf-clear-history]");

  const updateProtocol = () => {
    if (!protocol || !udpField) return;
    const udp = protocol.value === "udp";
    udpField.hidden = !udp;
    const input = udpField.querySelector("input");
    if (input) input.required = udp;
  };

  const updateServerCommand = () => {
    if (!serverPort || !serverCommand) return;
    serverCommand.textContent = `iperf3 -c <toolkit-address> -p ${serverPort.value || "5201"}`;
  };

  const replaceResults = (html, revision, count) => {
    if (!history || !resultsContainer) return;
    const previousRevision = Number(history.dataset.resultRevision || "0");
    if (revision === previousRevision) return;
    const openResultIds = Array.from(
      resultsContainer.querySelectorAll("details[open][id]"),
      (detail) => detail.id,
    );
    resultsContainer.innerHTML = html;
    openResultIds.forEach((id) => {
      const detail = document.getElementById(id);
      if (detail) detail.open = true;
    });
    history.dataset.resultRevision = String(revision);
    if (clearHistory) clearHistory.hidden = count === 0;
  };

  const updateServerState = (session) => {
    if (!serverWorkspace || !session) return;
    const status = serverWorkspace.querySelector("[data-iperf-server-status]");
    const started = serverWorkspace.querySelector("[data-iperf-server-started]");
    const testCount = serverWorkspace.querySelector("[data-iperf-server-test-count]");
    const lastTest = serverWorkspace.querySelector("[data-iperf-server-last-test]");
    const error = serverWorkspace.querySelector("[data-iperf-server-error]");
    const stateNote = serverWorkspace.querySelector("[data-iperf-server-state-note]");
    if (status) {
      status.textContent = session.status;
      status.classList.toggle("success", session.status === "running");
    }
    if (started) {
      started.textContent = session.started_at_display || "Starting…";
    }
    if (testCount) testCount.textContent = String(session.test_count);
    if (lastTest) {
      lastTest.textContent = session.last_test_at_display || "Waiting for a client";
    }
    if (error) {
      const message = session.error || session.last_error || "";
      error.textContent = message;
      error.hidden = !message;
    }
    if (stateNote && session.status === "stopping") {
      stateNote.textContent = "Stop requested; closing the listener…";
    }
  };

  const pollServer = async () => {
    if (!serverWorkspace) return;
    try {
      const response = await fetch(serverWorkspace.dataset.statusUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`status ${response.status}`);
      const payload = await response.json();
      updateServerState(payload.session);
      replaceResults(
        payload.results_html,
        Number(payload.result_revision || 0),
        Number(payload.result_count || 0),
      );
      if (!payload.session.active) {
        window.setTimeout(() => window.location.reload(), 500);
        return;
      }
      window.setTimeout(pollServer, 2000);
    } catch (_error) {
      window.setTimeout(pollServer, 5000);
    }
  };

  protocol?.addEventListener("change", updateProtocol);
  serverPort?.addEventListener("input", updateServerCommand);
  updateProtocol();
  updateServerCommand();
  pollServer();
})();
