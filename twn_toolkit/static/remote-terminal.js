(function () {
  const form = document.getElementById("remote-terminal-form");
  const workspace = document.getElementById("remote-terminal-workspace");
  const list = document.getElementById("remote-terminal-session-list");
  const initial = document.getElementById("remote-terminal-initial-sessions");
  if (!workspace || !initial) return;

  const tabs = document.getElementById("remote-terminal-tabs");
  const newSessionButton = document.getElementById("remote-terminal-new-session");
  const stageEmpty = document.getElementById("remote-terminal-stage-empty");
  const surface = document.getElementById("remote-terminal-surface");
  const screen = document.getElementById("remote-terminal-screen");
  const inputCapture = document.getElementById("remote-terminal-input-capture");
  const focusState = document.getElementById("remote-terminal-focus-state");
  const stopButton = document.getElementById("remote-terminal-stop");
  const popoutButton = document.getElementById("remote-terminal-popout");
  const saveHostButton = document.getElementById("remote-terminal-save-host");
  const downloadButton = document.getElementById("remote-terminal-download");
  const deleteButton = document.getElementById("remote-terminal-delete");
  const startButton = document.getElementById("remote-terminal-start");
  const startStatus = document.getElementById("remote-terminal-start-status");
  const stateBadge = document.getElementById("remote-terminal-session-state");
  const sessionMessage = document.getElementById("remote-terminal-session-message");
  const sessionTitle = document.getElementById("remote-terminal-session-title");
  const sessionTarget = document.getElementById("remote-terminal-session-target");
  const empty = document.getElementById("remote-terminal-empty");
  const count = document.getElementById("remote-terminal-session-count");
  if (!screen || !window.TwnTerminalEmulator) return;
  const terminal = new window.TwnTerminalEmulator(screen, {
    onData: (data) => queueInput(data, true),
  });
  let sessions = JSON.parse(initial.textContent || "[]");
  let selected = null;
  let cursor = 0;
  let pollTimer = null;
  let polling = false;
  let inputQueue = [];
  let inputTimer = null;
  let inputSending = false;
  let composing = false;
  let resizeTimer = null;

  if (form) form.addEventListener("submit", startSession);
  surface.addEventListener("click", () => {
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed) focusTerminal();
  });
  stopButton.addEventListener("click", stopSession);
  deleteButton?.addEventListener("click", () => {
    if (selected) deleteScrollback(selected);
  });
  popoutButton?.addEventListener("click", () => {
    if (!selected) return;
    const popup = window.open(
      selected.popout_url,
      `twn-remote-session-${selected.id}`,
      "popup,width=1120,height=760,resizable=yes,scrollbars=yes"
    );
    if (!popup) showMessage("The browser blocked the pop-out window. Allow pop-ups for this toolkit and try again.");
  });
  saveHostButton?.addEventListener("click", () => {
    if (!selected) return;
    document.dispatchEvent(new CustomEvent("twn:save-session-host", {detail: selected}));
  });
  inputCapture.addEventListener("keydown", captureTerminalKey);
  inputCapture.addEventListener("input", (event) => {
    if (composing || event.isComposing) return;
    flushCapturedText();
  });
  inputCapture.addEventListener("compositionstart", () => {
    composing = true;
  });
  inputCapture.addEventListener("compositionend", () => {
    composing = false;
    flushCapturedText();
  });
  inputCapture.addEventListener("focus", updateFocusState);
  inputCapture.addEventListener("blur", updateFocusState);
  inputCapture.addEventListener("beforeinput", (event) => {
    if (event.inputType !== "deleteContentBackward") return;
    event.preventDefault();
    queueInput(terminal.keySequence("Backspace"), true);
  });
  inputCapture.addEventListener("paste", (event) => {
    const text = event.clipboardData?.getData("text");
    if (text === undefined) {
      window.setTimeout(flushCapturedText, 0);
      return;
    }
    event.preventDefault();
    inputCapture.value = "";
    queueInput(terminal.formatPaste(text), true);
  });
  document.querySelectorAll("[data-terminal-key]").forEach((button) => {
    button.addEventListener("click", () => {
      queueInput(terminalKey(button.dataset.terminalKey), true);
      focusTerminal();
    });
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && selected) pollOutput();
  });
  if (window.ResizeObserver) {
    new ResizeObserver(scheduleResize).observe(surface);
  } else {
    window.addEventListener("resize", scheduleResize);
  }

  function renderList() {
    sessions.sort((left, right) => Number(right.created_at) - Number(left.created_at));
    if (list) list.replaceChildren(...sessions.map(sessionCard));
    if (empty) empty.hidden = sessions.length > 0;
    if (count) count.textContent = `${sessions.length} retained`;
    renderTabs();
  }

  function renderTabs() {
    if (!tabs) return;
    const activeSessions = sessions
      .filter(active)
      .sort((left, right) => Number(left.created_at) - Number(right.created_at));
    tabs.replaceChildren(...activeSessions.map((session) => {
      const tab = document.createElement("button");
      tab.type = "button";
      tab.className = `remote-terminal-tab ${session.state}`;
      tab.setAttribute("role", "tab");
      tab.setAttribute("aria-selected", String(selected?.id === session.id));
      tab.title = `${session.remote_username}@${session.host}:${session.port}`;
      const dot = document.createElement("span");
      dot.className = "remote-terminal-tab-dot";
      dot.setAttribute("aria-hidden", "true");
      const label = document.createElement("span");
      label.textContent = session.title;
      tab.append(dot, label);
      tab.addEventListener("click", () => openSession(session));
      return tab;
    }));
    tabs.classList.toggle("empty", !activeSessions.length);
    if (newSessionButton) newSessionButton.hidden = !activeSessions.length;
  }

  function sessionCard(session) {
    const card = document.createElement("article");
    card.className = `remote-terminal-session-card ${session.state}`;
    const identity = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = session.title;
    const target = document.createElement("span");
    target.textContent = `${session.remote_username}@${session.host}:${session.port}`;
    const metadata = document.createElement("small");
    metadata.textContent = `${stateLabel(session)} · ${formatTime(session.created_at)}`;
    identity.append(heading, target, metadata);
    const actions = document.createElement("div");
    actions.className = "remote-terminal-session-card-actions";
    const open = document.createElement("button");
    open.type = "button";
    open.className = "secondary remote-terminal-history-action";
    const openLabel = active(session) ? "Open session" : "View scrollback";
    open.setAttribute("aria-label", openLabel);
    open.title = openLabel;
    open.append(terminalActionIcon("view"));
    open.addEventListener("click", () => openSession(session));
    const download = document.createElement("a");
    download.className = "button-link secondary remote-terminal-history-action";
    download.href = session.download_url;
    download.download = "";
    download.setAttribute("aria-label", "Download scrollback");
    download.title = "Download scrollback";
    download.append(terminalActionIcon("download"));
    actions.append(open, download);
    if (!active(session)) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger remote-terminal-history-action";
      remove.setAttribute("aria-label", "Delete scrollback");
      remove.title = "Delete scrollback";
      remove.append(terminalActionIcon("delete"));
      remove.addEventListener("click", () => deleteScrollback(session));
      actions.append(remove);
    }
    card.append(identity, actions);
    return card;
  }

  function terminalActionIcon(name) {
    const namespace = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(namespace, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const definitions = {
      view: [
        ["path", {d: "M2.5 12s3.4-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.4 6.5-9.5 6.5S2.5 12 2.5 12Z"}],
        ["circle", {cx: "12", cy: "12", r: "2.75"}],
      ],
      download: [
        ["path", {d: "M12 3v12m-4-4 4 4 4-4M5 20h14"}],
      ],
      delete: [
        ["path", {d: "M4 7h16M9 7V4h6v3m-8 0 1 14h8l1-14M10 11v6m4-6v6"}],
      ],
    };
    (definitions[name] || []).forEach(([tag, attributes]) => {
      const element = document.createElementNS(namespace, tag);
      Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
      svg.append(element);
    });
    return svg;
  }

  async function startSession(event) {
    event.preventDefault();
    const credentialMode = form.querySelector('input[name="quick_credential_mode"]:checked')?.value || "temporary";
    const payload = {
      title: document.getElementById("remote-terminal-title").value,
      host: document.getElementById("remote-terminal-host").value,
      port: document.getElementById("remote-terminal-port").value,
      username: document.getElementById("remote-terminal-username").value,
      password: document.getElementById("remote-terminal-password").value,
      credential_id: credentialMode === "saved"
        ? document.getElementById("remote-terminal-credential").value
        : "",
      allow_unknown_hosts: document.getElementById("remote-terminal-unknown-host").checked,
      allow_legacy_algorithms: document.getElementById("remote-terminal-legacy").checked,
      record_transcript: document.getElementById("remote-terminal-transcript").checked,
      columns: terminalColumns(),
      rows: 32,
    };
    try {
      await startPayload(payload, {button: startButton, status: startStatus});
      document.getElementById("remote-terminal-password").value = "";
    } catch (_error) {
      // startPayload renders the actionable message beside the initiating control.
    }
  }

  async function startPayload(payload, controls = {}) {
    const button = controls.button || null;
    const status = controls.status || null;
    if (!form?.dataset.startUrl) throw new Error("New sessions must be started from the full workspace.");
    if (button) button.disabled = true;
    if (status) status.textContent = "Starting secure session…";
    try {
      const response = await fetch(form.dataset.startUrl, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The SSH session could not be started.");
      upsert(data.session);
      renderList();
      await openSession(data.session);
      if (status) status.textContent = data.session.investigation_id
        ? "Started and attached to the active case."
        : "Session started.";
      if (window.TwnLiveTools) window.TwnLiveTools.refresh();
      document.dispatchEvent(new CustomEvent("twn:remote-session-started", {detail: data.session}));
      return data.session;
    } catch (error) {
      if (status) status.textContent = error.message;
      else showMessage(error.message);
      throw error;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function openSession(session) {
    clearTimeout(pollTimer);
    selected = session;
    cursor = 0;
    workspace.hidden = false;
    if (stageEmpty) stageEmpty.hidden = true;
    terminal.reset(terminalColumns(), terminalRows());
    workspace.scrollIntoView({behavior: "smooth", block: "start"});
    updateWorkspace(session);
    await pollOutput();
    if (selected?.state === "running") focusTerminal();
    resizeRemote();
  }

  async function pollOutput() {
    if (!selected || polling) return;
    const pollingSession = selected;
    polling = true;
    try {
      const response = await fetch(`${pollingSession.output_url}?after=${cursor}`, {
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Terminal output is unavailable.");
      if (!selected || selected.id !== pollingSession.id) return;
      selected = data.session;
      upsert(selected);
      data.chunks.forEach((chunk) => appendOutput(chunk.output));
      cursor = Number(data.next_cursor || cursor);
      updateWorkspace(selected);
      renderList();
    } catch (error) {
      showMessage(error.message);
    } finally {
      polling = false;
      schedulePoll();
    }
  }

  function schedulePoll() {
    clearTimeout(pollTimer);
    if (!selected) return;
    const delay = document.hidden ? 5000 : active(selected) ? 250 : 2000;
    pollTimer = setTimeout(pollOutput, delay);
  }

  function queueInput(data, immediate) {
    if (!selected || selected.state !== "running" || !data) return;
    const item = {
      sessionId: selected.id,
      url: selected.input_url,
      data,
    };
    const last = inputQueue[inputQueue.length - 1];
    if (last && last.sessionId === item.sessionId && last.data.length + data.length <= 4000) {
      last.data += data;
    } else {
      inputQueue.push(item);
    }
    window.clearTimeout(inputTimer);
    inputTimer = window.setTimeout(flushInputQueue, immediate ? 0 : 30);
  }

  async function flushInputQueue() {
    if (inputSending || !inputQueue.length) return;
    inputSending = true;
    const item = inputQueue.shift();
    try {
      const response = await fetch(item.url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({data: item.data}),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Terminal input was not delivered.");
      if (selected && selected.id === item.sessionId) pollOutput();
    } catch (error) {
      showMessage(`${error.message} The toolkit did not retry it, so terminal input cannot be duplicated.`);
    } finally {
      inputSending = false;
      if (inputQueue.length) flushInputQueue();
    }
  }

  function flushCapturedText() {
    const value = inputCapture.value;
    inputCapture.value = "";
    if (!value) return;
    queueInput(value.replace(/\r\n|\n|\r/g, "\r"));
  }

  function captureTerminalKey(event) {
    const data = keyboardSequence(event);
    if (!data) return;
    event.preventDefault();
    inputCapture.value = "";
    queueInput(data, true);
  }

  function keyboardSequence(event) {
    if (event.metaKey) return "";
    if (event.shiftKey && !event.ctrlKey && !event.altKey && event.key === "Tab") {
      return "\u001b[Z";
    }
    if (event.ctrlKey && !event.altKey) {
      const key = event.key.toUpperCase();
      if (key.length === 1 && key >= "A" && key <= "Z") {
        return String.fromCharCode(key.charCodeAt(0) - 64);
      }
      return {"@": "\u0000", " ": "\u0000", "[": "\u001b", "\\": "\u001c", "]": "\u001d", "^": "\u001e", "_": "\u001f"}[event.key] || "";
    }
    if (event.altKey && !event.ctrlKey && event.key.length === 1) {
      return `\u001b${event.key}`;
    }
    return terminal.keySequence(event.key);
  }

  async function stopSession() {
    if (!selected || !active(selected)) return;
    if (!window.confirm(`Stop '${selected.title}'? The SSH connection will close.`)) return;
    stopButton.disabled = true;
    try {
      const response = await fetch(selected.stop_url, {
        method: "POST",
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The remote session could not be stopped.");
      selected = data.session;
      upsert(selected);
      updateWorkspace(selected);
      renderList();
      pollOutput();
      if (window.TwnLiveTools) window.TwnLiveTools.refresh();
    } catch (error) {
      showMessage(error.message);
      stopButton.disabled = false;
    }
  }

  async function deleteScrollback(session) {
    if (active(session)) {
      showMessage("Stop the remote session before deleting its retained history.");
      return;
    }
    const evidenceNote = session.investigation_id
      ? " Any finalized case evidence will remain attached to the case."
      : "";
    if (!window.confirm(`Delete the retained history for '${session.title}'?${evidenceNote}`)) return;
    try {
      const response = await fetch(session.delete_url, {
        method: "DELETE",
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The retained history could not be deleted.");
      sessions = sessions.filter((item) => item.id !== session.id);
      inputQueue = inputQueue.filter((item) => item.sessionId !== session.id);
      if (selected?.id === session.id) {
        clearTimeout(pollTimer);
        selected = null;
        cursor = 0;
        terminal.reset(terminalColumns(), terminalRows());
        workspace.hidden = true;
        if (stageEmpty) stageEmpty.hidden = false;
      }
      renderList();
    } catch (error) {
      showMessage(error.message);
    }
  }

  function updateWorkspace(session) {
    sessionTitle.textContent = session.title;
    sessionTarget.textContent = `${session.remote_username}@${session.host}:${session.port}`;
    stateBadge.textContent = stateLabel(session);
    stateBadge.className = `status-pill ${session.state}`;
    const isActive = active(session);
    inputCapture.disabled = session.state !== "running";
    surface.classList.toggle("input-disabled", inputCapture.disabled);
    document.querySelectorAll("[data-terminal-key]").forEach((button) => {
      button.disabled = inputCapture.disabled;
    });
    stopButton.hidden = !isActive;
    stopButton.disabled = !isActive;
    if (popoutButton) popoutButton.hidden = !isActive;
    if (saveHostButton) saveHostButton.hidden = Boolean(session.source_host_id);
    if (downloadButton) {
      downloadButton.href = session.download_url;
      downloadButton.hidden = !session.download_url;
    }
    if (deleteButton) deleteButton.hidden = isActive;
    if (session.last_error) showMessage(session.last_error);
    else if (session.output_truncated) showMessage("Reconnect scrollback reached its 10 MiB retention limit.");
    else sessionMessage.hidden = true;
    updateFocusState();
  }

  function appendOutput(chunk) {
    terminal.write(chunk);
  }

  function resizeRemote() {
    if (!selected || selected.state !== "running") return;
    const columns = terminalColumns();
    const rows = terminalRows();
    terminal.resize(columns, rows);
    fetch(selected.resize_url, {
      method: "POST",
      headers: {"Accept": "application/json", "Content-Type": "application/json"},
      body: JSON.stringify({columns, rows}),
    }).catch(() => {});
  }

  function scheduleResize() {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(resizeRemote, 150);
  }

  function terminalColumns() {
    return Math.max(40, Math.min(200, Math.floor((screen?.clientWidth || 960) / 8)));
  }

  function terminalRows() {
    return Math.max(10, Math.min(120, Math.floor((screen?.clientHeight || 500) / 21)));
  }

  function terminalKey(name) {
    return {
      "ctrl-c": "\u0003",
      "ctrl-d": "\u0004",
      backspace: terminal.keySequence("Backspace"),
      tab: "\t",
      up: terminal.keySequence("ArrowUp"),
      down: terminal.keySequence("ArrowDown"),
      escape: "\u001b",
    }[name] || "";
  }

  function focusTerminal() {
    if (inputCapture.disabled) return;
    inputCapture.focus({preventScroll: true});
    updateFocusState();
  }

  function updateFocusState() {
    if (inputCapture.disabled) focusState.textContent = active(selected || {}) ? "Connecting…" : "Read-only scrollback";
    else if (document.activeElement === inputCapture) focusState.textContent = "Typing in terminal";
    else focusState.textContent = "Click or tap to type";
  }

  function active(session) {
    return session.state === "connecting" || session.state === "running";
  }

  function stateLabel(session) {
    return {
      connecting: "Connecting",
      running: "Connected",
      stopped: "Stopped",
      error: "Connection error",
      interrupted: "Interrupted by restart",
    }[session.state] || session.state;
  }

  function showMessage(message) {
    sessionMessage.textContent = message;
    sessionMessage.hidden = false;
  }

  function upsert(session) {
    const index = sessions.findIndex((item) => item.id === session.id);
    if (index >= 0) sessions[index] = session;
    else sessions.push(session);
  }

  function formatTime(epoch) {
    return new Date(Number(epoch) * 1000).toLocaleString();
  }

  renderList();
  const requested = workspace.dataset.requestedSession;
  if (requested) {
    const match = sessions.find((session) => session.id === requested);
    if (match) openSession(match);
  }
  window.TwnRemoteTerminal = {
    start: startPayload,
    open: openSession,
    sessions: () => sessions.map((session) => ({...session})),
  };
})();
