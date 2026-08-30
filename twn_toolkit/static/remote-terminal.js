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
  const heightResizer = document.getElementById("remote-terminal-height-resizer");
  const widthControl = document.getElementById("remote-terminal-width");
  const screen = document.getElementById("remote-terminal-screen");
  const inputCapture = document.getElementById("remote-terminal-input-capture");
  const focusState = document.getElementById("remote-terminal-focus-state");
  const jumpLiveButton = document.getElementById("remote-terminal-jump-live");
  const jumpLiveLabel = document.getElementById("remote-terminal-jump-live-label");
  const stopButton = document.getElementById("remote-terminal-stop");
  const popoutButton = document.getElementById("remote-terminal-popout");
  const saveHostButton = document.getElementById("remote-terminal-save-host");
  const sessionMenu = document.getElementById("remote-terminal-session-menu");
  const attachCaseButton = document.getElementById("remote-terminal-attach-case");
  const caseLink = document.getElementById("remote-terminal-case-link");
  const saveDatastoreButton = document.getElementById("remote-terminal-save-datastore");
  const transcriptButton = document.getElementById("remote-terminal-transcript-view");
  const downloadButton = document.getElementById("remote-terminal-download");
  const deleteButton = document.getElementById("remote-terminal-delete");
  const startButton = document.getElementById("remote-terminal-start");
  const startStatus = document.getElementById("remote-terminal-start-status");
  const stateBadge = document.getElementById("remote-terminal-session-state");
  const sessionMessage = document.getElementById("remote-terminal-session-message");
  const sessionTitle = document.getElementById("remote-terminal-session-title");
  const sessionProtocol = document.getElementById("remote-terminal-session-protocol");
  const sessionRenameButton = document.getElementById("remote-terminal-session-rename");
  const renameDialog = document.getElementById("remote-terminal-rename-dialog");
  const renameForm = document.getElementById("remote-terminal-rename-form");
  const renameInput = document.getElementById("remote-terminal-rename-input");
  const renameStatus = document.getElementById("remote-terminal-rename-status");
  const renameSave = document.getElementById("remote-terminal-rename-save");
  const renameCancel = document.getElementById("remote-terminal-rename-cancel");
  const renameDismiss = document.getElementById("remote-terminal-rename-dismiss");
  const datastoreDialog = document.getElementById("remote-terminal-datastore-dialog");
  const datastoreForm = document.getElementById("remote-terminal-datastore-form");
  const datastoreFolder = document.getElementById("remote-terminal-datastore-folder");
  const datastoreCopy = document.getElementById("remote-terminal-datastore-copy");
  const datastoreStatus = document.getElementById("remote-terminal-datastore-status");
  const datastoreSave = document.getElementById("remote-terminal-datastore-save");
  const datastoreCancel = document.getElementById("remote-terminal-datastore-cancel");
  const datastoreDismiss = document.getElementById("remote-terminal-datastore-dismiss");
  const sessionTarget = document.getElementById("remote-terminal-session-target");
  const telnetCredentialControls = document.querySelector("[data-telnet-credential-controls]");
  const telnetCredentialButtons = Array.from(
    document.querySelectorAll("[data-telnet-credential]")
  );
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
  let pollGeneration = 0;
  let pollingGeneration = -1;
  let synchronizing = false;
  let focusAfterSync = false;
  let checkpointTimer = null;
  const checkpointCursors = new Map();
  const checkpointRequests = new Set();
  const CHECKPOINT_INITIAL_DELAY = 1500;
  const CHECKPOINT_REFRESH_DELAY = 30000;
  let inputQueue = [];
  let inputTimer = null;
  let inputSending = false;
  let composing = false;
  let resizeTimer = null;
  let renameSession = null;
  let datastoreSession = null;
  let renderedSessionFingerprint = "";
  let unreadOutput = false;
  let historyGapDetected = false;
  const DEFAULT_COLUMNS = 120;
  const DEFAULT_ROWS = 32;
  const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  const activeCase = workspace.dataset.activeCaseId
    ? {id: workspace.dataset.activeCaseId, title: workspace.dataset.activeCaseTitle}
    : null;

  if (form) form.addEventListener("submit", startSession);
  surface.addEventListener("click", () => {
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed) focusTerminal();
  });
  screen.addEventListener("scroll", updateLiveFollowState);
  jumpLiveButton?.addEventListener("click", (event) => {
    event.stopPropagation();
    jumpToLive({focus: true});
  });
  widthControl?.addEventListener("change", changeTerminalWidth);
  stopButton.addEventListener("click", stopSession);
  attachCaseButton?.addEventListener("click", () => {
    if (selected) attachSessionToCase(selected, attachCaseButton);
  });
  saveDatastoreButton?.addEventListener("click", () => {
    if (selected) {
      if (sessionMenu) sessionMenu.open = false;
      openDatastoreDialog(selected);
    }
  });
  sessionRenameButton?.addEventListener("click", () => {
    if (selected) openRenameDialog(selected);
  });
  renameForm?.addEventListener("submit", saveSessionName);
  renameCancel?.addEventListener("click", closeRenameDialog);
  renameDismiss?.addEventListener("click", closeRenameDialog);
  renameDialog?.addEventListener("click", (event) => {
    if (event.target === renameDialog) closeRenameDialog();
  });
  datastoreForm?.addEventListener("submit", saveSessionToDatastore);
  datastoreCancel?.addEventListener("click", closeDatastoreDialog);
  datastoreDismiss?.addEventListener("click", closeDatastoreDialog);
  datastoreDialog?.addEventListener("click", (event) => {
    if (event.target === datastoreDialog) closeDatastoreDialog();
  });
  deleteButton?.addEventListener("click", () => {
    if (selected) {
      if (sessionMenu) sessionMenu.open = false;
      deleteScrollback(selected);
    }
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
    if (sessionMenu) sessionMenu.open = false;
    document.dispatchEvent(new CustomEvent("twn:save-session-host", {detail: selected}));
  });
  downloadButton?.addEventListener("click", () => {
    if (sessionMenu) sessionMenu.open = false;
  });
  transcriptButton?.addEventListener("click", () => {
    if (sessionMenu) sessionMenu.open = false;
  });
  document.addEventListener("click", (event) => {
    if (sessionMenu?.open && !sessionMenu.contains(event.target)) {
      sessionMenu.open = false;
    }
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
    button.addEventListener("click", async () => {
      if (button.dataset.terminalKey === "paste") {
        await pasteClipboard();
      } else {
        queueInput(terminalKey(button.dataset.terminalKey), true);
      }
      focusTerminal();
    });
  });
  telnetCredentialButtons.forEach((button) => {
    button.addEventListener("click", () => sendTelnetCredential(button));
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) persistCheckpoint();
    else if (selected) pollOutput();
  });
  window.addEventListener("pagehide", () => persistCheckpoint());
  initializeTerminalHeight();
  if (window.ResizeObserver) {
    new ResizeObserver(() => {
      updateTerminalHeightAccessibility();
    }).observe(surface);
  }

  function renderList(force = false) {
    sessions.sort((left, right) => Number(right.created_at) - Number(left.created_at));
    const fingerprint = JSON.stringify({
      selected: selected?.id || "",
      sessions: sessions.map((session) => [
        session.id,
        session.title,
        session.state,
        session.protocol,
        session.host,
        session.port,
        session.console_device_id,
        session.console_device_label,
        session.console_baud_rate,
        session.remote_username,
        session.telnet_username_available,
        session.telnet_password_available,
        session.investigation_id,
        session.record_transcript,
      ]),
    });
    if (!force && fingerprint === renderedSessionFingerprint) return;
    renderedSessionFingerprint = fingerprint;
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
    tabs.replaceChildren(...activeSessions.map(sessionTab));
    tabs.classList.toggle("empty", !activeSessions.length);
    if (newSessionButton) newSessionButton.hidden = !activeSessions.length;
  }

  function sessionTab(session) {
    const isSelected = selected?.id === session.id;
    const shell = document.createElement("div");
    shell.className = `remote-terminal-tab-shell ${session.state}${isSelected ? " selected" : ""}`;
    const tab = document.createElement("button");
    tab.type = "button";
    tab.className = "remote-terminal-tab";
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(isSelected));
    tab.title = `${protocolLabel(session)} · ${remoteTarget(session)}`;
    const dot = document.createElement("span");
    dot.className = "remote-terminal-tab-dot";
    dot.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.textContent = session.title;
    tab.append(dot, label);
    tab.addEventListener("click", () => openSession(session, {focus: true}));
    const rename = tabAction("✎", `Rename ${session.title}`, "rename");
    rename.addEventListener("click", () => openRenameDialog(session));
    const close = tabAction("×", `Close ${session.title}`, "close");
    close.addEventListener("click", () => closeSessionTab(session, close));
    shell.append(tab, rename, close);
    return shell;
  }

  function tabAction(symbol, label, action) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `remote-terminal-tab-action ${action}`;
    button.title = label.split(" ", 1)[0];
    button.setAttribute("aria-label", label);
    const icon = document.createElement("span");
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = symbol;
    button.append(icon);
    return button;
  }

  function sessionCard(session) {
    const card = document.createElement("article");
    card.className = `remote-terminal-session-card ${session.state}`;
    const identity = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = session.title;
    const target = document.createElement("span");
    target.textContent = `${protocolLabel(session)} · ${remoteTarget(session)}`;
    const metadata = document.createElement("small");
    metadata.textContent = `${stateLabel(session)} · ${formatTime(session.created_at)}`;
    identity.append(heading, target, metadata);
    if (session.investigation_id) {
      const caseMetadata = document.createElement("small");
      caseMetadata.className = "remote-terminal-session-case";
      caseMetadata.textContent = session.record_transcript
        ? `Transcript · ${session.investigation_title || "Attached case"}`
        : `Activity · ${session.investigation_title || "Attached case"}`;
      identity.append(caseMetadata);
    }
    const actions = document.createElement("div");
    actions.className = "remote-terminal-session-card-actions";
    const open = document.createElement("button");
    open.type = "button";
    open.className = "secondary remote-terminal-history-action";
    const openLabel = active(session) ? "Open session" : "View scrollback";
    open.setAttribute("aria-label", openLabel);
    open.title = openLabel;
    open.append(terminalActionIcon("view"));
    open.addEventListener("click", () => openSession(session, {reveal: true, focus: true}));
    const download = document.createElement("a");
    download.className = "button-link secondary remote-terminal-history-action";
    download.href = session.download_url;
    download.download = "";
    download.setAttribute("aria-label", "Download scrollback");
    download.title = "Download scrollback";
    download.append(terminalActionIcon("download"));
    actions.append(open, download);
    if (datastoreDialog) {
      const save = document.createElement("button");
      save.type = "button";
      save.className = "secondary remote-terminal-history-action";
      save.setAttribute("aria-label", "Save scrollback to Datastore");
      save.title = "Save to Datastore";
      save.append(terminalActionIcon("datastore"));
      save.addEventListener("click", () => openDatastoreDialog(session));
      actions.append(save);
    }
    if (canAttachToActiveCase(session)) {
      const attach = document.createElement("button");
      attach.type = "button";
      attach.className = "secondary remote-terminal-history-action";
      attach.setAttribute("aria-label", `Attach ${session.title} to active case`);
      attach.title = "Attach to active case";
      attach.append(terminalActionIcon("case"));
      attach.addEventListener("click", () => attachSessionToCase(session, attach));
      actions.append(attach);
    }
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
      datastore: [
        ["path", {d: "M3 7.5h7l2 2h9v9.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7.5Z"}],
        ["path", {d: "M3 7.5V5a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v2.5"}],
        ["path", {d: "M12 12v6m-2-2 2 2 2-2"}],
      ],
      case: [
        ["path", {d: "M9.5 14.5 14.8 9.2a3 3 0 1 1 4.2 4.2l-6.7 6.7a5 5 0 0 1-7.1-7.1l7.1-7.1"}],
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
      protocol: document.getElementById("remote-terminal-protocol").value,
      title: document.getElementById("remote-terminal-title").value,
      host: document.getElementById("remote-terminal-host").value,
      port: document.getElementById("remote-terminal-port").value,
      username: credentialMode === "temporary"
        ? document.getElementById("remote-terminal-username").value
        : "",
      password: credentialMode === "temporary"
        ? document.getElementById("remote-terminal-password").value
        : "",
      credential_id: credentialMode === "saved"
        ? document.getElementById("remote-terminal-credential").value
        : "",
      allow_unknown_hosts: document.getElementById("remote-terminal-unknown-host").checked,
      allow_legacy_algorithms: document.getElementById("remote-terminal-legacy").checked,
      console_device_id: document.getElementById("remote-terminal-console-device").value,
      console_baud_rate: document.getElementById("remote-terminal-console-baud").value,
      console_data_bits: document.getElementById("remote-terminal-console-data-bits").value,
      console_parity: document.getElementById("remote-terminal-console-parity").value,
      console_stop_bits: document.getElementById("remote-terminal-console-stop-bits").value,
      console_flow_control: document.getElementById("remote-terminal-console-flow").value,
      columns: DEFAULT_COLUMNS,
      rows: DEFAULT_ROWS,
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
    if (status) status.textContent = "Starting remote session…";
    try {
      const response = await fetch(form.dataset.startUrl, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The remote session could not be started.");
      upsert(data.session);
      renderList();
      await openSession(data.session, {reveal: true, focus: true});
      if (status) {
        status.textContent = data.session.record_transcript
          ? "Started with transcript capture attached to the active case."
          : data.session.investigation_id
            ? "Started with session activity attached to the active case."
            : "Session started.";
      }
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

  async function openSession(session, options = {}) {
    const reveal = Boolean(options.reveal);
    const requestFocus = Boolean(options.focus);
    persistCheckpoint();
    clearTimeout(pollTimer);
    clearTimeout(checkpointTimer);
    checkpointTimer = null;
    pollGeneration += 1;
    selected = session;
    cursor = 0;
    synchronizing = true;
    unreadOutput = false;
    historyGapDetected = false;
    focusAfterSync = requestFocus;
    workspace.hidden = false;
    if (stageEmpty) stageEmpty.hidden = true;
    terminal.reset(sessionColumns(session), sessionRows(session));
    if (reveal) workspace.scrollIntoView({behavior: "smooth", block: "start"});
    updateWorkspace(session);
    await pollOutput({bootstrap: true, generation: pollGeneration});
    if (
      focusAfterSync
      && !synchronizing
      && finePointer.matches
      && selected?.state === "running"
      && !editable(document.activeElement)
    ) {
      focusAfterSync = false;
      focusTerminal();
    }
  }

  async function pollOutput(options = {}) {
    if (!selected) return;
    const generation = Number(options.generation ?? pollGeneration);
    if (pollingGeneration === generation) return;
    const pollingSession = selected;
    const requestCursor = cursor;
    const bootstrap = Boolean(options.bootstrap && requestCursor === 0);
    pollingGeneration = generation;
    let pollImmediately = false;
    try {
      const suffix = bootstrap ? "&bootstrap=1" : "";
      const response = await fetch(`${pollingSession.output_url}?after=${requestCursor}${suffix}`, {
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Terminal output is unavailable.");
      if (
        generation !== pollGeneration
        || !selected
        || selected.id !== pollingSession.id
      ) return;
      selected = data.session;
      upsert(selected);
      if (data.checkpoint) {
        const restored = terminal.restore(data.checkpoint.snapshot);
        if (!restored) {
          terminal.reset(sessionColumns(selected), sessionRows(selected));
          cursor = 0;
          pollImmediately = true;
          return;
        }
        cursor = Number(data.checkpoint.cursor || 0);
        checkpointCursors.set(selected.id, cursor);
      }
      syncTerminalGeometry(selected);
      if (data.history_gap) historyGapDetected = true;
      appendOutput(data.chunks.map((chunk) => chunk.output).join(""));
      cursor = Number(data.next_cursor || cursor);
      pollImmediately = Boolean(data.has_more);
      const wasSynchronizing = synchronizing;
      // Multiple pages are also normal during a large live-output burst. Only an
      // initial restore may keep the input disabled while those pages catch up;
      // a running terminal must never lose focus merely because live output is
      // arriving faster than one response page can carry it.
      synchronizing = wasSynchronizing && pollImmediately;
      updateWorkspace(selected);
      renderList();
      if (!synchronizing) {
        scheduleCheckpoint();
        if (wasSynchronizing) {
          if (
            focusAfterSync
            && finePointer.matches
            && selected.state === "running"
            && !editable(document.activeElement)
          ) {
            focusAfterSync = false;
            focusTerminal();
          }
        }
      }
    } catch (error) {
      showMessage(error.message);
    } finally {
      if (pollingGeneration === generation) pollingGeneration = -1;
      if (generation === pollGeneration) schedulePoll(pollImmediately);
    }
  }

  function schedulePoll(immediate = false) {
    clearTimeout(pollTimer);
    if (!selected) return;
    const delay = immediate ? 0 : document.hidden ? 5000 : active(selected) ? 250 : 2000;
    const generation = pollGeneration;
    pollTimer = setTimeout(() => pollOutput({generation}), delay);
  }

  function scheduleCheckpoint() {
    if (
      checkpointTimer
      || synchronizing
      || !selected?.checkpoint_url
      || cursor <= Number(checkpointCursors.get(selected.id) || 0)
    ) return;
    const delay = checkpointCursors.has(selected.id)
      ? CHECKPOINT_REFRESH_DELAY
      : CHECKPOINT_INITIAL_DELAY;
    checkpointTimer = window.setTimeout(() => {
      checkpointTimer = null;
      persistCheckpoint();
    }, delay);
  }

  async function persistCheckpoint() {
    if (
      synchronizing
      || !selected?.checkpoint_url
      || cursor <= Number(checkpointCursors.get(selected.id) || 0)
      || checkpointRequests.has(selected.id)
    ) return;
    const session = selected;
    const checkpointCursor = cursor;
    const snapshot = terminal.serialize({historyLimit: 12000});
    checkpointRequests.add(session.id);
    try {
      const response = await fetch(session.checkpoint_url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({cursor: checkpointCursor, snapshot}),
      });
      if (response.ok) {
        checkpointCursors.set(
          session.id,
          Math.max(checkpointCursor, Number(checkpointCursors.get(session.id) || 0))
        );
      }
    } catch (_error) {
      // Checkpoints are an optimization. Raw output replay remains the safe fallback.
    } finally {
      checkpointRequests.delete(session.id);
      if (
        selected?.id === session.id
        && cursor > Number(checkpointCursors.get(session.id) || 0)
      ) scheduleCheckpoint();
    }
  }

  function queueInput(data, immediate) {
    if (!selected || selected.state !== "running" || !data) return;
    jumpToLive({focus: false});
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

  function openRenameDialog(session) {
    if (!renameDialog || !renameInput) return;
    renameSession = session;
    renameInput.value = session.title || "";
    renameInput.setCustomValidity("");
    if (renameStatus) renameStatus.textContent = "";
    renameDialog.showModal();
    renameInput.focus();
    renameInput.select();
  }

  function closeRenameDialog() {
    renameSession = null;
    if (renameDialog?.open) renameDialog.close();
  }

  async function saveSessionName(event) {
    event.preventDefault();
    if (!renameSession || !renameInput) return;
    const session = renameSession;
    const title = renameInput.value.trim().replace(/\s+/g, " ");
    if (!title) {
      renameInput.setCustomValidity("Enter a name for this remote session.");
      renameInput.reportValidity();
      return;
    }
    renameInput.setCustomValidity("");
    renameInput.disabled = true;
    if (renameSave) renameSave.disabled = true;
    if (renameCancel) renameCancel.disabled = true;
    if (renameDismiss) renameDismiss.disabled = true;
    if (renameStatus) renameStatus.textContent = "Saving session name…";
    try {
      const response = await fetch(session.rename_url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({title}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The remote session could not be renamed.");
      upsert(data.session);
      if (selected?.id === data.session.id) {
        selected = data.session;
        updateWorkspace(selected);
      }
      renderList();
      if (window.TwnLiveTools) window.TwnLiveTools.refresh();
      closeRenameDialog();
    } catch (error) {
      if (renameStatus) renameStatus.textContent = error.message;
      renameInput.focus();
    } finally {
      renameInput.disabled = false;
      if (renameSave) renameSave.disabled = false;
      if (renameCancel) renameCancel.disabled = false;
      if (renameDismiss) renameDismiss.disabled = false;
    }
  }

  function canAttachToActiveCase(session) {
    return Boolean(
      activeCase
      && session.attach_case_url
      && !session.record_transcript
      && (!session.investigation_id || session.investigation_id === activeCase.id)
    );
  }

  async function attachSessionToCase(session, control) {
    if (!canAttachToActiveCase(session)) return;
    const description = active(session)
      ? "The final evidence will include all retained scrollback, including output produced before attachment. Capture will continue until the session ends."
      : "The retained scrollback will be copied into the case evidence library now.";
    if (!window.confirm(`Attach '${session.title}' to '${activeCase.title}'? ${description}`)) return;
    if (control) control.disabled = true;
    try {
      const response = await fetch(session.attach_case_url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({investigation_id: activeCase.id}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The remote session could not be attached to the case.");
      upsert(data.session);
      if (selected?.id === data.session.id) {
        selected = data.session;
        updateWorkspace(selected);
        showMessage(
          active(data.session)
            ? `Transcript capture is attached to ${data.session.investigation_title || activeCase.title}.`
            : `The retained transcript was added to ${data.session.investigation_title || activeCase.title}.`,
          "success"
        );
      }
      renderList();
      if (window.TwnLiveTools) window.TwnLiveTools.refresh();
    } catch (error) {
      showMessage(error.message);
      if (control) control.disabled = false;
    }
  }

  function openDatastoreDialog(session) {
    if (!datastoreDialog || !datastoreFolder) return;
    datastoreSession = session;
    if (datastoreStatus) datastoreStatus.textContent = "";
    if (datastoreCopy) {
      datastoreCopy.textContent = active(session)
        ? "This saves the output retained so far as a snapshot. The remote session remains connected and later output is not added to that file."
        : "This saves the completed retained scrollback as a text file. Repeated saves receive a new filename and never overwrite an existing file.";
    }
    datastoreDialog.showModal();
    datastoreFolder.focus();
  }

  function closeDatastoreDialog() {
    datastoreSession = null;
    if (datastoreDialog?.open) datastoreDialog.close();
  }

  async function saveSessionToDatastore(event) {
    event.preventDefault();
    if (!datastoreSession || !datastoreFolder) return;
    const session = datastoreSession;
    datastoreFolder.disabled = true;
    if (datastoreSave) datastoreSave.disabled = true;
    if (datastoreCancel) datastoreCancel.disabled = true;
    if (datastoreDismiss) datastoreDismiss.disabled = true;
    if (datastoreStatus) datastoreStatus.textContent = "Saving terminal output…";
    try {
      const response = await fetch(session.datastore_url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({folder: datastoreFolder.value}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The terminal output could not be saved.");
      closeDatastoreDialog();
      if (selected?.id === session.id) {
        showMessage(
          `Saved ${data.saved.kind} to Datastore/${data.saved.path}.`,
          "success"
        );
      }
    } catch (error) {
      if (datastoreStatus) datastoreStatus.textContent = error.message;
      datastoreFolder.focus();
    } finally {
      datastoreFolder.disabled = false;
      if (datastoreSave) datastoreSave.disabled = false;
      if (datastoreCancel) datastoreCancel.disabled = false;
      if (datastoreDismiss) datastoreDismiss.disabled = false;
    }
  }

  async function stopSession() {
    if (!selected || !active(selected)) return;
    if (!window.confirm(`Stop '${selected.title}'? The remote connection will close.`)) return;
    stopButton.disabled = true;
    await stopRemoteSession(selected, {dismiss: false, control: stopButton});
  }

  async function sendTelnetCredential(button) {
    if (!selected || selected.state !== "running" || selected.protocol !== "telnet") return;
    const field = button.dataset.telnetCredential;
    button.disabled = true;
    try {
      const response = await fetch(selected.credential_url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({field}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `The Telnet ${field} could not be sent.`);
      showMessage(`${field === "username" ? "Username" : "Password"} sent to the Telnet session.`, "success");
      focusTerminal();
    } catch (error) {
      showMessage(error.message);
    } finally {
      button.disabled = !selected || selected.state !== "running";
    }
  }

  async function closeSessionTab(session, control) {
    if (!active(session)) return;
    if (!window.confirm(
      `Close '${session.title}'? The remote connection will stop, but its scrollback will remain in Recent sessions.`
    )) return;
    control.disabled = true;
    await stopRemoteSession(session, {dismiss: true, control});
  }

  async function stopRemoteSession(session, {dismiss, control}) {
    const activeBefore = sessions
      .filter(active)
      .sort((left, right) => Number(left.created_at) - Number(right.created_at));
    const closedIndex = activeBefore.findIndex((item) => item.id === session.id);
    try {
      const response = await fetch(session.stop_url, {
        method: "POST",
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The remote session could not be stopped.");
      upsert(data.session);
      const closingSelected = selected?.id === session.id;
      if (dismiss && closingSelected) {
        const remaining = sessions
          .filter(active)
          .sort((left, right) => Number(left.created_at) - Number(right.created_at));
        const replacement = remaining[Math.min(closedIndex, remaining.length - 1)];
        if (replacement) await openSession(replacement, {focus: true});
        else clearSelectedSession();
      } else if (closingSelected) {
        selected = data.session;
        updateWorkspace(selected);
        pollOutput();
      }
      renderList();
      if (window.TwnLiveTools) window.TwnLiveTools.refresh();
    } catch (error) {
      showMessage(error.message);
      if (control) control.disabled = false;
    }
  }

  function clearSelectedSession() {
    persistCheckpoint();
    clearTimeout(pollTimer);
    clearTimeout(checkpointTimer);
    checkpointTimer = null;
    pollGeneration += 1;
    selected = null;
    cursor = 0;
    synchronizing = false;
    focusAfterSync = false;
    unreadOutput = false;
    historyGapDetected = false;
    inputQueue = [];
    terminal.reset(DEFAULT_COLUMNS, DEFAULT_ROWS);
    workspace.hidden = true;
    if (stageEmpty) stageEmpty.hidden = false;
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
        terminal.reset(DEFAULT_COLUMNS, DEFAULT_ROWS);
        workspace.hidden = true;
        if (stageEmpty) stageEmpty.hidden = false;
      }
      renderList();
    } catch (error) {
      showMessage(error.message);
    }
  }

  function updateWorkspace(session) {
    syncTerminalGeometry(session);
    sessionTitle.textContent = session.title;
    if (sessionProtocol) sessionProtocol.textContent = `${protocolLabel(session)} session`;
    sessionTarget.textContent = remoteTarget(session);
    if (caseLink) {
      caseLink.hidden = !session.investigation_id;
      if (session.investigation_id) {
        caseLink.href = session.investigation_url || "#";
        caseLink.textContent = session.record_transcript
          ? `Transcript captured in ${session.investigation_title || "attached case"}`
          : `Session activity recorded in ${session.investigation_title || "attached case"}`;
      }
    }
    if (attachCaseButton) {
      attachCaseButton.hidden = !canAttachToActiveCase(session);
      attachCaseButton.title = activeCase
        ? `Attach retained output to ${activeCase.title}`
        : "Open a case before attaching retained output";
    }
    if (sessionRenameButton) sessionRenameButton.hidden = !session.rename_url;
    if (workspace.dataset.popout === "true") {
      document.title = `${session.title} · Remote Terminal`;
    }
    stateBadge.textContent = stateLabel(session);
    stateBadge.className = `status-pill ${session.state}`;
    const isActive = active(session);
    if (widthControl) widthControl.disabled = !isActive;
    const inputDisabled = session.state !== "running" || synchronizing;
    if (inputCapture.disabled !== inputDisabled) inputCapture.disabled = inputDisabled;
    surface.classList.toggle("input-disabled", inputDisabled);
    document.querySelectorAll("[data-terminal-key]").forEach((button) => {
      if (button.disabled !== inputDisabled) button.disabled = inputDisabled;
    });
    const telnetCredentialAvailable = session.protocol === "telnet"
      && session.state === "running"
      && (session.telnet_username_available || session.telnet_password_available);
    if (telnetCredentialControls) telnetCredentialControls.hidden = !telnetCredentialAvailable;
    telnetCredentialButtons.forEach((button) => {
      const available = button.dataset.telnetCredential === "username"
        ? session.telnet_username_available
        : session.telnet_password_available;
      button.hidden = !available;
      button.disabled = !telnetCredentialAvailable || !available;
    });
    stopButton.hidden = !isActive;
    stopButton.disabled = !isActive;
    if (popoutButton) popoutButton.hidden = !isActive;
    if (saveHostButton) saveHostButton.hidden = Boolean(session.source_host_id);
    if (transcriptButton) {
      transcriptButton.href = session.transcript_url;
      transcriptButton.hidden = !session.transcript_url;
    }
    if (downloadButton) {
      downloadButton.href = session.download_url;
      downloadButton.hidden = !session.download_url;
    }
    if (deleteButton) deleteButton.hidden = isActive;
    if (session.last_error) showMessage(session.last_error);
    else if (session.output_truncated) {
      showMessage("The retained transcript reached 100 MiB. Live output continues, but later output is available only in the interactive session.");
    } else if (historyGapDetected || terminal.hasTrimmedHistory()) {
      showMessage("Earlier output is outside this interactive view. The retained transcript remains available from Session actions.");
    }
    else sessionMessage.hidden = true;
    updateFocusState();
  }

  function appendOutput(chunk) {
    if (!chunk) return;
    const followingLive = terminal.isNearBottom();
    terminal.write(chunk);
    if (!followingLive) unreadOutput = true;
    updateLiveFollowState();
  }

  function updateLiveFollowState() {
    if (!jumpLiveButton) return;
    const reviewingHistory = terminal.hasOutput && !terminal.isNearBottom();
    if (!reviewingHistory) unreadOutput = false;
    jumpLiveButton.hidden = !reviewingHistory;
    if (jumpLiveLabel) {
      jumpLiveLabel.textContent = unreadOutput ? "New output · Jump to live" : "Jump to live";
    }
  }

  function jumpToLive(options = {}) {
    unreadOutput = false;
    terminal.scrollToBottom();
    terminal.scrollToCursor();
    updateLiveFollowState();
    if (options.focus) focusTerminal();
  }

  function remoteTarget(session) {
    if (session.protocol === "console") {
      const parity = String(session.console_parity || "none").charAt(0).toUpperCase();
      return `${session.console_device_label || session.console_device_path || "Console device"} · ${session.console_baud_rate} ${session.console_data_bits}${parity}${session.console_stop_bits}`;
    }
    const username = String(session.remote_username || "").trim();
    return `${username ? `${username}@` : ""}${session.host}:${session.port}`;
  }

  async function resizeRemote(columns, rows) {
    if (!selected || selected.state !== "running") return;
    const session = selected;
    const previousColumns = sessionColumns(session);
    const previousRows = sessionRows(session);
    session.terminal_columns = columns;
    session.terminal_rows = rows;
    terminal.resize(columns, rows);
    syncWidthControl(columns);
    try {
      const response = await fetch(session.resize_url, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify({columns, rows}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The terminal size could not be changed.");
      upsert(session);
    } catch (error) {
      session.terminal_columns = previousColumns;
      session.terminal_rows = previousRows;
      terminal.resize(previousColumns, previousRows);
      syncWidthControl(previousColumns);
      showMessage(error.message);
    }
  }

  function scheduleRowResize() {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      if (!selected || selected.state !== "running") return;
      resizeRemote(sessionColumns(selected), viewportRows());
    }, 150);
  }

  function changeTerminalWidth() {
    if (!selected || selected.state !== "running" || !widthControl) return;
    const requested = widthControl.value === "fit"
      ? viewportColumns()
      : Number(widthControl.value);
    const columns = Math.max(40, Math.min(300, Math.round(requested || DEFAULT_COLUMNS)));
    resizeRemote(columns, sessionRows(selected));
  }

  function syncTerminalGeometry(session) {
    const columns = sessionColumns(session);
    const rows = sessionRows(session);
    terminal.resize(columns, rows);
    syncWidthControl(columns);
  }

  function syncWidthControl(columns) {
    if (!widthControl) return;
    widthControl.querySelectorAll("option[data-current-width]").forEach((option) => option.remove());
    const preset = Array.from(widthControl.options).find(
      (option) => option.value === String(columns)
    );
    if (preset) {
      widthControl.value = preset.value;
      window.TwnSelectControls?.sync(widthControl);
      return;
    }
    const option = document.createElement("option");
    option.value = String(columns);
    option.textContent = `${columns} columns`;
    option.dataset.currentWidth = "true";
    widthControl.prepend(option);
    widthControl.value = option.value;
    window.TwnSelectControls?.sync(widthControl);
  }

  function initializeTerminalHeight() {
    if (!heightResizer) return;
    const storageKey = "twn.remote-terminal.height.v1";
    const minimum = 260;
    const maximum = 1000;
    try {
      const saved = Number(window.localStorage.getItem(storageKey));
      if (saved) surface.style.height = `${Math.max(minimum, Math.min(maximum, saved))}px`;
    } catch (_error) {
      // The terminal still works when browser policy disables layout storage.
    }

    let startY = 0;
    let startHeight = 0;
    heightResizer.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      startY = event.clientY;
      startHeight = surface.getBoundingClientRect().height;
      document.body.classList.add("remote-terminal-resizing");
      heightResizer.setPointerCapture(event.pointerId);
    });
    heightResizer.addEventListener("pointermove", (event) => {
      if (!document.body.classList.contains("remote-terminal-resizing")) return;
      setTerminalHeight(startHeight + event.clientY - startY, false);
    });
    const finishResize = (event) => {
      if (!document.body.classList.contains("remote-terminal-resizing")) return;
      document.body.classList.remove("remote-terminal-resizing");
      if (heightResizer.hasPointerCapture(event.pointerId)) {
        heightResizer.releasePointerCapture(event.pointerId);
      }
      saveTerminalHeight();
    };
    heightResizer.addEventListener("pointerup", finishResize);
    heightResizer.addEventListener("pointercancel", finishResize);
    heightResizer.addEventListener("dblclick", () => {
      surface.style.removeProperty("height");
      try {
        window.localStorage.removeItem(storageKey);
      } catch (_error) {
        // Layout persistence is optional.
      }
      updateTerminalHeightAccessibility();
      scheduleRowResize();
    });
    heightResizer.addEventListener("keydown", (event) => {
      const step = event.shiftKey ? 64 : 24;
      if (event.key === "ArrowUp" || event.key === "ArrowDown") {
        event.preventDefault();
        setTerminalHeight(
          surface.getBoundingClientRect().height + (event.key === "ArrowDown" ? step : -step)
        );
      } else if (event.key === "Home") {
        event.preventDefault();
        surface.style.removeProperty("height");
        try {
          window.localStorage.removeItem(storageKey);
        } catch (_error) {
          // Layout persistence is optional.
        }
        updateTerminalHeightAccessibility();
        scheduleRowResize();
      }
    });

    function setTerminalHeight(value, persist = true) {
      const height = Math.round(Math.max(minimum, Math.min(maximum, Number(value) || 500)));
      surface.style.height = `${height}px`;
      heightResizer.setAttribute("aria-valuenow", String(height));
      scheduleRowResize();
      if (persist) saveTerminalHeight();
    }

    function saveTerminalHeight() {
      const height = Math.round(surface.getBoundingClientRect().height);
      try {
        window.localStorage.setItem(storageKey, String(height));
      } catch (_error) {
        // Layout persistence is optional.
      }
    }
  }

  function updateTerminalHeightAccessibility() {
    if (!heightResizer) return;
    const height = Math.round(surface.getBoundingClientRect().height);
    if (height > 0) heightResizer.setAttribute("aria-valuenow", String(height));
  }

  function viewportColumns() {
    return Math.max(40, Math.min(200, Math.floor((screen?.clientWidth || 960) / 8)));
  }

  function viewportRows() {
    return Math.max(10, Math.min(120, Math.floor((screen?.clientHeight || 500) / 21)));
  }

  function sessionColumns(session) {
    return Math.max(
      40,
      Math.min(300, Math.round(Number(session?.terminal_columns) || DEFAULT_COLUMNS))
    );
  }

  function sessionRows(session) {
    return Math.max(
      10,
      Math.min(120, Math.round(Number(session?.terminal_rows) || DEFAULT_ROWS))
    );
  }

  function terminalKey(name) {
    return {
      "ctrl-c": "\u0003",
      "ctrl-d": "\u0004",
      "ctrl-y": "\u0019",
      backspace: terminal.keySequence("Backspace"),
      tab: "\t",
      up: terminal.keySequence("ArrowUp"),
      down: terminal.keySequence("ArrowDown"),
      left: terminal.keySequence("ArrowLeft"),
      right: terminal.keySequence("ArrowRight"),
      escape: "\u001b",
    }[name] || "";
  }

  async function pasteClipboard() {
    if (!selected || selected.state !== "running") return;
    try {
      const text = await navigator.clipboard.readText();
      if (!text) {
        showMessage("The clipboard is empty.");
        return;
      }
      queueInput(terminal.formatPaste(text), true);
    } catch (_error) {
      showMessage("Clipboard access was blocked. Tap the terminal and use the device's Paste command.");
    }
  }

  function focusTerminal() {
    if (inputCapture.disabled) return;
    inputCapture.focus({preventScroll: true});
    updateFocusState();
  }

  function editable(element) {
    return Boolean(
      element
      && (
        element.matches?.("input, textarea, select")
        || element.isContentEditable
      )
    );
  }

  function updateFocusState() {
    if (synchronizing) focusState.textContent = "Restoring session…";
    else if (inputCapture.disabled) focusState.textContent = active(selected || {}) ? "Connecting…" : "Read-only scrollback";
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

  function protocolLabel(session) {
    return String(session?.protocol || "ssh").toUpperCase();
  }

  function showMessage(message, category = "warning") {
    sessionMessage.textContent = message;
    sessionMessage.className = `message ${category}`;
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
    if (match) openSession(match, {reveal: false, focus: false});
  }
  window.TwnRemoteTerminal = {
    start: startPayload,
    open: openSession,
    sessions: () => sessions.map((session) => ({...session})),
  };
})();
