(function () {
  const tray = document.getElementById("live-tool-tray");
  const toggle = document.getElementById("live-tool-tray-toggle");
  const body = document.getElementById("live-tool-tray-body");
  const list = document.getElementById("live-tool-list");
  const count = document.getElementById("live-tool-count");
  const dockSummary = document.getElementById("live-tool-dock-summary");
  if (!tray || !toggle || !body || !list || !count || !dockSummary || !tray.dataset.listUrl) {
    return;
  }

  let refreshTimer = null;
  let refreshing = false;
  let editingSessionId = "";

  toggle.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") !== "true";
    setExpanded(expanded);
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-open-live-tools]")) return;
    tray.hidden = false;
    setExpanded(true);
    toggle.focus();
    refresh();
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refresh();
  });

  function setExpanded(expanded) {
    toggle.setAttribute("aria-expanded", String(expanded));
    body.hidden = !expanded;
    tray.classList.toggle("collapsed", !expanded);
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const response = await fetch(tray.dataset.listUrl, {
        headers: {"Accept": "application/json"},
      });
      if (!response.ok) {
        if (response.status === 401 || response.redirected) tray.hidden = true;
        return;
      }
      const data = await response.json();
      render(Array.isArray(data.sessions) ? data.sessions : []);
    } catch (_error) {
      // A navigation or restart can briefly interrupt this low-priority refresh.
    } finally {
      refreshing = false;
      scheduleRefresh();
    }
  }

  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(refresh, document.hidden ? 30_000 : 5_000);
  }

  function render(sessions) {
    count.textContent = String(sessions.length);
    tray.hidden = sessions.length === 0;
    document.body.classList.toggle("has-live-tool-dock", sessions.length > 0);
    dockSummary.textContent = dockSummaryText(sessions);
    if (editingSessionId && sessions.some((session) => session.id === editingSessionId)) {
      return;
    }
    editingSessionId = "";
    list.replaceChildren(...sessions.map(sessionCard));
    if (!sessions.length) setExpanded(false);
  }

  function dockSummaryText(sessions) {
    if (!sessions.length) return "No active tools";
    if (sessions.length === 1) {
      return `${sessions[0].title || "Live tool"} · ${sessionSummary(sessions[0])}`;
    }
    const errors = sessions.filter((session) => session.state === "error").length;
    return errors
      ? `${sessions.length} tools · ${errors} needs attention`
      : `${sessions.length} tools monitoring`;
  }

  function sessionCard(session) {
    const card = document.createElement("article");
    card.className = `live-tool-card ${session.state === "error" ? "error" : ""}`;
    const identity = document.createElement("div");
    identity.className = "live-tool-card-identity";
    const titleRow = document.createElement("div");
    titleRow.className = "live-tool-card-title-row";
    const title = document.createElement("strong");
    title.textContent = session.title || "Live tool";
    titleRow.append(title);
    if (session.rename_url) {
      const rename = iconButton("✎", `Rename ${title.textContent}`, "live-tool-rename");
      rename.addEventListener("click", () => beginRename(session, identity, titleRow));
      titleRow.append(rename);
    }
    const summary = document.createElement("small");
    summary.textContent = sessionSummary(session);
    identity.append(titleRow, summary);

    const actions = document.createElement("div");
    actions.className = "live-tool-card-actions";
    const restore = document.createElement("a");
    restore.className = "live-tool-card-restore";
    restore.href = session.restore_url;
    restore.title = `Restore ${title.textContent}`;
    restore.setAttribute("aria-label", `Restore ${title.textContent}`);
    const stop = iconButton("×", `Stop ${title.textContent}`, "live-tool-stop");
    stop.disabled = session.can_stop === false;
    stop.addEventListener("click", () => stopSession(session, stop));
    actions.append(stop);
    card.append(restore, identity, actions);
    return card;
  }

  function iconButton(symbol, label, className) {
    const button = document.createElement("button");
    button.className = `live-tool-icon-action ${className}`;
    button.type = "button";
    button.title = label.split(" ", 1)[0];
    button.setAttribute("aria-label", label);
    button.append(iconSymbol(symbol));
    return button;
  }

  function iconSymbol(symbol) {
    const span = document.createElement("span");
    span.setAttribute("aria-hidden", "true");
    span.textContent = symbol;
    return span;
  }

  function beginRename(session, identity, titleRow) {
    editingSessionId = session.id;
    const form = document.createElement("form");
    form.className = "live-tool-rename-form";
    const input = document.createElement("input");
    input.className = "live-tool-rename-input";
    input.type = "text";
    input.maxLength = 100;
    input.required = true;
    input.value = session.title || "";
    input.setAttribute("aria-label", "Live tool name");
    const save = iconButton("✓", "Save live tool name", "live-tool-rename-save");
    save.type = "submit";
    const cancel = iconButton("×", "Cancel rename", "live-tool-rename-cancel");
    cancel.addEventListener("click", () => {
      editingSessionId = "";
      refresh();
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      renameSession(session, input, save, cancel);
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        cancel.click();
      }
    });
    form.append(input, save, cancel);
    titleRow.replaceWith(form);
    identity.classList.add("renaming");
    input.focus();
    input.select();
  }

  async function renameSession(session, input, save, cancel) {
    const title = input.value.trim().replace(/\s+/g, " ");
    if (!title) {
      input.setCustomValidity("Enter a name for this live tool.");
      input.reportValidity();
      return;
    }
    input.setCustomValidity("");
    input.disabled = true;
    save.disabled = true;
    cancel.disabled = true;
    try {
      const response = await fetch(session.rename_url, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({title}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The live tool could not be renamed.");
      editingSessionId = "";
      document.dispatchEvent(
        new CustomEvent("livetoolrenamed", {detail: {session: data.session}})
      );
      await refresh();
    } catch (error) {
      window.alert(error.message);
      input.disabled = false;
      save.disabled = false;
      cancel.disabled = false;
      input.focus();
    }
  }

  function sessionSummary(session) {
    if (session.state === "error") {
      return session.last_error || "The live tool stopped with an error.";
    }
    if (session.tool_key === "iperf3_server") {
      const tests = Number(session.rounds_completed || 0);
      const status = session.listener_status === "stopping"
        ? "stopping…"
        : tests
          ? `${tests} test${tests === 1 ? "" : "s"} · ${relativeAge(
              Math.max(0, Date.now() - Number(session.last_round_at || 0) * 1000)
            )}`
          : "listening for a client";
      return `${session.listener} · ${status}`;
    }
    if (session.tool_key === "remote_terminal") {
      if (session.state === "connecting") {
        return `${session.remote_username}@${session.host}:${session.port} · connecting…`;
      }
      return `${session.remote_username}@${session.host}:${session.port} · connected`;
    }
    if (!session.rounds_completed) {
      const noun = session.tool_key === "snmp_interface" ? "interface" : "target";
      return `${session.target_count} ${noun}${session.target_count === 1 ? "" : "s"} · starting…`;
    }
    const age = Math.max(0, Date.now() - Number(session.last_round_at || 0) * 1000);
    const status = session.tool_key === "snmp_interface" ? "responding" : "up";
    return `${session.last_up_count}/${session.target_count} ${status} · ${relativeAge(age)}`;
  }

  function relativeAge(age) {
    if (age < 10_000) return "just updated";
    if (age < 60_000) return `${Math.floor(age / 1000)}s ago`;
    return `${Math.floor(age / 60_000)}m ago`;
  }

  async function stopSession(session, button) {
    if (!window.confirm(`Stop '${session.title || "this live tool"}'?`)) return;
    button.disabled = true;
    try {
      const response = await fetch(session.stop_url, {
        method: "POST",
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The live tool could not be stopped.");
      document.dispatchEvent(new CustomEvent("livetoolstopped", {detail: {session}}));
      await refresh();
    } catch (error) {
      window.alert(error.message);
      button.disabled = false;
    }
  }

  setExpanded(false);
  window.TwnLiveTools = {
    refresh,
    collapse: () => setExpanded(false),
    expand: () => {
      tray.hidden = false;
      setExpanded(true);
      refresh();
    },
  };
  refresh();
})();
