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

  const expandedKey = "twn:live-tools-dock-expanded";
  let refreshTimer = null;
  let refreshing = false;

  toggle.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") !== "true";
    setExpanded(expanded);
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refresh();
  });

  function setExpanded(expanded) {
    toggle.setAttribute("aria-expanded", String(expanded));
    body.hidden = !expanded;
    tray.classList.toggle("collapsed", !expanded);
    localStorage.setItem(expandedKey, expanded ? "1" : "0");
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
    list.replaceChildren(...sessions.map(sessionCard));
    tray.hidden = sessions.length === 0;
    document.body.classList.toggle("has-live-tool-dock", sessions.length > 0);
    dockSummary.textContent = dockSummaryText(sessions);
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
    const title = document.createElement("strong");
    title.textContent = session.title || "Live tool";
    const summary = document.createElement("small");
    summary.textContent = sessionSummary(session);
    identity.append(title, summary);

    const actions = document.createElement("div");
    actions.className = "live-tool-card-actions";
    const restore = document.createElement("a");
    restore.className = "button-link compact";
    restore.href = session.restore_url;
    restore.textContent = "Restore";
    const stop = document.createElement("button");
    stop.className = "secondary compact";
    stop.type = "button";
    stop.textContent = "Stop";
    stop.addEventListener("click", () => stopSession(session, stop));
    actions.append(restore, stop);
    card.append(identity, actions);
    return card;
  }

  function sessionSummary(session) {
    if (session.state === "error") {
      return session.last_error || "The live tool stopped with an error.";
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

  setExpanded(localStorage.getItem(expandedKey) === "1");
  window.TwnLiveTools = {
    refresh,
    collapse: () => setExpanded(false),
  };
  refresh();
})();
