(function () {
  const form = document.getElementById("ping-form");
  const hostsInput = document.getElementById("ping-hosts");
  const intervalInput = document.getElementById("ping-interval");
  const timeoutInput = document.getElementById("ping-timeout");
  const startButton = document.getElementById("ping-start");
  const stopButton = document.getElementById("ping-stop");
  const updateTargetsButton = document.getElementById("ping-update-targets");
  const minimizeButton = document.getElementById("ping-minimize");
  const workspace = document.getElementById("ping-workspace");
  const minimizedPlaceholder = document.getElementById("ping-minimized");
  const restoreInlineButton = document.getElementById("ping-restore-inline");
  const profileSelect = document.getElementById("ping-profile");
  const profileNameInput = document.getElementById("ping-profile-name");
  const profileSaveButton = document.getElementById("ping-profile-save");
  const profileDeleteButton = document.getElementById("ping-profile-delete");
  const status = document.getElementById("ping-status");
  const validationWarning = document.getElementById("ping-validation-warning");
  const resultsPanel = document.getElementById("ping-results");
  const hostList = document.getElementById("ping-host-list");
  const hostFilter = document.getElementById("ping-host-filter");
  const hostStatusFilter = document.getElementById("ping-host-status-filter");
  const hostCount = document.getElementById("ping-host-count");
  const selectionCount = document.getElementById("ping-selection-count");
  const graphSummary = document.getElementById("ping-graph-summary");
  const graphEmpty = document.getElementById("ping-graph-empty");
  const graphGrid = document.getElementById("ping-graph-grid");
  const historyRange = document.getElementById("ping-history-range");
  const followLive = document.getElementById("ping-follow-live");
  const historyPosition = document.getElementById("ping-history-position");
  const exportHistory = document.getElementById("ping-export-history");
  const historyEnd = document.getElementById("ping-history-end");
  const historyOlder = document.getElementById("ping-history-older");
  const historyNewer = document.getElementById("ping-history-newer");
  const historyNavigationSummary = document.getElementById("ping-history-navigation-summary");
  const healthLoss = document.getElementById("ping-health-loss");
  const healthLatency = document.getElementById("ping-health-latency");
  const healthJitter = document.getElementById("ping-health-jitter");
  const healthSettingsSummary = document.getElementById("ping-health-settings-summary");
  const healthGrid = document.getElementById("ping-health-grid");
  const healthSummary = document.getElementById("ping-health-summary");
  const viewButtons = [...document.querySelectorAll("[data-ping-view]")];
  const sizeButtons = [...document.querySelectorAll("[data-ping-size]")];
  const popoutButton = document.getElementById("ping-popout");
  const gridPreview = document.getElementById("ping-grid-preview");
  const gridPreviewTitle = document.getElementById("ping-grid-preview-title");
  const gridPreviewAddress = document.getElementById("ping-grid-preview-address");
  const gridPreviewStatus = document.getElementById("ping-grid-preview-status");
  const gridPreviewStatistics = document.getElementById("ping-grid-preview-statistics");
  const gridPreviewCanvas = document.getElementById("ping-grid-preview-canvas");
  const gridPreviewClose = document.getElementById("ping-grid-preview-close");
  const gridPreviewDetail = document.getElementById("ping-grid-preview-detail");

  if (!form || !hostsInput || !intervalInput || !timeoutInput || !startButton || !stopButton || !updateTargetsButton ||
      !minimizeButton || !workspace || !minimizedPlaceholder || !restoreInlineButton ||
      !profileSelect || !profileNameInput || !profileSaveButton ||
      !profileDeleteButton || !status || !validationWarning || !resultsPanel ||
      !hostList || !hostFilter || !hostStatusFilter || !hostCount ||
      !selectionCount || !graphSummary || !graphEmpty || !graphGrid ||
      !historyRange || !followLive || !historyPosition ||
      !exportHistory || !historyEnd || !historyOlder ||
      !historyNewer || !historyNavigationSummary || !healthLoss ||
      !healthLatency || !healthJitter || !healthSettingsSummary ||
      !healthGrid || !healthSummary || !viewButtons.length ||
      !sizeButtons.length || !gridPreview || !gridPreviewTitle ||
      !gridPreviewAddress || !gridPreviewStatus || !gridPreviewStatistics ||
      !gridPreviewCanvas || !gridPreviewClose || !gridPreviewDetail) {
    return;
  }

  let running = false;
  let timer = null;
  let activeSession = null;
  let sampleCursor = 0;
  let pollInFlight = false;
  let loadedProfileName = "";
  let lockedViewEnd = null;
  let activeHostsSource = "";
  let activeHosts = new Set();
  let renderFrame = null;
  let resizeFrame = null;
  let renderedGraphGridWidth = 0;
  let hasStoredGraphSelection = false;
  let gridPreviewHost = "";
  let gridPreviewAnchor = null;
  let gridPreviewPinned = false;
  let gridPreviewShowTimer = null;
  let gridPreviewHideTimer = null;
  const history = new Map();
  const hostViews = new Map();
  const graphViews = new Map();
  const selectedHosts = new Set();
  const profileStorageKey = "twn:ping-profile";
  const graphSelectionStoragePrefix = "twn:ping-graphs:";
  const healthStoragePrefix = "twn:ping-health:";
  const viewStorageKey = "twn:ping-results-view";
  const sizeStorageKey = "twn:ping-graph-size";
  const historySampleBudget = 500_000;
  const visiblePollIntervalMs = 250;
  const hiddenPollIntervalMs = 5_000;
  const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  const previewView = {
    canvas: gridPreviewCanvas,
    chart: gridPreviewCanvas.parentElement,
    host: "",
    variant: "preview",
    visiblePoints: [],
  };
  const chartTooltip = document.createElement("div");
  chartTooltip.className = "ping-chart-tooltip";
  chartTooltip.hidden = true;
  document.body.appendChild(chartTooltip);
  window.addEventListener("themechange", renderAllCharts);
  if (window.ResizeObserver) {
    new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width || 0;
      if (Math.round(width) === renderedGraphGridWidth) return;
      renderedGraphGridWidth = Math.round(width);
      scheduleGraphResize();
    }).observe(graphGrid);
  } else {
    window.addEventListener("resize", scheduleGraphResize);
  }
  hostFilter.addEventListener("input", applyHostFilters);
  hostStatusFilter.addEventListener("change", applyHostFilters);
  viewButtons.forEach((button) => button.addEventListener("click", () => {
    setViewMode(button.dataset.pingView);
  }));
  sizeButtons.forEach((button) => button.addEventListener("click", () => {
    setGraphSize(button.dataset.pingSize);
  }));
  [healthLoss, healthLatency, healthJitter].forEach((input) => {
    input.addEventListener("input", () => {
      updateHealthSettingsSummary();
      persistHealthThresholds();
      refreshRenderedResults();
      renderAllCharts();
    });
  });
  popoutButton?.addEventListener("click", () => {
    if (!activeSession?.popout_url) return;
    const popup = window.open(
      activeSession.popout_url,
      `twn-ping-session-${activeSession.id}`,
      "popup,width=1280,height=820,resizable=yes,scrollbars=yes"
    );
    if (!popup) status.textContent = "The browser blocked the results window. Allow pop-ups for this toolkit and try again.";
  });
  gridPreviewClose.addEventListener("click", hideGridPreview);
  gridPreviewDetail.addEventListener("click", openPreviewDetail);
  gridPreview.addEventListener("pointerenter", cancelGridPreviewHide);
  gridPreview.addEventListener("pointerleave", () => scheduleGridPreviewHide());
  gridPreview.addEventListener("focusin", cancelGridPreviewHide);
  gridPreview.addEventListener("focusout", () => scheduleGridPreviewHide());
  gridPreviewCanvas.addEventListener("mousemove", (event) => showCanvasTooltip(previewView, event));
  gridPreviewCanvas.addEventListener("mouseleave", () => { chartTooltip.hidden = true; });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !gridPreview.hidden) hideGridPreview();
  });
  window.addEventListener("resize", () => {
    if (!gridPreview.hidden && gridPreviewAnchor) positionGridPreview(gridPreviewAnchor);
  });
  window.addEventListener("storage", (event) => {
    if (event.key === healthStorageKey()) {
      restoreHealthThresholds(activeSession?.config?.health_thresholds);
      refreshRenderedResults();
      renderAllCharts();
    }
  });

  setViewMode(readDisplayPreference(viewStorageKey, ["graphs", "grid"], "graphs"), {persist: false});
  setGraphSize(readDisplayPreference(sizeStorageKey, ["small", "medium", "large"], "large"), {persist: false});
  updateHealthSettingsSummary();

  minimizeButton.addEventListener("click", () => {
    if (!activeSession) return;
    workspace.hidden = true;
    minimizedPlaceholder.hidden = false;
    window.TwnLiveTools?.collapse();
    window.TwnLiveTools?.refresh();
  });
  restoreInlineButton.addEventListener("click", () => {
    workspace.hidden = false;
    minimizedPlaceholder.hidden = true;
    renderAllCharts();
  });

  historyRange.addEventListener("change", () => {
    if (!followLive.checked && lockedViewEnd != null) {
      lockedViewEnd = clampViewEnd(lockedViewEnd);
      syncSliderToLockedEnd();
    }
    renderAllCharts();
  });
  followLive.addEventListener("change", () => {
    if (followLive.checked) {
      historyPosition.value = "1000";
      lockedViewEnd = null;
    } else {
      lockViewToPosition();
    }
    renderAllCharts();
  });
  historyPosition.addEventListener("input", () => {
    followLive.checked = historyPosition.value === "1000";
    lockedViewEnd = followLive.checked ? null : viewEndForSliderPosition();
    renderAllCharts();
  });
  exportHistory.addEventListener("click", exportHistoryCsv);
  historyEnd.addEventListener("change", () => {
    const selected = new Date(historyEnd.value).getTime();
    if (!Number.isFinite(selected)) return;
    followLive.checked = false;
    lockedViewEnd = clampViewEnd(selected);
    syncSliderToLockedEnd();
    renderAllCharts();
  });
  historyOlder.addEventListener("click", () => shiftHistoryWindow(-1));
  historyNewer.addEventListener("click", () => shiftHistoryWindow(1));

  profileSelect.addEventListener("change", () => {
    const option = profileSelect.options[profileSelect.selectedIndex];
    if (!option || !option.value) {
      loadedProfileName = "";
      profileNameInput.value = "";
      hostsInput.value = "";
      restoreHealthThresholds({}, {preferStored: false});
      sessionStorage.removeItem(profileStorageKey);
      status.textContent = "Ready to create a new profile.";
      return;
    }
    const targets = JSON.parse(option.dataset.targets || "[]");
    hostsInput.value = targets
      .map((target) => target.label ? `${target.label} = ${target.host}` : target.host)
      .join("\n");
    intervalInput.value = option.dataset.interval || "2";
    timeoutInput.value = option.dataset.timeout || "1";
    restoreHealthThresholds(
      JSON.parse(option.dataset.healthThresholds || "{}"),
      {preferStored: false}
    );
    profileNameInput.value = option.value;
    loadedProfileName = option.value;
    sessionStorage.setItem(profileStorageKey, option.value);
    status.textContent = `Loaded profile '${option.value}'.`;
  });

  const savedPingProfile = sessionStorage.getItem(profileStorageKey);
  if (
    savedPingProfile
    && [...profileSelect.options].some((option) => option.value === savedPingProfile)
  ) {
    profileSelect.value = savedPingProfile;
    profileSelect.dispatchEvent(new Event("change"));
  }

  profileSaveButton.addEventListener("click", async () => {
    profileSaveButton.disabled = true;
    status.textContent = "Saving profile...";
    try {
      const response = await fetch(form.dataset.saveProfileUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          name: profileNameInput.value,
          original_name: loadedProfileName,
          hosts: hostsInput.value,
          interval: intervalInput.value,
          timeout: timeoutInput.value,
          health_thresholds: healthThresholdValues(),
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Profile could not be saved.");
      }
      updateProfileOption(data.profile, loadedProfileName);
      loadedProfileName = data.profile.name;
      sessionStorage.setItem(profileStorageKey, data.profile.name);
      profileNameInput.value = data.profile.name;
      status.textContent = `Saved profile '${data.profile.name}'.`;
    } catch (error) {
      status.textContent = error.message;
    } finally {
      profileSaveButton.disabled = false;
    }
  });

  profileDeleteButton.addEventListener("click", async () => {
    const name = profileSelect.value;
    if (!name) {
      status.textContent = "Select a saved profile to delete.";
      return;
    }
    if (!window.confirm(`Delete ping profile '${name}'?`)) {
      return;
    }
    profileDeleteButton.disabled = true;
    try {
      const response = await fetch(form.dataset.deleteProfileUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({name}),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Profile could not be deleted.");
      }
      profileSelect.querySelector(`option[value="${CSS.escape(name)}"]`)?.remove();
      profileSelect.value = "";
      if (loadedProfileName === name) {
        loadedProfileName = "";
        profileNameInput.value = "";
      }
      sessionStorage.removeItem(profileStorageKey);
      status.textContent = `Deleted profile '${name}'.`;
    } catch (error) {
      status.textContent = error.message;
    } finally {
      profileDeleteButton.disabled = false;
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (running) {
      return;
    }
    startButton.disabled = true;
    status.textContent = "Validating targets...";
    let targets;
    try {
      targets = await validateTargets(hostsInput.value);
    } catch (error) {
      status.textContent = error.message;
      startButton.disabled = false;
      return;
    }
    activeHostsSource = targetsToSource(targets);
    status.textContent = "Starting persistent ping session...";
    try {
      const response = await fetch(form.dataset.sessionStartUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          hosts: activeHostsSource,
          interval: intervalInput.value,
          timeout: timeoutInput.value,
          title: profileNameInput.value || profileSelect.value || "Ping",
          health_thresholds: healthThresholdValues(),
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "The persistent ping session could not be started.");
      }
      activateSession(data.session, {resetHistory: true});
      status.textContent = "Persistent ping session started. Waiting for the first round...";
      window.history.replaceState(
        null,
        "",
        `${window.location.pathname}?session=${encodeURIComponent(data.session.id)}`
      );
      window.TwnLiveTools?.refresh();
      pollSession();
    } catch (error) {
      status.textContent = error.message;
      startButton.disabled = false;
    }
  });

  stopButton.addEventListener("click", async () => {
    await stopPingRun();
  });
  updateTargetsButton.addEventListener("click", async () => {
    if (!running || !activeSession) return;
    updateTargetsButton.disabled = true;
    status.textContent = "Validating updated targets...";
    try {
      const targets = await validateTargets(hostsInput.value);
      const response = await fetch(activeSession.targets_url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          hosts: targetsToSource(targets),
          interval: intervalInput.value,
          timeout: timeoutInput.value,
          health_thresholds: healthThresholdValues(),
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "The live targets could not be updated.");
      }
      activeSession = data.session;
      activeHostsSource = targetsToSource(data.session.config.targets || targets);
      activeHosts = new Set(targets.map((target) => target.host));
      hostViews.forEach((view, host) => {
        if (!activeHosts.has(host)) {
          view.state = "removed";
          updateHostView(view);
          const graphView = graphViews.get(host);
          if (graphView) updateGraphStatus(graphView, "removed");
        }
      });
      applyHostFilters();
      status.textContent = `Updated the live run to ${targets.length} targets. Existing history was preserved.`;
      window.TwnLiveTools?.refresh();
    } catch (error) {
      status.textContent = error.message;
    } finally {
      updateTargetsButton.disabled = !running;
    }
  });
  window.addEventListener("pagehide", () => clearTimeout(timer));
  document.addEventListener("visibilitychange", () => {
    if (!activeSession || activeSession.state !== "running") return;
    clearTimeout(timer);
    if (!document.hidden && !pollInFlight) pollSession();
    else if (document.hidden) scheduleSessionPoll();
  });
  document.addEventListener("livetoolstopped", (event) => {
    if (event.detail?.session?.id === activeSession?.id) {
      markSessionStopped("Stopped from the Live tools tray.");
    }
  });

  async function pollSession() {
    clearTimeout(timer);
    if (!activeSession || pollInFlight) return;
    pollInFlight = true;
    try {
      await loadNewSamples();
      updateSessionStatus();
      if (activeSession.state !== "running") {
        markSessionStopped(
          activeSession.last_error || `Session ${activeSession.state}.`
        );
      }
    } catch (error) {
      status.textContent = error.message;
    } finally {
      pollInFlight = false;
      if (activeSession && activeSession.state === "running") {
        scheduleSessionPoll();
      }
    }
  }

  function scheduleSessionPoll() {
    clearTimeout(timer);
    timer = setTimeout(
      pollSession,
      document.hidden ? hiddenPollIntervalMs : visiblePollIntervalMs
    );
  }

  async function loadNewSamples() {
    let hasMore = true;
    let restored = 0;
    while (hasMore && activeSession) {
      const separator = activeSession.samples_url.includes("?") ? "&" : "?";
      const response = await fetch(
        `${activeSession.samples_url}${separator}after=${sampleCursor}&limit=10000`,
        {headers: {"Accept": "application/json"}}
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Ping history could not be loaded.");
      if (data.session) activeSession = data.session;
      const samples = Array.isArray(data.samples) ? data.samples : [];
      if (samples.length) {
        ingestSamples(samples);
        restored += samples.length;
      }
      sampleCursor = Number(data.next_after || sampleCursor);
      hasMore = Boolean(data.has_more);
      if (hasMore) status.textContent = `Restoring ping history… ${restored.toLocaleString()} samples loaded`;
    }
  }

  function ingestSamples(samples) {
    const rounds = new Map();
    samples.forEach((sample) => {
      const key = String(sample.sampled_at);
      const round = rounds.get(key) || [];
      round.push({
        host: sample.host,
        label: sample.label || "",
        reachable: Boolean(sample.reachable),
        latency_ms: sample.latency_ms,
      });
      rounds.set(key, round);
    });
    [...rounds.entries()].forEach(([sampledAt, results]) => {
      renderResults(results, new Date(Number(sampledAt) * 1000), true);
    });
    scheduleRenderedResults();
  }

  function scheduleRenderedResults() {
    if (renderFrame !== null) return;
    renderFrame = window.requestAnimationFrame(() => {
      renderFrame = null;
      refreshRenderedResults();
    });
  }

  async function stopPingRun() {
    if (!activeSession) return;
    stopButton.disabled = true;
    status.textContent = "Stopping...";
    try {
      const response = await fetch(activeSession.stop_url, {
        method: "POST",
        headers: {"Accept": "application/json"},
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The session could not be stopped.");
      activeSession = data.session;
      markSessionStopped("Stopped.");
      window.TwnLiveTools?.refresh();
    } catch (error) {
      status.textContent = error.message;
      stopButton.disabled = false;
    }
  }

  function markSessionStopped(message) {
    running = false;
    clearTimeout(timer);
    startButton.disabled = false;
    stopButton.disabled = true;
    updateTargetsButton.disabled = true;
    minimizeButton.disabled = true;
    status.textContent = message;
  }

  function activateSession(session, {resetHistory = false} = {}) {
    activeSession = session;
    running = session.state === "running";
    sampleCursor = 0;
    const config = session.config || {};
    const targets = Array.isArray(config.targets) ? config.targets : [];
    activeHostsSource = targetsToSource(targets);
    activeHosts = new Set(targets.map((target) => target.host));
    hostsInput.value = activeHostsSource;
    intervalInput.value = String(config.interval || session.interval || 2);
    timeoutInput.value = String(config.timeout || session.timeout || 1);
    restoreHealthThresholds(config.health_thresholds);
    persistHealthThresholds();
    if (resetHistory) resetResultsWorkspace();
    startButton.disabled = running;
    stopButton.disabled = !running;
    updateTargetsButton.disabled = !running;
    minimizeButton.disabled = !running;
    resultsPanel.hidden = false;
    if (popoutButton) popoutButton.disabled = !session.popout_url;
  }

  function resetResultsWorkspace() {
    history.clear();
    hostViews.clear();
    graphViews.clear();
    selectedHosts.clear();
    restoreGraphSelection();
    lockedViewEnd = null;
    followLive.checked = true;
    historyPosition.value = "1000";
    hostList.innerHTML = "";
    graphGrid.innerHTML = "";
    healthGrid.innerHTML = "";
    hideGridPreview();
    hostFilter.value = "";
    hostStatusFilter.value = "all";
    updateSelectionSummary();
  }

  function graphSelectionStorageKey() {
    return activeSession?.id
      ? `${graphSelectionStoragePrefix}${activeSession.id}`
      : "";
  }

  function restoreGraphSelection() {
    hasStoredGraphSelection = false;
    const storageKey = graphSelectionStorageKey();
    if (!storageKey) return;
    try {
      const stored = sessionStorage.getItem(storageKey);
      if (stored === null) return;
      const hosts = JSON.parse(stored);
      if (!Array.isArray(hosts)) throw new Error("Invalid graph selection");
      const validHosts = hosts.filter(
        (host) => typeof host === "string" && activeHosts.has(host)
      );
      if (hosts.length && !validHosts.length) {
        sessionStorage.removeItem(storageKey);
        return;
      }
      validHosts.forEach((host) => selectedHosts.add(host));
      hasStoredGraphSelection = true;
      if (validHosts.length !== hosts.length) {
        sessionStorage.setItem(storageKey, JSON.stringify(validHosts));
      }
    } catch (_error) {
      try {
        sessionStorage.removeItem(storageKey);
      } catch (_storageError) {
        // Monitoring remains usable when browser storage is unavailable.
      }
    }
  }

  function persistGraphSelection() {
    hasStoredGraphSelection = true;
    const storageKey = graphSelectionStorageKey();
    if (!storageKey) return;
    const hosts = [...selectedHosts].filter((host) => activeHosts.has(host));
    try {
      sessionStorage.setItem(storageKey, JSON.stringify(hosts));
    } catch (_error) {
      // Monitoring remains usable when browser storage is unavailable.
    }
  }

  function updateSessionStatus() {
    if (!activeSession) return;
    if (activeSession.state === "error") {
      status.textContent = activeSession.last_error || "The live ping session stopped with an error.";
      return;
    }
    if (!activeSession.rounds_completed) {
      status.textContent = "Persistent ping session is waiting for its first round...";
      return;
    }
    const durationMs = Number(activeSession.last_duration_ms);
    const engine = activeSession.last_engine === "fping"
      ? "high-capacity fping"
      : "compatibility ping";
    const duration = Number.isFinite(durationMs)
      ? `${(durationMs / 1000).toFixed(2)}s`
      : "an unknown duration";
    const completedAt = new Date(
      Number(activeSession.last_round_at) * 1000
      + (Number.isFinite(durationMs) ? durationMs : 0)
    );
    const intervalSeconds = Number(
      activeSession.config?.interval || activeSession.interval || 2
    );
    const constrained = Number.isFinite(durationMs)
      && Number.isFinite(intervalSeconds)
      && durationMs >= intervalSeconds * 1000;
    const cadenceNote = constrained
      ? ` The ${duration} round exceeded the ${intervalSeconds}s target; lower the ping timeout for a true ${intervalSeconds}-second cadence.`
      : "";
    status.textContent = `Last round completed in ${duration} using ${engine} at ${completedAt.toLocaleTimeString()}.${cadenceNote} This run can be safely minimized.`;
  }

  async function validateTargets(source) {
    const response = await fetch(form.dataset.validateUrl, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({hosts: source}),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Targets could not be validated.");
    }
    const targets = data.targets || [];
    const invalid = data.invalid || [];
    if (!targets.length) {
      showInvalidTargets(invalid);
      throw new Error("No valid targets were provided. Correct an entry and try again.");
    }
    showInvalidTargets(invalid);
    return targets;
  }

  function showInvalidTargets(invalid) {
    if (!invalid.length) {
      validationWarning.hidden = true;
      validationWarning.textContent = "";
      return;
    }
    const values = invalid
      .map((item) => item.error ? `${item.value} (${item.error})` : item.value)
      .join(", ");
    validationWarning.textContent = `${invalid.length} invalid target${invalid.length === 1 ? " was" : "s were"} skipped: ${values}`;
    validationWarning.hidden = false;
  }

  function targetsToSource(targets) {
    return targets
      .map((target) => target.label ? `${target.label} = ${target.host}` : target.host)
      .join("\n");
  }

  function renderResults(results, sampledAt = new Date(), deferCharts = false) {
    results.forEach((result) => {
      const hostHistory = history.get(result.host) || createHistory();
      addHistorySample(hostHistory, {
        latency: result.latency_ms == null ? null : Number(result.latency_ms),
        reachable: Boolean(result.reachable),
        time: sampledAt,
      });
      history.set(result.host, hostHistory);

      let hostView = hostViews.get(result.host);
      if (!hostView) {
        hostView = createHostView(result);
        hostViews.set(result.host, hostView);
        hostList.appendChild(hostView.button);
      }
      hostView.result = result;
      hostView.state = healthState(result, hostHistory);
      updateHostView(hostView);

      if (selectedHosts.has(result.host) && !graphViews.has(result.host)) {
        selectGraph(result.host, {persist: false});
      } else if (
        !hasStoredGraphSelection
        && hostViews.size === 1
        && selectedHosts.size === 0
      ) {
        selectGraph(result.host);
      }
      const graphView = graphViews.get(result.host);
      if (graphView && !deferCharts) updateGraphView(graphView, result, hostHistory);
    });
    if (deferCharts) return;
    hostCount.textContent = `${activeHosts.size} host${activeHosts.size === 1 ? "" : "s"}`;
    applyHostFilters();
    updateSelectionSummary();
    updateHealthSummary();
    refreshGridPreview();
    updateHistoryNavigator();
  }

  function refreshRenderedResults() {
    hostViews.forEach((view, host) => {
      const series = history.get(host);
      view.state = !activeHosts.has(host)
        ? "removed"
        : healthState(view.result, series);
      updateHostView(view);
      const graphView = graphViews.get(host);
      if (graphView && series) {
        updateGraphView(graphView, view.result, series);
        if (view.state === "removed") updateGraphStatus(graphView, "removed");
      }
    });
    hostCount.textContent = `${activeHosts.size} host${activeHosts.size === 1 ? "" : "s"}`;
    applyHostFilters();
    updateSelectionSummary();
    updateHealthSummary();
    refreshGridPreview();
    updateHistoryNavigator();
  }

  function createHostView(result) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ping-host-option";
    button.setAttribute("role", "option");
    button.setAttribute("aria-selected", "false");
    const indicator = document.createElement("span");
    indicator.className = "ping-host-state-dot";
    indicator.setAttribute("aria-hidden", "true");
    const identity = document.createElement("span");
    identity.className = "ping-host-option-identity";
    const label = document.createElement("strong");
    label.textContent = result.label || result.host;
    identity.appendChild(label);
    if (result.label) {
      const address = document.createElement("small");
      address.textContent = result.host;
      identity.appendChild(address);
    }
    const state = document.createElement("span");
    state.className = "ping-host-option-state";
    button.append(indicator, identity, state);
    const healthCard = createHealthCard(result);
    healthGrid.appendChild(healthCard.card);
    const view = {
      button,
      indicator,
      stateLabel: state,
      healthCard,
      result,
      state: "down",
    };
    button.addEventListener("click", () => toggleGraph(result.host));
    wireGridPreview(view);
    return view;
  }

  function updateHostView(view) {
    const selected = selectedHosts.has(view.result.host);
    view.button.dataset.state = view.state;
    view.button.classList.toggle("selected", selected);
    view.button.setAttribute("aria-selected", String(selected));
    view.stateLabel.textContent = healthStateLabel(view.state);
    updateHealthCard(view);
  }

  function toggleGraph(host) {
    if (selectedHosts.has(host)) {
      deselectGraph(host);
      return;
    }
    selectGraph(host);
  }

  function selectGraph(host, {persist = true} = {}) {
    const hostView = hostViews.get(host);
    if (!hostView) return;
    selectedHosts.add(host);
    updateHostView(hostView);
    let graphView = graphViews.get(host);
    if (!graphView) {
      graphView = createGraphView(hostView.result);
      graphViews.set(host, graphView);
      graphGrid.appendChild(graphView.card);
    }
    const series = history.get(host);
    if (series) updateGraphView(graphView, hostView.result, series);
    if (hostView.state === "removed") updateGraphStatus(graphView, "removed");
    if (persist) persistGraphSelection();
    updateSelectionSummary();
    applyHostFilters();
    updateHistoryNavigator();
  }

  function deselectGraph(host) {
    selectedHosts.delete(host);
    const hostView = hostViews.get(host);
    if (hostView) updateHostView(hostView);
    const graphView = graphViews.get(host);
    if (graphView) graphView.card.remove();
    graphViews.delete(host);
    persistGraphSelection();
    updateSelectionSummary();
    applyHostFilters();
    updateHistoryNavigator();
  }

  function createGraphView(result) {
    const card = document.createElement("article");
    card.className = "ping-graph-card";
    const header = document.createElement("header");
    const identity = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = result.label || result.host;
    identity.appendChild(title);
    if (result.label) {
      const address = document.createElement("code");
      address.textContent = result.host;
      identity.appendChild(address);
    }
    const actions = document.createElement("div");
    actions.className = "ping-graph-card-actions";
    const state = document.createElement("span");
    state.className = "pill";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "graph-close-button ping-graph-remove";
    const removeLabel = `Remove ${result.label || result.host} graph`;
    remove.title = removeLabel;
    remove.setAttribute("aria-label", removeLabel);
    remove.addEventListener("click", () => deselectGraph(result.host));
    actions.append(state, remove);
    const statistics = document.createElement("div");
    statistics.className = "ping-host-statistics";
    header.append(identity, statistics, actions);
    const chart = document.createElement("div");
    chart.className = "ping-history-canvas-wrap";
    const canvas = document.createElement("canvas");
    canvas.className = "ping-history-canvas";
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", `Latency history for ${result.label || result.host}`);
    chart.appendChild(canvas);
    card.append(header, chart);
    const view = {
      card,
      status: state,
      statistics,
      chart,
      canvas,
      host: result.host,
      variant: "detail",
      visiblePoints: [],
    };
    canvas.addEventListener("mousemove", (event) => showCanvasTooltip(view, event));
    canvas.addEventListener("mouseleave", () => {
      chartTooltip.hidden = true;
    });
    return view;
  }

  function updateGraphView(view, result, series) {
    updateGraphStatus(view, healthState(result, series));
    const statistics = statisticsCell(series);
    view.statistics.replaceChildren(...statistics.childNodes);
    renderHistoryCanvas(view, series);
  }

  function updateGraphStatus(view, state) {
    view.status.textContent = healthStateLabel(state);
    view.status.className = `pill${state === "healthy" ? " success" : state === "degraded" ? " warning" : state === "down" ? " error" : ""}`;
  }

  function updateSelectionSummary() {
    const count = selectedHosts.size;
    selectionCount.textContent = `${count} graphed`;
    graphSummary.textContent = count
      ? `${count} selected host${count === 1 ? "" : "s"}`
      : "Select a host from the list.";
    graphEmpty.hidden = count > 0;
    updateHealthSummary();
  }

  function applyHostFilters() {
    const query = hostFilter.value.trim().toLowerCase();
    const stateFilter = hostStatusFilter.value;
    hostViews.forEach((view, host) => {
      const identity = `${view.result.label || ""} ${host} ${view.state}`.toLowerCase();
      const stateMatches = stateFilter === "all"
        || stateFilter === view.state
        || (stateFilter === "selected" && selectedHosts.has(host));
      const hidden = !stateMatches || Boolean(query && !identity.includes(query));
      view.button.hidden = hidden;
      view.healthCard.card.hidden = hidden;
    });
  }

  function readDisplayPreference(key, allowed, fallback) {
    try {
      const value = localStorage.getItem(key);
      return allowed.includes(value) ? value : fallback;
    } catch (_error) {
      return fallback;
    }
  }

  function setViewMode(mode, {persist = true} = {}) {
    const selected = mode === "grid" ? "grid" : "graphs";
    resultsPanel.dataset.viewMode = selected;
    viewButtons.forEach((button) => {
      const active = button.dataset.pingView === selected;
      button.setAttribute("aria-pressed", String(active));
      button.classList.toggle("active", active);
    });
    if (persist) {
      try {
        localStorage.setItem(viewStorageKey, selected);
      } catch (_error) {
        // Display preferences are optional.
      }
    }
    if (selected === "graphs") hideGridPreview();
    window.requestAnimationFrame(() => {
      renderAllCharts();
      updateHealthSummary();
    });
  }

  function setGraphSize(size, {persist = true} = {}) {
    const selected = ["small", "medium", "large"].includes(size) ? size : "large";
    resultsPanel.dataset.graphSize = selected;
    sizeButtons.forEach((button) => {
      const active = button.dataset.pingSize === selected;
      button.setAttribute("aria-pressed", String(active));
      button.classList.toggle("active", active);
    });
    if (persist) {
      try {
        localStorage.setItem(sizeStorageKey, selected);
      } catch (_error) {
        // Display preferences are optional.
      }
    }
    window.requestAnimationFrame(renderAllCharts);
  }

  function healthStorageKey() {
    return activeSession?.id ? `${healthStoragePrefix}${activeSession.id}` : "";
  }

  function healthThresholdValues() {
    const value = (input) => {
      if (input.value.trim() === "") return null;
      const number = Number(input.value);
      return Number.isFinite(number) ? number : null;
    };
    return {
      loss_pct: value(healthLoss),
      latency_ms: value(healthLatency),
      jitter_ms: value(healthJitter),
    };
  }

  function restoreHealthThresholds(values, {preferStored = true} = {}) {
    let thresholds = values && typeof values === "object" ? values : {};
    const storageKey = healthStorageKey();
    if (preferStored && storageKey) {
      try {
        const stored = JSON.parse(localStorage.getItem(storageKey) || "null");
        if (stored && typeof stored === "object") thresholds = stored;
      } catch (_error) {
        // Invalid optional presentation state falls back to the session values.
      }
    }
    const assign = (input, key, fallback) => {
      const value = Object.prototype.hasOwnProperty.call(thresholds, key)
        ? thresholds[key]
        : fallback;
      input.value = value == null ? "" : String(value);
    };
    assign(healthLoss, "loss_pct", 5);
    assign(healthLatency, "latency_ms", 100);
    assign(healthJitter, "jitter_ms", 30);
    updateHealthSettingsSummary();
  }

  function persistHealthThresholds() {
    const storageKey = healthStorageKey();
    if (!storageKey) return;
    try {
      localStorage.setItem(storageKey, JSON.stringify(healthThresholdValues()));
    } catch (_error) {
      // Monitoring remains usable when browser storage is unavailable.
    }
  }

  function updateHealthSettingsSummary() {
    const thresholds = healthThresholdValues();
    const values = [];
    if (thresholds.loss_pct != null) values.push(`${thresholds.loss_pct}% loss`);
    if (thresholds.latency_ms != null) values.push(`${thresholds.latency_ms} ms latency`);
    if (thresholds.jitter_ms != null) values.push(`${thresholds.jitter_ms} ms jitter`);
    healthSettingsSummary.textContent = values.length ? values.join(" · ") : "No degradation thresholds";
  }

  function healthStateLabel(state) {
    if (state === "healthy") return "Healthy";
    if (state === "degraded") return "Degraded";
    if (state === "down") return "Down";
    return "Removed";
  }

  function healthMetrics(series) {
    if (!series) return {average: null, jitter: null, lossPct: 0, total: 0};
    const points = historyPoints(series);
    if (!points.length) return {average: null, jitter: null, lossPct: 0, total: 0};
    const newest = points[points.length - 1].time.getTime();
    const recent = points.filter((point) => point.time.getTime() >= newest - 60_000);
    let total = 0;
    let received = 0;
    let latencySum = 0;
    const latencies = [];
    recent.forEach((point) => {
      const sent = Math.max(1, Number(point.total) || 1);
      const replies = point.reachable ? Math.max(0, sent * (1 - Number(point.loss || 0))) : 0;
      total += sent;
      received += replies;
      if (replies && Number.isFinite(point.latency)) {
        latencySum += point.latency * replies;
        latencies.push(point.latency);
      }
    });
    const jitter = latencies.length > 1
      ? latencies.slice(1).reduce((sum, value, index) => sum + Math.abs(value - latencies[index]), 0) / (latencies.length - 1)
      : 0;
    return {
      average: received ? latencySum / received : null,
      jitter,
      lossPct: total ? (total - received) / total * 100 : 0,
      total,
    };
  }

  function healthState(result, series) {
    if (!result?.reachable) return "down";
    const metrics = healthMetrics(series);
    const thresholds = healthThresholdValues();
    const degraded = (
      thresholds.loss_pct != null && metrics.lossPct > thresholds.loss_pct
    ) || (
      thresholds.latency_ms != null && metrics.average != null && metrics.average > thresholds.latency_ms
    ) || (
      thresholds.jitter_ms != null && metrics.jitter != null && metrics.jitter > thresholds.jitter_ms
    );
    return degraded ? "degraded" : "healthy";
  }

  function createHealthCard(result) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "ping-health-card";
    const identity = document.createElement("span");
    identity.className = "ping-health-card-identity";
    const label = document.createElement("strong");
    label.textContent = result.label || result.host;
    const address = document.createElement("small");
    address.textContent = result.label ? result.host : "Live target";
    identity.append(label, address);
    const current = document.createElement("strong");
    current.className = "ping-health-current";
    const detail = document.createElement("small");
    detail.className = "ping-health-detail";
    const state = document.createElement("span");
    state.className = "ping-health-card-state";
    card.append(identity, current, detail, state);
    return {card, identity, current, detail, state};
  }

  function updateHealthCard(view) {
    const metrics = healthMetrics(history.get(view.result.host));
    const latency = view.result.reachable && Number.isFinite(Number(view.result.latency_ms))
      ? formatLatency(Number(view.result.latency_ms))
      : "No reply";
    view.healthCard.card.dataset.state = view.state;
    view.healthCard.current.textContent = latency;
    view.healthCard.detail.textContent = metrics.total
      ? `${metrics.lossPct.toFixed(1)}% loss · ${metrics.jitter.toFixed(1)} ms jitter`
      : "Waiting for history";
    view.healthCard.state.textContent = healthStateLabel(view.state);
    view.healthCard.card.setAttribute(
      "aria-label",
      `${view.result.label || view.result.host}: ${healthStateLabel(view.state)}, ${latency}. Show recent graph.`
    );
  }

  function updateHealthSummary() {
    const counts = {healthy: 0, degraded: 0, down: 0};
    hostViews.forEach((view, host) => {
      if (activeHosts.has(host) && counts[view.state] != null) counts[view.state] += 1;
    });
    const total = counts.healthy + counts.degraded + counts.down;
    healthSummary.textContent = total
      ? `${counts.healthy} healthy · ${counts.degraded} degraded · ${counts.down} down`
      : "Waiting for results.";
  }

  function wireGridPreview(view) {
    const card = view.healthCard.card;
    card.addEventListener("pointerenter", () => {
      if (!finePointer.matches) return;
      clearTimeout(gridPreviewShowTimer);
      gridPreviewShowTimer = setTimeout(
        () => showGridPreview(view.result.host, card, false),
        180
      );
    });
    card.addEventListener("pointerleave", () => {
      clearTimeout(gridPreviewShowTimer);
      scheduleGridPreviewHide();
    });
    card.addEventListener("focus", () => showGridPreview(view.result.host, card, false));
    card.addEventListener("blur", () => scheduleGridPreviewHide());
    card.addEventListener("click", () => {
      gridPreviewPinned = true;
      showGridPreview(view.result.host, card, true);
    });
  }

  function showGridPreview(host, anchor, pinned = false) {
    const view = hostViews.get(host);
    const series = history.get(host);
    if (!view || !series) return;
    if (gridPreviewPinned && !pinned && gridPreviewHost !== host) return;
    cancelGridPreviewHide();
    if (pinned) gridPreviewPinned = true;
    gridPreviewHost = host;
    gridPreviewAnchor = anchor;
    gridPreviewTitle.textContent = view.result.label || host;
    gridPreviewAddress.textContent = view.result.label ? host : "";
    gridPreviewAddress.hidden = !view.result.label;
    gridPreviewStatus.textContent = healthStateLabel(view.state);
    gridPreviewStatus.className = `pill${view.state === "healthy" ? " success" : view.state === "degraded" ? " warning" : view.state === "down" ? " error" : ""}`;
    const statistics = statisticsCell(series);
    gridPreviewStatistics.replaceChildren(...statistics.childNodes);
    previewView.host = host;
    gridPreview.hidden = false;
    window.requestAnimationFrame(() => {
      renderHistoryCanvas(previewView, series);
      positionGridPreview(anchor);
    });
  }

  function refreshGridPreview() {
    if (gridPreview.hidden || !gridPreviewHost || !gridPreviewAnchor) return;
    showGridPreview(gridPreviewHost, gridPreviewAnchor, gridPreviewPinned);
  }

  function scheduleGridPreviewHide() {
    if (gridPreviewPinned) return;
    clearTimeout(gridPreviewHideTimer);
    gridPreviewHideTimer = setTimeout(hideGridPreview, 220);
  }

  function cancelGridPreviewHide() {
    clearTimeout(gridPreviewHideTimer);
  }

  function hideGridPreview() {
    clearTimeout(gridPreviewShowTimer);
    clearTimeout(gridPreviewHideTimer);
    gridPreview.hidden = true;
    gridPreviewHost = "";
    gridPreviewAnchor = null;
    gridPreviewPinned = false;
    chartTooltip.hidden = true;
  }

  function positionGridPreview(anchor) {
    if (gridPreview.hidden || !anchor) return;
    if (window.matchMedia("(max-width: 760px)").matches) {
      gridPreview.style.left = "";
      gridPreview.style.top = "";
      return;
    }
    const margin = 12;
    const anchorBox = anchor.getBoundingClientRect();
    const previewBox = gridPreview.getBoundingClientRect();
    let left = anchorBox.right + margin;
    if (left + previewBox.width > window.innerWidth - margin) {
      left = anchorBox.left - previewBox.width - margin;
    }
    left = Math.max(margin, Math.min(left, window.innerWidth - previewBox.width - margin));
    const top = Math.max(
      margin,
      Math.min(anchorBox.top, window.innerHeight - previewBox.height - margin)
    );
    gridPreview.style.left = `${Math.round(left)}px`;
    gridPreview.style.top = `${Math.round(top)}px`;
  }

  function openPreviewDetail() {
    const host = gridPreviewHost;
    if (!host) return;
    selectGraph(host);
    setViewMode("graphs");
    hideGridPreview();
    window.requestAnimationFrame(() => {
      graphViews.get(host)?.card.scrollIntoView({behavior: "smooth", block: "center"});
    });
  }

  function createHistory() {
    return {raw: [], tenSecond: [], minute: []};
  }

  function addHistorySample(series, point) {
    series.raw.push(point);
    const now = point.time.getTime();
    const rawCutoff = now - 10 * 60 * 1000;
    while (series.raw.length && series.raw[0].time.getTime() < rawCutoff) {
      mergeBucket(series.tenSecond, pointToBucket(series.raw.shift()), 10_000);
    }
    const tenSecondCutoff = now - 60 * 60 * 1000;
    while (series.tenSecond.length && series.tenSecond[0].time.getTime() < tenSecondCutoff) {
      mergeBucket(series.minute, series.tenSecond.shift(), 60_000);
    }
    const retainedCutoff = now - 7 * 24 * 60 * 60 * 1000;
    while (series.minute.length && series.minute[0].time.getTime() < retainedCutoff) {
      series.minute.shift();
    }
    trimHistoryToBudget(series);
  }

  function trimHistoryToBudget(series) {
    const targetCount = Math.max(1, activeHosts.size);
    const perHostBudget = Math.max(
      600,
      Math.min(20_000, Math.floor(historySampleBudget / targetCount))
    );
    while (series.raw.length + series.tenSecond.length + series.minute.length > perHostBudget) {
      if (series.minute.length) series.minute.shift();
      else if (series.tenSecond.length) series.tenSecond.shift();
      else series.raw.shift();
    }
  }

  function pointToBucket(point) {
    const received = point.reachable && Number.isFinite(point.latency) ? 1 : 0;
    return {
      time: point.time,
      min: received ? point.latency : null,
      max: received ? point.latency : null,
      sum: received ? point.latency : 0,
      received,
      total: 1,
    };
  }

  function mergeBucket(target, source, bucketSize) {
    const bucketTime = Math.floor(source.time.getTime() / bucketSize) * bucketSize;
    let bucket = target[target.length - 1];
    if (!bucket || bucket.time.getTime() !== bucketTime) {
      bucket = {time: new Date(bucketTime), min: null, max: null, sum: 0, received: 0, total: 0};
      target.push(bucket);
    }
    if (source.received) {
      bucket.min = bucket.min == null ? source.min : Math.min(bucket.min, source.min);
      bucket.max = bucket.max == null ? source.max : Math.max(bucket.max, source.max);
    }
    bucket.sum += source.sum;
    bucket.received += source.received;
    bucket.total += source.total;
  }

  function historyPoints(series) {
    const aggregated = [...series.minute, ...series.tenSecond].map((bucket) => ({
      time: bucket.time,
      latency: bucket.received ? bucket.sum / bucket.received : null,
      min: bucket.min,
      max: bucket.max,
      reachable: bucket.received > 0,
      loss: (bucket.total - bucket.received) / bucket.total,
      total: bucket.total,
    }));
    return [...aggregated, ...series.raw.map((point) => ({
      ...point,
      min: point.latency,
      max: point.latency,
      loss: point.reachable ? 0 : 1,
      total: 1,
    }))];
  }

  function renderHistoryCanvas(view, series) {
    const points = historyPoints(series);
    if (!points.length) return;
    const canvas = view.canvas;
    const cssWidth = Math.floor(view.chart.clientWidth);
    if (cssWidth <= 0) return;
    const cssHeight = view.variant === "preview"
      ? 170
      : ({small: 110, medium: 170, large: 240}[resultsPanel.dataset.graphSize] || 240);
    const scale = window.devicePixelRatio || 1;
    canvas.width = Math.round(cssWidth * scale);
    canvas.height = Math.round(cssHeight * scale);
    canvas.style.width = `${cssWidth}px`;
    canvas.style.height = `${cssHeight}px`;
    const context = canvas.getContext("2d");
    context.scale(scale, scale);

    const plotTop = 14;
    const plotBottom = cssHeight - 38;
    const plotLeft = 44;
    const plotRight = 12;
    const plotWidth = cssWidth - plotLeft - plotRight;
    const earliest = points[0].time.getTime();
    const latest = points[points.length - 1].time.getTime();
    const selectedRange = Number(historyRange.value);
    const availableTravel = Math.max(0, latest - earliest - selectedRange);
    const sliderEndTime = latest - availableTravel * (1 - Number(historyPosition.value) / 1000);
    const endTime = followLive.checked
      ? latest
      : Math.max(earliest, Math.min(latest, lockedViewEnd ?? sliderEndTime));
    const startTime = Math.max(earliest, endTime - selectedRange);
    const visible = points.filter((point) => {
      const time = point.time.getTime();
      return time >= startTime && time <= endTime;
    });
    view.visiblePoints = visible;
    view.viewStart = startTime;
    view.viewEnd = endTime;
    view.plotLeft = plotLeft;
    view.plotWidth = plotWidth;
    const maxLatency = niceUpperBound(Math.max(
      1,
      ...visible.filter((point) => point.max != null).map((point) => point.max)
    ));
    const xFor = (time) => plotLeft + ((time - startTime) / Math.max(1, endTime - startTime)) * plotWidth;
    const yFor = (latency) => plotTop + ((maxLatency - latency) / maxLatency) * (plotBottom - plotTop);

    const darkTheme = document.documentElement.dataset.theme === "dark";
    const gridColor = darkTheme ? "#405149" : "#dce3e9";
    const labelColor = darkTheme ? "#a6b5ad" : "#667482";
    const lineColor = darkTheme ? "#6ccf91" : "#2f78a8";
    const lossColor = darkTheme ? "#ff7b7f" : "#b43a3a";

    context.clearRect(0, 0, cssWidth, cssHeight);
    context.strokeStyle = gridColor;
    context.lineWidth = 1;
    [plotTop, (plotTop + plotBottom) / 2, plotBottom].forEach((y) => {
      context.beginPath();
      context.moveTo(plotLeft, y);
      context.lineTo(cssWidth - plotRight, y);
      context.stroke();
    });
    context.fillStyle = labelColor;
    context.font = "9px system-ui, sans-serif";
    context.fillText(`${maxLatency} ms`, 4, plotTop + 3);
    context.fillText(`${maxLatency / 2} ms`, 4, ((plotTop + plotBottom) / 2) + 3);
    context.fillText("0 ms", 4, plotBottom + 3);

    const bins = new Map();
    visible.forEach((point) => {
      const x = Math.max(0, Math.min(plotWidth - 1, Math.round(xFor(point.time.getTime()) - plotLeft)));
      const bin = bins.get(x) || {
        min: null,
        max: null,
        sum: 0,
        received: 0,
        loss: false,
        samples: 0,
        summarized: false,
      };
      bin.samples += 1;
      if (point.total > 1) bin.summarized = true;
      if (point.reachable && point.latency != null) {
        bin.min = bin.min == null ? point.min : Math.min(bin.min, point.min);
        bin.max = bin.max == null ? point.max : Math.max(bin.max, point.max);
        bin.sum += point.latency;
        bin.received += 1;
      }
      if (point.loss > 0) bin.loss = true;
      bins.set(x, bin);
    });

    context.strokeStyle = lineColor;
    context.lineWidth = 2;
    context.beginPath();
    let drawing = false;
    [...bins.entries()].sort((a, b) => a[0] - b[0]).forEach(([pixel, bin]) => {
      const x = plotLeft + pixel;
      if (!bin.received) {
        drawing = false;
        context.moveTo(x, plotBottom);
        return;
      }
      const average = bin.sum / bin.received;
      const y = yFor(average);
      if (!drawing) context.moveTo(x, y);
      else context.lineTo(x, y);
      drawing = true;
    });
    context.stroke();

    const showIndividualDots = visible.length <= 90;
    [...bins.entries()].forEach(([pixel, bin]) => {
      const x = plotLeft + pixel;
      if (bin.received) {
        if (bin.summarized || bin.samples > 1) {
          context.strokeStyle = lineColor;
          context.lineWidth = 1;
          context.beginPath();
          context.moveTo(x, yFor(bin.max));
          context.lineTo(x, yFor(bin.min));
          context.stroke();
        }
        if (showIndividualDots) {
          context.fillStyle = lineColor;
          context.beginPath();
          context.arc(x, yFor(bin.sum / bin.received), 2.5, 0, Math.PI * 2);
          context.fill();
        }
      }
      if (bin.loss) {
        context.strokeStyle = lossColor;
        context.lineWidth = 2;
        context.beginPath();
        context.moveTo(x, plotBottom - 7);
        context.lineTo(x, plotBottom);
        context.stroke();
      }
    });
    context.fillStyle = labelColor;
    context.font = "9px system-ui, sans-serif";
    context.fillText(new Date(startTime).toLocaleTimeString(), plotLeft, cssHeight - 8);
    const endLabel = new Date(endTime).toLocaleTimeString();
    context.fillText(endLabel, cssWidth - plotRight - context.measureText(endLabel).width, cssHeight - 8);
  }

  function statisticsCell(series) {
    const item = document.createElement("div");
    const totals = [...series.minute, ...series.tenSecond].reduce(
      (summary, bucket) => ({
        min: bucket.received ? (summary.min == null ? bucket.min : Math.min(summary.min, bucket.min)) : summary.min,
        max: bucket.received ? (summary.max == null ? bucket.max : Math.max(summary.max, bucket.max)) : summary.max,
        sum: summary.sum + bucket.sum,
        received: summary.received + bucket.received,
        total: summary.total + bucket.total,
      }),
      {min: null, max: null, sum: 0, received: 0, total: 0}
    );
    series.raw.forEach((point) => {
      totals.total += 1;
      if (point.reachable && Number.isFinite(point.latency)) {
        totals.min = totals.min == null ? point.latency : Math.min(totals.min, point.latency);
        totals.max = totals.max == null ? point.latency : Math.max(totals.max, point.latency);
        totals.sum += point.latency;
        totals.received += 1;
      }
    });
    const current = series.raw[series.raw.length - 1];
    const values = [
      ["Now", current?.reachable && Number.isFinite(current.latency) ? formatLatency(current.latency) : "Down"],
      ["Min", totals.received ? formatLatency(totals.min) : "—"],
      ["Avg", totals.received ? formatLatency(totals.sum / totals.received) : "—"],
      ["Max", totals.received ? formatLatency(totals.max) : "—"],
      ["Loss", `${(totals.total ? (totals.total - totals.received) / totals.total * 100 : 0).toFixed(1)}%`],
    ];
    const grid = document.createElement("div");
    grid.className = "ping-statistics";
    values.forEach(([label, value]) => {
      const stat = document.createElement("span");
      const name = document.createElement("small");
      name.textContent = label;
      const measurement = document.createElement("strong");
      measurement.textContent = value;
      stat.append(name, measurement);
      grid.append(stat);
    });
    item.append(grid);
    return item;
  }

  function formatLatency(value) {
    return `${value < 1 ? value.toFixed(3) : value.toFixed(1)} ms`;
  }

  function niceUpperBound(value) {
    const exponent = 10 ** Math.floor(Math.log10(value));
    const normalized = value / exponent;
    const nice = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
    return nice * exponent;
  }

  function renderAllCharts() {
    graphViews.forEach((view, host) => {
      const series = history.get(host);
      if (series) renderHistoryCanvas(view, series);
    });
    if (!gridPreview.hidden && gridPreviewHost) {
      const series = history.get(gridPreviewHost);
      if (series) renderHistoryCanvas(previewView, series);
    }
    updateHistoryNavigator();
  }

  function scheduleGraphResize() {
    if (resizeFrame !== null) return;
    resizeFrame = window.requestAnimationFrame(() => {
      resizeFrame = null;
      renderAllCharts();
    });
  }

  function retainedBounds() {
    let earliest = Infinity;
    let latest = -Infinity;
    const visibleHosts = resultsPanel.dataset.viewMode === "grid"
      ? activeHosts
      : selectedHosts;
    visibleHosts.forEach((host) => {
      const series = history.get(host);
      if (!series) return;
      const points = historyPoints(series);
      if (points.length) {
        earliest = Math.min(earliest, points[0].time.getTime());
        latest = Math.max(latest, points[points.length - 1].time.getTime());
      }
    });
    return Number.isFinite(earliest) ? {earliest, latest} : null;
  }

  function updateHistoryNavigator() {
    const bounds = retainedBounds();
    if (!bounds) {
      historyPosition.disabled = true;
      historyPosition.value = "1000";
      historyEnd.disabled = true;
      historyEnd.value = "";
      historyOlder.disabled = true;
      historyNewer.disabled = true;
      historyNavigationSummary.textContent = "No graph selected";
      return;
    }
    const selectedRange = Number(historyRange.value);
    const canNavigate = bounds.latest - bounds.earliest > selectedRange;
    historyPosition.disabled = !canNavigate;
    const travel = Math.max(0, bounds.latest - bounds.earliest - selectedRange);
    if (followLive.checked) {
      historyPosition.value = "1000";
    }
    if (!canNavigate) {
      historyNavigationSummary.textContent = "Live";
      historyEnd.disabled = false;
      historyEnd.value = datetimeLocalValue(bounds.latest);
      historyOlder.disabled = true;
      historyNewer.disabled = true;
      return;
    }
    const endTime = followLive.checked
      ? bounds.latest
      : lockedViewEnd ?? viewEndForSliderPosition();
    historyNavigationSummary.textContent = followLive.checked
      ? "Live"
      : `Locked through ${new Date(endTime).toLocaleTimeString()}`;
    historyEnd.disabled = false;
    historyEnd.value = datetimeLocalValue(endTime);
    const oldestEnd = bounds.earliest + selectedRange;
    historyOlder.disabled = endTime <= oldestEnd;
    historyNewer.disabled = followLive.checked || endTime >= bounds.latest;
  }

  function viewEndForSliderPosition() {
    const bounds = retainedBounds();
    if (!bounds) return null;
    const selectedRange = Number(historyRange.value);
    const travel = Math.max(0, bounds.latest - bounds.earliest - selectedRange);
    return bounds.earliest + selectedRange + travel * (Number(historyPosition.value) / 1000);
  }

  function lockViewToPosition() {
    lockedViewEnd = viewEndForSliderPosition();
  }

  function clampViewEnd(value) {
    const bounds = retainedBounds();
    if (!bounds) return value;
    const oldestEnd = Math.min(bounds.latest, bounds.earliest + Number(historyRange.value));
    return Math.max(oldestEnd, Math.min(bounds.latest, value));
  }

  function shiftHistoryWindow(direction) {
    const bounds = retainedBounds();
    if (!bounds) return;
    const currentEnd = followLive.checked ? bounds.latest : (lockedViewEnd ?? bounds.latest);
    const target = currentEnd + direction * Number(historyRange.value);
    if (target >= bounds.latest) {
      followLive.checked = true;
      lockedViewEnd = null;
      historyPosition.value = "1000";
    } else {
      followLive.checked = false;
      lockedViewEnd = clampViewEnd(target);
      syncSliderToLockedEnd();
    }
    renderAllCharts();
  }

  function syncSliderToLockedEnd() {
    const bounds = retainedBounds();
    if (!bounds || lockedViewEnd == null) return;
    const selectedRange = Number(historyRange.value);
    const travel = Math.max(0, bounds.latest - bounds.earliest - selectedRange);
    if (!travel) return;
    const position = (lockedViewEnd - bounds.earliest - selectedRange) / travel;
    historyPosition.value = String(Math.round(Math.max(0, Math.min(1, position)) * 1000));
  }

  function datetimeLocalValue(timestamp) {
    const value = new Date(timestamp);
    const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 19);
  }

  function showCanvasTooltip(view, event) {
    if (!view.visiblePoints.length) return;
    const rect = view.canvas.getBoundingClientRect();
    const plotX = event.clientX - rect.left;
    if (plotX < view.plotLeft || plotX > view.plotLeft + view.plotWidth) {
      chartTooltip.hidden = true;
      return;
    }
    const time = view.viewStart
      + ((plotX - view.plotLeft) / view.plotWidth) * (view.viewEnd - view.viewStart);
    let low = 0;
    let high = view.visiblePoints.length - 1;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (view.visiblePoints[middle].time.getTime() < time) low = middle + 1;
      else high = middle;
    }
    const candidates = [view.visiblePoints[low], view.visiblePoints[Math.max(0, low - 1)]];
    const point = candidates.reduce((closest, candidate) => (
      Math.abs(candidate.time.getTime() - time) < Math.abs(closest.time.getTime() - time)
        ? candidate
        : closest
    ));
    const details = point.reachable
      ? point.total > 1
        ? `Avg ${formatLatency(point.latency)} · Min ${formatLatency(point.min)} · Max ${formatLatency(point.max)} · Loss ${(point.loss * 100).toFixed(1)}%`
        : formatLatency(point.latency)
      : "Unreachable";
    chartTooltip.textContent = `${formatTimestamp(point.time)} · ${details}`;
    chartTooltip.hidden = false;
    positionTooltip(event);
  }

  function exportHistoryCsv() {
    const rows = [[
      "host", "timestamp", "resolution", "minimum_ms", "average_ms",
      "maximum_ms", "sent", "received", "loss_percent",
    ]];
    history.forEach((series, host) => {
      const appendBucket = (bucket, resolution) => {
        rows.push([
          host,
          bucket.time.toISOString(),
          resolution,
          bucket.min == null ? "" : bucket.min,
          bucket.received ? bucket.sum / bucket.received : "",
          bucket.max == null ? "" : bucket.max,
          bucket.total,
          bucket.received,
          ((bucket.total - bucket.received) / bucket.total * 100).toFixed(3),
        ]);
      };
      series.minute.forEach((bucket) => appendBucket(bucket, "1 minute"));
      series.tenSecond.forEach((bucket) => appendBucket(bucket, "10 seconds"));
      series.raw.forEach((point) => appendBucket(pointToBucket(point), "raw"));
    });
    if (rows.length === 1) return;
    const csv = rows.map((row) => row.map(csvValue).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], {type: "text/csv;charset=utf-8"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = `ping-history-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function csvValue(value) {
    const text = String(value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function formatTimestamp(value) {
    return value.toLocaleString([], {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function positionTooltip(event) {
    chartTooltip.style.left = `${event.clientX + 12}px`;
    chartTooltip.style.top = `${event.clientY + 12}px`;
  }

  function updateProfileOption(profile, originalName) {
    if (originalName && originalName !== profile.name) {
      profileSelect.querySelector(`option[value="${CSS.escape(originalName)}"]`)?.remove();
    }
    let option = profileSelect.querySelector(`option[value="${CSS.escape(profile.name)}"]`);
    if (!option) {
      option = document.createElement("option");
      option.value = profile.name;
      profileSelect.appendChild(option);
    }
    option.textContent = profile.name;
    option.dataset.interval = String(profile.interval);
    option.dataset.timeout = String(profile.timeout || 1);
    option.dataset.targets = JSON.stringify(profile.targets);
    option.dataset.healthThresholds = JSON.stringify(
      profile.health_thresholds || healthThresholdValues()
    );
    profileSelect.value = profile.name;
  }

  async function restoreLiveSession(sessionId) {
    startButton.disabled = true;
    status.textContent = "Restoring live ping session...";
    try {
      const response = await fetch(
        `${form.dataset.sessionStartUrl}/${encodeURIComponent(sessionId)}`,
        {headers: {"Accept": "application/json"}}
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Live ping session could not be restored.");
      activateSession(data.session, {resetHistory: true});
      await loadNewSamples();
      updateSessionStatus();
      if (activeSession.state === "running") pollSession();
      else markSessionStopped(activeSession.last_error || `Session ${activeSession.state}.`);
    } catch (error) {
      status.textContent = error.message;
      startButton.disabled = false;
    }
  }

  if (form.dataset.requestedSession) {
    restoreLiveSession(form.dataset.requestedSession);
  }
})();
