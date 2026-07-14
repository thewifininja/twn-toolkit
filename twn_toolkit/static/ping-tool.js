(function () {
  const form = document.getElementById("ping-form");
  const hostsInput = document.getElementById("ping-hosts");
  const intervalInput = document.getElementById("ping-interval");
  const startButton = document.getElementById("ping-start");
  const stopButton = document.getElementById("ping-stop");
  const updateTargetsButton = document.getElementById("ping-update-targets");
  const profileSelect = document.getElementById("ping-profile");
  const profileNameInput = document.getElementById("ping-profile-name");
  const profileSaveButton = document.getElementById("ping-profile-save");
  const profileDeleteButton = document.getElementById("ping-profile-delete");
  const status = document.getElementById("ping-status");
  const validationWarning = document.getElementById("ping-validation-warning");
  const resultsPanel = document.getElementById("ping-results");
  const tableBody = document.querySelector(".ping-table tbody");
  const historyRange = document.getElementById("ping-history-range");
  const followLive = document.getElementById("ping-follow-live");
  const historyPosition = document.getElementById("ping-history-position");
  const exportHistory = document.getElementById("ping-export-history");
  const historyEnd = document.getElementById("ping-history-end");
  const historyOlder = document.getElementById("ping-history-older");
  const historyNewer = document.getElementById("ping-history-newer");
  const historyNavigationSummary = document.getElementById("ping-history-navigation-summary");

  if (!form || !hostsInput || !intervalInput || !startButton || !stopButton || !updateTargetsButton ||
      !profileSelect || !profileNameInput || !profileSaveButton ||
      !profileDeleteButton || !status || !validationWarning || !resultsPanel ||
      !tableBody || !historyRange || !followLive || !historyPosition ||
      !exportHistory || !historyEnd || !historyOlder ||
      !historyNewer || !historyNavigationSummary) {
    return;
  }

  let running = false;
  let timer = null;
  let loadedProfileName = "";
  let lockedViewEnd = null;
  let runId = "";
  let pendingProbesSent = 0;
  let pendingRepliesReceived = 0;
  let lastActivityReport = 0;
  let activeHostsSource = "";
  let activeHosts = new Set();
  let activeTargetRevision = 0;
  const history = new Map();
  const resultRows = new Map();
  const profileStorageKey = "twn:ping-profile";
  const activityIntervalMs = 30_000;
  const chartTooltip = document.createElement("div");
  chartTooltip.className = "ping-chart-tooltip";
  chartTooltip.hidden = true;
  document.body.appendChild(chartTooltip);
  window.addEventListener("themechange", renderAllCharts);

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
      sessionStorage.removeItem(profileStorageKey);
      status.textContent = "Ready to create a new profile.";
      return;
    }
    const targets = JSON.parse(option.dataset.targets || "[]");
    hostsInput.value = targets
      .map((target) => target.label ? `${target.label} = ${target.host}` : target.host)
      .join("\n");
    intervalInput.value = option.dataset.interval || "2";
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
    activeHosts = new Set(targets.map((target) => target.host));
    activeTargetRevision += 1;
    running = true;
    history.clear();
    resultRows.clear();
    lockedViewEnd = null;
    followLive.checked = true;
    historyPosition.value = "1000";
    tableBody.innerHTML = "";
    startButton.disabled = true;
    stopButton.disabled = false;
    updateTargetsButton.disabled = false;
    resultsPanel.hidden = false;
    resetActivityRun();
    reportPingActivity("start", {
      targets: targets.length,
      target_hosts: targets.map((target) => ({
        host: target.host,
        label: target.label || "",
      })),
    });
    runRound();
  });

  stopButton.addEventListener("click", () => {
    stopPingRun();
  });
  updateTargetsButton.addEventListener("click", async () => {
    if (!running) return;
    updateTargetsButton.disabled = true;
    status.textContent = "Validating updated targets...";
    try {
      const targets = await validateTargets(hostsInput.value);
      activeHostsSource = targetsToSource(targets);
      activeHosts = new Set(targets.map((target) => target.host));
      activeTargetRevision += 1;
      resultRows.forEach((view, host) => {
        if (!activeHosts.has(host)) {
          view.status.textContent = "Removed";
          view.status.className = "ping-paused";
        }
      });
      status.textContent = `Updated active targets to ${targets.length}. Existing history was preserved.`;
    } catch (error) {
      status.textContent = error.message;
    } finally {
      updateTargetsButton.disabled = !running;
    }
  });
  window.addEventListener("pagehide", () => {
    if (running || pendingProbesSent || pendingRepliesReceived) {
      flushPingActivity("final", true);
    }
  });

  async function runRound() {
    if (!running) {
      return;
    }
    const roundStarted = performance.now();
    const roundRevision = activeTargetRevision;
    const roundHostsSource = activeHostsSource;
    status.textContent = "Pinging...";
    try {
      const response = await fetch(form.dataset.runUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({hosts: roundHostsSource}),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Ping request failed.");
      }
      if (!running) {
        return;
      }
      if (roundRevision === activeTargetRevision) {
        renderResults(data.results || []);
        trackPingRound(data.results || []);
        status.textContent = `Last round completed at ${new Date().toLocaleTimeString()}.`;
      }
    } catch (error) {
      status.textContent = error.message;
      running = false;
      startButton.disabled = false;
      stopButton.disabled = true;
      updateTargetsButton.disabled = true;
      flushPingActivity("final");
      return;
    }

    const seconds = Math.max(1, Math.min(60, Number(intervalInput.value) || 2));
    const remainingDelay = Math.max(0, (seconds * 1000) - (performance.now() - roundStarted));
    timer = setTimeout(runRound, remainingDelay);
  }

  function stopPingRun() {
    running = false;
    clearTimeout(timer);
    startButton.disabled = false;
    stopButton.disabled = true;
    updateTargetsButton.disabled = true;
    status.textContent = "Stopped.";
    flushPingActivity("final");
  }

  function resetActivityRun() {
    runId = window.crypto && window.crypto.randomUUID
      ? window.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    pendingProbesSent = 0;
    pendingRepliesReceived = 0;
    lastActivityReport = performance.now();
  }

  function trackPingRound(results) {
    pendingProbesSent += results.length;
    pendingRepliesReceived += results.filter((result) => result.reachable).length;
    if (performance.now() - lastActivityReport >= activityIntervalMs) {
      flushPingActivity("checkpoint");
    }
  }

  function flushPingActivity(event, beacon = false) {
    if (!form.dataset.activityUrl || (!pendingProbesSent && !pendingRepliesReceived && event !== "start" && event !== "final")) {
      return;
    }
    const payload = {
      event,
      run_id: runId,
      probes_sent: pendingProbesSent,
      replies_received: pendingRepliesReceived,
    };
    pendingProbesSent = 0;
    pendingRepliesReceived = 0;
    lastActivityReport = performance.now();
    reportPingActivityPayload(payload, beacon);
  }

  function reportPingActivity(event, extra = {}) {
    reportPingActivityPayload({event, run_id: runId, ...extra});
  }

  function reportPingActivityPayload(payload, beacon = false) {
    const body = JSON.stringify(payload);
    if (beacon && navigator.sendBeacon) {
      const blob = new Blob([body], {type: "application/json"});
      navigator.sendBeacon(form.dataset.activityUrl, blob);
      return;
    }
    fetch(form.dataset.activityUrl, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body,
      keepalive: true,
    }).catch(() => {});
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
    const values = invalid.map((item) => item.value).join(", ");
    validationWarning.textContent = `${invalid.length} invalid target${invalid.length === 1 ? " was" : "s were"} skipped: ${values}`;
    validationWarning.hidden = false;
  }

  function targetsToSource(targets) {
    return targets
      .map((target) => target.label ? `${target.label} = ${target.host}` : target.host)
      .join("\n");
  }

  function renderResults(results) {
    results.forEach((result) => {
      const hostHistory = history.get(result.host) || createHistory();
      addHistorySample(hostHistory, {
        latency: result.latency_ms == null ? null : Number(result.latency_ms),
        reachable: Boolean(result.reachable),
        time: new Date(),
      });
      history.set(result.host, hostHistory);

      let view = resultRows.get(result.host);
      if (!view) {
        view = createResultRow(result);
        resultRows.set(result.host, view);
        tableBody.appendChild(view.row);
      }
      view.status.textContent = result.reachable ? "Up" : "Down";
      view.status.className = result.reachable ? "ping-up" : "ping-down";
      const statistics = statisticsCell(hostHistory);
      view.statistics.replaceChildren(...statistics.childNodes);
      renderHistoryCanvas(view, hostHistory);
    });
    updateHistoryNavigator();
  }

  function createResultRow(result) {
    const row = document.createElement("tr");
    const host = hostCell(result);
    const statistics = document.createElement("div");
    statistics.className = "ping-host-statistics";
    host.appendChild(statistics);
    row.appendChild(host);
    const statusCell = cell("");
    row.appendChild(statusCell);
    const historyCell = document.createElement("td");
    historyCell.className = "ping-history-cell";
    const chart = document.createElement("div");
    chart.className = "ping-history-canvas-wrap";
    const canvas = document.createElement("canvas");
    canvas.className = "ping-history-canvas";
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", `Latency history for ${result.label || result.host}`);
    chart.appendChild(canvas);
    historyCell.appendChild(chart);
    row.appendChild(historyCell);
    const view = {row, status: statusCell, statistics, chart, canvas, host: result.host, visiblePoints: []};
    canvas.addEventListener("mousemove", (event) => showCanvasTooltip(view, event));
    canvas.addEventListener("mouseleave", () => {
      chartTooltip.hidden = true;
    });
    return view;
  }

  function createHistory() {
    return {raw: [], tenSecond: [], minute: []};
  }

  function addHistorySample(series, point) {
    series.raw.push(point);
    const now = point.time.getTime();
    const rawCutoff = now - 60 * 60 * 1000;
    while (series.raw.length && series.raw[0].time.getTime() < rawCutoff) {
      mergeBucket(series.tenSecond, pointToBucket(series.raw.shift()), 10_000);
    }
    const tenSecondCutoff = now - 24 * 60 * 60 * 1000;
    while (series.tenSecond.length && series.tenSecond[0].time.getTime() < tenSecondCutoff) {
      mergeBucket(series.minute, series.tenSecond.shift(), 60_000);
    }
    const retainedCutoff = now - 7 * 24 * 60 * 60 * 1000;
    while (series.minute.length && series.minute[0].time.getTime() < retainedCutoff) {
      series.minute.shift();
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
    const cssWidth = Math.max(320, view.chart.clientWidth || 420);
    const cssHeight = 150;
    const scale = window.devicePixelRatio || 1;
    canvas.width = Math.round(cssWidth * scale);
    canvas.height = Math.round(cssHeight * scale);
    canvas.style.width = `${cssWidth}px`;
    canvas.style.height = `${cssHeight}px`;
    const context = canvas.getContext("2d");
    context.scale(scale, scale);

    const plotTop = 14;
    const plotBottom = 112;
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
    const item = document.createElement("td");
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
      ["Current", current?.reachable && Number.isFinite(current.latency) ? formatLatency(current.latency) : "Down"],
      ["Minimum", totals.received ? formatLatency(totals.min) : "—"],
      ["Average", totals.received ? formatLatency(totals.sum / totals.received) : "—"],
      ["Maximum", totals.received ? formatLatency(totals.max) : "—"],
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
    resultRows.forEach((view, host) => {
      const series = history.get(host);
      if (series) renderHistoryCanvas(view, series);
    });
    updateHistoryNavigator();
  }

  function retainedBounds() {
    let earliest = Infinity;
    let latest = -Infinity;
    history.forEach((series) => {
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
    if (!bounds) return;
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

  function cell(value) {
    const item = document.createElement("td");
    item.textContent = value;
    return item;
  }

  function hostCell(result) {
    const item = document.createElement("td");
    if (!result.label) {
      item.textContent = result.host;
      return item;
    }
    const label = document.createElement("strong");
    label.textContent = result.label;
    const host = document.createElement("span");
    host.className = "ping-host-address";
    host.textContent = result.host;
    item.append(label, host);
    return item;
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
    option.dataset.targets = JSON.stringify(profile.targets);
    profileSelect.value = profile.name;
  }
})();
