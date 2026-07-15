(() => {
  const root = document.querySelector(".snmp-interface-monitor");
  if (!root) return;

  const hostSelect = root.querySelector(".snmp-monitor-host");
  const discoverButton = root.querySelector(".snmp-monitor-discover");
  const selection = root.querySelector(".snmp-monitor-selection");
  const interfaceSelect = root.querySelector(".snmp-monitor-interface");
  const addButton = root.querySelector(".snmp-monitor-add");
  const intervalSelect = root.querySelector(".snmp-monitor-interval");
  const windowSelect = root.querySelector(".snmp-monitor-window");
  const historyPosition = root.querySelector(".snmp-monitor-history-position");
  const historySummary = root.querySelector(".snmp-monitor-history-summary");
  const historyOlder = root.querySelector(".snmp-monitor-history-older");
  const historyLive = root.querySelector(".snmp-monitor-history-live");
  const historyNewer = root.querySelector(".snmp-monitor-history-newer");
  const startButton = root.querySelector(".snmp-monitor-start");
  const stopButton = root.querySelector(".snmp-monitor-stop");
  const clearButton = root.querySelector(".snmp-monitor-clear");
  const status = root.querySelector(".snmp-monitor-status");
  const monitorSet = root.querySelector(".snmp-monitor-set");
  const count = root.querySelector(".snmp-monitor-count");
  const targetList = root.querySelector(".snmp-monitor-targets");

  const targets = new Map();
  let discoveredInterfaces = [];
  let discoveredHost = null;
  let running = false;
  let timer = null;
  let pollController = null;
  let pollInFlight = false;
  let historyEndAt = null;
  const MAX_POINTS = 10000;

  const postJson = async (url, payload, signal) => {
    const response = await fetch(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "same-origin",
      body: JSON.stringify(payload),
      signal,
    });
    let data = {};
    try { data = await response.json(); } catch (_error) { /* handled below */ }
    if (!response.ok) throw new Error(data.error || `Request failed (HTTP ${response.status}).`);
    return data;
  };

  const setStatus = (message, type = "") => {
    status.textContent = message;
    status.classList.toggle("error", type === "error");
    status.classList.toggle("success", type === "success");
  };

  const formatRate = (value) => {
    if (!Number.isFinite(value)) return "—";
    const units = [[1e12, "Tbps"], [1e9, "Gbps"], [1e6, "Mbps"], [1e3, "Kbps"]];
    for (const [size, unit] of units) {
      if (value >= size) return `${(value / size).toFixed(value >= size * 100 ? 0 : 1)} ${unit}`;
    }
    return `${Math.round(value)} bps`;
  };

  const formatSpeed = (value) => value ? formatRate(value) : "Speed unavailable";
  const formatDuration = (milliseconds) => {
    const minutes = milliseconds / 60000;
    if (minutes < 1) return `${Math.round(milliseconds / 1000)} seconds`;
    if (minutes === 1) return "1 minute";
    if (minutes < 60) return `${minutes} minutes`;
    return minutes === 60 ? "1 hour" : `${minutes / 60} hours`;
  };
  const formatPercent = (rate, speed) => speed ? `${Math.min(999, rate / speed * 100).toFixed(2)}% of link speed` : "Link speed unavailable";
  const targetKey = (hostName, interfaceIndex) => `${hostName}::${interfaceIndex}`;
  const interfaceName = (item) => item.name || item.description || `Interface ${item.index}`;
  const interfaceLabel = (item) => {
    const primary = interfaceName(item);
    const secondary = item.alias && item.alias !== primary ? ` — ${item.alias}` : "";
    return `${primary}${secondary} · ${item.oper_status} · ${formatSpeed(item.speed_bps)}`;
  };

  const monitorPayload = () => ({
    targets: [...targets.values()].map((target) => ({
      host_name: target.hostName,
      interface_index: target.interface.index,
      interface_label: target.label,
    })),
    interval: Number(intervalSelect.value),
  });

  const samplePayload = (target) => ({
    host_name: target.hostName,
    interface_index: target.interface.index,
  });

  const metric = (label, className, secondaryClass = "") => {
    const node = document.createElement("div");
    const caption = document.createElement("span");
    const value = document.createElement("strong");
    const secondary = document.createElement("small");
    caption.textContent = label;
    value.textContent = "—";
    value.className = className;
    secondary.className = secondaryClass;
    node.append(caption, value, secondary);
    return {node, value, secondary};
  };

  const createTargetCard = (target) => {
    const card = document.createElement("article");
    card.className = "snmp-monitor-target";
    const header = document.createElement("div");
    header.className = "snmp-monitor-target-head";
    const identity = document.createElement("div");
    const title = document.createElement("h4");
    const subtitle = document.createElement("p");
    title.textContent = `${target.hostName} · ${target.label}`;
    subtitle.textContent = `${target.hostAddress} · ifIndex ${target.interface.index}${target.interface.alias ? ` · ${target.interface.alias}` : ""}`;
    identity.append(title, subtitle);
    const remove = document.createElement("button");
    remove.className = "secondary compact snmp-monitor-remove";
    remove.type = "button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => removeTarget(target.key));
    header.append(identity, remove);

    const metrics = document.createElement("div");
    metrics.className = "snmp-monitor-summary";
    const link = metric("Link", "snmp-target-link", "snmp-target-speed");
    const download = metric("Download / interface TX", "snmp-target-download", "snmp-target-download-percent");
    const upload = metric("Upload / interface RX", "snmp-target-upload", "snmp-target-upload-percent");
    const peaks = metric("Observed peaks", "snmp-target-peaks", "snmp-target-health");
    link.value.textContent = target.interface.oper_status || "unknown";
    link.secondary.textContent = formatSpeed(target.interface.speed_bps);
    peaks.secondary.textContent = "Errors and discards: —";
    metrics.append(link.node, download.node, upload.node, peaks.node);

    const chartWrap = document.createElement("div");
    chartWrap.className = "snmp-monitor-chart-wrap";
    const canvas = document.createElement("canvas");
    canvas.className = "snmp-monitor-chart";
    canvas.setAttribute("aria-label", `${target.hostName} ${target.label} bandwidth history`);
    const empty = document.createElement("p");
    empty.className = "snmp-monitor-empty";
    empty.textContent = "The first poll establishes a counter baseline. Rates appear after the next sample.";
    const legend = document.createElement("div");
    legend.className = "snmp-monitor-legend";
    legend.innerHTML = '<span class="download">Download / interface TX</span><span class="upload">Upload / interface RX</span>';
    const tooltip = document.createElement("div");
    tooltip.className = "snmp-monitor-tooltip";
    tooltip.hidden = true;
    tooltip.setAttribute("role", "status");
    tooltip.innerHTML = '<strong class="snmp-monitor-tooltip-time"></strong><span class="download"></span><span class="upload"></span>';
    canvas.addEventListener("pointermove", (event) => updateChartHover(target, event));
    canvas.addEventListener("pointerdown", (event) => updateChartHover(target, event));
    canvas.addEventListener("pointerleave", () => clearChartHover(target));
    canvas.addEventListener("pointercancel", () => clearChartHover(target));
    chartWrap.append(canvas, empty, tooltip, legend);
    card.append(header, metrics, chartWrap);

    target.ui = {card, remove, link, download, upload, peaks, canvas, empty, tooltip};
    return card;
  };

  const updateSetControls = () => {
    count.textContent = String(targets.size);
    monitorSet.hidden = targets.size === 0;
    startButton.disabled = running || targets.size === 0;
    stopButton.disabled = !running;
    clearButton.disabled = ![...targets.values()].some((target) => target.points.length);
    addButton.disabled = running || targets.size >= 20 || !interfaceSelect.value;
    targets.forEach((target) => { target.ui.remove.disabled = running; });
  };

  const addTarget = () => {
    const selected = discoveredInterfaces.find((item) => String(item.index) === interfaceSelect.value);
    if (!selected || !discoveredHost) return;
    const key = targetKey(discoveredHost.name, selected.index);
    if (targets.has(key)) {
      setStatus(`${discoveredHost.name} / ${interfaceName(selected)} is already in the monitor set.`, "error");
      return;
    }
    if (targets.size >= 20) {
      setStatus("A monitor set can contain up to 20 interfaces.", "error");
      return;
    }
    const target = {
      key,
      hostName: discoveredHost.name,
      hostAddress: discoveredHost.host,
      interface: selected,
      label: interfaceName(selected),
      baseline: null,
      points: [],
      hoverAt: null,
      chartState: null,
      lastError: "",
      ui: null,
    };
    targets.set(key, target);
    targetList.append(createTargetCard(target));
    updateSetControls();
    updateHistoryControls();
    setStatus(`Added ${target.hostName} / ${target.label}. Select another host or interface, or start monitoring.`, "success");
    drawChart(target);
  };

  const removeTarget = (key) => {
    if (running) return;
    const target = targets.get(key);
    if (!target) return;
    target.ui.card.remove();
    targets.delete(key);
    updateSetControls();
    updateHistoryControls();
    drawAllCharts();
    setStatus(targets.size ? `${targets.size} interface(s) remain in the monitor set.` : "The monitor set is empty.");
  };

  const counterDelta = (current, previous, bits) => {
    if (current >= previous) return current - previous;
    if (bits === 32) return (1n << 32n) - previous + current;
    return null;
  };

  const sampleReset = (target, sample) => {
    const baseline = target.baseline;
    if (!baseline || baseline.bits !== sample.counter_bits) return true;
    if (sample.sys_uptime != null && baseline.uptime != null && sample.sys_uptime < baseline.uptime) return true;
    return sample.counter_discontinuity != null
      && baseline.discontinuity != null
      && sample.counter_discontinuity !== baseline.discontinuity;
  };

  const rememberBaseline = (target, sample) => {
    target.baseline = {
      at: sample.sampled_at_ms,
      input: BigInt(sample.input_octets),
      output: BigInt(sample.output_octets),
      bits: sample.counter_bits,
      uptime: sample.sys_uptime,
      discontinuity: sample.counter_discontinuity,
    };
  };

  const applySample = (target, sample) => {
    const currentInput = BigInt(sample.input_octets);
    const currentOutput = BigInt(sample.output_octets);
    const ui = target.ui;
    ui.link.value.textContent = sample.oper_status || "unknown";
    ui.link.secondary.textContent = formatSpeed(sample.speed_bps || target.interface.speed_bps);
    ui.peaks.secondary.textContent = `Interface RX/TX errors ${sample.input_errors ?? "—"}/${sample.output_errors ?? "—"} · discards ${sample.input_discards ?? "—"}/${sample.output_discards ?? "—"}`;
    target.lastError = "";

    if (sampleReset(target, sample)) {
      rememberBaseline(target, sample);
      ui.empty.hidden = false;
      ui.empty.textContent = "Counter baseline established. Waiting for the next sample.";
      return;
    }
    const baseline = target.baseline;
    const elapsed = (sample.sampled_at_ms - baseline.at) / 1000;
    const inputDelta = counterDelta(currentInput, baseline.input, baseline.bits);
    const outputDelta = counterDelta(currentOutput, baseline.output, baseline.bits);
    rememberBaseline(target, sample);
    if (elapsed <= 0 || inputDelta == null || outputDelta == null) {
      ui.empty.hidden = false;
      ui.empty.textContent = "The device counters reset. A new baseline was established.";
      return;
    }
    // IF-MIB counters are interface-relative: transmitted octets travel toward the
    // attached endpoint (download), while received octets arrive from it (upload).
    const downloadRate = Number(outputDelta) * 8 / elapsed;
    const uploadRate = Number(inputDelta) * 8 / elapsed;
    const speed = sample.speed_bps || target.interface.speed_bps || null;
    target.points.push({at: sample.sampled_at_ms, download: downloadRate, upload: uploadRate});
    if (target.points.length > MAX_POINTS) target.points.splice(0, target.points.length - MAX_POINTS);
    ui.download.value.textContent = formatRate(downloadRate);
    ui.download.secondary.textContent = formatPercent(downloadRate, speed);
    ui.upload.value.textContent = formatRate(uploadRate);
    ui.upload.secondary.textContent = formatPercent(uploadRate, speed);
    const peakDownload = Math.max(...target.points.map((point) => point.download));
    const peakUpload = Math.max(...target.points.map((point) => point.upload));
    ui.peaks.value.textContent = `${formatRate(peakDownload)} down / ${formatRate(peakUpload)} up`;
    ui.empty.hidden = true;
    drawChart(target);
  };

  const resetTarget = (target) => {
    target.baseline = null;
    target.points = [];
    target.hoverAt = null;
    target.chartState = null;
    target.lastError = "";
    target.ui.download.value.textContent = "—";
    target.ui.download.secondary.textContent = "";
    target.ui.upload.value.textContent = "—";
    target.ui.upload.secondary.textContent = "";
    target.ui.tooltip.hidden = true;
    target.ui.peaks.value.textContent = "—";
    target.ui.peaks.secondary.textContent = "Errors and discards: —";
    target.ui.empty.hidden = false;
    target.ui.empty.textContent = "The first poll establishes a counter baseline. Rates appear after the next sample.";
    drawChart(target);
  };

  const clearGraphs = () => {
    targets.forEach(resetTarget);
    historyEndAt = null;
    updateSetControls();
    updateHistoryControls();
    setStatus("Graphs and counter baselines cleared. Monitoring will establish fresh baselines on the next poll.");
  };

  const historyBounds = () => {
    const populated = [...targets.values()].filter((target) => target.points.length);
    if (!populated.length) return null;
    return {
      earliest: Math.min(...populated.map((target) => target.points[0].at)),
      latest: Math.max(...populated.map((target) => target.points.at(-1).at)),
    };
  };

  const visiblePoints = (target) => {
    const bounds = historyBounds();
    if (!bounds) return [];
    const windowMs = Number(windowSelect.value);
    const end = historyEndAt ?? bounds.latest;
    const start = end - windowMs;
    return target.points.filter((point) => point.at >= start && point.at <= end);
  };

  const updateHistoryControls = () => {
    const bounds = historyBounds();
    const windowMs = Number(windowSelect.value);
    const canNavigate = Boolean(bounds && bounds.latest - bounds.earliest > windowMs);
    const live = historyEndAt == null;
    historyPosition.disabled = !canNavigate;
    historyOlder.disabled = !canNavigate;
    historyNewer.disabled = !canNavigate || live;
    historyLive.disabled = live || !bounds;
    if (!bounds) {
      historyPosition.value = "1000";
      historySummary.textContent = `Live · last ${formatDuration(windowMs)}`;
      return;
    }
    const end = historyEndAt ?? bounds.latest;
    const span = Math.max(1, bounds.latest - bounds.earliest);
    historyPosition.value = String(Math.round((end - bounds.earliest) / span * 1000));
    historySummary.textContent = live
      ? `Live · last ${formatDuration(windowMs)}`
      : `Ending ${new Date(end).toLocaleString()} · ${formatDuration(windowMs)}`;
  };

  const setHistoryEnd = (value) => {
    const bounds = historyBounds();
    if (!bounds) return;
    historyEndAt = value >= bounds.latest ? null : Math.max(bounds.earliest, value);
    updateHistoryControls();
    drawAllCharts();
  };

  const niceScale = (maximum) => {
    if (!Number.isFinite(maximum) || maximum <= 0) return 1e3;
    const exponent = 10 ** Math.floor(Math.log10(maximum));
    const normalized = maximum / exponent;
    const factor = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
    return Math.max(1e3, factor * exponent);
  };

  const drawChart = (target) => {
    const canvas = target.ui.canvas;
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(300, rect.width);
    const height = Math.max(160, rect.height);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    const context = canvas.getContext("2d");
    context.scale(dpr, dpr);
    const styles = getComputedStyle(document.documentElement);
    const line = styles.getPropertyValue("--line").trim() || "#d3dfd8";
    const muted = styles.getPropertyValue("--muted").trim() || "#617069";
    const downloadColor = styles.getPropertyValue("--brand-green").trim() || "#2da747";
    const uploadColor = styles.getPropertyValue("--brand-red").trim() || "#db3c46";
    const padding = {left: 66, right: 12, top: 18, bottom: 28};
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const points = visiblePoints(target);
    const maxDownload = Math.max(0, ...points.map((point) => point.download));
    const maxUpload = Math.max(0, ...points.map((point) => point.upload));
    const totalMaximum = maxDownload + maxUpload;
    const downloadShare = totalMaximum > 0 ? maxDownload / totalMaximum : 0.5;
    const downloadHeightShare = Math.max(0.2, Math.min(0.8, downloadShare));
    const centerY = padding.top + plotHeight * downloadHeightShare;
    const downloadScale = niceScale(maxDownload);
    const uploadScale = niceScale(maxUpload);

    context.font = "12px system-ui, sans-serif";
    context.fillStyle = muted;
    context.strokeStyle = line;
    context.lineWidth = 1;
    [0, downloadHeightShare, 1].forEach((position) => {
      const y = padding.top + plotHeight * position;
      context.beginPath();
      context.moveTo(padding.left, y);
      context.lineTo(width - padding.right, y);
      context.stroke();
    });
    context.strokeStyle = muted;
    context.beginPath();
    context.moveTo(padding.left, centerY);
    context.lineTo(width - padding.right, centerY);
    context.stroke();
    context.fillText(formatRate(downloadScale), 4, padding.top + 4);
    context.fillText("0 bps", 4, centerY + 4);
    context.fillText(formatRate(uploadScale), 4, padding.top + plotHeight + 4);
    context.fillText("DOWN", padding.left + 8, padding.top + 15);
    context.fillText("UP", padding.left + 8, centerY + 18);

    if (!points.length) {
      target.chartState = null;
      target.hoverAt = null;
      target.ui.tooltip.hidden = true;
      return;
    }
    const windowMs = Number(windowSelect.value);
    const latest = historyEndAt ?? historyBounds()?.latest ?? points.at(-1).at;
    const earliest = latest - windowMs;
    const xFor = (point) => padding.left + Math.max(0, Math.min(1, (point.at - earliest) / windowMs)) * plotWidth;
    const drawArea = (key, direction, color, scale, availableHeight) => {
      const coordinates = points.map((point) => ({
        x: xFor(point),
        y: centerY + direction * Math.min(point[key], scale) / scale * availableHeight,
      }));
      context.save();
      context.fillStyle = color;
      context.globalAlpha = 0.22;
      context.beginPath();
      context.moveTo(coordinates[0].x, centerY);
      coordinates.forEach(({x, y}) => context.lineTo(x, y));
      context.lineTo(coordinates.at(-1).x, centerY);
      context.closePath();
      context.fill();
      context.restore();
      context.strokeStyle = color;
      context.lineWidth = 2;
      context.lineJoin = "round";
      context.beginPath();
      coordinates.forEach(({x, y}, index) => {
        if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
      });
      context.stroke();
    };
    drawArea("download", -1, downloadColor, downloadScale, centerY - padding.top);
    drawArea("upload", 1, uploadColor, uploadScale, padding.top + plotHeight - centerY);
    target.chartState = {points, width, padding, plotWidth, earliest, windowMs};
    const hovered = points.find((point) => point.at === target.hoverAt);
    if (hovered) {
      const x = xFor(hovered);
      target.ui.tooltip.style.left = `${Math.max(100, Math.min(rect.width - 100, x / width * rect.width))}px`;
      const downloadY = centerY - Math.min(hovered.download, downloadScale) / downloadScale * (centerY - padding.top);
      const uploadY = centerY + Math.min(hovered.upload, uploadScale) / uploadScale * (padding.top + plotHeight - centerY);
      context.save();
      context.strokeStyle = muted;
      context.setLineDash([4, 4]);
      context.beginPath();
      context.moveTo(x, padding.top);
      context.lineTo(x, padding.top + plotHeight);
      context.stroke();
      context.setLineDash([]);
      [[downloadY, downloadColor], [uploadY, uploadColor]].forEach(([y, color]) => {
        context.fillStyle = color;
        context.beginPath();
        context.arc(x, y, 4, 0, Math.PI * 2);
        context.fill();
      });
      context.restore();
    } else if (target.hoverAt != null) {
      target.hoverAt = null;
      target.ui.tooltip.hidden = true;
    }
    const first = new Date(earliest).toLocaleTimeString();
    const last = new Date(latest).toLocaleTimeString();
    context.fillStyle = muted;
    context.fillText(first, padding.left, height - 8);
    const measured = context.measureText(last).width;
    context.fillText(last, width - padding.right - measured, height - 8);
  };

  const updateChartHover = (target, event) => {
    const state = target.chartState;
    if (!state?.points.length) return;
    const rect = target.ui.canvas.getBoundingClientRect();
    const displayedX = event.clientX - rect.left;
    const chartX = displayedX * state.width / Math.max(1, rect.width);
    const localX = Math.max(
      state.padding.left,
      Math.min(state.width - state.padding.right, chartX),
    );
    const hoveredAt = state.earliest + (localX - state.padding.left) / state.plotWidth * state.windowMs;
    const point = state.points.reduce((nearest, candidate) => (
      Math.abs(candidate.at - hoveredAt) < Math.abs(nearest.at - hoveredAt) ? candidate : nearest
    ));
    target.hoverAt = point.at;
    const tooltip = target.ui.tooltip;
    tooltip.querySelector(".snmp-monitor-tooltip-time").textContent = new Date(point.at).toLocaleString();
    tooltip.querySelector(".download").textContent = `Download / interface TX: ${formatRate(point.download)}`;
    tooltip.querySelector(".upload").textContent = `Upload / interface RX: ${formatRate(point.upload)}`;
    tooltip.hidden = false;
    drawChart(target);
  };

  const clearChartHover = (target) => {
    if (target.hoverAt == null && target.ui.tooltip.hidden) return;
    target.hoverAt = null;
    target.ui.tooltip.hidden = true;
    drawChart(target);
  };

  const drawAllCharts = () => targets.forEach(drawChart);

  const schedulePoll = () => {
    if (!running) return;
    const intervalMs = Number(intervalSelect.value) * 1000;
    window.clearTimeout(timer);
    timer = window.setTimeout(poll, intervalMs);
  };

  const poll = async () => {
    if (!running || pollInFlight) return;
    pollInFlight = true;
    const entries = [...targets.values()];
    pollController = new AbortController();
    let successes = 0;
    let failures = 0;
    try {
      const round = await postJson(
        root.dataset.samplesUrl,
        {targets: entries.map(samplePayload)},
        pollController.signal,
      );
      (round.results || []).forEach((result, index) => {
        const target = entries[index];
        if (!target) return;
        if (result.status === "success") {
          successes += 1;
          applySample(target, result.sample);
        } else {
          failures += 1;
          target.lastError = result.error || "Polling failed.";
          target.ui.empty.hidden = false;
          target.ui.empty.textContent = target.lastError;
        }
      });
    } catch (error) {
      if (error.name !== "AbortError") {
        failures = entries.length;
        entries.forEach((target) => {
          target.lastError = error.message;
          target.ui.empty.hidden = false;
          target.ui.empty.textContent = error.message;
        });
      }
    } finally {
      pollController = null;
      pollInFlight = false;
    }
    if (running) {
      const detail = failures ? ` ${failures} interface(s) could not be polled.` : "";
      setStatus(`Monitoring ${targets.size} interface(s). ${successes} responded on the latest round.${detail}`, failures ? "error" : "success");
      updateSetControls();
      updateHistoryControls();
      drawAllCharts();
      schedulePoll();
    }
  };

  const setRunningControls = (isRunning) => {
    hostSelect.disabled = isRunning;
    interfaceSelect.disabled = isRunning;
    discoverButton.disabled = isRunning;
    selection.querySelectorAll("button").forEach((button) => { button.disabled = isRunning; });
    updateSetControls();
  };

  const stop = async (notify = true) => {
    if (!running) return;
    const payload = monitorPayload();
    running = false;
    window.clearTimeout(timer);
    pollController?.abort();
    pollController = null;
    setRunningControls(false);
    if (notify) {
      try { await postJson(root.dataset.stopUrl, payload); } catch (_error) { /* already stopped locally */ }
      const samples = [...targets.values()].reduce((total, target) => total + target.points.length, 0);
      setStatus(`Monitoring stopped. ${samples} traffic sample${samples === 1 ? "" : "s"} remain visible.`);
    }
  };

  discoverButton.addEventListener("click", async () => {
    if (!hostSelect.value) {
      setStatus("Select a saved host first.", "error");
      return;
    }
    discoverButton.disabled = true;
    selection.hidden = true;
    setStatus("Discovering standard IF-MIB interfaces…");
    try {
      const result = await postJson(root.dataset.discoverUrl, {host_name: hostSelect.value});
      discoveredInterfaces = result.interfaces || [];
      discoveredHost = {name: hostSelect.value, host: result.host || hostSelect.selectedOptions[0]?.textContent?.split("·").at(-1)?.trim() || ""};
      interfaceSelect.replaceChildren(...discoveredInterfaces.map((item) => {
        const option = document.createElement("option");
        option.value = item.index;
        option.textContent = interfaceLabel(item);
        return option;
      }));
      if (!discoveredInterfaces.length) throw new Error("No interfaces were returned by this device.");
      selection.hidden = false;
      setStatus(`Discovered ${discoveredInterfaces.length} interfaces on ${discoveredHost.name} in ${result.elapsed_ms} ms.`, "success");
    } catch (error) {
      discoveredInterfaces = [];
      discoveredHost = null;
      setStatus(error.message, "error");
    } finally {
      discoverButton.disabled = false;
      updateSetControls();
    }
  });

  interfaceSelect.addEventListener("change", updateSetControls);
  addButton.addEventListener("click", addTarget);
  intervalSelect.addEventListener("change", () => {
    if (!running) return;
    if (!pollInFlight) schedulePoll();
    const seconds = Number(intervalSelect.value);
    setStatus(`Polling interval changed to every ${seconds} second${seconds === 1 ? "" : "s"}. Existing history was retained.`, "success");
  });
  windowSelect.addEventListener("change", () => {
    updateHistoryControls();
    drawAllCharts();
  });
  historyPosition.addEventListener("input", () => {
    const bounds = historyBounds();
    if (!bounds) return;
    const fraction = Number(historyPosition.value) / 1000;
    setHistoryEnd(bounds.earliest + (bounds.latest - bounds.earliest) * fraction);
  });
  historyOlder.addEventListener("click", () => {
    const bounds = historyBounds();
    if (!bounds) return;
    const windowMs = Number(windowSelect.value);
    setHistoryEnd((historyEndAt ?? bounds.latest) - windowMs);
  });
  historyNewer.addEventListener("click", () => {
    const bounds = historyBounds();
    if (!bounds) return;
    setHistoryEnd((historyEndAt ?? bounds.latest) + Number(windowSelect.value));
  });
  historyLive.addEventListener("click", () => {
    historyEndAt = null;
    updateHistoryControls();
    drawAllCharts();
  });
  startButton.addEventListener("click", async () => {
    if (!targets.size || running) return;
    try {
      await postJson(root.dataset.startUrl, monitorPayload());
      targets.forEach(resetTarget);
      running = true;
      historyEndAt = null;
      setRunningControls(true);
      setStatus(`Starting monitor set for ${targets.size} interface(s)…`);
      await poll();
    } catch (error) {
      setStatus(error.message, "error");
    }
  });
  stopButton.addEventListener("click", () => stop(true));
  clearButton.addEventListener("click", clearGraphs);
  window.addEventListener("resize", () => window.requestAnimationFrame(drawAllCharts));
  window.addEventListener("themechange", () => window.requestAnimationFrame(drawAllCharts));
  window.addEventListener("pagehide", () => {
    if (!running) return;
    const blob = new Blob([JSON.stringify(monitorPayload())], {type: "application/json"});
    navigator.sendBeacon?.(root.dataset.stopUrl, blob);
    running = false;
    window.clearTimeout(timer);
    pollController?.abort();
  });
  updateHistoryControls();
  updateSetControls();
})();
