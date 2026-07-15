(() => {
  const root = document.querySelector(".snmp-interface-monitor");
  if (!root) return;

  const hostSelect = root.querySelector(".snmp-monitor-host");
  const discoverButton = root.querySelector(".snmp-monitor-discover");
  const selection = root.querySelector(".snmp-monitor-selection");
  const interfaceSelect = root.querySelector(".snmp-monitor-interface");
  const addButton = root.querySelector(".snmp-monitor-add");
  const intervalSelect = root.querySelector(".snmp-monitor-interval");
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
  let nextPollAt = 0;
  let pollController = null;

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
    const inbound = metric("Inbound / download", "snmp-target-in", "snmp-target-in-percent");
    const outbound = metric("Outbound / upload", "snmp-target-out", "snmp-target-out-percent");
    const peaks = metric("Observed peaks", "snmp-target-peaks", "snmp-target-health");
    link.value.textContent = target.interface.oper_status || "unknown";
    link.secondary.textContent = formatSpeed(target.interface.speed_bps);
    peaks.secondary.textContent = "Errors and discards: —";
    metrics.append(link.node, inbound.node, outbound.node, peaks.node);

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
    legend.innerHTML = '<span class="inbound">Inbound / download</span><span class="outbound">Outbound / upload</span>';
    chartWrap.append(canvas, empty, legend);
    card.append(header, metrics, chartWrap);

    target.ui = {card, remove, link, inbound, outbound, peaks, canvas, empty};
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
      lastError: "",
      ui: null,
    };
    targets.set(key, target);
    targetList.append(createTargetCard(target));
    updateSetControls();
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
    ui.peaks.secondary.textContent = `Errors ${sample.input_errors ?? "—"} in / ${sample.output_errors ?? "—"} out · Discards ${sample.input_discards ?? "—"} in / ${sample.output_discards ?? "—"} out`;
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
    const inboundRate = Number(inputDelta) * 8 / elapsed;
    const outboundRate = Number(outputDelta) * 8 / elapsed;
    const speed = sample.speed_bps || target.interface.speed_bps || null;
    target.points.push({at: sample.sampled_at_ms, inbound: inboundRate, outbound: outboundRate});
    if (target.points.length > 3600) target.points.shift();
    ui.inbound.value.textContent = formatRate(inboundRate);
    ui.inbound.secondary.textContent = formatPercent(inboundRate, speed);
    ui.outbound.value.textContent = formatRate(outboundRate);
    ui.outbound.secondary.textContent = formatPercent(outboundRate, speed);
    const peakIn = Math.max(...target.points.map((point) => point.inbound));
    const peakOut = Math.max(...target.points.map((point) => point.outbound));
    ui.peaks.value.textContent = `${formatRate(peakIn)} in / ${formatRate(peakOut)} out`;
    ui.empty.hidden = true;
    drawChart(target);
  };

  const resetTarget = (target) => {
    target.baseline = null;
    target.points = [];
    target.lastError = "";
    target.ui.inbound.value.textContent = "—";
    target.ui.inbound.secondary.textContent = "";
    target.ui.outbound.value.textContent = "—";
    target.ui.outbound.secondary.textContent = "";
    target.ui.peaks.value.textContent = "—";
    target.ui.peaks.secondary.textContent = "Errors and discards: —";
    target.ui.empty.hidden = false;
    target.ui.empty.textContent = "The first poll establishes a counter baseline. Rates appear after the next sample.";
    drawChart(target);
  };

  const clearGraphs = () => {
    targets.forEach(resetTarget);
    updateSetControls();
    setStatus("Graphs and counter baselines cleared. Monitoring will establish fresh baselines on the next poll.");
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
    const height = Math.max(250, rect.height);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    const context = canvas.getContext("2d");
    context.scale(dpr, dpr);
    const styles = getComputedStyle(document.documentElement);
    const line = styles.getPropertyValue("--line").trim() || "#d3dfd8";
    const muted = styles.getPropertyValue("--muted").trim() || "#617069";
    const inboundColor = styles.getPropertyValue("--brand-green").trim() || "#2da747";
    const outboundColor = styles.getPropertyValue("--brand-red").trim() || "#db3c46";
    const padding = {left: 72, right: 18, top: 20, bottom: 34};
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const centerY = padding.top + plotHeight / 2;
    const maximum = Math.max(1, ...target.points.flatMap((point) => [point.inbound, point.outbound]));
    const scale = niceScale(maximum);

    context.font = "12px system-ui, sans-serif";
    context.fillStyle = muted;
    context.strokeStyle = line;
    context.lineWidth = 1;
    [0, 0.5, 1].forEach((position) => {
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
    context.fillText(formatRate(scale), 4, padding.top + 4);
    context.fillText("0 bps", 4, centerY + 4);
    context.fillText(formatRate(scale), 4, padding.top + plotHeight + 4);
    context.fillText("IN", padding.left + 8, padding.top + 15);
    context.fillText("OUT", padding.left + 8, centerY + 18);

    if (!target.points.length) return;
    const drawLine = (key, direction, color) => {
      context.strokeStyle = color;
      context.lineWidth = 2.5;
      context.lineJoin = "round";
      context.beginPath();
      target.points.forEach((point, index) => {
        const x = padding.left + (target.points.length === 1 ? plotWidth : plotWidth * index / (target.points.length - 1));
        const magnitude = Math.min(point[key], scale) / scale * plotHeight / 2;
        const y = centerY + direction * magnitude;
        if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
      });
      context.stroke();
    };
    drawLine("inbound", -1, inboundColor);
    drawLine("outbound", 1, outboundColor);
    const first = new Date(target.points[0].at).toLocaleTimeString();
    const last = new Date(target.points.at(-1).at).toLocaleTimeString();
    context.fillStyle = muted;
    context.fillText(first, padding.left, height - 8);
    const measured = context.measureText(last).width;
    context.fillText(last, width - padding.right - measured, height - 8);
  };

  const drawAllCharts = () => targets.forEach(drawChart);

  const schedulePoll = () => {
    if (!running) return;
    const intervalMs = Number(intervalSelect.value) * 1000;
    if (!nextPollAt) nextPollAt = Date.now();
    nextPollAt += intervalMs;
    timer = window.setTimeout(poll, Math.max(0, nextPollAt - Date.now()));
  };

  const poll = async () => {
    if (!running) return;
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
    }
    if (running) {
      const detail = failures ? ` ${failures} interface(s) could not be polled.` : "";
      setStatus(`Monitoring ${targets.size} interface(s). ${successes} responded on the latest round.${detail}`, failures ? "error" : "success");
      updateSetControls();
      schedulePoll();
    }
  };

  const setRunningControls = (isRunning) => {
    hostSelect.disabled = isRunning;
    interfaceSelect.disabled = isRunning;
    intervalSelect.disabled = isRunning;
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
  startButton.addEventListener("click", async () => {
    if (!targets.size || running) return;
    try {
      await postJson(root.dataset.startUrl, monitorPayload());
      targets.forEach(resetTarget);
      running = true;
      nextPollAt = 0;
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
  updateSetControls();
})();
