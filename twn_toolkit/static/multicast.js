(() => {
  const form = document.querySelector("#multicast-form");
  if (!form) return;

  const modeInputs = [...form.querySelectorAll('input[name="mode"]')];
  const sections = [...form.querySelectorAll("[data-mode-section]")];
  const listenOnly = [...form.querySelectorAll("[data-listen-only]")];
  const format = form.querySelector("#multicast-stream-format");
  const rtpClock = form.querySelector("#multicast-rtp-clock");
  const membership = form.querySelector("#multicast-membership");
  const source = form.querySelector("#multicast-source");
  const receiveInterface = form.querySelector('[name="receive_interface"]');
  const sendInterface = form.querySelector('[name="send_interface"]');
  const group = form.querySelector("#multicast-group");
  const port = form.querySelector("#multicast-port");
  const preset = form.querySelector("#multicast-preset");
  const startButton = form.querySelector("#multicast-run");
  const runModeMeta = form.querySelector("#multicast-run-mode-meta");
  const cancelButton = form.querySelector("#multicast-cancel");
  const runbarCancelButton = document.querySelector("#multicast-runbar-cancel");
  const runbarState = document.querySelector("[data-multicast-run-state]");
  const runbarTitle = document.querySelector("[data-multicast-run-title]");
  const runbarSummary = document.querySelector("[data-multicast-run-summary]");
  const runbarIndicator = document.querySelector("[data-multicast-run-indicator]");
  const results = document.querySelector("#multicast-results");
  const livePanel = document.querySelector("#multicast-live-panel");
  const liveTitle = document.querySelector("#multicast-live-title");
  const liveMeta = document.querySelector("#multicast-live-meta");
  const liveStatus = document.querySelector("#multicast-live-state");
  const liveElapsed = document.querySelector("#multicast-live-elapsed");
  const liveRemaining = document.querySelector("#multicast-live-remaining");
  const liveProgressBar = document.querySelector("#multicast-live-progress-bar");
  const liveReceived = document.querySelector("#multicast-live-received");
  const liveReceivedBytes = document.querySelector("#multicast-live-received-bytes");
  const liveSent = document.querySelector("#multicast-live-sent");
  const liveSentBytes = document.querySelector("#multicast-live-sent-bytes");
  const liveRate = document.querySelector("#multicast-live-rate");
  const livePps = document.querySelector("#multicast-live-pps");
  const liveSources = document.querySelector("#multicast-live-sources");
  const liveUnexpected = document.querySelector("#multicast-live-unexpected");
  const liveSourceList = document.querySelector("#multicast-live-source-list");
  const liveCanvas = document.querySelector("#multicast-live-timeline");
  const presets = {
    mdns: {group: "224.0.0.251", port: "5353"},
    llmnr: {group: "224.0.0.252", port: "5355"},
    ssdp: {group: "239.255.255.250", port: "1900"},
    "ws-discovery": {group: "239.255.255.250", port: "3702"},
  };

  let activeController = null;
  let activeReport = null;
  let liveData = {receive: {}, send: {}};

  function workspaceController() {
    return window.TwnToolWorkspace?.forElement(form);
  }

  function setRunbar(state, title, summary, complete = false) {
    if (runbarState) runbarState.textContent = state;
    if (runbarTitle) runbarTitle.textContent = title;
    if (runbarSummary) runbarSummary.textContent = summary;
    runbarIndicator?.classList.toggle("complete", complete);
  }

  function selectedMode() {
    return modeInputs.find((input) => input.checked)?.value || "listen";
  }

  function updateMode() {
    const mode = selectedMode();
    const modeCopy = {
      listen: {button: "Listen to group", meta: "Listen mode"},
      send: {button: "Send test stream", meta: "Send mode"},
      path: {button: "Run end-to-end test", meta: "End-to-end mode"},
    };
    if (startButton) startButton.textContent = modeCopy[mode]?.button || "Run multicast test";
    if (runModeMeta) runModeMeta.textContent = modeCopy[mode]?.meta || "Multicast test";
    if (mode === "path" && receiveInterface?.value === sendInterface?.value) {
      const alternate = [...receiveInterface.options].find(
        (option) => option.value !== sendInterface.value
      );
      if (alternate) receiveInterface.value = alternate.value;
    }
    sections.forEach((section) => {
      const modes = (section.dataset.modeSection || "").split(/\s+/);
      section.hidden = !modes.includes(mode);
    });
    listenOnly.forEach((field) => { field.hidden = mode !== "listen"; });
    if (source) {
      source.placeholder = membership?.value === "ssm"
        ? (mode === "path" ? "Uses sender interface address" : "Required for SSM")
        : "Optional for ASM";
    }
    updateFormat();
  }

  function updateFormat() {
    if (rtpClock) {
      rtpClock.hidden = selectedMode() !== "listen" || format?.value !== "rtp";
    }
  }

  function syncPreset() {
    if (!preset || !group || !port) return;
    const match = Object.entries(presets).find(
      ([, values]) => values.group === group.value.trim() && values.port === port.value
    );
    preset.value = match?.[0] || "custom";
  }

  modeInputs.forEach((input) => input.addEventListener("change", updateMode));
  membership?.addEventListener("change", updateMode);
  format?.addEventListener("change", updateFormat);
  sendInterface?.addEventListener("change", updateMode);
  preset?.addEventListener("change", () => {
    const values = presets[preset.value];
    if (!values) return;
    group.value = values.group;
    port.value = values.port;
    if (membership) membership.value = "asm";
    if (source) source.value = "";
    updateMode();
  });
  group?.addEventListener("input", syncPreset);
  port?.addEventListener("input", syncPreset);
  updateMode();
  syncPreset();

  function formatBytes(value) {
    const bytes = Number(value || 0);
    if (bytes < 1024) return `${bytes.toLocaleString()} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GiB`;
  }

  function drawTimeline(canvas, timeline, cssHeight = 220) {
    if (!canvas || !timeline?.length) return;
    const parentWidth = Math.max(240, canvas.parentElement?.clientWidth || 640);
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.floor(parentWidth * ratio);
    canvas.height = Math.floor(cssHeight * ratio);
    canvas.style.width = `${parentWidth}px`;
    canvas.style.height = `${cssHeight}px`;
    const context = canvas.getContext("2d");
    context.scale(ratio, ratio);
    const style = getComputedStyle(document.documentElement);
    const foreground = style.getPropertyValue("--ink").trim() || "#17231d";
    const muted = style.getPropertyValue("--muted").trim() || "#647269";
    const accent = style.getPropertyValue("--action-primary").trim() || "#2f7d57";
    const border = style.getPropertyValue("--line").trim() || "#d8e1db";
    const width = parentWidth;
    const height = cssHeight;
    const left = 52;
    const right = 18;
    const top = 18;
    const bottom = 34;
    const plotWidth = width - left - right;
    const plotHeight = height - top - bottom;
    const maximum = Math.max(1, ...timeline.map((bucket) => bucket.packets));

    context.clearRect(0, 0, width, height);
    context.font = "12px system-ui, sans-serif";
    context.strokeStyle = border;
    context.fillStyle = muted;
    context.lineWidth = 1;
    [0, 0.5, 1].forEach((position) => {
      const y = top + plotHeight * position;
      context.beginPath();
      context.moveTo(left, y);
      context.lineTo(width - right, y);
      context.stroke();
      const value = Math.round(maximum * (1 - position));
      context.fillText(value.toLocaleString(), 4, y + 4);
    });

    context.beginPath();
    timeline.forEach((bucket, index) => {
      const x = left + (index / Math.max(1, timeline.length - 1)) * plotWidth;
      const y = top + plotHeight - (bucket.packets / maximum) * plotHeight;
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.strokeStyle = accent;
    context.lineWidth = 2;
    context.stroke();
    context.lineTo(width - right, top + plotHeight);
    context.lineTo(left, top + plotHeight);
    context.closePath();
    context.globalAlpha = 0.14;
    context.fillStyle = accent;
    context.fill();
    context.globalAlpha = 1;
    context.fillStyle = foreground;
    context.fillText("0s", left, height - 10);
    const finalSecond = timeline.at(-1)?.second || 0;
    const label = `${finalSecond}s`;
    context.fillText(label, width - right - context.measureText(label).width, height - 10);
  }

  function installReport(report) {
    activeReport = report;
    const receive = report?.mode === "path"
      ? report.receive
      : report?.mode === "listen" ? report : null;
    drawTimeline(document.querySelector("#multicast-timeline"), receive?.timeline, 220);
    document.querySelector("#multicast-download-report")?.addEventListener("click", () => {
      const blob = new Blob(
        [`${JSON.stringify(activeReport, null, 2)}\n`],
        {type: "application/json"}
      );
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `multicast-${activeReport.mode || "test"}-${Date.now()}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
    });
  }

  function existingReport() {
    const dataElement = document.querySelector("#multicast-result-data");
    if (!dataElement) return;
    try {
      installReport(JSON.parse(dataElement.textContent || "{}"));
    } catch (_error) {
      // A malformed embedded report should not prevent a new live run.
    }
  }

  function setLiveState(label, className = "planned") {
    liveStatus.className = `pill ${className}`;
    liveStatus.textContent = label;
  }

  function setLiveProgress(value) {
    const normalized = Math.max(0, Math.min(100, Number(value) || 0));
    liveProgressBar.value = normalized;
    liveProgressBar.setAttribute("value", String(normalized));
    liveProgressBar.setAttribute("aria-valuenow", String(Math.round(normalized)));
  }

  function resetLive(payload) {
    liveData = {receive: {}, send: {}};
    livePanel.hidden = false;
    liveTitle.textContent = "Preparing multicast test";
    liveMeta.textContent = `${payload.group}:${payload.port} · ${payload.mode}`;
    setLiveState("starting");
    liveElapsed.textContent = "0.0s elapsed";
    liveRemaining.textContent = `${payload.duration}s remaining`;
    setLiveProgress(0);
    liveReceived.textContent = "0";
    liveReceivedBytes.textContent = "0 bytes";
    liveSent.textContent = "0";
    liveSentBytes.textContent = "0 bytes";
    liveRate.textContent = "0 Mbps";
    livePps.textContent = "0 packets/second";
    liveSources.textContent = "0";
    liveUnexpected.textContent = "0 unexpected packets";
    liveSourceList.innerHTML = '<p class="field-note">Waiting for multicast traffic.</p>';
    const context = liveCanvas?.getContext("2d");
    context?.clearRect(0, 0, liveCanvas.width, liveCanvas.height);
    livePanel.scrollIntoView({behavior: "smooth", block: "start"});
  }

  function updateSourceList(sources) {
    if (!sources?.length) {
      liveSourceList.innerHTML = '<p class="field-note">The group is joined; no sources have arrived yet.</p>';
      return;
    }
    liveSourceList.replaceChildren();
    sources.forEach((item) => {
      const row = document.createElement("div");
      const endpoint = document.createElement("code");
      endpoint.textContent = `${item.address}:${item.port}`;
      const count = document.createElement("strong");
      count.textContent = Number(item.packets || 0).toLocaleString();
      row.append(endpoint, count);
      liveSourceList.append(row);
    });
  }

  function handleProgress(event, duration, mode) {
    const lane = event.lane || (event.phase === "sending" ? "send" : "receive");
    liveData[lane] = {...liveData[lane], ...event};
    const receive = liveData.receive;
    const send = liveData.send;
    const elapsed = Math.max(Number(receive.elapsed_seconds || 0), Number(send.elapsed_seconds || 0));
    const remaining = Math.max(0, duration - elapsed);
    const rateSource = Number(receive.packets_received || 0) ? receive : send;
    const titles = {
      joining: "Joining multicast group",
      joined: "Group joined; waiting for traffic",
      receiving: "Listening to multicast traffic",
      sending: "Generating sequenced multicast traffic",
    };
    liveTitle.textContent = mode === "path"
      ? "Measuring end-to-end multicast delivery"
      : titles[event.phase] || "Multicast test in progress";
    setLiveState(
      mode === "path" && Number(send.packets_sent || 0)
        ? "sending + receiving"
        : event.phase || "running"
    );
    liveElapsed.textContent = `${elapsed.toFixed(1)}s elapsed`;
    liveRemaining.textContent = `${remaining.toFixed(1)}s remaining`;
    setLiveProgress(elapsed * 100 / Math.max(1, duration));
    liveReceived.textContent = Number(receive.packets_received || 0).toLocaleString();
    liveReceivedBytes.textContent = formatBytes(receive.bytes_received);
    liveSent.textContent = Number(send.packets_sent || 0).toLocaleString();
    liveSentBytes.textContent = formatBytes(send.bytes_sent);
    liveRate.textContent = `${Number(rateSource.megabits_per_second || 0).toFixed(4)} Mbps`;
    livePps.textContent = `${Number(rateSource.packets_per_second || 0).toLocaleString()} packets/second`;
    liveSources.textContent = Number(receive.sources || 0).toLocaleString();
    liveUnexpected.textContent = `${Number(receive.unexpected_source_packets || 0).toLocaleString()} unexpected packets`;
    updateSourceList(receive.top_sources);
    drawTimeline(liveCanvas, receive.timeline, 190);
  }

  function insertReport(html, report) {
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const rendered = parsed.querySelector(".multicast-report");
    if (!rendered) throw new Error("The completed multicast report could not be rendered.");
    results.innerHTML = rendered.outerHTML;
    installReport(report);
    results.querySelector(".multicast-report")?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }

  function handleStreamEvent(event, payload) {
    if (event.type === "progress") {
      handleProgress(
        event,
        Number(payload.duration || 1) + (payload.mode === "path" ? 1 : 0),
        payload.mode
      );
    } else if (event.type === "complete") {
      insertReport(event.html, event.result);
      setRunbar("Test complete", "Multicast test", event.result.summary, true);
      liveTitle.textContent = event.result.summary;
      liveMeta.textContent = "The full multicast report is ready below.";
      setLiveProgress(100);
      const statusClass = event.result.status === "success"
        ? "success"
        : event.result.status === "degraded" ? "planned" : "error";
      setLiveState(event.result.status, statusClass);
    } else if (event.type === "cancelled") {
      throw new DOMException("The multicast test was cancelled.", "AbortError");
    } else if (event.type === "error") {
      throw new Error(event.error || "The multicast test failed.");
    }
  }

  async function runLiveTest(payload, controller) {
    const response = await fetch(form.dataset.runUrl, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "The multicast test could not be started.");
    }
    if (!response.body) throw new Error("Live streaming is unavailable in this browser.");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const chunk = await reader.read();
      buffer += decoder.decode(chunk.value || new Uint8Array(), {stream: !chunk.done});
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines.filter(Boolean)) {
        handleStreamEvent(JSON.parse(line), payload);
      }
      if (chunk.done) break;
    }
    if (buffer.trim()) handleStreamEvent(JSON.parse(buffer), payload);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    activeController?.abort();
    const data = new FormData(form);
    const payload = Object.fromEntries(data.entries());
    payload.authorized = data.has("authorized");
    payload.loopback = data.has("loopback");
    const controller = new AbortController();
    activeController = controller;
    results.replaceChildren();
    resetLive(payload);
    workspaceController()?.setState("results", {focusResults: true});
    setRunbar("Live test", "Multicast test", `${payload.group}:${payload.port} · ${payload.mode}`);
    startButton.disabled = true;
    cancelButton.hidden = false;
    if (runbarCancelButton) runbarCancelButton.hidden = false;
    try {
      await runLiveTest(payload, controller);
    } catch (error) {
      if (activeController !== controller) return;
      if (error.name === "AbortError") {
        setRunbar("Test stopped", "Multicast test", "Cancelled before completion");
        liveTitle.textContent = "Multicast test cancelled";
        liveMeta.textContent = "The socket is closing and the group membership is being released.";
        setLiveState("cancelled", "planned");
      } else {
        setRunbar("Test failed", "Multicast test", error.message);
        liveTitle.textContent = "Multicast test failed";
        liveMeta.textContent = error.message;
        setLiveState("error", "error");
      }
    } finally {
      if (activeController === controller) {
        activeController = null;
        startButton.disabled = false;
        cancelButton.hidden = true;
        if (runbarCancelButton) runbarCancelButton.hidden = true;
      }
    }
  });

  cancelButton?.addEventListener("click", () => activeController?.abort());
  runbarCancelButton?.addEventListener("click", () => activeController?.abort());
  window.addEventListener("resize", () => {
    const receive = activeReport?.mode === "path"
      ? activeReport.receive
      : activeReport?.mode === "listen" ? activeReport : null;
    drawTimeline(document.querySelector("#multicast-timeline"), receive?.timeline, 220);
    drawTimeline(liveCanvas, liveData.receive.timeline, 190);
  });
  existingReport();
})();
