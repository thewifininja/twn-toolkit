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

  function selectedMode() {
    return modeInputs.find((input) => input.checked)?.value || "listen";
  }

  function updateMode() {
    const mode = selectedMode();
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

  modeInputs.forEach((input) => input.addEventListener("change", updateMode));
  membership?.addEventListener("change", updateMode);
  format?.addEventListener("change", updateFormat);
  sendInterface?.addEventListener("change", updateMode);
  updateMode();

  const dataElement = document.querySelector("#multicast-result-data");
  if (!dataElement) return;
  let report;
  try {
    report = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const receive = report.mode === "path" ? report.receive : report.mode === "listen" ? report : null;
  const canvas = document.querySelector("#multicast-timeline");

  function renderTimeline() {
    if (!canvas || !receive?.timeline?.length) return;
    const parentWidth = Math.max(320, canvas.parentElement?.clientWidth || 640);
    const cssHeight = 220;
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
    const maximum = Math.max(1, ...receive.timeline.map((bucket) => bucket.packets));

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
    receive.timeline.forEach((bucket, index) => {
      const x = left + (index / Math.max(1, receive.timeline.length - 1)) * plotWidth;
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
    const finalSecond = receive.timeline.at(-1)?.second || 0;
    const label = `${finalSecond}s`;
    context.fillText(label, width - right - context.measureText(label).width, height - 10);
  }

  renderTimeline();
  window.addEventListener("resize", renderTimeline);

  document.querySelector("#multicast-download-report")?.addEventListener("click", () => {
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `multicast-${report.mode || "test"}-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  });
})();
