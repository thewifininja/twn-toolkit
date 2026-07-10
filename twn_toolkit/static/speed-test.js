(function () {
  const root = document.getElementById("speed-test");
  if (!root) return;

  const startButton = document.getElementById("speed-start");
  const cancelButton = document.getElementById("speed-cancel");
  const phase = document.getElementById("speed-phase");
  const status = document.getElementById("speed-status");
  const progress = document.querySelector(".speed-progress");
  const progressBar = document.getElementById("speed-progress-bar");
  const values = {
    latency: document.getElementById("speed-latency"),
    jitter: document.getElementById("speed-jitter"),
    download: document.getElementById("speed-download"),
    upload: document.getElementById("speed-upload"),
  };

  const testSeconds = 8;
  const streamCount = 2;
  const downloadBytes = 512 * 1024 * 1024;
  const uploadBytes = 16 * 1024 * 1024;
  let controller = null;

  startButton.addEventListener("click", runTest);
  cancelButton.addEventListener("click", () => controller?.abort());

  async function runTest() {
    controller = new AbortController();
    setRunning(true);
    resetResults();
    try {
      status.textContent = "Measuring unloaded latency...";
      const latency = await measureLatency(controller.signal);
      values.latency.textContent = formatNumber(latency.average);
      values.jitter.textContent = formatNumber(latency.jitter);

      status.textContent = "Measuring download throughput...";
      const download = await measureDownload(controller.signal);
      values.download.textContent = formatSpeed(download.speed);

      status.textContent = "Measuring upload throughput...";
      const upload = await measureUpload(controller.signal);
      values.upload.textContent = formatSpeed(upload.speed);

      await recordCompletion(download.bytes, upload.bytes);

      setProgress(100);
      phase.textContent = "Complete";
      status.textContent = `Completed at ${new Date().toLocaleTimeString()}.`;
    } catch (error) {
      if (error.name === "AbortError") {
        phase.textContent = "Cancelled";
        status.textContent = "Test cancelled.";
      } else {
        phase.textContent = "Error";
        status.textContent = error.message || "The speed test could not be completed.";
      }
    } finally {
      setRunning(false);
      controller = null;
    }
  }

  async function measureLatency(signal) {
    phase.textContent = "Latency";
    const samples = [];
    for (let index = 0; index < 12; index += 1) {
      const started = performance.now();
      const response = await fetch(`${root.dataset.pingUrl}?r=${cacheBust()}`, {
        cache: "no-store",
        signal,
      });
      if (!response.ok) throw new Error("The latency endpoint did not respond.");
      const elapsed = performance.now() - started;
      if (index >= 2) samples.push(elapsed);
      setProgress(((index + 1) / 12) * 20);
      await delay(60, signal);
    }
    const average = samples.reduce((sum, sample) => sum + sample, 0) / samples.length;
    const jitter = samples.slice(1).reduce(
      (sum, sample, index) => sum + Math.abs(sample - samples[index]),
      0
    ) / Math.max(1, samples.length - 1);
    return {average, jitter};
  }

  async function measureDownload(signal) {
    phase.textContent = "Download";
    setActiveMeter("download");
    const started = performance.now();
    let totalBytes = 0;

    async function stream() {
      while ((performance.now() - started) / 1000 < testSeconds) {
        const url = `${root.dataset.downloadUrl}?bytes=${downloadBytes}&r=${cacheBust()}`;
        const response = await fetch(url, {cache: "no-store", signal});
        if (!response.ok || !response.body) throw new Error("The download endpoint did not respond.");
        const reader = response.body.getReader();
        while (true) {
          const result = await reader.read();
          if (result.done) break;
          totalBytes += result.value.byteLength;
          showThroughput("Download", totalBytes, started, 20, 60);
          if ((performance.now() - started) / 1000 >= testSeconds) {
            await reader.cancel();
            break;
          }
        }
      }
    }

    await Promise.all(Array.from({length: streamCount}, stream));
    return {
      bytes: totalBytes,
      speed: megabitsPerSecond(totalBytes, performance.now() - started),
    };
  }

  async function measureUpload(signal) {
    phase.textContent = "Upload";
    setActiveMeter("upload");
    const payload = randomPayload(uploadBytes);
    const started = performance.now();
    let totalBytes = 0;

    async function stream() {
      while ((performance.now() - started) / 1000 < testSeconds) {
        const response = await fetch(`${root.dataset.uploadUrl}?r=${cacheBust()}`, {
          method: "POST",
          body: payload,
          cache: "no-store",
          headers: {"Content-Type": "application/octet-stream"},
          signal,
        });
        if (!response.ok) throw new Error("The upload endpoint did not accept test data.");
        const result = await response.json();
        totalBytes += Number(result.bytes_received) || 0;
        showThroughput("Upload", totalBytes, started, 60, 40);
      }
    }

    await Promise.all(Array.from({length: streamCount}, stream));
    return {
      bytes: totalBytes,
      speed: megabitsPerSecond(totalBytes, performance.now() - started),
    };
  }

  async function recordCompletion(downloadBytes, uploadBytes) {
    if (!root.dataset.activityUrl) return;
    try {
      await fetch(root.dataset.activityUrl, {
        method: "POST",
        cache: "no-store",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({download_bytes: downloadBytes, upload_bytes: uploadBytes}),
      });
    } catch (_error) {
      // Metrics must never turn a completed speed test into a visible failure.
    }
  }

  function randomPayload(size) {
    const data = new Uint8Array(size);
    const chunkSize = 65536;
    for (let offset = 0; offset < size; offset += chunkSize) {
      crypto.getRandomValues(data.subarray(offset, Math.min(size, offset + chunkSize)));
    }
    return data;
  }

  function showThroughput(label, bytes, started, progressStart, progressSpan) {
    const elapsed = performance.now() - started;
    values[label.toLowerCase()].textContent = formatSpeed(megabitsPerSecond(bytes, elapsed));
    phase.textContent = label;
    setProgress(progressStart + Math.min(1, elapsed / (testSeconds * 1000)) * progressSpan);
  }

  function megabitsPerSecond(bytes, milliseconds) {
    return (bytes * 8) / Math.max(milliseconds, 1) / 1000;
  }

  function formatSpeed(value) {
    if (!Number.isFinite(value)) return "—";
    if (value >= 100) return value.toFixed(0);
    if (value >= 10) return value.toFixed(1);
    return value.toFixed(2);
  }

  function formatNumber(value) {
    return Number.isFinite(value) ? value.toFixed(1) : "—";
  }

  function cacheBust() {
    return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  function delay(milliseconds, signal) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, milliseconds);
      signal.addEventListener("abort", () => {
        clearTimeout(timer);
        reject(new DOMException("Cancelled", "AbortError"));
      }, {once: true});
    });
  }

  function setProgress(percent) {
    const bounded = Math.max(0, Math.min(100, percent));
    progressBar.style.width = `${bounded}%`;
    progress.setAttribute("aria-valuenow", String(Math.round(bounded)));
  }

  function setRunning(running) {
    startButton.disabled = running;
    cancelButton.disabled = !running;
  }

  function setActiveMeter(kind) {
    document.querySelectorAll(".speed-headline").forEach((meter) => {
      meter.classList.toggle("active", meter.id === `speed-${kind}-meter`);
    });
  }

  function resetResults() {
    Object.values(values).forEach((element) => { element.textContent = "—"; });
    phase.textContent = "Starting";
    setActiveMeter("");
    setProgress(0);
  }
})();
