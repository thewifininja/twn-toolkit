(function () {
  const form = document.getElementById("ping-form");
  const hostsInput = document.getElementById("ping-hosts");
  const intervalInput = document.getElementById("ping-interval");
  const startButton = document.getElementById("ping-start");
  const stopButton = document.getElementById("ping-stop");
  const profileSelect = document.getElementById("ping-profile");
  const profileNameInput = document.getElementById("ping-profile-name");
  const profileLoadButton = document.getElementById("ping-profile-load");
  const profileSaveButton = document.getElementById("ping-profile-save");
  const profileDeleteButton = document.getElementById("ping-profile-delete");
  const status = document.getElementById("ping-status");
  const resultsPanel = document.getElementById("ping-results");
  const tableBody = document.querySelector(".ping-table tbody");

  if (!form || !hostsInput || !intervalInput || !startButton || !stopButton ||
      !profileSelect || !profileNameInput || !profileLoadButton ||
      !profileSaveButton || !profileDeleteButton || !status || !resultsPanel ||
      !tableBody) {
    return;
  }

  let running = false;
  let timer = null;
  let loadedProfileName = "";
  const history = new Map();

  profileLoadButton.addEventListener("click", () => {
    const option = profileSelect.options[profileSelect.selectedIndex];
    if (!option || !option.value) {
      loadedProfileName = "";
      profileNameInput.value = "";
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
    status.textContent = `Loaded profile '${option.value}'.`;
  });

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
      status.textContent = `Deleted profile '${name}'.`;
    } catch (error) {
      status.textContent = error.message;
    } finally {
      profileDeleteButton.disabled = false;
    }
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running) {
      return;
    }
    running = true;
    history.clear();
    tableBody.innerHTML = "";
    startButton.disabled = true;
    stopButton.disabled = false;
    resultsPanel.hidden = false;
    runRound();
  });

  stopButton.addEventListener("click", () => {
    running = false;
    clearTimeout(timer);
    startButton.disabled = false;
    stopButton.disabled = true;
    status.textContent = "Stopped.";
  });

  async function runRound() {
    if (!running) {
      return;
    }
    const roundStarted = performance.now();
    status.textContent = "Pinging...";
    try {
      const response = await fetch(form.dataset.runUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({hosts: hostsInput.value}),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Ping request failed.");
      }
      if (!running) {
        return;
      }
      renderResults(data.results || []);
      status.textContent = `Last round completed at ${new Date().toLocaleTimeString()}.`;
    } catch (error) {
      status.textContent = error.message;
      running = false;
      startButton.disabled = false;
      stopButton.disabled = true;
      return;
    }

    const seconds = Math.max(1, Math.min(60, Number(intervalInput.value) || 2));
    const remainingDelay = Math.max(0, (seconds * 1000) - (performance.now() - roundStarted));
    timer = setTimeout(runRound, remainingDelay);
  }

  function renderResults(results) {
    tableBody.innerHTML = "";
    results.forEach((result) => {
      const hostHistory = history.get(result.host) || [];
      hostHistory.push({
        latency: result.latency_ms == null ? null : Number(result.latency_ms),
        reachable: Boolean(result.reachable),
        time: new Date(),
      });
      history.set(result.host, hostHistory.slice(-300));

      const row = document.createElement("tr");
      row.appendChild(hostCell(result));

      const statusCell = cell(result.reachable ? "Up" : "Down");
      statusCell.className = result.reachable ? "ping-up" : "ping-down";
      row.appendChild(statusCell);

      row.appendChild(cell(result.latency_ms == null ? "-" : `${result.latency_ms} ms`));

      const historyCell = document.createElement("td");
      historyCell.className = "ping-history-cell";
      historyCell.appendChild(historyGraph(history.get(result.host)));
      row.appendChild(historyCell);
      tableBody.appendChild(row);
    });
  }

  function historyGraph(points) {
    const namespace = "http://www.w3.org/2000/svg";
    const height = 86;
    const padding = 10;
    const step = 14;
    const width = Math.max(240, padding * 2 + Math.max(0, points.length - 1) * step);
    const latencies = points
      .filter((point) => point.reachable && Number.isFinite(point.latency))
      .map((point) => point.latency);
    const maxLatency = Math.max(1, ...latencies);
    const yFor = (latency) => (
      padding + ((maxLatency - latency) / maxLatency) * (height - padding * 2)
    );

    const scroll = document.createElement("div");
    scroll.className = "ping-history-scroll";

    const svg = document.createElementNS(namespace, "svg");
    svg.classList.add("ping-history-graph");
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `Latency history, scaled from 0 to ${maxLatency} milliseconds`);

    [padding, height / 2, height - padding].forEach((y) => {
      const gridLine = document.createElementNS(namespace, "line");
      gridLine.classList.add("ping-history-grid");
      gridLine.setAttribute("x1", 0);
      gridLine.setAttribute("x2", width);
      gridLine.setAttribute("y1", y);
      gridLine.setAttribute("y2", y);
      svg.appendChild(gridLine);
    });

    let segment = [];
    const drawSegment = () => {
      if (!segment.length) {
        return;
      }
      const polyline = document.createElementNS(namespace, "polyline");
      polyline.classList.add("ping-history-line");
      polyline.setAttribute("points", segment.join(" "));
      svg.appendChild(polyline);
      segment = [];
    };

    points.forEach((point, index) => {
      const x = padding + index * step;
      if (!point.reachable || !Number.isFinite(point.latency)) {
        drawSegment();
        const failure = document.createElementNS(namespace, "line");
        failure.classList.add("ping-history-failure");
        failure.setAttribute("x1", x);
        failure.setAttribute("x2", x);
        failure.setAttribute("y1", height - padding - 8);
        failure.setAttribute("y2", height - padding);
        addTitle(failure, `${point.time.toLocaleTimeString()}: unreachable`, namespace);
        svg.appendChild(failure);
        return;
      }

      const y = yFor(point.latency);
      segment.push(`${x},${y}`);
      const marker = document.createElementNS(namespace, "circle");
      marker.classList.add("ping-history-point");
      marker.setAttribute("cx", x);
      marker.setAttribute("cy", y);
      marker.setAttribute("r", 2.5);
      addTitle(marker, `${point.time.toLocaleTimeString()}: ${point.latency} ms`, namespace);
      svg.appendChild(marker);
    });
    drawSegment();

    scroll.appendChild(svg);
    requestAnimationFrame(() => {
      scroll.scrollLeft = scroll.scrollWidth;
    });
    return scroll;
  }

  function addTitle(element, text, namespace) {
    const title = document.createElementNS(namespace, "title");
    title.textContent = text;
    element.appendChild(title);
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
