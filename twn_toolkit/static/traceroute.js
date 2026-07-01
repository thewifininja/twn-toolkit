(function () {
  const form = document.getElementById("traceroute-form");
  const results = document.getElementById("traceroute-live-results");
  const template = document.getElementById("traceroute-result-template");
  if (!form || !results || !template) return;

  const startButton = document.getElementById("traceroute-start");
  const cancelButton = document.getElementById("traceroute-cancel");
  const status = document.getElementById("traceroute-status");
  const toolbar = document.getElementById("traceroute-results-toolbar");
  const toggleAllButton = document.getElementById("traceroute-toggle-all");
  let controllers = [];
  let cancelled = false;

  function createResult(host) {
    const element = template.content.firstElementChild.cloneNode(true);
    element.querySelector(".traceroute-live-host").textContent = host;
    results.append(element);
    return {
      element,
      details: element.querySelector(".traceroute-result-details"),
      host: element.querySelector(".traceroute-live-host"),
      meta: element.querySelector(".traceroute-live-meta"),
      miniHops: element.querySelector(".traceroute-mini-hops"),
      state: element.querySelector(".traceroute-live-state"),
      path: element.querySelector(".traceroute-path"),
      output: element.querySelector(".traceroute-live-output"),
      respondingHops: 0,
    };
  }

  function appendHop(view, hop) {
    if (hop.responded) view.respondingHops += 1;
    const latencyClass = !hop.responded
      ? "unanswered"
      : hop.average_ms >= 100 ? "slow" : hop.average_ms >= 30 ? "medium" : "fast";
    const miniHop = document.createElement("span");
    miniHop.className = `traceroute-mini-hop ${latencyClass}`;
    miniHop.title = hop.responded
      ? `Hop ${hop.number}: ${hop.name || hop.addresses.join(", ") || "Response"} · ${hop.average_ms} ms`
      : `Hop ${hop.number}: no response`;
    miniHop.setAttribute("aria-label", miniHop.title);
    view.miniHops.append(miniHop);
    const article = document.createElement("article");
    article.className = `traceroute-hop ${latencyClass}`;

    const marker = document.createElement("div");
    marker.className = "traceroute-marker";
    marker.textContent = hop.number;
    const card = document.createElement("div");
    card.className = "traceroute-hop-card";
    const number = document.createElement("span");
    number.className = "traceroute-hop-number";
    number.textContent = `Hop ${hop.number}`;
    const name = document.createElement("strong");
    name.textContent = hop.name || hop.addresses.join(", ") || "No response";
    card.append(number, name);

    if (hop.name && hop.addresses.length) {
      const addresses = document.createElement("small");
      addresses.textContent = hop.addresses.join(", ");
      card.append(addresses);
    }
    const metrics = document.createElement("div");
    metrics.className = "traceroute-hop-metrics";
    if (hop.latencies_ms.length) {
      metrics.textContent = `Average ${hop.average_ms} ms · Probes ${hop.latencies_ms.join(" · ")} ms`;
      if (hop.loss_percent) metrics.textContent += ` · Loss ${hop.loss_percent}%`;
    } else {
      metrics.textContent = "No probe replies";
    }
    card.append(metrics);
    article.append(marker, card);
    view.path.append(article);
  }

  function handleEvent(view, event) {
    if (event.type === "start") {
      view.meta.textContent = `${event.family} · ${event.method} · trace in progress`;
      view.state.textContent = "tracing";
    } else if (event.type === "output") {
      view.output.textContent += `${event.line}\n`;
    } else if (event.type === "hop") {
      appendHop(view, event.hop);
      view.meta.textContent = `Hop ${event.hop.number} received · waiting for next hop`;
    } else if (event.type === "complete") {
      view.state.className = `pill traceroute-live-state ${event.reached ? "success" : "planned"}`;
      view.state.textContent = event.reached ? "destination reached" : "trace incomplete";
      view.meta.textContent = `${view.respondingHops} responding hop${view.respondingHops === 1 ? "" : "s"}`;
    } else if (event.type === "error") {
      throw new Error(event.error);
    }
  }

  async function runTrace(host, basePayload, view) {
    const controller = new AbortController();
    controllers.push(controller);
    view.state.textContent = "starting";
    try {
      const response = await fetch(form.dataset.runUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({...basePayload, host}),
        signal: controller.signal,
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Traceroute could not be started.");
      }
      if (!response.body) throw new Error("Streaming responses are unavailable in this browser.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const chunk = await reader.read();
        buffer += decoder.decode(chunk.value || new Uint8Array(), {stream: !chunk.done});
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        lines.filter(Boolean).forEach((line) => handleEvent(view, JSON.parse(line)));
        if (chunk.done) break;
      }
      if (buffer.trim()) handleEvent(view, JSON.parse(buffer));
    } catch (error) {
      view.state.className = `pill traceroute-live-state ${error.name === "AbortError" ? "planned" : "error"}`;
      view.state.textContent = error.name === "AbortError" ? "cancelled" : "error";
      view.meta.textContent = error.name === "AbortError" ? "Trace cancelled" : error.message;
    } finally {
      controllers = controllers.filter((item) => item !== controller);
    }
  }

  async function runQueue(hosts, payload, views) {
    let next = 0;
    async function worker() {
      while (!cancelled && next < hosts.length) {
        const index = next++;
        await runTrace(hosts[index], payload, views[index]);
      }
    }
    await Promise.all([worker(), worker()]);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    controllers.forEach((controller) => controller.abort());
    controllers = [];
    cancelled = false;
    const data = new FormData(form);
    const hosts = [...new Set(
      String(data.get("hosts") || "").split(/[\r\n]+/).map((host) => host.trim()).filter(Boolean)
    )];
    if (!hosts.length) {
      status.textContent = "Enter at least one destination.";
      return;
    }
    if (hosts.length > 10) {
      status.textContent = "A maximum of 10 destinations is allowed.";
      return;
    }
    data.delete("hosts");
    const payload = Object.fromEntries(data.entries());
    results.replaceChildren();
    toolbar.hidden = false;
    toggleAllButton.textContent = "Expand All";
    const views = hosts.map(createResult);
    startButton.disabled = true;
    cancelButton.disabled = false;
    status.textContent = `Tracing ${hosts.length} destination${hosts.length === 1 ? "" : "s"}…`;
    try {
      await runQueue(hosts, payload, views);
      status.textContent = cancelled ? "Traceroutes cancelled." : "All traceroutes completed.";
    } finally {
      startButton.disabled = false;
      cancelButton.disabled = true;
    }
  });

  cancelButton.addEventListener("click", () => {
    cancelled = true;
    controllers.forEach((controller) => controller.abort());
  });

  toggleAllButton.addEventListener("click", () => {
    const sections = [...results.querySelectorAll(".traceroute-result-details")];
    const collapse = sections.some((section) => section.open);
    sections.forEach((section) => {
      section.open = !collapse;
    });
    toggleAllButton.textContent = collapse ? "Expand All" : "Collapse All";
  });
})();
