(() => {
  const viewer = document.querySelector("#pcap-floating-window");
  if (!viewer) return;

  const scrim = document.querySelector("[data-pcap-scrim]");
  const STORAGE_KEY = "twn-pcap-viewer";
  const MAX_VISIBLE_ROWS = 1000;
  const title = viewer.querySelector("#pcap-floating-title");
  const status = viewer.querySelector("[data-pcap-status]");
  const count = viewer.querySelector("[data-pcap-count]");
  const rows = viewer.querySelector("[data-pcap-rows]");
  const empty = viewer.querySelector("[data-pcap-empty]");
  const scrollRegion = viewer.querySelector("[data-pcap-scroll-region]");
  const autoScroll = viewer.querySelector("[data-pcap-auto-scroll]");
  const liveDot = viewer.querySelector("[data-pcap-live-dot]");
  const reload = viewer.querySelector("[data-pcap-reload]");
  const loadMore = viewer.querySelector("[data-pcap-load-more]");
  const download = viewer.querySelector("[data-pcap-download]");
  const stopForm = viewer.querySelector("[data-pcap-stop-form]");
  const stopButton = stopForm.querySelector("button");
  const dragHandle = viewer.querySelector("[data-pcap-drag-handle]");

  let source = null;
  let nextStart = 0;
  let nextCursor = null;
  let loading = false;
  let live = false;
  let minimized = false;
  let totalSeen = 0;
  let packetTimer = null;
  let statusTimer = null;
  let generation = 0;

  const sameOriginUrl = (value) => {
    if (!value) return "";
    try {
      const parsed = new URL(value, window.location.href);
      return parsed.origin === window.location.origin ? parsed.href : "";
    } catch (_error) {
      return "";
    }
  };

  const saveState = () => {
    if (!source) {
      window.sessionStorage.removeItem(STORAGE_KEY);
      return;
    }
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        ...source,
        minimized,
        autoScroll: autoScroll.checked,
        nextStart: live ? nextStart : 0,
        nextCursor: live ? nextCursor : null,
        totalSeen: live ? totalSeen : 0,
      }),
    );
  };

  const endpointText = (packet, direction) => {
    const address = packet[`${direction}_ip`] || "";
    const port = packet[`${direction}_port`];
    if (!address) return packet[`${direction}_mac`] || "—";
    if (port === null || port === undefined) return address;
    return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
  };

  const addText = (parent, tagName, value) => {
    const element = document.createElement(tagName);
    element.textContent = value;
    parent.append(element);
  };

  const endpointCell = (packet, direction) => {
    const cell = document.createElement("td");
    const endpoint = endpointText(packet, direction);
    addText(cell, "strong", endpoint);
    const mac = packet[`${direction}_mac`] || "";
    if (mac && mac !== endpoint) addText(cell, "small", mac);
    return cell;
  };

  const packetRow = (packet) => {
    const row = document.createElement("tr");
    const sequence = document.createElement("td");
    addText(sequence, "strong", String(packet.number));
    addText(sequence, "small", packet.time_display);
    row.append(sequence);
    row.append(endpointCell(packet, "source"));
    row.append(endpointCell(packet, "destination"));

    const protocol = document.createElement("td");
    addText(protocol, "strong", packet.protocol);
    const details = [
      packet.detail,
      packet.vlan_ids.length ? `VLAN ${packet.vlan_ids.join(", ")}` : "",
    ].filter(Boolean);
    if (details.length) addText(protocol, "small", details.join(" · "));
    row.append(protocol);

    const length = document.createElement("td");
    addText(length, "strong", `${packet.wire_length} B`);
    if (packet.captured_length !== packet.wire_length) {
      addText(length, "small", `${packet.captured_length} B captured`);
    }
    row.append(length);
    row.addEventListener("click", () => {
      rows.querySelector(".is-selected")?.classList.remove("is-selected");
      row.classList.add("is-selected");
    });
    return row;
  };

  const scrollToLatest = () => {
    if (autoScroll.checked && !minimized) {
      scrollRegion.scrollTop = scrollRegion.scrollHeight;
    }
  };

  const trimRows = () => {
    while (rows.children.length > MAX_VISIBLE_ROWS) {
      rows.firstElementChild.remove();
    }
  };

  const clearTimers = () => {
    window.clearTimeout(packetTimer);
    window.clearTimeout(statusTimer);
    packetTimer = null;
    statusTimer = null;
  };

  const setMinimized = (value) => {
    minimized = Boolean(value);
    viewer.classList.toggle("is-minimized", minimized);
    viewer.setAttribute("aria-expanded", String(!minimized));
    if (scrim) scrim.hidden = minimized;
    saveState();
    if (!minimized) scrollToLatest();
  };

  const closeViewer = () => {
    generation += 1;
    clearTimers();
    loading = false;
    source = null;
    viewer.hidden = true;
    if (scrim) scrim.hidden = true;
    rows.replaceChildren();
    window.sessionStorage.removeItem(STORAGE_KEY);
  };

  const updateCaptureStatus = async (token) => {
    if (!source?.statusUrl || token !== generation) return;
    try {
      const response = await fetch(source.statusUrl, {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) return;
      const payload = await response.json();
      if (token !== generation) return;
      live = Boolean(payload.active);
      source.live = live;
      liveDot.hidden = !live;
      stopForm.hidden = !live || !source.stopUrl;
      download.hidden = !payload.downloadable || !source.downloadUrl;
      if (!live && payload.status) {
        status.textContent = `${payload.status} · ${totalSeen.toLocaleString()} packet headers loaded`;
        saveState();
      }
    } catch (_error) {
      // Packet polling remains authoritative after a transient status failure.
    }
    if (live && token === generation) {
      statusTimer = window.setTimeout(
        () => updateCaptureStatus(token),
        1000,
      );
    }
  };

  const schedulePacketLoad = (token, delay) => {
    window.clearTimeout(packetTimer);
    packetTimer = window.setTimeout(() => loadPackets(token), delay);
  };

  const loadPackets = async (token = generation) => {
    if (!source || loading || token !== generation) return;
    loading = true;
    loadMore.disabled = true;
    status.textContent = nextStart
      ? live
        ? "Capturing packets…"
        : "Loading more packet headers…"
      : live
        ? "Waiting for captured packets…"
        : "Loading packet headers…";
    try {
      const url = new URL(source.viewerUrl);
      url.searchParams.set("start", String(nextStart));
      if (nextCursor !== null) {
        url.searchParams.set("cursor", String(nextCursor));
      }
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
      });
      const payload = await response.json();
      if (token !== generation) return;
      if (!response.ok) {
        throw new Error(payload.error || "Packet inspection failed.");
      }
      payload.packets.forEach((packet) => rows.append(packetRow(packet)));
      nextStart = payload.next_start;
      nextCursor = payload.next_cursor;
      totalSeen = Math.max(totalSeen, nextStart);
      trimRows();
      empty.hidden = rows.children.length > 0;
      count.textContent = totalSeen.toLocaleString();
      status.textContent = payload.waiting
        ? "Waiting for the next complete packet…"
        : live
          ? `Capturing packets · ${totalSeen.toLocaleString()} loaded`
          : `${totalSeen.toLocaleString()} packet header${totalSeen === 1 ? "" : "s"} loaded`;
      scrollToLatest();
      loadMore.hidden = live || !payload.has_more;
      if (live) saveState();
      if (live && token === generation) {
        schedulePacketLoad(token, payload.has_more ? 0 : 1000);
      }
    } catch (error) {
      status.textContent = error.message || "Packet headers could not be loaded.";
      loadMore.hidden = true;
      if (live && token === generation) schedulePacketLoad(token, 2000);
    } finally {
      loading = false;
      loadMore.disabled = false;
    }
  };

  const openViewer = (candidate, restore = false) => {
    const viewerUrl = sameOriginUrl(candidate.viewerUrl);
    if (!viewerUrl) return;
    generation += 1;
    clearTimers();
    source = {
      viewerUrl,
      title: String(candidate.title || "Packet viewer").slice(0, 180),
      statusUrl: sameOriginUrl(candidate.statusUrl),
      stopUrl: sameOriginUrl(candidate.stopUrl),
      downloadUrl: sameOriginUrl(candidate.downloadUrl),
      live: Boolean(candidate.live),
    };
    live = source.live;
    loading = false;
    const resumeLive = restore && live && Number(candidate.nextStart) > 0;
    nextStart = resumeLive ? Number(candidate.nextStart) : 0;
    nextCursor = resumeLive ? candidate.nextCursor : null;
    totalSeen = resumeLive ? Number(candidate.totalSeen || nextStart) : 0;
    rows.replaceChildren();
    empty.hidden = false;
    title.textContent = source.title;
    count.textContent = totalSeen.toLocaleString();
    liveDot.hidden = !live;
    stopForm.action = source.stopUrl || "";
    stopForm.hidden = !live || !source.stopUrl;
    download.href = source.downloadUrl || "#";
    download.hidden = live || !source.downloadUrl;
    loadMore.hidden = true;
    viewer.hidden = false;
    if (scrim) scrim.hidden = false;
    autoScroll.checked = candidate.autoScroll !== false;
    setMinimized(restore ? Boolean(candidate.minimized) : false);
    saveState();
    const token = generation;
    loadPackets(token);
    updateCaptureStatus(token);
  };

  document.addEventListener("click", (event) => {
    const opener = event.target.closest("[data-pcap-viewer-open]");
    if (opener) {
      openViewer({
        viewerUrl: opener.dataset.pcapViewerUrl,
        title: opener.dataset.pcapViewerTitle,
        statusUrl: opener.dataset.pcapViewerStatusUrl,
        stopUrl: opener.dataset.pcapViewerStopUrl,
        downloadUrl: opener.dataset.pcapViewerDownloadUrl,
        live: opener.dataset.pcapViewerLive === "true",
      });
      return;
    }
    if (event.target.closest("[data-pcap-close]")) closeViewer();
    if (event.target.closest("[data-pcap-minimize]")) {
      setMinimized(!minimized);
    }
  });

  dragHandle.addEventListener("click", (event) => {
    if (minimized && !event.target.closest("button")) setMinimized(false);
  });
  loadMore.addEventListener("click", () => loadPackets());
  reload.addEventListener("click", () => {
    generation += 1;
    clearTimers();
    loading = false;
    nextStart = 0;
    nextCursor = null;
    totalSeen = 0;
    rows.replaceChildren();
    empty.hidden = false;
    count.textContent = "0";
    const token = generation;
    loadPackets(token);
    updateCaptureStatus(token);
  });
  autoScroll.addEventListener("change", saveState);
  scrollRegion.addEventListener("scroll", () => {
    const distance =
      scrollRegion.scrollHeight -
      scrollRegion.scrollTop -
      scrollRegion.clientHeight;
    if (autoScroll.checked && distance > 80) {
      autoScroll.checked = false;
      saveState();
    }
  });
  stopForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!source?.stopUrl) return;
    stopButton.disabled = true;
    status.textContent = "Stopping capture…";
    try {
      await fetch(source.stopUrl, { method: "POST" });
      live = false;
      liveDot.hidden = true;
      stopForm.hidden = true;
      window.setTimeout(() => updateCaptureStatus(generation), 250);
    } catch (_error) {
      status.textContent = "The stop request could not be sent.";
    } finally {
      stopButton.disabled = false;
    }
  });

  let drag = null;
  dragHandle.addEventListener("pointerdown", (event) => {
    if (minimized || event.target.closest("button")) return;
    const rect = viewer.getBoundingClientRect();
    drag = {
      pointerId: event.pointerId,
      offsetX: event.clientX - rect.left,
      offsetY: event.clientY - rect.top,
    };
    viewer.style.left = `${rect.left}px`;
    viewer.style.top = `${rect.top}px`;
    viewer.style.right = "auto";
    viewer.style.bottom = "auto";
    viewer.style.transform = "none";
    dragHandle.setPointerCapture(event.pointerId);
  });
  dragHandle.addEventListener("pointermove", (event) => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    const left = Math.max(
      8,
      Math.min(window.innerWidth - viewer.offsetWidth - 8, event.clientX - drag.offsetX),
    );
    const top = Math.max(
      8,
      Math.min(window.innerHeight - 56, event.clientY - drag.offsetY),
    );
    viewer.style.left = `${left}px`;
    viewer.style.top = `${top}px`;
  });
  dragHandle.addEventListener("pointerup", (event) => {
    if (drag?.pointerId === event.pointerId) drag = null;
  });

  try {
    const restored = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) || "null");
    if (restored?.viewerUrl) openViewer(restored, true);
  } catch (_error) {
    window.sessionStorage.removeItem(STORAGE_KEY);
  }
})();
