(() => {
  const rows = [...document.querySelectorAll("[data-capture-row]")];
  const viewers = [...document.querySelectorAll("[data-pcap-viewer]")];

  const updateRow = (row, payload) => {
    row.dataset.captureActive = String(payload.active);
    row.querySelector("[data-capture-status]").textContent = payload.status;
    row.querySelector("[data-capture-elapsed]").textContent =
      `${Number(payload.elapsed_seconds || 0).toFixed(1)}s`;
    row.querySelector("[data-capture-size]").textContent = payload.size_display;
    row.querySelector("[data-capture-packets]").textContent =
      payload.packet_count || "—";
    row.querySelector("[data-capture-reason]").textContent =
      payload.termination_reason || (payload.active ? "In progress" : "—");

    const status = row.querySelector("[data-capture-status]");
    status.className = `pill ${
      payload.status === "completed"
        ? "success"
        : payload.status === "error"
          ? "error"
          : "planned"
    }`;
    const error = row.querySelector("[data-capture-error]");
    error.textContent = payload.error || "";
    error.hidden = !payload.error;
    row.querySelector("[data-capture-stop]").hidden = !payload.active;
    row.querySelector("[data-capture-download]").hidden = !payload.downloadable;
    row.querySelector("[data-capture-delete]").hidden = payload.active;
    const save = row.querySelector("[data-capture-save]");
    if (save) save.hidden = !payload.downloadable;
    const viewer = row.querySelector("[data-pcap-viewer]");
    if (viewer) viewer.hidden = !payload.viewable;
  };

  const refreshRows = async () => {
    const activeRows = rows.filter((row) => row.dataset.captureActive === "true");
    await Promise.all(
      activeRows.map(async (row) => {
        try {
          const response = await fetch(row.dataset.statusUrl, {
            headers: { Accept: "application/json" },
          });
          if (response.ok) updateRow(row, await response.json());
        } catch (_error) {
          // A later poll will recover after a transient navigation/network error.
        }
      }),
    );
    if (rows.some((row) => row.dataset.captureActive === "true")) {
      window.setTimeout(refreshRows, 1000);
    }
  };

  const endpointText = (packet, direction) => {
    const address = packet[`${direction}_ip`] || "";
    const port = packet[`${direction}_port`];
    if (!address) return packet[`${direction}_mac`] || "—";
    if (port === null || port === undefined) return address;
    return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
  };

  const addText = (parent, tagName, value, className = "") => {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    element.textContent = value;
    parent.append(element);
    return element;
  };

  const endpointCell = (packet, direction) => {
    const cell = document.createElement("td");
    addText(cell, "strong", endpointText(packet, direction));
    const mac = packet[`${direction}_mac`] || "";
    if (mac && mac !== endpointText(packet, direction)) {
      addText(cell, "small", mac);
    }
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
    return row;
  };

  const setupViewer = (viewer) => {
    const owner = viewer.closest("[data-packets-url]");
    const packetsUrl = viewer.dataset.packetsUrl || owner?.dataset.packetsUrl;
    if (!packetsUrl) return;
    const status = viewer.querySelector("[data-pcap-viewer-status]");
    const table = viewer.querySelector("[data-pcap-viewer-table]");
    const body = viewer.querySelector("[data-pcap-viewer-rows]");
    const more = viewer.querySelector("[data-pcap-viewer-more]");
    const refresh = viewer.querySelector("[data-pcap-viewer-refresh]");
    let nextStart = 0;
    let nextCursor = null;
    let loading = false;

    const load = async ({ reset = false } = {}) => {
      if (loading) return;
      if (reset) {
        nextStart = 0;
        nextCursor = null;
        body.replaceChildren();
        table.hidden = true;
      }
      loading = true;
      status.textContent = nextStart
        ? "Checking for more packets…"
        : "Loading packet headers…";
      more.disabled = true;
      refresh.disabled = true;
      try {
        const url = new URL(packetsUrl, window.location.href);
        url.searchParams.set("start", String(nextStart));
        if (nextCursor !== null) {
          url.searchParams.set("cursor", String(nextCursor));
        }
        const response = await fetch(url, {
          headers: { Accept: "application/json" },
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Packet inspection failed.");
        payload.packets.forEach((packet) => body.append(packetRow(packet)));
        nextStart = payload.next_start;
        nextCursor = payload.next_cursor;
        table.hidden = body.children.length === 0;
        more.hidden = !payload.has_more;
        status.textContent = payload.waiting
          ? "Waiting for the next complete packet…"
          : body.children.length
            ? `Showing ${body.children.length.toLocaleString()} packet header${body.children.length === 1 ? "" : "s"}.`
            : "No packet records were found in this capture.";
      } catch (error) {
        status.textContent = error.message || "Packet headers could not be loaded.";
        more.hidden = true;
      } finally {
        loading = false;
        more.disabled = false;
        refresh.disabled = false;
      }
    };

    viewer.addEventListener("toggle", () => {
      if (viewer.open && !body.children.length) load();
    });
    more.addEventListener("click", () => load());
    refresh.addEventListener("click", () => load({ reset: true }));

    window.setInterval(() => {
      const captureRow = viewer.closest("[data-capture-row]");
      if (
        viewer.open &&
        captureRow?.dataset.captureActive === "true" &&
        !loading
      ) {
        load();
      }
    }, 2000);
  };

  viewers.forEach(setupViewer);
  if (rows.length) refreshRows();
})();
