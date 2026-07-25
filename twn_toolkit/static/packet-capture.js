(() => {
  const rows = [...document.querySelectorAll("[data-capture-row]")];
  if (!rows.length) return;

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
    const viewer = row.querySelector("[data-capture-viewer]");
    if (viewer) {
      viewer.hidden = !payload.viewable;
      viewer.dataset.pcapViewerLive = String(payload.active);
      viewer.textContent = payload.active ? "Open live viewer" : "Inspect PCAP";
    }
  };

  const refresh = async () => {
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
      window.setTimeout(refresh, 1000);
    }
  };

  refresh();
})();
