(() => {
  const root = document.querySelector("#switch-order-tool");
  const source = document.querySelector("#switch-order-source");
  const loadButton = document.querySelector("#load-switch-order");
  const editor = document.querySelector("#switch-order-editor");
  const list = document.querySelector("#switch-order-list");
  const status = document.querySelector("#switch-order-status");
  const detail = document.querySelector("#switch-order-detail");
  const preview = document.querySelector("#switch-move-preview");
  const alphabetizeButton = document.querySelector("#alphabetize-switches");
  const applyButton = document.querySelector("#apply-switch-order");
  const confirmation = document.querySelector("#confirm-switch-order");
  const profile = document.querySelector("#switch-order-profile");
  const vdom = document.querySelector("#switch-order-vdom");
  if (!root || !source || !loadButton || !editor || !list || !status || !detail || !preview ||
      !alphabetizeButton || !applyButton || !confirmation || !profile || !vdom) return;

  const targetLabel = document.querySelector("#switch-order-target");
  const runBox = document.querySelector("#switch-order-run");
  const displayNote = document.querySelector("#switch-order-display-note");
  let leaving = false;
  window.addEventListener("pagehide", () => { leaving = true; });
  window.addEventListener("pageshow", () => { leaving = false; });
  let targetRevision = "";
  let revision = 0;
  let loadToken = "";
  let previewToken = "";
  let loadedTarget = null;
  let loading = false;
  let applying = false;
  let originalIds = [];
  let draggedItem = null;

  profile.addEventListener("change", () => {
    vdom.value = profile.selectedOptions[0]?.dataset.vdom || "root";
    window.TwnSelectControls?.sync(vdom);
    invalidateTarget();
  });
  vdom.addEventListener("input", invalidateTarget);
  vdom.addEventListener("change", invalidateTarget);

  function invalidateTarget() {
    revision += 1;
    loadToken = previewToken = targetRevision = "";
    loadedTarget = null;
    originalIds = [];
    list.replaceChildren();
    preview.replaceChildren();
    confirmation.checked = false;
    if (targetLabel) targetLabel.textContent = "";
    editor.hidden = false;
    setStatus("Target changed. Load its current order before reviewing moves.");
    updateApplyState();
  }

  function targetMatches() {
    return loadedTarget && loadedTarget.profile === profile.value && loadedTarget.vdom === vdom.value;
  }

  function orderBody() {
    const body = new FormData();
    body.set("profile", loadedTarget.profile);
    body.set("vdom", loadedTarget.vdom);
    body.set("target_revision", targetRevision);
    originalIds.forEach((id) => body.append("original_switch_id", id));
    currentIds().forEach((id) => body.append("switch_id", id));
    return body;
  }

  loadButton.addEventListener("click", async () => {
    if (loading || applying) return;
    loading = true;
    const generation = ++revision;
    const requestedProfile = profile.value;
    loadToken = previewToken = targetRevision = "";
    loadedTarget = null;
    loadButton.disabled = true;
    editor.hidden = false;
    setStatus("Loading managed switches…");
    list.innerHTML = "";
    preview.innerHTML = "";
    confirmation.checked = false;
    applyButton.disabled = true;
    try {
      const data = await runOrder(root.dataset.loadUrl, new FormData(source), generation, false);
      if (generation !== revision) return;
      if (!data.load_token) throw new Error("This response cannot authorize a reorder. Update the executing instance and reload.");
      loadToken = data.load_token;
      targetRevision = data.target_revision || "";
      if (displayNote) displayNote.hidden = false;
      loadedTarget = {profile: requestedProfile, vdom: data.vdom};
      if (targetLabel) targetLabel.textContent = `${requestedProfile} · ${data.target_origin} · VDOM ${data.vdom}`;
      vdom.value = data.vdom;
      window.TwnSelectControls?.sync(vdom);
      renderSwitches(data.switches || []);
      originalIds = currentIds();
      const switchLabel = data.row_count === 1 ? "FortiSwitch" : "FortiSwitches";
      setStatus(`${data.row_count} ${switchLabel} loaded in FortiGate table order.`, "success");
      updatePreview();
    } catch (error) {
      if (generation === revision) setStatus(error.message, "error");
    } finally {
      loading = false;
      loadButton.disabled = false;
      updateApplyState();
    }
  });

  alphabetizeButton.addEventListener("click", () => {
    if (applying || !loadToken) return;
    const collator = new Intl.Collator(undefined, {numeric: true, sensitivity: "base"});
    const rows = Array.from(list.children);
    rows.sort((left, right) => collator.compare(left.dataset.name, right.dataset.name));
    rows.forEach((row) => list.appendChild(row));
    setStatus("Alphabetized by displayed switch name. Review, then apply.");
    updatePreview();
  });

  confirmation.addEventListener("change", async () => {
    const generation = ++revision;
    previewToken = "";
    updateApplyState();
    if (!confirmation.checked || applying || !loadToken || !targetMatches()) return;
    const expected = calculateMoves(originalIds, currentIds()).map((move) => [move.switchId, move.after]);
    if (!expected.length) { confirmation.checked = false; return; }
    const body = orderBody();
    body.set("load_token", loadToken);
    setStatus("Checking the reviewed order…");
    try {
      const response = await fetch(root.dataset.previewUrl, {method: "POST", body});
      const data = await response.json();
      if (generation !== revision) return;
      if (!response.ok) throw new Error(data.error || "Reload and review the current order.");
      if (!data.preview_token || JSON.stringify(data.moves.map((move) => [move.switch_id, move.after])) !== JSON.stringify(expected)) {
        throw new Error("The move preview no longer matches. Reload and review it again.");
      }
      previewToken = data.preview_token;
      setStatus("Reviewed order confirmed for this target. Ready to apply.", "success");
    } catch (error) {
      if (generation !== revision) return;
      confirmation.checked = false;
      loadToken = "";
      setStatus(error.message, "error");
    } finally {
      if (generation === revision) updateApplyState();
    }
  });

  list.addEventListener("click", (event) => {
    if (applying || !loadToken) return;
    const button = event.target.closest("button[data-direction]");
    if (!button) return;
    const row = button.closest(".switch-order-item");
    if (button.dataset.direction === "up" && row.previousElementSibling) {
      list.insertBefore(row, row.previousElementSibling);
    } else if (button.dataset.direction === "down" && row.nextElementSibling) {
      list.insertBefore(row.nextElementSibling, row);
    }
    updatePreview();
  });

  list.addEventListener("dragstart", (event) => {
    if (applying || !loadToken) { event.preventDefault(); return; }
    draggedItem = event.target.closest(".switch-order-item");
    if (!draggedItem) return;
    draggedItem.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
  });

  list.addEventListener("dragover", (event) => {
    event.preventDefault();
    const target = event.target.closest(".switch-order-item");
    if (applying || !loadToken || !draggedItem || !target || target === draggedItem) return;
    const after = event.clientY > target.getBoundingClientRect().top + target.offsetHeight / 2;
    list.insertBefore(draggedItem, after ? target.nextSibling : target);
  });

  list.addEventListener("dragend", () => {
    draggedItem?.classList.remove("dragging");
    draggedItem = null;
    setStatus("Order changed. Review the moves, then apply.");
    updatePreview();
  });

  applyButton.addEventListener("click", async () => {
    if (applying || !previewToken || !confirmation.checked || !targetMatches()) return;
    const generation = revision;
    const body = orderBody();
    body.set("confirmed", "on");
    body.set("preview_token", previewToken);
    previewToken = "";
    applying = true;
    profile.disabled = vdom.disabled = loadButton.disabled = true;
    updateApplyState();
    setStatus("Applying moves and verifying the resulting order…");
    status.dataset.operationState = "submitted";
    const waitingTimer = window.setTimeout(() => {
      status.dataset.operationState = "uncertain";
      setStatus("Still waiting for the appliance. Leaving this page does not cancel changes. Do not apply again until you have reconciled the current order.");
    }, 30000);
    try {
      const data = await runOrder(root.dataset.applyUrl, body, generation, true);
      if (generation !== revision) {
        setStatus("The previous target's apply request finished. Reload that target to reconcile its order.");
        return;
      }
      renderSwitches(data.switches || []);
      originalIds = currentIds();
      loadToken = data.load_token || "";
      targetRevision = data.target_revision || "";
      updatePreview();
      status.dataset.operationState = "complete";
      setStatus(data.message, "success");
    } catch (error) {
      status.dataset.operationState = error.state || "uncertain";
      loadToken = "";
      confirmation.checked = false;
      setStatus(`${error.message} The apply outcome may be incomplete. Reload and reconcile the target before retrying.`, "error");
    } finally {
      window.clearTimeout(waitingTimer);
      applying = false;
      profile.disabled = vdom.disabled = loadButton.disabled = false;
      updateApplyState();
    }
  });

  async function runOrder(url, body, generation, mutation) {
    let response;
    let queued;
    // Only the supervised contract supports an admission retry. The exact same
    // signed request resolves to its receipt; a legacy synchronous server does not.
    const attempts = mutation && root.dataset.queuedOrders === "true" ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        response = await fetch(url, {method: "POST", body, headers: {Accept: "application/json"}, signal: AbortSignal.timeout(15000)});
        queued = await response.json();
        break;
      } catch (error) {
        if (attempt + 1 === attempts) throw new Error("Admission could not be confirmed. Check Your recent switch-order runs before another apply.");
        setStatus("Recovering the submitted operation…");
      }
    }
    if (!response.ok) throw new Error(queued.user_message || queued.error || "Unable to submit switch order.");
    if (response.status !== 202) return queued;
    const link = document.createElement("a");
    link.href = queued.job_url;
    link.textContent = "Open retained run";
    link.className = "button-link secondary";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "secondary";
    cancel.textContent = "Cancel run";
    if (runBox) { runBox.hidden = false; runBox.replaceChildren(link, cancel); }
    cancel.addEventListener("click", async () => {
      cancel.disabled = true;
      try {
        const result = await fetch(queued.cancel_url, {method: "POST", signal: AbortSignal.timeout(15000)});
        if (!result.ok) throw new Error();
        setStatus("Cancellation requested. Already attempted changes are not undone.");
      } catch (_) {
        cancel.disabled = false;
        setStatus("Cancellation could not be confirmed. Open the retained run to check.", "error");
      }
    });
    try {
      while (!leaving) {
        if (generation !== revision && !mutation) throw new Error("Target changed; the previous load is retained in its run.");
        await new Promise(resolve => window.setTimeout(resolve, 1500));
        if (leaving || document.hidden) continue;
        let job;
        try {
          const result = await fetch(queued.status_url, {headers: {Accept: "application/json"}, cache: "no-store", signal: AbortSignal.timeout(10000)});
          if ([401, 403, 404, 410].includes(result.status)) throw Object.assign(new Error("This run is no longer accessible. Check the retained run before another apply."), {terminal: true});
          if (!result.ok) throw new Error();
          job = await result.json();
        } catch (error) {
          if (error.terminal) throw error;
          if (generation === revision) setStatus("Status unavailable; retrying. The retained run remains available.");
          continue;
        }
        if (job.state === "succeeded") return job.data;
        if (!["queued", "running", "cancel_requested"].includes(job.state)) {
          throw Object.assign(new Error(job.error || `Run ${job.state}.`), {state: job.state});
        }
        if (generation === revision) setStatus(job.state === "cancel_requested" ? "Cancellation requested; changes are not undone." :
          job.state === "queued" ? "Queued. You can navigate away and return to the retained run." :
          `Run in progress: ${job.stage || "checking appliance"}. ${job.data.completed_moves?.length || 0} moves acknowledged.`);
      }
      throw new Error("The page was closed. Check the retained run before another apply.");
    } finally {
      cancel.hidden = true;
    }
  }

  function renderSwitches(switches) {
    list.innerHTML = "";
    switches.forEach((item) => {
      const row = document.createElement("li");
      row.className = "switch-order-item";
      row.draggable = true;
      row.dataset.id = item.id;
      row.dataset.name = item.name;

      const handle = document.createElement("span");
      handle.className = "drag-handle";
      handle.textContent = "☰";
      handle.title = "Drag to reorder";

      const details = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = item.name;
      if (item.description && item.description !== item.name) {
        const description = document.createElement("small");
        description.className = "switch-order-description";
        description.textContent = item.description;
        details.append(name, description);
      } else {
        details.append(name);
      }
      const identifiers = document.createElement("span");
      identifiers.textContent = item.serial && item.serial !== item.id
        ? `${item.id} · ${item.serial}` : item.id;
      details.append(identifiers);

      const controls = document.createElement("div");
      controls.className = "switch-order-row-actions";
      controls.append(
        directionButton("up", "Move up", "↑"),
        directionButton("down", "Move down", "↓"),
      );
      row.append(handle, details, controls);
      list.appendChild(row);
    });
  }

  function setStatus(message, type = "", technicalDetail = "") {
    status.textContent = message;
    status.className = ["switch-order-status", type].filter(Boolean).join(" ");
    detail.textContent = technicalDetail ? `Technical detail: ${technicalDetail}` : "";
    detail.hidden = !technicalDetail;
  }

  function directionButton(direction, label, text) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.dataset.direction = direction;
    button.setAttribute("aria-label", label);
    button.textContent = text;
    return button;
  }

  function currentIds() {
    return Array.from(list.children).map((row) => row.dataset.id);
  }

  function updatePreview() {
    revision += 1;
    previewToken = "";
    confirmation.checked = false;
    preview.innerHTML = "";
    const moves = calculateMoves(originalIds, currentIds());
    moves.forEach((move) => {
      const item = document.createElement("li");
      item.textContent = `Move ${move.switchId} after ${move.after}`;
      preview.appendChild(item);
    });
    if (!moves.length) {
      const item = document.createElement("li");
      item.textContent = "No changes.";
      preview.appendChild(item);
    }
    updateApplyState();
  }

  function updateApplyState() {
    const available = Boolean(loadToken && targetMatches() && !applying && !loading);
    const hasMoves = calculateMoves(originalIds, currentIds()).length > 0;
    alphabetizeButton.disabled = !available;
    confirmation.disabled = !available || !hasMoves;
    list.querySelectorAll("button").forEach((button) => { button.disabled = !available; });
    list.querySelectorAll(".switch-order-item").forEach((row) => { row.draggable = available; });
    applyButton.disabled = !available || !previewToken || !hasMoves || !confirmation.checked;
  }

  function calculateMoves(current, desired) {
    const simulated = [...current];
    const moves = [];
    for (let index = 1; index < desired.length; index += 1) {
      const switchId = desired[index];
      const after = desired[index - 1];
      const switchIndex = simulated.indexOf(switchId);
      if (switchIndex > 0 && simulated[switchIndex - 1] === after) continue;
      simulated.splice(switchIndex, 1);
      simulated.splice(simulated.indexOf(after) + 1, 0, switchId);
      moves.push({switchId, after});
    }
    return moves;
  }
})();
