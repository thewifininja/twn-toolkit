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
    loadToken = previewToken = "";
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
    originalIds.forEach((id) => body.append("original_switch_id", id));
    currentIds().forEach((id) => body.append("switch_id", id));
    return body;
  }

  loadButton.addEventListener("click", async () => {
    if (loading || applying) return;
    loading = true;
    const generation = ++revision;
    const requestedProfile = profile.value;
    loadToken = previewToken = "";
    loadedTarget = null;
    loadButton.disabled = true;
    editor.hidden = false;
    setStatus("Loading managed switches…");
    list.innerHTML = "";
    preview.innerHTML = "";
    confirmation.checked = false;
    applyButton.disabled = true;
    window.toolkitLoading?.show("Loading managed FortiSwitches…");
    try {
      const response = await fetch(root.dataset.loadUrl, {
        method: "POST",
        body: new FormData(source),
      });
      const data = await response.json();
      if (generation !== revision) return;
      if (!response.ok) throw new Error(data.error || "Unable to load managed switches.");
      if (!data.load_token) throw new Error("This response cannot authorize a reorder. Update the executing instance and reload.");
      loadToken = data.load_token;
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
      window.toolkitLoading?.hide();
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
      const response = await fetch(root.dataset.applyUrl, {method: "POST", body});
      const data = await response.json();
      if (generation !== revision) {
        setStatus("The previous target's apply request finished. Reload that target to reconcile its order.");
        return;
      }
      if (!response.ok) {
        status.dataset.operationState = data.completed_moves?.length ? "partial" : "uncertain";
        loadToken = "";
        confirmation.checked = false;
        const summary = data.user_message || data.message || data.error || "Unable to apply switch order.";
        const technicalDetail = data.detail || (data.user_message ? data.error : "");
        setStatus(`${summary} Reload the current order before another apply.`, "error", technicalDetail);
        return;
      }
      renderSwitches(data.switches || []);
      originalIds = currentIds();
      loadToken = data.load_token || "";
      updatePreview();
      status.dataset.operationState = "complete";
      setStatus(data.message, "success");
    } catch (error) {
      status.dataset.operationState = "uncertain";
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
