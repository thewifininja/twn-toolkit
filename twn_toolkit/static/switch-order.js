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

  let originalIds = [];
  let draggedItem = null;

  profile.addEventListener("change", () => {
    vdom.value = profile.selectedOptions[0]?.dataset.vdom || "root";
  });

  loadButton.addEventListener("click", async () => {
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
      if (!response.ok) throw new Error(data.error || "Unable to load managed switches.");
      vdom.value = data.vdom;
      renderSwitches(data.switches || []);
      originalIds = currentIds();
      const switchLabel = data.row_count === 1 ? "FortiSwitch" : "FortiSwitches";
      setStatus(`${data.row_count} ${switchLabel} loaded in FortiGate table order.`, "success");
      updatePreview();
    } catch (error) {
      setStatus(error.message, "error");
    } finally {
      loadButton.disabled = false;
      window.toolkitLoading?.hide();
    }
  });

  alphabetizeButton.addEventListener("click", () => {
    const collator = new Intl.Collator(undefined, {numeric: true, sensitivity: "base"});
    const rows = Array.from(list.children);
    rows.sort((left, right) => collator.compare(left.dataset.name, right.dataset.name));
    rows.forEach((row) => list.appendChild(row));
    setStatus("Alphabetized by displayed switch name. Review, then apply.");
    updatePreview();
  });

  confirmation.addEventListener("change", updateApplyState);

  list.addEventListener("click", (event) => {
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
    draggedItem = event.target.closest(".switch-order-item");
    if (!draggedItem) return;
    draggedItem.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
  });

  list.addEventListener("dragover", (event) => {
    event.preventDefault();
    const target = event.target.closest(".switch-order-item");
    if (!draggedItem || !target || target === draggedItem) return;
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
    const moves = calculateMoves(originalIds, currentIds());
    if (!moves.length) return;
    const body = new FormData();
    body.set("profile", profile.value);
    body.set("vdom", vdom.value);
    body.set("confirmed", "on");
    currentIds().forEach((id) => body.append("switch_id", id));
    applyButton.disabled = true;
    alphabetizeButton.disabled = true;
    setStatus("Applying moves and verifying the resulting order…");
    window.toolkitLoading?.show("Applying switch moves and verifying order…");
    try {
      const response = await fetch(root.dataset.applyUrl, {method: "POST", body});
      const data = await response.json();
      if (!response.ok) {
        const summary = data.user_message || data.message || data.error || "Unable to apply switch order.";
        const technicalDetail = data.detail || (data.user_message ? data.error : "");
        setStatus(summary, "error", technicalDetail);
        applyButton.disabled = false;
        return;
      }
      renderSwitches(data.switches || []);
      originalIds = currentIds();
      confirmation.checked = false;
      updatePreview();
      setStatus(data.message, "success");
    } catch (error) {
      setStatus(error.message, "error");
      applyButton.disabled = false;
    } finally {
      alphabetizeButton.disabled = false;
      window.toolkitLoading?.hide();
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
    applyButton.disabled = calculateMoves(originalIds, currentIds()).length === 0 ||
      !confirmation.checked;
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
