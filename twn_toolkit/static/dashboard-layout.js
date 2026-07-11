(() => {
  const editor = document.querySelector("[data-dashboard-editor]");
  if (!editor) return;

  const grid = editor.querySelector("[data-dashboard-grid]");
  const editButton = editor.querySelector("[data-dashboard-edit]");
  const controls = editor.querySelector("[data-dashboard-edit-controls]");
  const cancelButton = editor.querySelector("[data-dashboard-cancel]");
  const divider = editor.querySelector("[data-dashboard-hidden-divider]");
  const form = document.querySelector("#dashboard-layout-form");
  if (!grid || !editButton || !controls || !cancelButton || !divider || !form) return;

  let snapshot = [];
  let draggedCard = null;
  let pointerCard = null;

  const cards = () => [...grid.querySelectorAll("[data-widget-id]")];

  function arrangeGroups() {
    const all = cards();
    const visible = all.filter((card) => card.dataset.widgetHidden !== "true");
    const hidden = all.filter((card) => card.dataset.widgetHidden === "true");
    visible.forEach((card) => grid.append(card));
    grid.append(divider);
    hidden.forEach((card) => grid.append(card));
    divider.hidden = hidden.length === 0 || !editor.classList.contains("is-editing");
  }

  function updateCard(card) {
    const isHidden = card.dataset.widgetHidden === "true";
    card.hidden = !editor.classList.contains("is-editing") && isHidden;
    card.classList.toggle("dashboard-card-hidden", isHidden);
    const toggle = card.querySelector(".dashboard-visibility-toggle");
    if (toggle) {
      toggle.textContent = isHidden ? "Show" : "Hide";
      toggle.setAttribute("aria-pressed", isHidden ? "false" : "true");
    }
  }

  function setEditing(enabled) {
    editor.classList.toggle("is-editing", enabled);
    editButton.hidden = enabled;
    controls.hidden = !enabled;
    cards().forEach((card) => {
      card.draggable = enabled;
      const cardEditor = card.querySelector(".dashboard-card-editor");
      if (cardEditor) cardEditor.hidden = !enabled;
      updateCard(card);
    });
    arrangeGroups();
  }

  function enterEditing() {
    snapshot = cards().map((card) => ({
      id: card.dataset.widgetId,
      hidden: card.dataset.widgetHidden === "true",
    }));
    setEditing(true);
  }

  function cancelEditing() {
    snapshot.forEach((item) => {
      const card = grid.querySelector(`[data-widget-id="${CSS.escape(item.id)}"]`);
      if (!card) return;
      card.dataset.widgetHidden = item.hidden ? "true" : "false";
      grid.append(card);
      updateCard(card);
    });
    setEditing(false);
  }

  function moveNear(card, target, after = false) {
    if (!card || !target || card === target) return;
    if (card.dataset.widgetHidden !== target.dataset.widgetHidden) return;
    grid.insertBefore(card, after ? target.nextSibling : target);
  }

  editButton.addEventListener("click", enterEditing);
  cancelButton.addEventListener("click", cancelEditing);

  grid.addEventListener("click", (event) => {
    const toggle = event.target.closest(".dashboard-visibility-toggle");
    if (!toggle) return;
    const card = toggle.closest("[data-widget-id]");
    card.dataset.widgetHidden = card.dataset.widgetHidden === "true" ? "false" : "true";
    updateCard(card);
    arrangeGroups();
  });

  grid.addEventListener("dragstart", (event) => {
    const card = event.target.closest("[data-widget-id]");
    if (!card || !editor.classList.contains("is-editing")) return;
    draggedCard = card;
    card.classList.add("is-dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", card.dataset.widgetId);
  });

  grid.addEventListener("dragover", (event) => {
    const target = event.target.closest("[data-widget-id]");
    if (!draggedCard || !target || draggedCard === target) return;
    if (draggedCard.dataset.widgetHidden !== target.dataset.widgetHidden) return;
    event.preventDefault();
    const bounds = target.getBoundingClientRect();
    const after = event.clientY > bounds.top + bounds.height / 2 ||
      (Math.abs(event.clientY - (bounds.top + bounds.height / 2)) < bounds.height / 3 &&
       event.clientX > bounds.left + bounds.width / 2);
    moveNear(draggedCard, target, after);
  });

  grid.addEventListener("dragend", () => {
    if (draggedCard) draggedCard.classList.remove("is-dragging");
    draggedCard = null;
  });

  grid.addEventListener("pointerdown", (event) => {
    if (!event.target.closest(".dashboard-drag-handle")) return;
    pointerCard = event.target.closest("[data-widget-id]");
    pointerCard?.classList.add("is-dragging");
    event.target.setPointerCapture?.(event.pointerId);
  });

  grid.addEventListener("pointermove", (event) => {
    if (!pointerCard || event.pointerType === "mouse") return;
    event.preventDefault();
    const target = document.elementFromPoint(event.clientX, event.clientY)?.closest("[data-widget-id]");
    if (target) moveNear(pointerCard, target, false);
  });

  function finishPointerMove() {
    pointerCard?.classList.remove("is-dragging");
    pointerCard = null;
  }
  grid.addEventListener("pointerup", finishPointerMove);
  grid.addEventListener("pointercancel", finishPointerMove);

  grid.addEventListener("keydown", (event) => {
    const handle = event.target.closest(".dashboard-drag-handle");
    if (!handle || !["ArrowLeft", "ArrowUp", "ArrowRight", "ArrowDown"].includes(event.key)) return;
    const card = handle.closest("[data-widget-id]");
    const peers = cards().filter((item) => item.dataset.widgetHidden === card.dataset.widgetHidden);
    const index = peers.indexOf(card);
    const direction = ["ArrowLeft", "ArrowUp"].includes(event.key) ? -1 : 1;
    const target = peers[index + direction];
    if (!target) return;
    event.preventDefault();
    moveNear(card, target, direction > 0);
    handle.focus();
  });

  form.addEventListener("submit", () => {
    const all = cards();
    form.elements.order.value = all.map((card) => card.dataset.widgetId).join(",");
    form.elements.hidden.value = all
      .filter((card) => card.dataset.widgetHidden === "true")
      .map((card) => card.dataset.widgetId)
      .join(",");
  });
})();
