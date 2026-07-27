(() => {
  const editor = document.querySelector("[data-favorites-editor]");
  if (!editor) return;

  const list = editor.querySelector("[data-favorites-list]");
  const editButton = editor.querySelector("[data-favorites-edit]");
  const controls = editor.querySelector("[data-favorites-edit-controls]");
  const cancelButton = editor.querySelector("[data-favorites-cancel]");
  const form = document.querySelector("#favorites-order-form");
  const status = editor.querySelector("[data-favorites-status]");
  if (!list || !editButton || !controls || !cancelButton || !form) return;

  let snapshot = [];
  let draggedItem = null;
  let pointerItem = null;

  const items = () => [...list.querySelectorAll("[data-favorite-id]")];

  const announcePosition = (item) => {
    if (!status || !item) return;
    const label = item.querySelector(".side-nav-label")?.textContent?.trim() || "Favorite";
    status.textContent = `${label} moved to position ${items().indexOf(item) + 1}.`;
  };

  const moveNear = (item, target, after = false) => {
    if (!item || !target || item === target) return;
    list.insertBefore(item, after ? target.nextSibling : target);
    announcePosition(item);
  };

  const setEditing = (enabled) => {
    editor.classList.toggle("is-editing", enabled);
    editButton.hidden = enabled;
    controls.hidden = !enabled;
    items().forEach((item) => {
      item.draggable = enabled;
      const handle = item.querySelector(".side-nav-favorite-drag-handle");
      if (handle) handle.hidden = !enabled;
    });
  };

  editButton.addEventListener("click", () => {
    snapshot = items().map((item) => item.dataset.favoriteId);
    if (status) status.textContent = "";
    setEditing(true);
    items()[0]?.querySelector(".side-nav-favorite-drag-handle")?.focus();
  });

  cancelButton.addEventListener("click", () => {
    snapshot.forEach((toolId) => {
      const item = list.querySelector(`[data-favorite-id="${CSS.escape(toolId)}"]`);
      if (item) list.append(item);
    });
    setEditing(false);
    if (status) status.textContent = "Favorite order restored.";
    editButton.focus();
  });

  list.addEventListener("dragstart", (event) => {
    const item = event.target.closest("[data-favorite-id]");
    if (!item || !editor.classList.contains("is-editing")) return;
    draggedItem = item;
    item.classList.add("is-dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", item.dataset.favoriteId);
  });

  list.addEventListener("dragover", (event) => {
    const target = event.target.closest("[data-favorite-id]");
    if (!draggedItem || !target || draggedItem === target) return;
    event.preventDefault();
    const bounds = target.getBoundingClientRect();
    moveNear(draggedItem, target, event.clientY > bounds.top + bounds.height / 2);
  });

  list.addEventListener("dragend", () => {
    draggedItem?.classList.remove("is-dragging");
    draggedItem = null;
  });

  list.addEventListener("pointerdown", (event) => {
    const handle = event.target.closest(".side-nav-favorite-drag-handle");
    if (!handle) return;
    pointerItem = handle.closest("[data-favorite-id]");
    pointerItem?.classList.add("is-dragging");
    handle.setPointerCapture?.(event.pointerId);
  });

  list.addEventListener("pointermove", (event) => {
    if (!pointerItem || event.pointerType === "mouse") return;
    event.preventDefault();
    const target = document.elementFromPoint(event.clientX, event.clientY)
      ?.closest("[data-favorite-id]");
    if (!target || target === pointerItem) return;
    const bounds = target.getBoundingClientRect();
    moveNear(pointerItem, target, event.clientY > bounds.top + bounds.height / 2);
  });

  const finishPointerMove = () => {
    pointerItem?.classList.remove("is-dragging");
    pointerItem = null;
  };
  list.addEventListener("pointerup", finishPointerMove);
  list.addEventListener("pointercancel", finishPointerMove);

  list.addEventListener("keydown", (event) => {
    const handle = event.target.closest(".side-nav-favorite-drag-handle");
    if (!handle || !["ArrowUp", "ArrowDown"].includes(event.key)) return;
    const item = handle.closest("[data-favorite-id]");
    const all = items();
    const index = all.indexOf(item);
    const direction = event.key === "ArrowUp" ? -1 : 1;
    const target = all[index + direction];
    if (!target) return;
    event.preventDefault();
    moveNear(item, target, direction > 0);
    handle.focus();
  });

  form.addEventListener("submit", () => {
    form.elements.order.value = items()
      .map((item) => item.dataset.favoriteId)
      .join(",");
  });
})();
