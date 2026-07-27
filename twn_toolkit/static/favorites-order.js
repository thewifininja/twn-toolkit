(() => {
  const editor = document.querySelector("[data-favorites-reorder]");
  if (!editor) return;

  const list = editor.querySelector("[data-favorites-list]");
  const form = editor.querySelector("[data-favorites-order-form]");
  const status = editor.querySelector("[data-favorites-status]");
  if (!list || !form) return;

  let draggedItem = null;
  let dragChanged = false;
  let pointerItem = null;
  let pointerChanged = false;
  let saveSequence = 0;
  let saveQueue = Promise.resolve();

  const items = () => [...list.querySelectorAll("[data-favorite-id]")];

  const itemLabel = (item) => (
    item?.querySelector(".side-nav-label")?.textContent?.trim() || "Favorite"
  );

  const positionMessage = (item, suffix = "") => {
    const label = itemLabel(item);
    const position = items().indexOf(item) + 1;
    return `${label} moved to position ${position} of ${items().length}.${suffix}`;
  };

  const moveNear = (item, target, after = false) => {
    if (!item || !target || item === target) return false;
    const before = items().map((entry) => entry.dataset.favoriteId).join(",");
    list.insertBefore(item, after ? target.nextSibling : target);
    const changed = before !== items()
      .map((entry) => entry.dataset.favoriteId)
      .join(",");
    if (changed && status) status.textContent = positionMessage(item);
    return changed;
  };

  const syncQuickLaunch = async () => {
    const currentGrid = document.querySelector(".workspace-quick-grid");
    if (!currentGrid) return;
    const response = await fetch(window.location.href, {
      credentials: "same-origin",
      headers: {"X-Requested-With": "XMLHttpRequest"},
    });
    if (!response.ok || response.redirected) {
      throw new Error("Quick launch could not be refreshed.");
    }
    const updatedPage = new DOMParser().parseFromString(
      await response.text(),
      "text/html",
    );
    const updatedGrid = updatedPage.querySelector(".workspace-quick-grid");
    if (updatedGrid) currentGrid.replaceWith(updatedGrid);
  };

  const persistOrder = (item) => {
    const data = new FormData(form);
    data.set(
      "order",
      items().map((entry) => entry.dataset.favoriteId).join(","),
    );
    const sequence = ++saveSequence;
    if (status) status.textContent = positionMessage(item, " Saving.");
    editor.classList.add("is-saving");

    saveQueue = saveQueue
      .catch(() => {})
      .then(async () => {
        const response = await fetch(form.action, {
          method: form.method || "POST",
          body: data,
          credentials: "same-origin",
          headers: {"X-Requested-With": "XMLHttpRequest"},
        });
        if (!response.ok || response.redirected) {
          throw new Error("Favorite order could not be saved.");
        }
        if (sequence === saveSequence) await syncQuickLaunch();
      })
      .then(() => {
        if (sequence !== saveSequence) return;
        editor.classList.remove("has-save-error");
        if (status) status.textContent = positionMessage(item, " Saved.");
      })
      .catch(() => {
        if (sequence !== saveSequence) return;
        editor.classList.add("has-save-error");
        if (status) {
          status.textContent = "Favorite order could not be saved. Refresh and try again.";
        }
      })
      .finally(() => {
        if (sequence === saveSequence) editor.classList.remove("is-saving");
      });
  };

  list.addEventListener("dragstart", (event) => {
    const handle = event.target.closest(".side-nav-favorite-drag-handle");
    if (!handle) return;
    draggedItem = handle.closest("[data-favorite-id]");
    if (!draggedItem) return;
    dragChanged = false;
    draggedItem.classList.add("is-dragging");
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", draggedItem.dataset.favoriteId);
    }
  });

  list.addEventListener("dragover", (event) => {
    const target = event.target.closest("[data-favorite-id]");
    if (!draggedItem || !target || draggedItem === target) return;
    event.preventDefault();
    const bounds = target.getBoundingClientRect();
    if (moveNear(draggedItem, target, event.clientY > bounds.top + bounds.height / 2)) {
      dragChanged = true;
    }
  });

  list.addEventListener("dragend", () => {
    const item = draggedItem;
    item?.classList.remove("is-dragging");
    draggedItem = null;
    if (item && dragChanged) persistOrder(item);
    dragChanged = false;
  });

  list.addEventListener("pointerdown", (event) => {
    const handle = event.target.closest(".side-nav-favorite-drag-handle");
    if (!handle || event.pointerType === "mouse") return;
    pointerItem = handle.closest("[data-favorite-id]");
    pointerChanged = false;
    pointerItem?.classList.add("is-dragging");
    handle.setPointerCapture?.(event.pointerId);
  });

  list.addEventListener("pointermove", (event) => {
    if (!pointerItem) return;
    event.preventDefault();
    const target = document.elementFromPoint(event.clientX, event.clientY)
      ?.closest("[data-favorite-id]");
    if (!target || target === pointerItem) return;
    const bounds = target.getBoundingClientRect();
    if (moveNear(pointerItem, target, event.clientY > bounds.top + bounds.height / 2)) {
      pointerChanged = true;
    }
  });

  const finishPointerMove = () => {
    const item = pointerItem;
    item?.classList.remove("is-dragging");
    pointerItem = null;
    if (item && pointerChanged) persistOrder(item);
    pointerChanged = false;
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
    if (moveNear(item, target, direction > 0)) {
      handle.focus();
      persistOrder(item);
    }
  });
})();
