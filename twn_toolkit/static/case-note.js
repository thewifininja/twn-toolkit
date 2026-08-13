(() => {
  const dialog = document.querySelector("[data-case-note-dialog]");
  const openButton = document.querySelector("[data-case-note-open]");
  if (!dialog || !openButton) return;

  const note = dialog.querySelector("textarea[name='note']");
  const closeButtons = dialog.querySelectorAll("[data-case-note-close]");

  const close = () => {
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  };

  openButton.addEventListener("click", () => {
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    window.requestAnimationFrame(() => note.focus());
  });

  closeButtons.forEach((button) => button.addEventListener("click", close));
  dialog.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    const bounds = dialog.getBoundingClientRect();
    const inside =
      event.clientX >= bounds.left &&
      event.clientX <= bounds.right &&
      event.clientY >= bounds.top &&
      event.clientY <= bounds.bottom;
    if (!inside) close();
  });
})();
