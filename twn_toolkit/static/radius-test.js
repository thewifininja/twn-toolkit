(() => {
  document.querySelectorAll("[data-radius-show-profiles]").forEach((button) => {
    button.addEventListener("click", () => {
      const tab = document.getElementById("radius-profiles-tab");
      tab?.click();
      tab?.focus();
    });
  });
})();
