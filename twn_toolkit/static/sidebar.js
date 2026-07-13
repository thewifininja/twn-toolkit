(() => {
  const button = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("app-sidebar");
  const topbar = document.querySelector(".topbar");
  const desktopQuery = window.matchMedia("(min-width: 901px)");

  if (!button || !sidebar) return;

  const updateTopbarHeight = () => {
    if (!topbar) return;
    document.documentElement.style.setProperty(
      "--topbar-height",
      `${Math.ceil(topbar.getBoundingClientRect().height)}px`,
    );
  };

  const applyState = () => {
    const collapsed = document.body.classList.contains("sidebar-collapsed");
    const open = document.body.classList.contains("sidebar-open");
    const expanded = desktopQuery.matches ? !collapsed : open;
    button.setAttribute("aria-expanded", String(expanded));
    button.setAttribute("aria-label", expanded ? "Hide navigation" : "Show navigation");
    button.setAttribute("title", expanded ? "Hide navigation" : "Show navigation");
  };

  const toggle = () => {
    if (desktopQuery.matches) {
      document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem(
        "twn-sidebar-collapsed",
        document.body.classList.contains("sidebar-collapsed") ? "1" : "0",
      );
    } else {
      document.body.classList.toggle("sidebar-open");
    }
    applyState();
  };

  updateTopbarHeight();
  window.addEventListener("resize", updateTopbarHeight);
  if (window.ResizeObserver && topbar) {
    new ResizeObserver(updateTopbarHeight).observe(topbar);
  }

  if (desktopQuery.matches && localStorage.getItem("twn-sidebar-collapsed") === "1") {
    document.body.classList.add("sidebar-collapsed");
  }

  button.addEventListener("click", toggle);
  sidebar.addEventListener("click", (event) => {
    if (!desktopQuery.matches && event.target.closest("a")) {
      document.body.classList.remove("sidebar-open");
      applyState();
    }
  });
  desktopQuery.addEventListener("change", () => {
    document.body.classList.remove("sidebar-open");
    if (!desktopQuery.matches) {
      document.body.classList.remove("sidebar-collapsed");
    } else if (localStorage.getItem("twn-sidebar-collapsed") === "1") {
      document.body.classList.add("sidebar-collapsed");
    }
    applyState();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      document.body.classList.remove("sidebar-open");
      applyState();
    }
  });

  applyState();
})();
