(() => {
  const button = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("app-sidebar");
  const topbar = document.querySelector(".topbar");
  const scroll = sidebar?.querySelector(".side-nav-scroll");
  const searchInput = document.getElementById("side-nav-search-input");
  const searchResults = document.getElementById("side-nav-search-results");
  const searchEmpty = document.getElementById("side-nav-search-empty");
  const dashboardSearchInput = document.getElementById("dashboard-tool-search-input");
  const dashboardSearchResults = document.getElementById("dashboard-tool-search-results");
  const dashboardSearchEmpty = document.getElementById("dashboard-tool-search-empty");
  const rootPanel = sidebar?.querySelector("[data-nav-root]");
  const categoryPanels = Array.from(sidebar?.querySelectorAll("[data-nav-panel]") || []);
  const categoryButtons = Array.from(sidebar?.querySelectorAll("[data-nav-open]") || []);
  const resizer = sidebar?.querySelector(".sidebar-resizer");
  const root = document.documentElement;
  const desktopQuery = window.matchMedia(
    "(min-width: 901px) and (hover: hover) and (pointer: fine)",
  );
  const minimumWidth = 220;
  const maximumWidth = 400;
  let activePanel = null;

  if (!button || !sidebar || !rootPanel) return;

  const normalizeSearch = (value) => value.toLocaleLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "");

  const searchableTools = (() => {
    const tools = new Map();
    sidebar.querySelectorAll("[data-nav-tool]").forEach((link) => {
      if (link.closest(".side-nav-favorites")) return;
      const label = link.querySelector(".side-nav-label")?.textContent?.trim();
      const category = link.dataset.navCategory?.trim() || "Tools";
      const subgroup = link.dataset.navSubgroup?.trim() || "";
      if (!label || tools.has(link.href)) return;
      const path = [category, subgroup]
        .filter((part, index, values) => part && part !== label && values.indexOf(part) === index)
        .join(" › ");
      tools.set(link.href, {
        href: link.href,
        label,
        icon: link.querySelector(".side-nav-icon")?.textContent?.trim() || "•",
        category,
        path,
        active: link.classList.contains("active"),
        search: normalizeSearch(`${label} ${path}`),
      });
    });
    return [...tools.values()];
  })();

  const searchMatches = (value, category = "") => {
    const query = normalizeSearch(value.trim());
    if (!query) return [];
    return searchableTools.filter(
      (tool) => (!category || tool.category === category) && tool.search.includes(query),
    );
  };

  const searchResult = (tool, className) => {
    const link = document.createElement("a");
    link.className = `${className}${tool.active ? " active" : ""}`;
    link.href = tool.href;
    link.title = tool.path ? `${tool.label} — ${tool.path}` : tool.label;

    const icon = document.createElement("span");
    icon.className = "side-nav-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = tool.icon;
    const label = document.createElement("strong");
    label.textContent = tool.label;
    const path = document.createElement("small");
    path.textContent = tool.path;
    link.append(icon, label, path);
    return link;
  };

  const activeCategory = () => activePanel?.dataset.navLabel || "";

  const renderSearch = () => {
    if (!scroll || !searchInput || !searchResults || !searchEmpty) return;
    const searching = Boolean(searchInput.value.trim());
    scroll.classList.toggle("searching", searching);
    searchResults.replaceChildren();
    searchResults.hidden = !searching;
    searchEmpty.hidden = true;
    if (!searching) return;

    const matches = searchMatches(searchInput.value, activeCategory());
    searchResults.hidden = matches.length === 0;
    searchResults.replaceChildren(
      ...matches.map((tool) => searchResult(tool, "side-nav-search-result")),
    );
    searchEmpty.hidden = matches.length > 0;
  };

  const renderDashboardSearch = () => {
    if (!dashboardSearchInput || !dashboardSearchResults || !dashboardSearchEmpty) return;
    const searching = Boolean(dashboardSearchInput.value.trim());
    dashboardSearchResults.replaceChildren();
    dashboardSearchResults.hidden = !searching;
    dashboardSearchEmpty.hidden = true;
    if (!searching) return;

    const matches = searchMatches(dashboardSearchInput.value).slice(0, 10);
    dashboardSearchResults.hidden = matches.length === 0;
    dashboardSearchResults.replaceChildren(
      ...matches.map((tool) => searchResult(tool, "workspace-tool-search-result")),
    );
    dashboardSearchEmpty.hidden = matches.length > 0;
  };

  const clearSearch = () => {
    if (!searchInput?.value) return;
    searchInput.value = "";
    renderSearch();
  };

  const showPanel = (panelName = "", {focus = false} = {}) => {
    clearSearch();
    activePanel = categoryPanels.find((panel) => panel.dataset.navPanel === panelName) || null;
    rootPanel.hidden = Boolean(activePanel);
    categoryPanels.forEach((panel) => {
      panel.hidden = panel !== activePanel;
    });
    if (!activePanel && root.dataset.layout === "focus" && desktopQuery.matches) {
      rootPanel.querySelector(".side-nav-favorites")?.removeAttribute("open");
    }
    const label = activeCategory();
    if (searchInput) {
      searchInput.placeholder = label ? `Search ${label}…` : "Find a tool…";
      searchInput.setAttribute("aria-label", label ? `Search ${label}` : "Find a tool");
    }
    if (scroll) scroll.scrollTop = 0;
    if (focus) {
      (activePanel?.querySelector("[data-nav-back]") || rootPanel.querySelector("a, button"))?.focus();
    }
  };

  const closeFocusPanel = () => {
    if (root.dataset.layout !== "focus" || !desktopQuery.matches || !activePanel) return;
    showPanel("");
  };

  categoryButtons.forEach((categoryButton) => {
    categoryButton.addEventListener("click", () => {
      showPanel(categoryButton.dataset.navOpen || "", {focus: true});
    });
  });
  categoryPanels.forEach((panel) => {
    panel.querySelector("[data-nav-back]")?.addEventListener("click", () => {
      showPanel("", {focus: true});
    });
  });

  searchInput?.addEventListener("input", renderSearch);
  searchInput?.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && searchInput.value) {
      event.stopPropagation();
      clearSearch();
    }
  });
  dashboardSearchInput?.addEventListener("input", renderDashboardSearch);
  dashboardSearchInput?.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && dashboardSearchInput.value) {
      event.stopPropagation();
      dashboardSearchInput.value = "";
      renderDashboardSearch();
    }
  });

  const updateTopbarHeight = () => {
    if (!topbar) return;
    root.style.setProperty(
      "--topbar-height",
      `${Math.ceil(topbar.getBoundingClientRect().height)}px`,
    );
  };

  const updateMobileViewportHeight = () => {
    const viewportHeight = window.visualViewport?.height || window.innerHeight;
    root.style.setProperty(
      "--mobile-visual-viewport-height",
      `${Math.floor(viewportHeight)}px`,
    );
  };

  const updateSidebarGeometry = () => {
    updateTopbarHeight();
    updateMobileViewportHeight();
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

  const setSidebarWidth = (value) => {
    const width = Math.max(minimumWidth, Math.min(maximumWidth, Math.round(value)));
    root.dataset.sidebarWidth = String(width);
    root.style.setProperty("--ui-sidebar-expanded-width", `${width}px`);
    resizer?.setAttribute("aria-valuenow", String(width));
    return width;
  };

  const saveSidebarWidth = async (width) => {
    if (!sidebar.dataset.appearanceUrl) return;
    try {
      await fetch(sidebar.dataset.appearanceUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        credentials: "same-origin",
        body: JSON.stringify({sidebar_width: String(width)}),
      });
    } catch (_error) {
      // The current width remains useful for this page even if persistence fails.
    }
  };

  if (resizer) {
    resizer.addEventListener("pointerdown", (event) => {
      if (!desktopQuery.matches || root.dataset.layout === "focus") return;
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = sidebar.getBoundingClientRect().width;
      document.body.classList.add("sidebar-resizing");
      resizer.setPointerCapture(event.pointerId);
      const move = (moveEvent) => setSidebarWidth(startWidth + moveEvent.clientX - startX);
      const finish = () => {
        document.body.classList.remove("sidebar-resizing");
        resizer.removeEventListener("pointermove", move);
        resizer.removeEventListener("pointerup", finish);
        resizer.removeEventListener("pointercancel", finish);
        saveSidebarWidth(Number(root.dataset.sidebarWidth));
      };
      resizer.addEventListener("pointermove", move);
      resizer.addEventListener("pointerup", finish);
      resizer.addEventListener("pointercancel", finish);
    });
    resizer.addEventListener("keydown", (event) => {
      if (!desktopQuery.matches || root.dataset.layout === "focus") return;
      const current = Number(root.dataset.sidebarWidth) || 274;
      const next = event.key === "ArrowLeft" ? current - 8
        : event.key === "ArrowRight" ? current + 8
          : event.key === "Home" ? minimumWidth
            : event.key === "End" ? maximumWidth
              : null;
      if (next === null) return;
      event.preventDefault();
      saveSidebarWidth(setSidebarWidth(next));
    });
  }

  updateSidebarGeometry();
  setSidebarWidth(Number(root.dataset.sidebarWidth) || 274);
  window.addEventListener("resize", updateSidebarGeometry);
  window.visualViewport?.addEventListener("resize", updateSidebarGeometry);
  window.visualViewport?.addEventListener("scroll", updateSidebarGeometry);
  if (window.ResizeObserver && topbar) {
    new ResizeObserver(updateSidebarGeometry).observe(topbar);
  }

  if (desktopQuery.matches && localStorage.getItem("twn-sidebar-collapsed") === "1") {
    document.body.classList.add("sidebar-collapsed");
  }

  const initiallyActive = root.dataset.layout === "focus" && desktopQuery.matches
    ? null
    : categoryPanels.find((panel) => panel.dataset.navActive === "true");
  showPanel(initiallyActive?.dataset.navPanel || "");
  let renderedLayout = root.dataset.layout;
  window.addEventListener("themechange", () => {
    const previousLayout = renderedLayout;
    renderedLayout = root.dataset.layout;
    if (renderedLayout === previousLayout) return;
    if (renderedLayout === "focus" && desktopQuery.matches && activePanel) {
      showPanel("");
    } else if (previousLayout === "focus" && !activePanel) {
      const currentToolPanel = categoryPanels.find((panel) => panel.dataset.navActive === "true");
      showPanel(currentToolPanel?.dataset.navPanel || "");
    }
  });

  button.addEventListener("click", toggle);
  sidebar.addEventListener("click", (event) => {
    if (!desktopQuery.matches && event.target.closest("a")) {
      document.body.classList.remove("sidebar-open");
      applyState();
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (!sidebar.contains(event.target)) closeFocusPanel();
  });
  sidebar.addEventListener("focusout", (event) => {
    if (event.relatedTarget && sidebar.contains(event.relatedTarget)) return;
    window.requestAnimationFrame(() => {
      if (!sidebar.matches(":hover") && !sidebar.contains(document.activeElement)) {
        closeFocusPanel();
      }
    });
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
    if (event.key !== "Escape") return;
    if (searchInput?.value) {
      clearSearch();
    } else if (activePanel) {
      showPanel("", {focus: true});
    } else {
      document.body.classList.remove("sidebar-open");
      applyState();
    }
  });

  applyState();
})();
