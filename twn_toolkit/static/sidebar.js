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
  const favoritesSection = sidebar?.querySelector("[data-nav-favorites]");
  const categoryAccordions = Array.from(sidebar?.querySelectorAll("details[data-nav-category]") || []);
  const subgroupAccordions = Array.from(sidebar?.querySelectorAll("details[data-nav-subgroup]") || []);
  const resizer = sidebar?.querySelector(".sidebar-resizer");
  const root = document.documentElement;
  // Layout mode is a viewport decision. Chromium on touch-capable Linux
  // systems can report a coarse/non-hover primary pointer even when a mouse or
  // touchpad is in use, which must not turn a wide workspace into an overlay.
  const desktopQuery = window.matchMedia("(min-width: 901px)");
  const minimumWidth = 220;
  const maximumWidth = 400;
  const categoryStorageKey = "twn-sidebar-category";
  const favoritesStorageKey = "twn-sidebar-favorites-open";
  let syncingAccordions = false;

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

  const searchMatches = (value) => {
    const query = normalizeSearch(value.trim());
    if (!query) return [];
    return searchableTools.filter((tool) => tool.search.includes(query));
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

  const renderSearch = () => {
    if (!scroll || !searchInput || !searchResults || !searchEmpty) return;
    const searching = Boolean(searchInput.value.trim());
    scroll.classList.toggle("searching", searching);
    searchResults.replaceChildren();
    searchResults.hidden = !searching;
    searchEmpty.hidden = true;
    if (!searching) return;

    const matches = searchMatches(searchInput.value);
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

  const subgroupStorageKey = (category) => (
    `twn-sidebar-subgroup:${category?.dataset.navCategory || "tools"}`
  );

  const openCategory = (category, {persist = true} = {}) => {
    if (!category) return;
    syncingAccordions = true;
    categoryAccordions.forEach((candidate) => {
      candidate.open = candidate === category;
    });
    syncingAccordions = false;
    if (persist) localStorage.setItem(categoryStorageKey, category.dataset.navCategory || "");
  };

  const openSubgroup = (subgroup, {persist = true} = {}) => {
    const category = subgroup?.closest("details[data-nav-category]");
    if (!subgroup || !category) return;
    syncingAccordions = true;
    category.querySelectorAll("details[data-nav-subgroup]").forEach((candidate) => {
      candidate.open = candidate === subgroup;
    });
    syncingAccordions = false;
    if (persist) {
      localStorage.setItem(
        subgroupStorageKey(category),
        subgroup.dataset.navSubgroup || "",
      );
    }
  };

  categoryAccordions.forEach((category) => {
    category.addEventListener("toggle", () => {
      if (syncingAccordions) return;
      if (category.open) {
        openCategory(category);
      } else if (localStorage.getItem(categoryStorageKey) === category.dataset.navCategory) {
        localStorage.removeItem(categoryStorageKey);
      }
    });
  });

  subgroupAccordions.forEach((subgroup) => {
    subgroup.addEventListener("toggle", () => {
      if (syncingAccordions) return;
      const category = subgroup.closest("details[data-nav-category]");
      if (!category) return;
      if (subgroup.open) {
        openSubgroup(subgroup);
      } else if (
        localStorage.getItem(subgroupStorageKey(category)) === subgroup.dataset.navSubgroup
      ) {
        localStorage.removeItem(subgroupStorageKey(category));
      }
    });
  });

  if (favoritesSection) {
    const storedFavoritesState = localStorage.getItem(favoritesStorageKey);
    if (storedFavoritesState !== null) {
      favoritesSection.open = storedFavoritesState === "1";
    }
    favoritesSection.addEventListener("toggle", () => {
      localStorage.setItem(favoritesStorageKey, favoritesSection.open ? "1" : "0");
    });
  }

  const activeCategory = categoryAccordions.find(
    (category) => category.dataset.navActive === "true",
  );
  const storedCategory = categoryAccordions.find(
    (category) => category.dataset.navCategory === localStorage.getItem(categoryStorageKey),
  );
  if (activeCategory) {
    openCategory(activeCategory);
  } else if (storedCategory) {
    openCategory(storedCategory, {persist: false});
  } else {
    categoryAccordions.forEach((category) => { category.open = false; });
  }

  categoryAccordions.forEach((category) => {
    const subgroups = Array.from(category.querySelectorAll("details[data-nav-subgroup]"));
    const activeSubgroup = subgroups.find(
      (subgroup) => subgroup.dataset.navActive === "true",
    );
    const storedSubgroup = subgroups.find(
      (subgroup) => subgroup.dataset.navSubgroup === localStorage.getItem(subgroupStorageKey(category)),
    );
    if (activeSubgroup) {
      openSubgroup(activeSubgroup);
    } else if (storedSubgroup) {
      openSubgroup(storedSubgroup, {persist: false});
    } else {
      subgroups.forEach((subgroup) => { subgroup.open = false; });
    }
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

  const focusLayoutActive = () => (
    desktopQuery.matches
    && root.dataset.layout === "focus"
    && !document.body.classList.contains("sidebar-collapsed")
  );

  const expandFocusSidebar = () => {
    if (focusLayoutActive()) {
      document.body.classList.add("focus-sidebar-expanded");
    }
  };

  const collapseFocusSidebar = () => {
    document.body.classList.remove("focus-sidebar-expanded");
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
      collapseFocusSidebar();
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

  button.addEventListener("click", toggle);
  sidebar.addEventListener("pointerenter", expandFocusSidebar);
  sidebar.addEventListener("pointerleave", () => {
    if (!sidebar.contains(document.activeElement)) collapseFocusSidebar();
  });
  sidebar.addEventListener("focusin", expandFocusSidebar);
  sidebar.addEventListener("focusout", () => {
    requestAnimationFrame(() => {
      if (!sidebar.matches(":hover") && !sidebar.contains(document.activeElement)) {
        collapseFocusSidebar();
      }
    });
  });
  sidebar.addEventListener("click", (event) => {
    if (!desktopQuery.matches && event.target.closest("a")) {
      document.body.classList.remove("sidebar-open");
      applyState();
    }
  });
  desktopQuery.addEventListener("change", () => {
    document.body.classList.remove("sidebar-open");
    collapseFocusSidebar();
    if (!desktopQuery.matches) {
      document.body.classList.remove("sidebar-collapsed");
    } else if (localStorage.getItem("twn-sidebar-collapsed") === "1") {
      document.body.classList.add("sidebar-collapsed");
    }
    applyState();
  });

  new MutationObserver(() => {
    if (root.dataset.layout !== "focus") collapseFocusSidebar();
  }).observe(root, {attributes: true, attributeFilter: ["data-layout"]});

  document.addEventListener("pointerdown", (event) => {
    if (!sidebar.contains(event.target)) collapseFocusSidebar();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (searchInput?.value) {
      clearSearch();
    } else if (document.body.classList.contains("focus-sidebar-expanded")) {
      collapseFocusSidebar();
    } else {
      document.body.classList.remove("sidebar-open");
      applyState();
    }
  });

  applyState();
})();
