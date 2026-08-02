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
  const desktopQuery = window.matchMedia(
    "(min-width: 901px) and (hover: hover) and (pointer: fine)",
  );

  if (!button || !sidebar) return;

  const normalizeSearch = (value) => value.toLocaleLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "");

  const searchableTools = (() => {
    const tools = new Map();
    sidebar.querySelectorAll(".side-nav-section a[href]").forEach((link) => {
      const label = link.querySelector(".side-nav-label")?.textContent?.trim();
      const section = link.closest(".side-nav-section");
      const category = section?.querySelector(":scope > summary .side-nav-label")?.textContent?.trim() || "Tools";
      if (!label || category === "Favorites" || tools.has(link.href)) return;
      const subsection = link.closest(".side-nav-subsection")
        ?.querySelector(":scope > summary .side-nav-subsection-title > span:last-child")
        ?.textContent?.trim() || "";
      const parent = link.closest(".side-nav-tree > li")?.querySelector(":scope > .side-nav-parent-row .side-nav-label")?.textContent?.trim() || "";
      const path = [category, parent, subsection].filter((part, index, values) => part && values.indexOf(part) === index).join(" › ");
      tools.set(link.href, {
        href: link.href,
        label,
        icon: link.querySelector(".side-nav-icon")?.textContent?.trim() || "•",
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
    link.title = `${tool.label} — ${tool.path}`;

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

  searchInput?.addEventListener("input", renderSearch);
  searchInput?.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && searchInput.value) {
      event.stopPropagation();
      searchInput.value = "";
      renderSearch();
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
    document.documentElement.style.setProperty(
      "--topbar-height",
      `${Math.ceil(topbar.getBoundingClientRect().height)}px`,
    );
  };

  const updateMobileViewportHeight = () => {
    const viewportHeight = window.visualViewport?.height || window.innerHeight;
    document.documentElement.style.setProperty(
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

  updateSidebarGeometry();
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
