(() => {
  const controllers = new WeakMap();

  function create(root) {
    if (!root) return null;
    if (root.twnToolWorkspaceController) return root.twnToolWorkspaceController;
    if (controllers.has(root)) return controllers.get(root);

    const settings = root.querySelector("[data-tool-settings-panel]");
    const runbar = root.querySelector("[data-tool-runbar]");
    const results = root.querySelector("[data-tool-results-anchor]");
    const openButtons = [...root.querySelectorAll("[data-tool-settings-open]")];
    const closeButtons = [...root.querySelectorAll("[data-tool-settings-close]")];
    let returnFocus = null;

    if (!settings || !runbar) return null;

    const inResultsState = () => root.dataset.toolState === "results";

    const sync = () => {
      const resultsState = inResultsState();
      const settingsOpen = resultsState && root.dataset.settingsOpen === "true";
      runbar.hidden = !resultsState;
      settings.hidden = resultsState && !settingsOpen;
      settings.classList.toggle("is-drawer", settingsOpen);
      if (settingsOpen) {
        settings.setAttribute("role", "dialog");
        settings.setAttribute("aria-modal", "true");
      } else {
        settings.removeAttribute("role");
        settings.removeAttribute("aria-modal");
      }
      closeButtons.forEach((button) => {
        button.hidden = !settingsOpen;
      });
      openButtons.forEach((button) => {
        button.setAttribute("aria-expanded", String(settingsOpen));
      });
      root.classList.toggle("settings-open", settingsOpen);
      document.body.classList.toggle(
        "tool-settings-visible",
        Boolean(document.querySelector('[data-tool-workspace][data-settings-open="true"]')),
      );
    };

    const closeSettings = ({restoreFocus = true} = {}) => {
      if (!inResultsState()) return;
      delete root.dataset.settingsOpen;
      sync();
      if (restoreFocus && returnFocus?.isConnected) returnFocus.focus();
    };

    const openSettings = (trigger) => {
      if (!inResultsState()) return;
      returnFocus = trigger || document.activeElement;
      root.dataset.settingsOpen = "true";
      sync();
      window.requestAnimationFrame(() => {
        const firstField = settings.querySelector("input:not([type='hidden']), textarea, select, button:not([hidden])");
        firstField?.focus({preventScroll: true});
      });
    };

    const setState = (state, {focusResults = false} = {}) => {
      root.dataset.toolState = state === "results" ? "results" : "setup";
      delete root.dataset.settingsOpen;
      sync();
      if (focusResults && root.dataset.toolState === "results") {
        window.requestAnimationFrame(() => {
          (results || runbar).scrollIntoView({behavior: "smooth", block: "start"});
          results?.focus({preventScroll: true});
        });
      }
    };

    openButtons.forEach((button) => {
      button.addEventListener("click", () => openSettings(button));
    });
    closeButtons.forEach((button) => {
      button.addEventListener("click", () => closeSettings());
    });
    root.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && root.dataset.settingsOpen === "true") {
        event.preventDefault();
        closeSettings();
        return;
      }
      if (event.key !== "Tab" || root.dataset.settingsOpen !== "true") return;
      const focusable = [...settings.querySelectorAll(
        "a[href], button:not([disabled]):not([hidden]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex='-1'])",
      )].filter((element) => element.getClientRects().length);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });

    const controller = {closeSettings, openSettings, setState, sync};
    controllers.set(root, controller);
    root.twnToolWorkspaceController = controller;
    sync();
    if (inResultsState()) {
      window.requestAnimationFrame(() => {
        (results || runbar).scrollIntoView({behavior: "smooth", block: "start"});
        results?.focus({preventScroll: true});
      });
    }
    return controller;
  }

  window.TwnToolWorkspace = {
    create,
    forElement(element) {
      return create(element?.closest?.("[data-tool-workspace]") || element);
    },
  };

  document.querySelectorAll("[data-tool-workspace]").forEach(create);
})();
