(() => {
  let sequence = 0;
  let openControl = null;
  const controls = new WeakMap();

  window.TwnSelectControls = {
    sync(select) {
      controls.get(select)?.sync();
    },
  };

  const optionLabel = (option) => option?.label || option?.textContent?.trim() || "Select an option";

  const controlLabel = (select) => {
    const explicit = select.getAttribute("aria-label");
    if (explicit) return explicit;
    const label = select.labels?.[0];
    if (!label) return select.name || select.id || "Select an option";
    const clone = label.cloneNode(true);
    clone.querySelectorAll("select, input, textarea, button").forEach((control) => control.remove());
    return clone.textContent.replace(/\s+/g, " ").trim() || select.name || select.id || "Select an option";
  };

  const enhance = (select) => {
    if (
      select.dataset.toolkitSelectEnhanced === "true"
      || select.multiple
      || Number(select.getAttribute("size") || 1) > 1
      || select.hasAttribute("data-native-select")
    ) return;

    select.dataset.toolkitSelectEnhanced = "true";
    const id = `toolkit-select-${++sequence}`;
    const label = controlLabel(select);
    const wrapper = document.createElement("span");
    const trigger = document.createElement("button");
    const value = document.createElement("span");
    const chevron = document.createElement("span");
    const menu = document.createElement("div");
    let activeIndex = -1;
    let typeahead = "";
    let typeaheadTimer = null;
    let lookupSerial = 0;
    let lookupAbort = null;
    let lookupTimer = null;
    let lookupPanel = null;

    const openLookup = () => {
      menu.replaceChildren();
      menu.setAttribute("role", "dialog");
      trigger.setAttribute("aria-haspopup", "dialog");
      const search = document.createElement("input");
      search.type = "search";
      search.maxLength = 200;
      search.autocomplete = "off";
      search.setAttribute("aria-label", `Search ${label.toLocaleLowerCase()}`);
      search.placeholder = select.dataset.lookupPlaceholder || "Search…";
      const results = document.createElement("div");
      results.setAttribute("role", "listbox");
      results.setAttribute("aria-label", `${label} results`);
      const status = document.createElement("p");
      status.className = "field-note";
      status.setAttribute("role", "status");
      const navigation = document.createElement("div");
      navigation.className = "button-row";
      const previous = document.createElement("button"), next = document.createElement("button");
      for (const button of [previous, next]) { button.type = "button"; button.className = "secondary compact"; }
      previous.textContent = "Previous"; next.textContent = "Next";
      navigation.append(previous, next);
      menu.append(search, status, results, navigation);
      lookupPanel = {search, results};
      let page = 1;
      const load = async (requestedPage = 1) => {
        clearTimeout(lookupTimer);
        lookupAbort?.abort();
        const abort = new AbortController(); lookupAbort = abort;
        const serial = ++lookupSerial;
        results.replaceChildren(); previous.disabled = next.disabled = true;
        status.textContent = "Searching…";
        try {
          const found = await select.twnLookup({query: search.value.trim(), page: requestedPage, signal: abort.signal});
          if (serial !== lookupSerial || menu.hidden) return;
          page = found.page;
          for (const item of found.options) {
            const button = document.createElement("button");
            button.type = "button"; button.className = "toolkit-select-option";
            button.setAttribute("role", "option");
            button.setAttribute("aria-selected", String(select.value === item.id));
            button.textContent = item.label;
            button.addEventListener("click", () => {
              if (select.disabled) return;
              select.twnLookupSelected?.(item);
              const previousValue = select.value;
              select.querySelectorAll('option[data-lookup-choice]').forEach((option) => { if (option.value !== item.id) option.remove(); });
              let option = [...select.options].find((option) => option.value === item.id);
              if (!option) { option = new Option(item.label, item.id); option.dataset.lookupChoice = "true"; select.add(option); }
              const changed = previousValue !== item.id;
              select.value = item.id; sync(); close({restoreFocus: true});
              if (changed) {
                select.dispatchEvent(new Event("input", {bubbles: true}));
                select.dispatchEvent(new Event("change", {bubbles: true}));
              }
            });
            results.append(button);
          }
          status.textContent = found.options.length ? `Page ${page} of ${found.pages}` : "No available matches on this page.";
          previous.disabled = page <= 1; next.disabled = page >= found.pages;
          navigation.hidden = found.pages <= 1;
          position();
        } catch (error) {
          if (serial === lookupSerial && !abort.signal.aborted) status.textContent = error.message || "Choices could not be loaded.";
        }
      };
      search.addEventListener("input", () => {
        ++lookupSerial; lookupAbort?.abort(); clearTimeout(lookupTimer);
        results.replaceChildren(); status.textContent = "Searching…";
        previous.disabled = next.disabled = true;
        lookupTimer = setTimeout(() => load(1), 250);
      });
      search.addEventListener("keydown", (event) => {
        if (event.key === "Enter") { event.preventDefault(); load(1); }
      });
      previous.addEventListener("click", () => load(page - 1));
      next.addEventListener("click", () => load(page + 1));
      load(); search.focus();
    };

    wrapper.className = "toolkit-select";
    trigger.className = "toolkit-select-trigger";
    trigger.type = "button";
    trigger.id = `${id}-trigger`;
    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    trigger.setAttribute("aria-controls", `${id}-menu`);
    trigger.setAttribute("aria-label", label);
    value.className = "toolkit-select-value";
    chevron.className = "toolkit-select-chevron";
    chevron.setAttribute("aria-hidden", "true");
    trigger.append(value, chevron);

    menu.className = "toolkit-select-menu";
    menu.id = `${id}-menu`;
    menu.hidden = true;
    menu.setAttribute("role", "listbox");
    menu.setAttribute("aria-label", `${label} options`);

    select.parentNode.insertBefore(wrapper, select);
    wrapper.append(select, trigger);
    (select.closest("dialog, [popover]") || document.body).append(menu);
    select.classList.add("toolkit-select-native");
    select.tabIndex = -1;
    select.setAttribute("aria-hidden", "true");

    const menuOptions = () => [...menu.querySelectorAll("[data-toolkit-select-index]")];

    const setActive = (index, {scroll = true} = {}) => {
      const options = [...select.options];
      if (!options.length) return;
      const next = Math.max(0, Math.min(index, options.length - 1));
      activeIndex = next;
      menuOptions().forEach((button) => {
        const isActive = Number(button.dataset.toolkitSelectIndex) === activeIndex;
        button.classList.toggle("is-active", isActive);
      });
      const active = menu.querySelector(`[data-toolkit-select-index="${activeIndex}"]`);
      if (active) {
        trigger.setAttribute("aria-activedescendant", active.id);
        if (scroll) active.scrollIntoView({block: "nearest"});
      }
    };

    const moveActive = (direction) => {
      const options = [...select.options];
      if (!options.length) return;
      let next = activeIndex < 0 ? select.selectedIndex : activeIndex;
      for (let attempt = 0; attempt < options.length; attempt += 1) {
        next = (next + direction + options.length) % options.length;
        if (!options[next].disabled && !options[next].parentElement?.disabled) {
          setActive(next);
          return;
        }
      }
    };

    const rebuild = () => {
      menu.replaceChildren();
      let optionIndex = 0;
      [...select.children].forEach((child) => {
        if (child instanceof HTMLOptGroupElement) {
          const group = document.createElement("div");
          group.className = "toolkit-select-group";
          group.setAttribute("role", "group");
          group.setAttribute("aria-label", child.label);
          const heading = document.createElement("div");
          heading.className = "toolkit-select-group-label";
          heading.textContent = child.label;
          group.append(heading);
          [...child.children].forEach((option) => {
            group.append(buildOption(option, optionIndex));
            optionIndex += 1;
          });
          menu.append(group);
          return;
        }
        if (child instanceof HTMLOptionElement) {
          menu.append(buildOption(child, optionIndex));
          optionIndex += 1;
        }
      });
    };

    const close = ({restoreFocus = false} = {}) => {
      if (menu.hidden) return;
      ++lookupSerial; lookupAbort?.abort(); clearTimeout(lookupTimer); lookupPanel = null;
      menu.hidden = true;
      wrapper.classList.remove("is-open");
      trigger.setAttribute("aria-expanded", "false");
      trigger.removeAttribute("aria-activedescendant");
      if (openControl?.close === close) openControl = null;
      if (restoreFocus) trigger.focus();
    };

    const position = () => {
      if (menu.hidden) return;
      const rect = trigger.getBoundingClientRect();
      const margin = 8;
      const gap = 4;
      const viewportWidth = document.documentElement.clientWidth;
      const viewportHeight = document.documentElement.clientHeight;
      const width = Math.min(
        Math.max(rect.width, Math.min(260, viewportWidth - margin * 2)),
        viewportWidth - margin * 2,
      );
      const left = Math.max(margin, Math.min(rect.left, viewportWidth - width - margin));
      const below = viewportHeight - rect.bottom - margin - gap;
      const above = rect.top - margin - gap;
      const desiredHeight = Math.min(menu.scrollHeight, 340);
      const opensUp = below < Math.min(desiredHeight, 180) && above > below;
      const availableHeight = Math.max(120, opensUp ? above : below);

      menu.style.left = `${Math.round(left)}px`;
      menu.style.width = `${Math.round(width)}px`;
      menu.style.maxHeight = `${Math.round(Math.min(340, availableHeight))}px`;
      menu.style.top = opensUp
        ? `${Math.round(Math.max(margin, rect.top - Math.min(desiredHeight, availableHeight) - gap))}px`
        : `${Math.round(rect.bottom + gap)}px`;
      menu.classList.toggle("opens-up", opensUp);
    };

    const open = () => {
      if (trigger.disabled) return;
      if (openControl && openControl.close !== close) openControl.close();
      if (!select.twnLookup) rebuild();
      menu.hidden = false;
      wrapper.classList.add("is-open");
      trigger.setAttribute("aria-expanded", "true");
      activeIndex = select.selectedIndex >= 0 ? select.selectedIndex : 0;
      openControl = {close, menu, trigger, position};
      position();
      if (select.twnLookup) openLookup();
      else setActive(activeIndex);
    };

    const choose = (index) => {
      const option = select.options[index];
      if (!option || option.disabled || option.parentElement?.disabled) return;
      const changed = select.selectedIndex !== index;
      select.selectedIndex = index;
      sync();
      close({restoreFocus: true});
      if (changed) {
        select.dispatchEvent(new Event("input", {bubbles: true}));
        select.dispatchEvent(new Event("change", {bubbles: true}));
      }
    };

    function buildOption(option, index) {
      const button = document.createElement("button");
      const disabled = option.disabled || option.parentElement?.disabled;
      button.className = "toolkit-select-option";
      button.type = "button";
      button.id = `${id}-option-${index}`;
      button.dataset.toolkitSelectIndex = String(index);
      button.setAttribute("role", "option");
      button.setAttribute("aria-selected", option.selected ? "true" : "false");
      button.disabled = disabled;
      button.textContent = optionLabel(option);
      button.addEventListener("mousedown", (event) => event.preventDefault());
      button.addEventListener("click", () => choose(index));
      return button;
    }

    const sync = () => {
      const option = select.selectedOptions[0] || select.options[0];
      value.textContent = optionLabel(option);
      value.classList.toggle("is-placeholder", !select.value);
      trigger.disabled = select.disabled;
      wrapper.hidden = select.hidden;
      if (select.disabled) close();
      if (!menu.hidden && !lookupPanel) {
        rebuild();
        setActive(select.selectedIndex, {scroll: false});
        position();
      }
    };

    const handleKey = (event) => {
      if (lookupPanel) {
        if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close({restoreFocus: true}); }
        else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
          event.preventDefault();
          const options = [...lookupPanel.results.querySelectorAll("button")];
          const index = options.indexOf(document.activeElement);
          const next = index + (event.key === "ArrowDown" ? 1 : -1);
          if (next < 0) lookupPanel.search.focus();
          else options[Math.min(next, options.length - 1)]?.focus();
        }
        return;
      }
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (menu.hidden) open();
        else moveActive(event.key === "ArrowDown" ? 1 : -1);
        return;
      }
      if (event.key === "Home" || event.key === "End") {
        if (menu.hidden) return;
        event.preventDefault();
        const options = [...select.options];
        const indexes = options
          .map((option, index) => ({option, index}))
          .filter(({option}) => !option.disabled && !option.parentElement?.disabled);
        const target = event.key === "Home" ? indexes[0] : indexes[indexes.length - 1];
        if (target) setActive(target.index);
        return;
      }
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        if (menu.hidden) open();
        else choose(activeIndex);
        return;
      }
      if (event.key === "Escape") {
        if (menu.hidden) return;
        event.preventDefault();
        close({restoreFocus: true});
        return;
      }
      if (event.key === "Tab") {
        close();
        return;
      }
      if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
        typeahead += event.key.toLocaleLowerCase();
        window.clearTimeout(typeaheadTimer);
        typeaheadTimer = window.setTimeout(() => { typeahead = ""; }, 700);
        const options = [...select.options];
        const match = options.findIndex((option) => (
          !option.disabled
          && !option.parentElement?.disabled
          && optionLabel(option).toLocaleLowerCase().startsWith(typeahead)
        ));
        if (match >= 0) {
          event.preventDefault();
          if (menu.hidden) open();
          setActive(match);
        }
      }
    };

    trigger.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (menu.hidden) open();
      else close({restoreFocus: true});
    });
    trigger.addEventListener("keydown", handleKey);
    menu.addEventListener("keydown", handleKey);
    select.addEventListener("change", sync);
    select.addEventListener("input", sync);
    select.addEventListener("invalid", (event) => {
      event.preventDefault();
      trigger.focus();
      open();
    });
    select.form?.addEventListener("reset", () => queueMicrotask(sync));

    new MutationObserver(sync).observe(select, {
      attributes: true,
      attributeFilter: ["disabled", "hidden", "label", "selected"],
      childList: true,
      subtree: true,
    });

    controls.set(select, {sync});
    sync();
    if (select.autofocus) queueMicrotask(() => trigger.focus());
  };

  const enhanceWithin = (root) => {
    if (root instanceof HTMLSelectElement) enhance(root);
    root.querySelectorAll?.("select").forEach(enhance);
  };

  document.addEventListener("click", (event) => {
    if (!openControl) return;
    if (openControl.menu.contains(event.target) || openControl.trigger.contains(event.target)) return;
    openControl.close();
  });
  window.addEventListener("resize", () => openControl?.position());
  window.addEventListener("scroll", (event) => {
    if (openControl && !openControl.menu.contains(event.target)) openControl.close();
  }, true);

  enhanceWithin(document);
  new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node instanceof Element) enhanceWithin(node);
      });
    });
  }).observe(document.body, {childList: true, subtree: true});
})();
