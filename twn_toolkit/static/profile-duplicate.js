(() => {
  const currentUrl = new URL(window.location.href);
  const duplicatedName = currentUrl.searchParams.get("duplicated");
  if (duplicatedName) {
    const matchingOption = [...document.querySelectorAll("select option")].find(
      (option) => option.value === duplicatedName,
    );
    if (matchingOption) {
      const select = matchingOption.closest("select");
      select.value = duplicatedName;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    const main = document.querySelector("main.shell");
    if (main) {
      const messages = document.createElement("section");
      messages.className = "messages";
      const message = document.createElement("div");
      message.className = "message success";
      message.textContent = `Duplicated as ${duplicatedName}.`;
      messages.append(message);
      main.prepend(messages);
    }
    currentUrl.searchParams.delete("duplicated");
    window.history.replaceState({}, "", currentUrl);
  }

  const selectedName = (button) => {
    if (button.dataset.profileName) return button.dataset.profileName;
    const selector = button.dataset.profileSelect;
    return selector ? document.querySelector(selector)?.value?.trim() || "" : "";
  };

  document.querySelectorAll("[data-profile-duplicate]").forEach((button) => {
    button.addEventListener("click", async () => {
      const name = selectedName(button);
      if (!name) {
        window.alert("Select a saved item to duplicate.");
        return;
      }
      const originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = "Duplicating…";
      try {
        const body = new URLSearchParams({ name });
        const response = await fetch(button.dataset.profileDuplicate, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || "The item could not be duplicated.");
        const copiedName = payload.profile?.name || "the new copy";
        const url = new URL(window.location.href);
        url.searchParams.set("duplicated", copiedName);
        window.location.assign(url);
      } catch (error) {
        window.alert(error.message);
        button.disabled = false;
        button.textContent = originalLabel;
      }
    });
  });
})();
