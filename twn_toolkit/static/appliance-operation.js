(() => {
  document.querySelectorAll("form[data-appliance-operation]").forEach((form) => {
    const notice = document.createElement("div");
    notice.className = "operation-status";
    notice.hidden = true;
    notice.setAttribute("role", "status");
    notice.setAttribute("aria-live", "polite");
    notice.setAttribute("aria-atomic", "true");
    const title = document.createElement("strong");
    const detail = document.createElement("p");
    notice.append(title, detail);
    form.append(notice);
    let submitted = false;
    let timer;
    const show = (state, heading, message) => {
      notice.hidden = false;
      notice.dataset.operationState = state;
      title.textContent = heading;
      detail.textContent = message;
    };
    form.addEventListener("submit", (event) => {
      if (event.defaultPrevented) return;
      if (submitted) { event.preventDefault(); return; }
      submitted = true;
      // aria-disabled retains successful form controls, including the submitter.
      form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach((button) => {
        button.setAttribute("aria-disabled", "true");
      });
      show("submitted", "Changes submitted", "Waiting for the appliance response. Do not submit these changes again.");
      timer = window.setTimeout(() => {
        show("uncertain", "Still waiting for a result", "A delayed response does not confirm failure. If the connection is lost, check the appliance before building another preview. Leaving this page does not cancel changes.");
      }, 30000);
    });
    window.addEventListener("pagehide", () => window.clearTimeout(timer));
    window.addEventListener("pageshow", (event) => {
      if (!event.persisted || !submitted) return;
      show("uncertain", "This preview was already submitted", "Check the result and the appliance, then build a fresh preview. This page will not submit the same changes again.");
    });
  });
})();
