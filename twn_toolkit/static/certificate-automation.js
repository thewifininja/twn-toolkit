(() => {
  const updateKeyFields = (form) => {
    const selected = form.querySelector('input[name="key_source"]:checked');
    const upload = form.querySelector(".certificate-key-upload");
    if (upload) upload.hidden = selected?.value !== "upload";
  };

  document.querySelectorAll(".certificate-request-form").forEach((form) => {
    form.querySelectorAll('input[name="key_source"]').forEach((input) => {
      input.addEventListener("change", () => updateKeyFields(form));
    });
    updateKeyFields(form);
  });

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
})();
