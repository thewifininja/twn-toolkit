(function () {
  const forms = document.querySelectorAll(".snmp-profile-form");
  if (!forms.length) return;

  forms.forEach((form) => {
    const deleteButton = form.querySelector(".snmp-delete-profile");
    const status = form.querySelector(".snmp-form-status");

    if (form.dataset.kind === "credentials") {
      form.elements.version.addEventListener("change", () => updateCredentialFields(form));
      form.elements.security_level.addEventListener("change", () => updateCredentialFields(form));
      updateCredentialFields(form);
    }
  });

  function updateCredentialFields(form) {
    const isV3 = form.elements.version.value === "v3";
    const level = form.elements.security_level.value;
    form.querySelector(".snmp-v2-fields").hidden = isV3;
    form.querySelector(".snmp-v3-fields").hidden = !isV3;
    form.querySelector(".snmp-auth-fields").hidden = !isV3 || level === "noauthnopriv";
    form.querySelector(".snmp-priv-fields").hidden = !isV3 || level !== "authpriv";
  }
})();
