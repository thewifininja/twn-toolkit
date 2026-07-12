(() => {
  const form = document.querySelector("[data-sftp-form]");
  if (!form) return;
  const destination = form.querySelector("[data-sftp-destination]");
  const protocol = form.querySelector("[data-transfer-protocol]");
  const port = form.querySelector("[data-transfer-port]");
  const hostKeyOption = form.querySelector("[data-ssh-host-key-option]");
  let previousProtocol = protocol?.value;
  const update = () => {
    const selected = form.querySelector("[data-sftp-output-mode]:checked");
    if (destination) destination.hidden = selected?.value !== "datastore";
  };
  for (const input of form.querySelectorAll("[data-sftp-output-mode]")) {
    input.addEventListener("change", update);
  }
  update();
  const updateProtocol = () => {
    if (port && protocol) {
      const previousDefault = previousProtocol === "ftp" ? "21" : "22";
      if (!port.value || port.value === previousDefault) port.value = protocol.value === "ftp" ? "21" : "22";
      previousProtocol = protocol.value;
    }
    if (hostKeyOption && protocol) hostKeyOption.hidden = protocol.value === "ftp";
  };
  protocol?.addEventListener("change", updateProtocol);
  updateProtocol();
})();
