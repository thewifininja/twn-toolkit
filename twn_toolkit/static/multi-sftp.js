(() => {
  const form = document.querySelector("[data-sftp-form]");
  if (!form) return;
  const destination = form.querySelector("[data-sftp-destination]");
  const protocol = form.querySelector("[data-transfer-protocol]");
  const port = form.querySelector("[data-transfer-port]");
  const sshOptions = form.querySelectorAll("[data-ssh-host-key-option]");
  const downloadToken = form.querySelector("[data-download-token]");
  let previousProtocol = protocol?.value;
  let downloadPoll = 0;
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
    if (protocol) {
      for (const option of sshOptions) option.hidden = protocol.value === "ftp";
    }
  };
  protocol?.addEventListener("change", updateProtocol);
  updateProtocol();

  form.addEventListener("submit", () => {
    const outputMode = form.querySelector("[data-sftp-output-mode]:checked")?.value;
    if (outputMode !== "download" || !downloadToken) return;
    const token = window.crypto?.randomUUID?.()
      || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const cookieName = `twn_download_ready_${token}`;
    downloadToken.value = token;
    window.clearInterval(downloadPoll);
    downloadPoll = window.setInterval(() => {
      const complete = document.cookie.split("; ").some((item) => item.startsWith(`${cookieName}=`));
      if (!complete) return;
      window.clearInterval(downloadPoll);
      downloadPoll = 0;
      document.cookie = `${cookieName}=; Max-Age=0; Path=/; SameSite=Lax`;
      window.toolkitLoading?.hide();
      const resultsUrl = new URL(form.action || window.location.href, window.location.href);
      resultsUrl.searchParams.set("download_result", token);
      window.location.assign(resultsUrl);
    }, 250);
  });
})();
