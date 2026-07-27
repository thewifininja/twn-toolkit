(() => {
  const protocol = document.querySelector("[data-iperf-protocol]");
  const udpField = document.querySelector("[data-iperf-udp-field]");
  const serverPort = document.querySelector("[name='server_port']");
  const serverCommand = document.querySelector(".iperf-server-callout code");

  const updateProtocol = () => {
    if (!protocol || !udpField) return;
    const udp = protocol.value === "udp";
    udpField.hidden = !udp;
    const input = udpField.querySelector("input");
    if (input) input.required = udp;
  };

  const updateServerCommand = () => {
    if (!serverPort || !serverCommand) return;
    serverCommand.textContent = `iperf3 -c <toolkit-address> -p ${serverPort.value || "5201"}`;
  };

  protocol?.addEventListener("change", updateProtocol);
  serverPort?.addEventListener("input", updateServerCommand);
  updateProtocol();
  updateServerCommand();
})();
