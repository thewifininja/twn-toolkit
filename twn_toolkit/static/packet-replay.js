(() => {
  const picker = document.querySelector(".packet-replay-source-picker");
  if (!picker) return;

  const datastore = picker.querySelector('select[name="datastore_capture"]');
  const upload = picker.querySelector('input[name="packet_file"]');
  const packetHex = picker.querySelector('textarea[name="packet_hex"]');
  if (!datastore || !upload || !packetHex) return;

  datastore.addEventListener("change", () => {
    if (!datastore.value) return;
    upload.value = "";
    packetHex.value = "";
  });

  upload.addEventListener("change", () => {
    if (!upload.files?.length) return;
    datastore.value = "";
    packetHex.value = "";
  });

  packetHex.addEventListener("input", () => {
    if (!packetHex.value.trim()) return;
    datastore.value = "";
    upload.value = "";
  });
})();
