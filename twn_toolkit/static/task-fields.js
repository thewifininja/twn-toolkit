(function () {
  const form = document.getElementById("task-form");
  const loadButton = document.getElementById("load-fields");
  const applyButton = document.getElementById("apply-fields");
  const fieldList = document.getElementById("field-list");
  const fieldsInput = document.getElementById("fields-input");
  const endpointInput = document.getElementById("endpoint-template");
  const status = document.getElementById("field-status");
  const builder = document.querySelector("[data-fields-url]");
  const fetchButton = document.getElementById("fetch-data");
  const preview = document.getElementById("data-preview");
  const previewStatus = document.getElementById("preview-status");
  const previewTable = document.getElementById("preview-table");

  if (!form || !loadButton || !applyButton || !fieldList || !fieldsInput || !endpointInput || !status || !builder ||
      !fetchButton || !preview || !previewStatus || !previewTable) {
    return;
  }

  let draggedItem = null;

  loadButton.addEventListener("click", async () => {
    const formData = new FormData(form);
    loadButton.disabled = true;
    applyButton.disabled = true;
    status.textContent = "Loading fields...";
    fieldList.innerHTML = "";

    try {
      const response = await fetch(builder.dataset.fieldsUrl, {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to load fields.");
      }
      renderFields(data.fields || []);
      applyButton.disabled = data.fields.length === 0;
      if (data.endpoint_used) {
        endpointInput.value = data.endpoint_used;
      }
      status.textContent = `Loaded ${data.fields.length} fields from ${data.row_count} row(s). Select, reorder, then apply.`;
    } catch (error) {
      status.textContent = error.message;
      fieldList.innerHTML = "";
      applyButton.disabled = true;
    } finally {
      loadButton.disabled = false;
    }
  });

  fieldList.addEventListener("change", () => {
    status.textContent = "Selection changed. Apply when ready.";
  });

  applyButton.addEventListener("click", applySelectedFields);

  fetchButton.addEventListener("click", async () => {
    const formData = new FormData(form);
    fetchButton.disabled = true;
    preview.hidden = false;
    previewStatus.textContent = "Fetching data...";
    clearPreview();

    try {
      const response = await fetch(builder.dataset.previewUrl, {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to fetch data.");
      }
      renderPreview(data.columns || [], data.rows || []);
      if (data.endpoint_used) {
        endpointInput.value = data.endpoint_used;
      }
      previewStatus.textContent = `${data.row_count} row(s) using ${data.endpoint_used}.`;
    } catch (error) {
      previewStatus.textContent = error.message;
    } finally {
      fetchButton.disabled = false;
    }
  });

  fieldList.addEventListener("dragstart", (event) => {
    const row = event.target.closest(".field-item");
    if (!row) {
      return;
    }
    draggedItem = row;
    row.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
  });

  fieldList.addEventListener("dragend", () => {
    if (draggedItem) {
      draggedItem.classList.remove("dragging");
    }
    draggedItem = null;
    status.textContent = "Field order changed. Apply when ready.";
  });

  fieldList.addEventListener("dragover", (event) => {
    event.preventDefault();
    const target = event.target.closest(".field-item");
    if (!draggedItem || !target || target === draggedItem) {
      return;
    }
    const rect = target.getBoundingClientRect();
    const afterTarget = event.clientY > rect.top + rect.height / 2;
    fieldList.insertBefore(draggedItem, afterTarget ? target.nextSibling : target);
  });

  function renderFields(fields) {
    const fragment = document.createDocumentFragment();
    fields.forEach((field) => {
      const item = document.createElement("div");
      item.className = "field-item";
      item.draggable = true;
      item.dataset.field = field.name;

      const dragHandle = document.createElement("span");
      dragHandle.className = "drag-handle";
      dragHandle.textContent = "::";
      dragHandle.title = "Drag to reorder";

      const label = document.createElement("label");
      label.className = "field-check";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = Boolean(field.selected);

      const name = document.createElement("strong");
      name.textContent = field.name;

      label.appendChild(checkbox);
      label.appendChild(name);

      const sample = document.createElement("span");
      sample.className = "field-sample";
      sample.textContent = field.sample === "" || field.sample == null ? "No sample value" : String(field.sample);

      item.appendChild(dragHandle);
      item.appendChild(label);
      item.appendChild(sample);
      fragment.appendChild(item);
    });
    fieldList.appendChild(fragment);
  }

  function applySelectedFields() {
    const selected = Array.from(fieldList.querySelectorAll(".field-item"))
      .filter((item) => item.querySelector("input").checked)
      .map((item) => item.dataset.field);

    if (selected.length === 0) {
      status.textContent = "Select at least one field before applying.";
      return;
    }

    fieldsInput.value = selected.join(", ");
    status.textContent = `Applied ${selected.length} field(s) to the CSV fields above.`;
  }

  function clearPreview() {
    previewTable.querySelector("thead").innerHTML = "";
    previewTable.querySelector("tbody").innerHTML = "";
  }

  function renderPreview(columns, rows) {
    clearPreview();
    const headerRow = document.createElement("tr");
    columns.forEach((column) => {
      const header = document.createElement("th");
      header.scope = "col";
      header.textContent = column;
      headerRow.appendChild(header);
    });
    previewTable.querySelector("thead").appendChild(headerRow);

    const body = document.createDocumentFragment();
    rows.forEach((row) => {
      const tableRow = document.createElement("tr");
      columns.forEach((column) => {
        const cell = document.createElement("td");
        const value = row[column];
        cell.textContent = value == null ? "" : String(value);
        tableRow.appendChild(cell);
      });
      body.appendChild(tableRow);
    });
    previewTable.querySelector("tbody").appendChild(body);
  }
})();
