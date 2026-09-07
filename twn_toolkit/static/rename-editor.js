(function () {
  const sourceForm = document.getElementById("task-form");
  const loadButton = document.getElementById("load-objects");
  const editor = document.getElementById("rename-editor");
  const editorForm = document.getElementById("rename-editor-form");
  const status = document.getElementById("rename-editor-status");
  const tableBody = document.querySelector("#rename-table tbody");
  const selectAll = document.getElementById("select-all-objects");
  const profileInput = document.getElementById("rename-profile");
  const endpointInput = document.getElementById("rename-endpoint");

  if (!sourceForm || !loadButton || !editor || !editorForm || !status || !tableBody ||
      !selectAll || !profileInput || !endpointInput) {
    return;
  }

  let edited = false;
  editorForm.addEventListener("input", () => { edited = true; });
  editorForm.addEventListener("change", () => { edited = true; });
  loadButton.addEventListener("click", async () => {
    if (edited && !window.confirm("Discard the current rename edits and load devices again?")) return;
    const formData = new FormData(sourceForm);
    loadButton.disabled = true;
    editor.hidden = false;
    status.textContent = "Loading devices...";
    tableBody.innerHTML = "";

    try {
      const data = await window.TwnApplianceRead(loadButton.dataset.objectsUrl, formData, status);
      if (["profile", "endpoint_template"].some(name => String(formData.get(name) || "") !== String(new FormData(sourceForm).get(name) || ""))) {
        throw new Error("The profile or endpoint changed. Load again for the current selection.");
      }


      profileInput.value = String(formData.get("profile") || "");
      endpointInput.value = String(formData.get("endpoint_template") || "");
      renderObjects(data.objects || []);
      edited = false;
      window.TwnUnsavedForms?.acknowledge(editorForm, window.TwnUnsavedForms.capture(editorForm));
      status.textContent = `${data.row_count} device(s) loaded.`;
    } catch (error) {
      status.textContent = error.message;
    } finally {
      loadButton.disabled = false;
    }
  });

  selectAll.addEventListener("change", () => {
    tableBody.querySelectorAll(".rename-select").forEach((checkbox) => {
      checkbox.checked = selectAll.checked;
      setRowEnabled(checkbox.closest("tr"), checkbox.checked);
    });
  });

  tableBody.addEventListener("change", (event) => {
    if (!event.target.classList.contains("rename-select")) {
      return;
    }
    setRowEnabled(event.target.closest("tr"), event.target.checked);
    updateSelectAll();
  });

  tableBody.addEventListener("input", (event) => {
    if (!event.target.classList.contains("rename-new-name")) {
      return;
    }
    const row = event.target.closest("tr");
    const checkbox = row.querySelector(".rename-select");
    checkbox.checked = true;
    setRowEnabled(row, true);
    updateSelectAll();
  });

  editorForm.addEventListener("submit", (event) => {
    if (!tableBody.querySelector(".rename-select:checked")) {
      event.preventDefault();
      status.textContent = "Select at least one device to rename.";
    }
  });

  function renderObjects(objects) {
    selectAll.checked = false;
    const fragment = document.createDocumentFragment();
    objects.forEach((object) => {
      const row = document.createElement("tr");

      const selectCell = document.createElement("td");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.className = "rename-select";
      checkbox.setAttribute("aria-label", `Select ${object.current_name}`);
      selectCell.appendChild(checkbox);

      row.appendChild(selectCell);
      row.appendChild(textCell(object.identifier, "identifier"));
      row.appendChild(textCell(object.current_name, "current_name"));
      row.appendChild(inputCell("new_name", object.current_name, "rename-new-name"));
      row.appendChild(inputCell("vdom", object.vdom, ""));
      setRowEnabled(row, false);
      fragment.appendChild(row);
    });
    tableBody.appendChild(fragment);
  }

  function textCell(value, inputName) {
    const cell = document.createElement("td");
    cell.textContent = value || "";
    if (inputName) {
      cell.appendChild(hiddenInput(inputName, value));
    }
    return cell;
  }

  function inputCell(name, value, className) {
    const cell = document.createElement("td");
    const input = document.createElement("input");
    input.name = name;
    input.value = value || "";
    input.className = className;
    input.required = true;
    cell.appendChild(input);
    return cell;
  }

  function hiddenInput(name, value) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value || "";
    return input;
  }

  function setRowEnabled(row, enabled) {
    row.querySelectorAll("[name]").forEach((input) => {
      input.disabled = !enabled;
    });
  }

  function updateSelectAll() {
    const checkboxes = Array.from(tableBody.querySelectorAll(".rename-select"));
    selectAll.checked = checkboxes.length > 0 && checkboxes.every((checkbox) => checkbox.checked);
  }
})();
