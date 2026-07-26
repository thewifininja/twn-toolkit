(() => {
  const fixedHeaders = [
    { label: "Name", key: "name", locked: true },
    { label: "Host", key: "host", locked: true },
  ];

  const normalize = (value) => {
    const normalized = String(value).trim().toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "");
    if (["ip_fqdn", "fqdn", "address", "target"].includes(normalized)) return "host";
    if (["friendly_name", "friendly_label", "label"].includes(normalized)) return "name";
    return normalized;
  };

  const create = (root, options = {}) => {
    if (!root) return null;
    const matrix = root.querySelector("[data-ssh-matrix]");
    const gridPanel = root.querySelector("[data-ssh-matrix-grid]");
    const rawPanel = root.querySelector("[data-ssh-matrix-raw]");
    const matrixHead = root.querySelector("[data-ssh-matrix-head]");
    const matrixBody = root.querySelector("[data-ssh-matrix-body]");
    const matrixError = root.querySelector("[data-ssh-matrix-error]");
    const matrixNotice = root.querySelector("[data-ssh-matrix-notice]");
    const matrixSummary = root.querySelector("[data-ssh-matrix-summary]");
    const modeToggle = root.querySelector("[data-ssh-matrix-toggle]");
    const commands = options.commands || null;
    const picker = options.picker || null;
    const targetLimit = Number(
      root.dataset.sshTargetLimit
      || root.closest("[data-ssh-target-limit]")?.dataset.sshTargetLimit,
    ) || 5000;

    let headers = fixedHeaders.map((header) => ({ ...header }));
    let rows = [["", ""]];
    let matrixMode = "grid";
    let rawDraftDirty = false;

    const notifyChange = () => {
      if (typeof options.onChange === "function") options.onChange();
    };

    const parseLine = (line, delimiter) => {
      const values = [];
      let value = "";
      let quoted = false;
      for (let index = 0; index < line.length; index += 1) {
        const character = line[index];
        if (character === "\"") {
          if (quoted && line[index + 1] === "\"") {
            value += "\"";
            index += 1;
          } else {
            quoted = !quoted;
          }
        } else if (character === delimiter && !quoted) {
          values.push(value.trim());
          value = "";
        } else {
          value += character;
        }
      }
      if (quoted) throw new Error("A quoted matrix value is not closed.");
      values.push(value.trim());
      if (delimiter === "|" && !values[0]) values.shift();
      if (delimiter === "|" && !values.at(-1)) values.pop();
      return values;
    };

    const parseMatrix = (source) => {
      const lines = String(source).split(/\r?\n/).filter((line) => line.trim());
      if (!lines.length) {
        return {
          headers: fixedHeaders.map((header) => ({ ...header })),
          rows: [["", ""]],
        };
      }
      const firstLine = lines[0];
      const delimiter = firstLine.includes("\t")
        ? "\t"
        : firstLine.includes("|")
          ? "|"
          : firstLine.includes(",")
            ? ","
            : "";
      if (!delimiter) {
        throw new Error("Separate matrix columns with pipes, tabs, or commas.");
      }
      const parsed = lines.map((line) => parseLine(line, delimiter));
      const sourceHeaders = parsed[0];
      if (sourceHeaders.length > 20) {
        throw new Error("A maximum of 20 matrix columns is allowed.");
      }
      const keys = sourceHeaders.map(normalize);
      if (keys.some((key) => !/^[a-z][a-z0-9_]*$/.test(key))) {
        throw new Error("Variable headings must begin with a letter.");
      }
      if (new Set(keys).size !== keys.length) {
        throw new Error("Matrix headings must be unique after normalization.");
      }
      const hostIndex = keys.indexOf("host");
      if (hostIndex < 0) throw new Error("The matrix needs a Host column.");
      const nameIndex = keys.indexOf("name");
      if (keys.includes("row_number")) {
        throw new Error("row_number is built in and cannot be a matrix column.");
      }
      const customIndexes = keys
        .map((_key, index) => index)
        .filter((index) => index !== hostIndex && index !== nameIndex);
      const nextHeaders = [
        ...fixedHeaders.map((header) => ({ ...header })),
        ...customIndexes.map((index) => ({
          label: sourceHeaders[index],
          key: keys[index],
          locked: false,
        })),
      ];
      const nextRows = parsed.slice(1).map((sourceRow, rowIndex) => {
        if (sourceRow.length > sourceHeaders.length) {
          throw new Error(
            `Matrix row ${rowIndex + 2} has ${sourceRow.length} values; expected ${sourceHeaders.length}.`,
          );
        }
        const paddedRow = [
          ...sourceRow,
          ...Array.from(
            { length: sourceHeaders.length - sourceRow.length },
            () => "",
          ),
        ];
        return [
          nameIndex >= 0 ? paddedRow[nameIndex] : "",
          paddedRow[hostIndex],
          ...customIndexes.map((index) => paddedRow[index]),
        ];
      });
      if (nextRows.length > targetLimit) {
        throw new Error(`A maximum of ${targetLimit} targets is allowed.`);
      }
      return {
        headers: nextHeaders,
        rows: nextRows.length
          ? nextRows
          : [nextHeaders.map(() => "")],
      };
    };

    const escapeMatrixValue = (value) => {
      const normalized = String(value).trim();
      if (!/[|"]/.test(normalized)) return normalized;
      return `"${normalized.replaceAll("\"", "\"\"")}"`;
    };

    const syncRawMatrix = () => {
      const populatedRows = rows.filter(
        (row) => row.some((value) => String(value).trim()),
      );
      if (!populatedRows.length) {
        matrix.value = "";
        return;
      }
      matrix.value = [
        headers.map((header) => escapeMatrixValue(header.label)).join(" | "),
        ...populatedRows.map(
          (row) => row.map(
            (value, index) => (
              index === 0 && !String(value).trim() ? row[1] : value
            ),
          ).map(escapeMatrixValue).join(" | "),
        ),
      ].join("\n");
    };

    const referencedVariables = () => {
      if (!commands) return [];
      const found = [];
      const pattern = /\{\{\s*([A-Za-z][A-Za-z0-9 _/-]*?)\s*\}\}/g;
      for (const match of commands.value.matchAll(pattern)) {
        const key = normalize(match[1]);
        if (!found.includes(key)) found.push(key);
      }
      return found;
    };

    const setMatrixError = (message = "") => {
      matrixError.textContent = message;
      matrixError.hidden = !message;
    };

    const setMatrixNotice = (message = "") => {
      matrixNotice.textContent = message;
      matrixNotice.hidden = !message;
    };

    const validateGrid = ({ focus = false, requireTargets = false } = {}) => {
      let firstInvalid = null;
      let message = "";
      const keys = headers.map((header) => normalize(header.label));
      const referenced = new Set(referencedVariables());
      const headerInputs = [
        ...matrixHead.querySelectorAll("[data-ssh-header-index]"),
      ];
      headerInputs.forEach((input) => {
        const index = Number(input.dataset.sshHeaderIndex);
        const key = keys[index];
        const invalid = !/^[a-z][a-z0-9_]*$/.test(key)
          || key === "row_number"
          || keys.filter((candidate) => candidate === key).length > 1;
        input.setAttribute("aria-invalid", String(invalid));
        if (invalid && !firstInvalid) {
          firstInvalid = input;
          message = "Variable headings must be unique, begin with a letter, and cannot use row_number.";
        }
      });

      let populatedCount = 0;
      matrixBody.querySelectorAll("[data-ssh-row-index]").forEach((rowElement) => {
        const rowIndex = Number(rowElement.dataset.sshRowIndex);
        const row = rows[rowIndex];
        const populated = row.some((value) => String(value).trim());
        if (populated) populatedCount += 1;
        rowElement.querySelectorAll("[data-ssh-cell-index]").forEach((input) => {
          const columnIndex = Number(input.dataset.sshCellIndex);
          const value = String(row[columnIndex]).trim();
          const key = keys[columnIndex];
          const invalid = value.length > 500
            || (populated && key === "host" && (!value || /\s/.test(value)))
            || (populated && referenced.has(key) && !value);
          input.setAttribute("aria-invalid", String(invalid));
          if (invalid && !firstInvalid) {
            firstInvalid = input;
            message = key === "host"
              ? `Target row ${rowIndex + 1} needs a valid host without spaces.`
              : `Target row ${rowIndex + 1} needs a value for {{ ${key} }}.`;
          }
        });
      });
      if (requireTargets && !populatedCount && !firstInvalid) {
        message = "Add at least one target before saving.";
      }
      setMatrixError(message);
      if (focus && firstInvalid) firstInvalid.focus();
      return !message;
    };

    const renderGrid = () => {
      matrixHead.replaceChildren();
      matrixBody.replaceChildren();
      const headerRow = document.createElement("tr");
      const rowNumberHeader = document.createElement("th");
      rowNumberHeader.className = "multi-ssh-row-number multi-ssh-grid-corner";
      rowNumberHeader.scope = "col";
      rowNumberHeader.textContent = "#";
      headerRow.append(rowNumberHeader);
      headers.forEach((header, columnIndex) => {
        const cell = document.createElement("th");
        cell.scope = "col";
        if (header.locked) {
          const label = document.createElement("span");
          label.className = "multi-ssh-fixed-heading";
          label.textContent = header.label;
          cell.append(label);
        } else {
          const editor = document.createElement("div");
          editor.className = "multi-ssh-variable-heading";
          const input = document.createElement("input");
          input.value = header.label;
          input.maxLength = 80;
          input.dataset.sshHeaderIndex = String(columnIndex);
          input.setAttribute("data-1p-ignore", "");
          input.setAttribute(
            "aria-label",
            `Variable column ${columnIndex - 1}`,
          );
          const remove = document.createElement("button");
          remove.className = "link-button subtle";
          remove.type = "button";
          remove.textContent = "×";
          remove.title = `Remove ${header.label} column`;
          remove.setAttribute(
            "aria-label",
            `Remove ${header.label} variable column`,
          );
          remove.dataset.sshRemoveColumn = String(columnIndex);
          editor.append(input, remove);
          cell.append(editor);
        }
        headerRow.append(cell);
      });
      const actionsHeader = document.createElement("th");
      actionsHeader.className = "multi-ssh-actions-cell";
      actionsHeader.scope = "col";
      actionsHeader.textContent = "Actions";
      headerRow.append(actionsHeader);
      matrixHead.append(headerRow);

      rows.forEach((row, rowIndex) => {
        const rowElement = document.createElement("tr");
        rowElement.dataset.sshRowIndex = String(rowIndex);
        const rowNumber = document.createElement("th");
        rowNumber.className = "multi-ssh-row-number";
        rowNumber.scope = "row";
        rowNumber.textContent = String(rowIndex + 1);
        rowElement.append(rowNumber);
        headers.forEach((header, columnIndex) => {
          const cell = document.createElement("td");
          const input = document.createElement("input");
          input.value = row[columnIndex] || "";
          input.maxLength = 500;
          input.dataset.sshCellIndex = String(columnIndex);
          input.setAttribute("data-1p-ignore", "");
          input.setAttribute(
            "aria-label",
            `${header.label} row ${rowIndex + 1}`,
          );
          input.placeholder = header.key === "name"
            ? "Closet switch"
            : header.key === "host"
              ? "switch.example.com"
              : header.label;
          cell.append(input);
          rowElement.append(cell);
        });
        const actions = document.createElement("td");
        actions.className = "multi-ssh-actions-cell";
        const actionGroup = document.createElement("div");
        actionGroup.className = "multi-ssh-matrix-row-actions";
        const duplicate = document.createElement("button");
        duplicate.className = "link-button subtle";
        duplicate.type = "button";
        duplicate.textContent = "Copy";
        duplicate.title = `Duplicate row ${rowIndex + 1}`;
        duplicate.setAttribute("aria-label", `Duplicate row ${rowIndex + 1}`);
        duplicate.dataset.sshDuplicateRow = String(rowIndex);
        const remove = document.createElement("button");
        remove.className = "link-button text-danger";
        remove.type = "button";
        remove.textContent = "Delete";
        remove.setAttribute("aria-label", `Delete row ${rowIndex + 1}`);
        remove.dataset.sshDeleteRow = String(rowIndex);
        actionGroup.append(duplicate, remove);
        actions.append(actionGroup);
        rowElement.append(actions);
        matrixBody.append(rowElement);
      });
      matrixSummary.textContent = `${rows.filter((row) => row.some((value) => String(value).trim())).length} target(s) · ${Math.max(0, headers.length - 2)} custom variable column(s)`;
      validateGrid();
    };

    const focusCell = (rowIndex, columnIndex) => {
      const rowElement = matrixBody.querySelector(
        `[data-ssh-row-index="${rowIndex}"]`,
      );
      const input = rowElement?.querySelector(
        `[data-ssh-cell-index="${columnIndex}"]`,
      );
      if (input) {
        input.focus();
        input.select();
      }
    };

    const addBlankRow = () => {
      if (rows.length >= targetLimit) {
        setMatrixError(`A maximum of ${targetLimit} targets is allowed.`);
        return false;
      }
      rows.push(headers.map(() => ""));
      return true;
    };

    const nextVariableLabel = () => {
      const existing = new Set(
        headers.map((header) => normalize(header.label)),
      );
      let number = 1;
      while (existing.has(`variable_${number}`)) number += 1;
      return `Variable ${number}`;
    };

    const matrixChanged = () => {
      rawDraftDirty = false;
      setMatrixNotice();
      syncRawMatrix();
      matrixSummary.textContent = `${rows.filter((row) => row.some((value) => String(value).trim())).length} target(s) · ${Math.max(0, headers.length - 2)} custom variable column(s)`;
      updateVariablePicker();
      validateGrid();
      notifyChange();
    };

    const importTargets = (targets, { replace = false } = {}) => {
      if (!Array.isArray(targets) || !targets.length) {
        throw new Error("Enter at least one host or IP range to import.");
      }
      const existingRows = rows.filter(
        (row) => row.some((value) => String(value).trim()),
      );
      const nextTotal = (replace ? 0 : existingRows.length) + targets.length;
      if (nextTotal > targetLimit) {
        throw new Error(
          `This import would create ${nextTotal} targets; the maximum is ${targetLimit}.`,
        );
      }
      const importedRows = targets.map((target) => headers.map((header) => {
        if (header.key === "host") return String(target.host || "").trim();
        if (header.key === "name") {
          return String(target.label || target.host || "").trim();
        }
        return "";
      }));
      const firstImportedRow = replace ? 0 : existingRows.length;
      rows = replace
        ? importedRows
        : [...existingRows, ...importedRows];
      renderGrid();
      matrixChanged();
      const targetLabel = targets.length === 1 ? "target" : "targets";
      setMatrixNotice(
        `Imported ${targets.length} ${targetLabel}; the matrix now contains ${rows.length}.`,
      );
      focusCell(firstImportedRow, 0);
      return { imported: targets.length, total: rows.length };
    };

    const pasteSpreadsheetBlock = (event, input, rowElement) => {
      const clipboard = event.clipboardData?.getData("text/plain") || "";
      if (!clipboard.includes("\t") && !/[\r\n]/.test(clipboard)) return;
      event.preventDefault();
      const startRow = Number(rowElement.dataset.sshRowIndex);
      const startColumn = Number(input.dataset.sshCellIndex);
      const lines = clipboard.replace(/\r\n?/g, "\n").split("\n");
      if (lines.at(-1) === "") lines.pop();
      const pastedRows = lines.map((line) => line.split("\t"));
      const pastedHeaderKeys = (pastedRows[0] || []).map(normalize);
      if (
        startRow === 0
        && startColumn === 0
        && pastedHeaderKeys.includes("host")
      ) {
        try {
          const parsed = parseMatrix(clipboard);
          headers = parsed.headers;
          rows = parsed.rows;
          renderGrid();
          matrixChanged();
          focusCell(0, 0);
        } catch (error) {
          setMatrixError(error.message);
        }
        return;
      }

      const width = Math.max(...pastedRows.map((row) => row.length));
      const requiredColumns = startColumn + width;
      const requiredRows = startRow + pastedRows.length;
      if (requiredColumns > 20) {
        setMatrixError("A maximum of 20 matrix columns is allowed.");
        return;
      }
      if (requiredRows > targetLimit) {
        setMatrixError(`A maximum of ${targetLimit} targets is allowed.`);
        return;
      }
      while (headers.length < requiredColumns) {
        const label = nextVariableLabel();
        headers.push({ label, key: normalize(label), locked: false });
        rows = rows.map((row) => [...row, ""]);
      }
      while (rows.length < requiredRows) {
        rows.push(headers.map(() => ""));
      }
      pastedRows.forEach((pastedRow, rowOffset) => {
        pastedRow.forEach((value, columnOffset) => {
          rows[startRow + rowOffset][startColumn + columnOffset] = value;
        });
      });
      renderGrid();
      matrixChanged();
      focusCell(
        Math.min(requiredRows - 1, rows.length - 1),
        Math.min(requiredColumns - 1, headers.length - 1),
      );
    };

    const headerVariables = () => {
      if (matrixMode === "grid") {
        return headers.map((header) => normalize(header.label));
      }
      try {
        return parseMatrix(matrix.value).headers.map(
          (header) => normalize(header.label),
        );
      } catch (_error) {
        return [];
      }
    };

    const insertVariable = (name) => {
      if (!commands) return;
      const insertion = `{{ ${name} }}`;
      const start = commands.selectionStart ?? commands.value.length;
      const end = commands.selectionEnd ?? commands.value.length;
      commands.setRangeText(insertion, start, end, "end");
      commands.focus();
      commands.dispatchEvent(new Event("input", { bubbles: true }));
    };

    const updateVariablePicker = () => {
      if (!picker) return;
      picker.querySelectorAll("[data-ssh-variable-dynamic]").forEach(
        (element) => element.remove(),
      );
      const builtIns = new Set(["name", "host", "row_number"]);
      [...new Set(headerVariables())]
        .filter(
          (name) => /^[a-z][a-z0-9_]*$/.test(name) && !builtIns.has(name),
        )
        .forEach((name) => {
          const button = document.createElement("button");
          button.className = "secondary ssh-variable-chip";
          button.type = "button";
          button.dataset.sshVariable = name;
          button.dataset.sshVariableDynamic = "";
          button.textContent = `{{ ${name} }}`;
          picker.append(button);
        });
    };

    const setMatrixMode = (mode, { sync = true } = {}) => {
      if (mode === "grid") {
        try {
          const parsed = parseMatrix(matrix.value);
          headers = parsed.headers;
          rows = parsed.rows;
          rawDraftDirty = false;
          setMatrixNotice();
          renderGrid();
        } catch (error) {
          if (matrixMode !== "raw") {
            setMatrixError(error.message);
            return false;
          }
          setMatrixError();
          setMatrixNotice(
            "Raw Matrix is incomplete, so Table Editor is showing the last valid table. Switch back to Raw Matrix to continue the draft; editing or saving the table will replace it.",
          );
        }
      } else if (sync && !rawDraftDirty) {
        syncRawMatrix();
        setMatrixNotice();
      } else if (mode === "raw") {
        setMatrixNotice();
      }
      matrixMode = mode;
      gridPanel.hidden = mode !== "grid";
      rawPanel.hidden = mode !== "raw";
      const nextMode = mode === "grid" ? "raw" : "grid";
      const nextLabel = nextMode === "raw" ? "Raw matrix" : "Table editor";
      modeToggle.dataset.sshMatrixMode = nextMode;
      modeToggle.textContent = nextLabel;
      modeToggle.setAttribute("aria-label", `Switch to ${nextLabel}`);
      modeToggle.title = `Switch to ${nextLabel}`;
      updateVariablePicker();
      return true;
    };

    modeToggle.addEventListener("click", () => {
      setMatrixMode(modeToggle.dataset.sshMatrixMode);
    });
    root.querySelector("[data-ssh-add-target]").addEventListener("click", () => {
      if (!addBlankRow()) return;
      renderGrid();
      matrixChanged();
      focusCell(rows.length - 1, 0);
    });
    root.querySelector("[data-ssh-add-variable]").addEventListener("click", () => {
      const label = nextVariableLabel();
      const key = normalize(label);
      const existing = headers.map((header) => normalize(header.label));
      if (headers.length >= 20) {
        setMatrixError("A maximum of 20 matrix columns is allowed.");
        return;
      }
      if (existing.includes(key)) return;
      headers.push({ label, key, locked: false });
      rows = rows.map((row) => [...row, ""]);
      renderGrid();
      matrixChanged();
      const headerInput = matrixHead.querySelector(
        `[data-ssh-header-index="${headers.length - 1}"]`,
      );
      headerInput?.focus();
      headerInput?.select();
    });
    matrixHead.addEventListener("input", (event) => {
      const input = event.target.closest("[data-ssh-header-index]");
      if (!input) return;
      const index = Number(input.dataset.sshHeaderIndex);
      headers[index].label = input.value;
      headers[index].key = normalize(input.value);
      matrixChanged();
    });
    matrixHead.addEventListener("click", (event) => {
      const button = event.target.closest("[data-ssh-remove-column]");
      if (!button) return;
      const index = Number(button.dataset.sshRemoveColumn);
      headers.splice(index, 1);
      rows = rows.map(
        (row) => row.filter((_value, columnIndex) => columnIndex !== index),
      );
      renderGrid();
      matrixChanged();
    });
    matrixBody.addEventListener("input", (event) => {
      const input = event.target.closest("[data-ssh-cell-index]");
      const rowElement = event.target.closest("[data-ssh-row-index]");
      if (!input || !rowElement) return;
      rows[Number(rowElement.dataset.sshRowIndex)][
        Number(input.dataset.sshCellIndex)
      ] = input.value;
      matrixChanged();
    });
    matrixBody.addEventListener("keydown", (event) => {
      const input = event.target.closest("[data-ssh-cell-index]");
      const rowElement = event.target.closest("[data-ssh-row-index]");
      if (!input || !rowElement) return;
      const rowIndex = Number(rowElement.dataset.sshRowIndex);
      const columnIndex = Number(input.dataset.sshCellIndex);
      let nextRow = rowIndex;
      let nextColumn = columnIndex;
      if (
        event.key === "Enter"
        && !event.metaKey
        && !event.ctrlKey
        && !event.altKey
      ) {
        nextRow += event.shiftKey ? -1 : 1;
        if (nextRow >= rows.length && !addBlankRow()) return;
        if (nextRow < 0) return;
      } else if (event.key === "Tab") {
        nextColumn += event.shiftKey ? -1 : 1;
        if (nextColumn >= headers.length) {
          nextColumn = 0;
          nextRow += 1;
        } else if (nextColumn < 0) {
          nextColumn = headers.length - 1;
          nextRow -= 1;
        }
        if (nextRow >= rows.length && !addBlankRow()) return;
        if (nextRow < 0) return;
      } else {
        return;
      }
      event.preventDefault();
      if (
        rows.length
        !== matrixBody.querySelectorAll("[data-ssh-row-index]").length
      ) {
        renderGrid();
        matrixChanged();
      }
      focusCell(nextRow, nextColumn);
    });
    matrixBody.addEventListener("paste", (event) => {
      const input = event.target.closest("[data-ssh-cell-index]");
      const rowElement = event.target.closest("[data-ssh-row-index]");
      if (input && rowElement) {
        pasteSpreadsheetBlock(event, input, rowElement);
      }
    });
    matrixBody.addEventListener("click", (event) => {
      const duplicate = event.target.closest("[data-ssh-duplicate-row]");
      const remove = event.target.closest("[data-ssh-delete-row]");
      if (duplicate) {
        if (rows.length >= targetLimit) {
          setMatrixError(`A maximum of ${targetLimit} targets is allowed.`);
          return;
        }
        const index = Number(duplicate.dataset.sshDuplicateRow);
        rows.splice(index + 1, 0, [...rows[index]]);
      } else if (remove) {
        rows.splice(Number(remove.dataset.sshDeleteRow), 1);
        if (!rows.length) rows.push(headers.map(() => ""));
      } else {
        return;
      }
      renderGrid();
      matrixChanged();
    });
    matrix.addEventListener("input", () => {
      rawDraftDirty = true;
      setMatrixNotice();
      updateVariablePicker();
      notifyChange();
    });
    commands?.addEventListener("input", () => {
      if (matrixMode === "grid") validateGrid();
      notifyChange();
    });
    picker?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-ssh-variable]");
      if (button) insertVariable(button.dataset.sshVariable);
    });

    if (!setMatrixMode("grid")) {
      setMatrixMode("raw", { sync: false });
    }
    updateVariablePicker();

    return {
      get mode() {
        return matrixMode;
      },
      get value() {
        return matrix.value;
      },
      load(value) {
        matrix.value = String(value || "");
        rawDraftDirty = false;
        if (!setMatrixMode("grid")) setMatrixMode("raw", { sync: false });
        notifyChange();
      },
      parse: parseMatrix,
      importTargets,
      setMode: setMatrixMode,
      sync: syncRawMatrix,
      validate: validateGrid,
    };
  };

  globalThis.TwnSshMatrixEditor = { create, normalize };
})();
