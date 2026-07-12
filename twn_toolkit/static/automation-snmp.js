(() => {
  const escapeHtml = (value) => String(value ?? "").replace(
    /[&<>"']/g,
    (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]),
  );
  document.querySelectorAll("[data-snmp-rule-builder]").forEach((builder) => {
    const form = builder.closest("form");
    const hidden = form?.querySelector("[data-snmp-rules-json]");
    const list = builder.querySelector("[data-snmp-rule-list]");
    const empty = builder.querySelector("[data-snmp-rule-empty]");
    const add = builder.querySelector("[data-add-snmp-rule]");
    if (!form || !hidden || !list || !empty || !add) return;
    let choices = [];
    let rules = [];
    try { choices = JSON.parse(builder.dataset.oidChoices || "[]"); } catch (_error) { choices = []; }
    try { rules = JSON.parse(hidden.value || "[]"); } catch (_error) { rules = []; }
    const ruleId = () => globalThis.crypto?.randomUUID?.() || `snmp-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const comparisonOptions = (selected) => `
      <option value="unavailable" ${selected === "unavailable" ? "selected" : ""}>SNMP value is unavailable</option>
      <optgroup label="Numeric">
        <option value="greater_than" ${selected === "greater_than" ? "selected" : ""}>Greater than</option>
        <option value="at_least" ${selected === "at_least" ? "selected" : ""}>Greater than or equal to</option>
        <option value="less_than" ${selected === "less_than" ? "selected" : ""}>Less than</option>
        <option value="at_most" ${selected === "at_most" ? "selected" : ""}>Less than or equal to</option>
      </optgroup>
      <optgroup label="Text">
        <option value="equals" ${selected === "equals" ? "selected" : ""}>Equals</option>
        <option value="not_equals" ${selected === "not_equals" ? "selected" : ""}>Does not equal</option>
        <option value="contains" ${selected === "contains" ? "selected" : ""}>Contains</option>
        <option value="not_contains" ${selected === "not_contains" ? "selected" : ""}>Does not contain</option>
      </optgroup>`;
    const sync = () => { hidden.value = JSON.stringify(rules); };
    const render = () => {
      list.replaceChildren();
      empty.hidden = rules.length > 0;
      rules.forEach((rule, index) => {
        const card = document.createElement("section");
        card.className = "snmp-rule-card";
        const selectedOid = `${rule.oid_profile_name || ""}|${rule.oid || ""}`;
        card.innerHTML = `
          <div class="snmp-rule-card-head"><strong>Rule ${index + 1}</strong><span>AND</span></div>
          <div class="form-grid">
            <label>Rule name<input data-snmp-field="name" maxlength="100" value="${escapeHtml(rule.name || `Rule ${index + 1}`)}"></label>
            <label>OID from saved profile<select data-snmp-field="oid_selection"><option value="">Select an OID</option>${choices.map((choice) => `<option value="${escapeHtml(choice.value)}" ${choice.value === selectedOid ? "selected" : ""}>${escapeHtml(choice.display)}</option>`).join("")}</select></label>
          </div>
          <div class="form-grid snmp-rule-comparison">
            <label>Rule matches when<select data-snmp-field="comparison">${comparisonOptions(rule.comparison || "unavailable")}</select></label>
            <label data-snmp-rule-expected>Comparison value<input data-snmp-field="expected_value" maxlength="500" value="${escapeHtml(rule.expected_value || "")}"></label>
            <label class="check" data-snmp-rule-case><input type="checkbox" data-snmp-field="case_sensitive" ${rule.case_sensitive ? "checked" : ""}>Text comparison is case-sensitive</label>
          </div>
          <div class="button-row snmp-rule-actions"><button class="secondary" type="button" data-snmp-up ${index === 0 ? "disabled" : ""}>Move up</button><button class="secondary" type="button" data-snmp-down ${index === rules.length - 1 ? "disabled" : ""}>Move down</button><button class="text-danger" type="button" data-snmp-remove>Remove rule</button></div>`;
        list.append(card);
        const comparison = card.querySelector('[data-snmp-field="comparison"]');
        const expected = card.querySelector("[data-snmp-rule-expected]");
        const caseSensitive = card.querySelector("[data-snmp-rule-case]");
        const syncVisibility = () => {
          expected.hidden = comparison.value === "unavailable";
          caseSensitive.hidden = !["equals", "not_equals", "contains", "not_contains"].includes(comparison.value);
        };
        card.addEventListener("input", (event) => {
          const field = event.target.dataset.snmpField;
          if (!field) return;
          if (field === "oid_selection") {
            const choice = choices.find((item) => item.value === event.target.value);
            rule.oid_profile_name = choice?.profile_name || "";
            rule.oid = choice?.oid || "";
          } else if (field === "case_sensitive") rule[field] = event.target.checked;
          else rule[field] = event.target.value;
          syncVisibility(); sync();
        });
        card.querySelector("[data-snmp-up]").addEventListener("click", () => { [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]]; sync(); render(); });
        card.querySelector("[data-snmp-down]").addEventListener("click", () => { [rules[index + 1], rules[index]] = [rules[index], rules[index + 1]]; sync(); render(); });
        card.querySelector("[data-snmp-remove]").addEventListener("click", () => { rules.splice(index, 1); sync(); render(); });
        syncVisibility();
      });
      sync();
    };
    add.addEventListener("click", () => {
      const choice = choices[0] || {};
      rules.push({id:ruleId(), name:`Rule ${rules.length + 1}`, oid_profile_name:choice.profile_name || "", oid:choice.oid || "", comparison:"unavailable", expected_value:"", case_sensitive:false});
      render();
    });
    render();
  });
})();
