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

  const acmeRoot = document.querySelector("[data-acme-job]");
  if (!acmeRoot) return;

  const jobData = acmeRoot.querySelector(".acme-job-data");
  let job = JSON.parse(jobData?.textContent || "{}");
  let confirmedChallengeId = "";
  let pollTimer = null;

  const statusClass = (status) => {
    if (status === "issued") return "success";
    if (["failed", "cancelled", "interrupted"].includes(status)) return "error";
    return "warning";
  };

  const setStatus = (status) => {
    const pill = acmeRoot.querySelector("[data-acme-status]");
    pill.textContent = status.replaceAll("_", " ").replace(/\b\w/g, (value) => value.toUpperCase());
    pill.classList.remove("success", "warning", "error");
    pill.classList.add(statusClass(status));
  };

  const renderCleanup = () => {
    const cleanup = acmeRoot.querySelector("[data-acme-cleanup]");
    const list = acmeRoot.querySelector("[data-acme-cleanup-list]");
    const terminal = ["issued", "failed", "cancelled", "interrupted"].includes(job.status);
    cleanup.hidden = !terminal || !job.challenges?.length;
    if (cleanup.hidden) return;
    list.replaceChildren();
    job.challenges.forEach((challenge) => {
      const row = document.createElement("div");
      const name = document.createElement("code");
      const value = document.createElement("code");
      name.textContent = challenge.record_name;
      value.textContent = challenge.record_value;
      row.append(name, value);
      list.append(row);
    });
  };

  const renderJob = () => {
    acmeRoot.querySelector("[data-acme-name]").textContent = job.name;
    acmeRoot.querySelector("[data-acme-meta]").textContent =
      `${job.environment[0].toUpperCase()}${job.environment.slice(1)} · ${job.domains.join(", ")}`;
    acmeRoot.querySelector("[data-acme-message]").textContent = job.message || "";
    setStatus(job.status);

    const challengePanel = acmeRoot.querySelector("[data-acme-challenge]");
    const challenge = job.challenge;
    challengePanel.hidden = job.status !== "awaiting_dns" || !challenge;
    if (!challengePanel.hidden) {
      acmeRoot.querySelector("[data-acme-record-name]").textContent = challenge.record_name;
      acmeRoot.querySelector("[data-acme-record-value]").textContent = challenge.record_value;
      const count = Number(challenge.remaining || 0);
      acmeRoot.querySelector("[data-acme-remaining]").textContent = count
        ? `${count} additional DNS challenge${count === 1 ? "" : "s"} will follow. Do not remove earlier values.`
        : "This is the final DNS challenge. Keep all values published through issuance.";
    }

    const result = acmeRoot.querySelector("[data-acme-result]");
    result.hidden = job.status !== "issued" || !job.certificate;
    if (!result.hidden) {
      const expires = new Date(job.certificate.not_after).toLocaleString();
      acmeRoot.querySelector("[data-acme-certificate-summary]").textContent =
        `${job.environment === "staging" ? "Staging" : "Production"} certificate valid until ${expires}.`;
      const download = acmeRoot.querySelector("[data-acme-download]");
      download.href = job.download_url;
    }
    acmeRoot.querySelector("[data-acme-cancel]").hidden = !job.cancellable;
    renderCleanup();
  };

  const request = async (url, body) => {
    const response = await fetch(url, {
      method: body ? "POST" : "GET",
      body,
      headers: {"X-Requested-With": "XMLHttpRequest"},
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "The ACME request could not be updated.");
    return payload;
  };

  const renderDnsCheck = (element, check) => {
    const system = check.system || {};
    const authoritative = check.authoritative || {};
    element.replaceChildren();
    element.classList.remove("success", "warning", "error");

    const headline = document.createElement("strong");
    if (check.found && check.cache_disagreement && authoritative.ready) {
      headline.textContent = "Authoritative DNS is ready; the toolkit resolver still has an older answer.";
    } else if (check.found && check.source === "authoritative") {
      headline.textContent = "The exact TXT value is visible on every authoritative nameserver.";
    } else if (check.found) {
      headline.textContent = "The exact TXT value is visible through the toolkit resolver.";
    } else if (Number(authoritative.matched || 0)) {
      headline.textContent = "DNS is only partially propagated.";
    } else {
      headline.textContent = "The exact TXT value is not ready yet.";
    }
    element.classList.add(check.found ? "success" : "warning");
    element.append(headline);

    const breakdown = document.createElement("div");
    breakdown.className = "acme-dns-check-breakdown";

    const systemLine = document.createElement("p");
    const systemLabel = document.createElement("span");
    systemLabel.textContent = "Toolkit resolver";
    const resolvers = system.resolvers?.length
      ? system.resolvers.join(", ")
      : "system default";
    let systemMessage = "";
    if (system.found) {
      systemMessage = `Exact value visible via ${resolvers}.`;
    } else if (system.values?.length) {
      const ttl = system.ttl !== null
        && system.ttl !== undefined
        && Number.isFinite(Number(system.ttl))
        ? ` (${Number(system.ttl)}s response TTL)`
        : "";
      systemMessage = `A different TXT value is still returned via ${resolvers}; it may be cached${ttl}.`;
    } else if (system.error) {
      systemMessage = `Not visible via ${resolvers}: ${system.error}`;
    } else {
      systemMessage = `No TXT value is visible via ${resolvers}.`;
    }
    systemLine.append(systemLabel, document.createTextNode(systemMessage));
    breakdown.append(systemLine);

    const authorityLine = document.createElement("p");
    const authorityLabel = document.createElement("span");
    authorityLabel.textContent = "Authoritative DNS";
    const total = Number(authoritative.total || 0);
    const checked = Number(authoritative.checked || 0);
    const matched = Number(authoritative.matched || 0);
    let authorityMessage = "";
    if (authoritative.ready) {
      authorityMessage = `Exact value visible on all ${total} nameserver${total === 1 ? "" : "s"}.`;
    } else if (matched) {
      authorityMessage = `Exact value visible on ${matched} of ${total} nameservers. Wait for them to agree.`;
    } else if (checked) {
      authorityMessage = `Not visible on ${checked} responding nameserver${checked === 1 ? "" : "s"}.`;
    } else if (authoritative.error) {
      authorityMessage = `Direct check unavailable: ${authoritative.error}`;
    } else {
      authorityMessage = "Direct check unavailable; the toolkit resolver result is shown above.";
    }
    authorityLine.append(authorityLabel, document.createTextNode(authorityMessage));
    breakdown.append(authorityLine);
    element.append(breakdown);
  };

  const schedulePoll = () => {
    window.clearTimeout(pollTimer);
    if (!job.active) return;
    pollTimer = window.setTimeout(async () => {
      try {
        const payload = await request(job.status_url);
        const previousChallenge = job.challenge?.id || "";
        job = payload.job;
        if (previousChallenge !== (job.challenge?.id || "")) confirmedChallengeId = "";
        renderJob();
      } catch (error) {
        acmeRoot.querySelector("[data-acme-message]").textContent = error.message;
      }
      schedulePoll();
    }, 2000);
  };

  acmeRoot.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const selector = button.dataset.copyTarget === "record-name"
        ? "[data-acme-record-name]"
        : "[data-acme-record-value]";
      const value = acmeRoot.querySelector(selector).textContent;
      try {
        await navigator.clipboard.writeText(value);
        const original = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => { button.textContent = original; }, 1200);
      } catch {
        window.prompt("Copy this value:", value);
      }
    });
  });

  acmeRoot.querySelector("[data-acme-dns-check]").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const result = acmeRoot.querySelector("[data-acme-dns-result]");
    button.disabled = true;
    result.hidden = false;
    result.classList.remove("success", "warning", "error");
    result.textContent = "Checking the toolkit resolver and authoritative DNS…";
    try {
      const body = new FormData();
      body.set("challenge_id", job.challenge.id);
      const payload = await request(job.dns_check_url, body);
      renderDnsCheck(result, payload.result);
      if (payload.result.found) {
        confirmedChallengeId = job.challenge.id;
      }
    } catch (error) {
      result.replaceChildren();
      result.classList.add("error");
      result.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  acmeRoot.querySelector("[data-acme-continue]").addEventListener("click", async (event) => {
    if (
      confirmedChallengeId !== job.challenge?.id
      && !window.confirm("The toolkit has not seen this exact TXT value yet. Continue validation anyway?")
    ) return;
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const body = new FormData();
      body.set("challenge_id", job.challenge.id);
      const payload = await request(job.continue_url, body);
      job = payload.job;
      renderJob();
      schedulePoll();
    } catch (error) {
      window.alert(error.message);
      button.disabled = false;
    }
  });

  acmeRoot.querySelector("[data-acme-cancel]").addEventListener("click", async (event) => {
    if (!window.confirm("Cancel this Certbot request? Any published TXT values will need to be removed manually.")) return;
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const payload = await request(job.cancel_url, new FormData());
      job = payload.job;
      renderJob();
      schedulePoll();
    } catch (error) {
      window.alert(error.message);
      button.disabled = false;
    }
  });

  renderJob();
  schedulePoll();
})();
