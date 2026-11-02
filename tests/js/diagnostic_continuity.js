// In-memory protocol/DOM model; no browser, network, timer waits or third-party modules.
module.exports = async function checkContinuity(source) {
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.dataset = {}; this.attributes = {}; this._text = ""; }
    set textContent(value) { this._text = value; this.children = []; }
    get textContent() { return this._text + this.children.map(x => x.textContent).join(""); }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(type, fn) { this.events[type] = fn; }
    replaceChildren(...children) { this._text = ""; this.children = children; }
    after(element) { this.afterElement = element; }
  }
  const reply = (state, status = 200) => ({ ok: status < 400, status, headers: { get: () => "application/json" }, json: async () => ({ state }) });
  class FixtureURL { constructor(value) { const parts = value.replace(/^https?:\/\/[^/]+/, "").split("#")[0].split("?"); this.pathname = parts[0]; this.search = parts[1] ? "?" + parts[1] : ""; } }
  function setup({ dirty = false, guard = true, protectedForm = true } = {}) {
    const panel = new Element("section"), status = new Element("p"), state = new Element("span"), form = new Element("form"), cancel = new Element("button"), link = new Element("a");
    const draft = { value: "new unsent settings" };
    panel.dataset = { diagnosticStatusUrl: "/owned/old/status", diagnosticResultUrl: "/owned/old?job=first" };
    form.method = "post"; form.target = "";
    form.action = "https://fixture.test/owned/old/cancel";
    form.querySelector = () => cancel;
    panel.querySelector = selector => ({ "[data-diagnostic-status]": status, "[data-diagnostic-state]": state, "[data-diagnostic-cancel]": form, "[data-diagnostic-result-link]": link })[selector] || null;
    const timers = new Map(), calls = [], responses = [], events = {}, docEvents = {};
    let clock = 0, reloads = 0;
    const window = {
      location: { href: "https://fixture.test/current?job=second", reload: () => { reloads += 1; } },
      setTimeout: fn => { timers.set(++clock, fn); return clock; }, clearTimeout: id => timers.delete(id),
      addEventListener: (type, fn) => { events[type] = fn; },
    };
    if (guard) window.TwnUnsavedForms = { hasChanges: () => dirty };
    const document = { hidden: false, querySelector: selector => selector === "[data-diagnostic-status-url]" ? panel : protectedForm ? form : null,
      createElement: tag => new Element(tag), createTextNode: text => Object.assign(new Element("text"), { textContent: text }),
      addEventListener: (type, fn) => { docEvents[type] = fn; } };
    const fetch = async (url, options) => {
      calls.push({ url, options });
      if (!responses.length) throw new Error("Missing fixture response");
      const next = responses.shift();
      if (typeof next === "function") return next();
      return next;
    };
    class FormData { constructor(target) { this.target = target; } }
    new Function("document", "window", "fetch", "AbortSignal", "FormData", "URL", "HTMLFormElement", source)(document, window, fetch, { timeout: () => ({}) }, FormData, FixtureURL, Element);
    return { panel, status, state, form, cancel, link, draft, calls, responses, timers, events, docEvents,
      get reloads() { return reloads; },
      tick: async () => { const first = timers.entries().next().value; assert(first, "Expected scheduled poll"); timers.delete(first[0]); await first[1](); },
      retry: async () => { const button = status.children.find(x => x.tagName === "button"); assert(button, "Retry status missing"); await button.events.click(); await flush(); },
    };
  }
  const flush = async () => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };
  const results = [];
  async function test(name, fn) { await fn(); results.push(name); }
  await test("clean completion reloads only the retained GET", async () => {
    const f = setup(); f.responses.push(reply("succeeded")); await f.tick();
    assert(f.reloads === 1 && f.calls.length === 1 && !f.calls[0].options.method, "Completion repeated execution or failed clean GET reload");
    assert(f.timers.size === 0, "Terminal job kept polling");
  });
  await test("dirty completion keeps draft and opens exact old result in new tab", async () => {
    const f = setup({ dirty: true }); f.responses.push(reply("succeeded")); await f.tick();
    assert(f.reloads === 0 && f.draft.value === "new unsent settings", "Draft lost");
    assert(f.link.href === "/owned/old?job=first" && f.link.target === "_blank" && f.link.rel === "noopener", "Result identity or isolation wrong");
    assert(f.state.textContent === "Finished" && f.cancel.disabled && f.timers.size === 0, "Terminal controls stale");
  });
  await test("missing draft guard fails closed for an opted-in form", async () => {
    const f = setup({ guard: false }); f.responses.push(reply("failed")); await f.tick();
    assert(f.reloads === 0 && f.link.target === "_blank", "Missing guard discarded settings");
  });
  await test("poll failure retries GET without submission", async () => {
    const f = setup({ dirty: true }); f.responses.push(() => { throw new Error("offline"); }); await f.tick();
    assert(f.status.textContent.includes("Retry status") && f.timers.size === 1, "Retry affordance missing");
    f.responses.push(reply("running")); await f.retry();
    assert(f.calls.length === 2 && f.calls.every(x => !x.options.method), "Retry executed a submission");
    assert(f.reloads === 0 && f.draft.value === "new unsent settings", "Retry lost draft");
  });
  await test("forbidden polling pauses until explicit status retry", async () => {
    const f = setup({ dirty: true }); f.responses.push(reply("", 403)); await f.tick();
    assert(f.timers.size === 0 && f.status.textContent.includes("do not have access"), "Permission failure looped or unclear");
    f.responses.push(reply("running")); await f.retry(); assert(f.timers.size === 1, "Explicit retry did not recover");
  });
  await test("expired result pauses without losing settings", async () => {
    const f = setup({ dirty: true }); f.responses.push(reply("", 410)); await f.tick();
    assert(!f.timers.size && f.status.textContent.includes("no longer retained") && !f.reloads, "Expiry discarded draft or kept polling");
  });
  await test("cancel is one POST of cancel form then read-only status", async () => {
    const f = setup({ dirty: true }); let complete;
    f.responses.push(() => new Promise(resolve => { complete = resolve; }), reply("cancelled"));
    let prevented = 0;
    const pending = f.form.events.submit({ preventDefault: () => { prevented += 1; } });
    await f.form.events.submit({ preventDefault: () => { prevented += 1; } });
    complete({ ok: true, redirected: true, url: "https://fixture.test/owned/old?job=first" }); await pending; await flush();
    assert(prevented === 2 && f.calls.filter(x => x.options.method === "POST").length === 1, "Repeated click duplicated cancellation");
    assert(f.calls[0].options.body.target === f.form, "Cancellation sent primary form settings");
    assert(!f.reloads && f.state.textContent === "Cancelled" && f.link.target === "_blank", "Cancel lost new draft or result link");
  });
  await test("cancel denial remains actionable and is never retried automatically", async () => {
    const f = setup({ dirty: true }); f.responses.push(reply("", 403), reply("running"));
    await f.form.events.submit({ preventDefault() {} }); await flush();
    assert(f.form.afterElement.textContent.includes("permission to cancel"), "Cancel denial hidden by polling");
    assert(f.calls.filter(x => x.options.method === "POST").length === 1 && !f.reloads, "Denied cancellation replayed or navigated");
  });
  await test("unconfirmed run is not labelled successful", async () => {
    const f = setup({ dirty: true }); f.responses.push(reply("unknown")); await f.tick();
    assert(f.status.textContent.includes("unconfirmed") && f.state.textContent === "Unconfirmed" && !f.reloads, "Unknown state misrepresented");
  });
  await test("back-forward restoration resumes status without executing", async () => {
    const f = setup({ dirty: true }); f.events.pagehide(); assert(!f.timers.size, "Pagehide kept timers");
    f.responses.push(reply("running")); f.events.pageshow(); await flush();
    assert(f.calls.length === 1 && !f.calls[0].options.method && f.timers.size === 1, "History restoration did not resume GET polling");
  });
  await test("late status after pagehide cannot reload a hidden draft", async () => {
    const f = setup({ dirty: true }); let complete;
    f.responses.push(() => new Promise(resolve => { complete = resolve; }));
    const pending = f.tick(); f.events.pagehide(); complete(reply("succeeded")); await pending;
    assert(!f.reloads && !f.link.target && !f.timers.size, "Stale completion changed the departed page");
    f.responses.push(reply("succeeded")); f.events.pageshow(); await flush();
    assert(!f.reloads && f.link.target === "_blank", "Returning to the draft did not safely show retained result");
  });
  await test("login redirect cannot confirm cancellation", async () => {
    const f = setup({ dirty: true }); f.responses.push({ ok: true, redirected: true, url: "https://fixture.test/login" }, reply("running"));
    await f.form.events.submit({ preventDefault() {} }); await flush();
    assert(f.form.afterElement.textContent.includes("Sign in again"), "Login redirect accepted as cancellation");
    assert(f.calls.filter(x => x.options.method === "POST").length === 1, "Login redirect retried cancellation");
  });
  await test("login redirect pauses status polling without losing the draft", async () => {
    const f = setup({ dirty: true }); f.responses.push({ ok: true, status: 200, redirected: true, url: "https://fixture.test/login" }); await f.tick();
    assert(!f.timers.size && f.status.textContent.includes("Sign in again") && !f.reloads, "Expired session was not actionable");
  });
  await test("unchanged native POST is protected while the previous run finishes", async () => {
    const f = setup(); const event = { target: f.form, defaultPrevented: false };
    f.events.submit(event); await flush();
    f.responses.push(reply("succeeded")); await f.tick();
    assert(!f.reloads && f.link.target === "_blank" && f.status.textContent.includes("new request"), "Old completion interrupted native submission");
    assert(f.calls.every(x => !x.options.method), "Observer repeated the native POST");
  });
  await test("later submit cancellation does not leave navigation pending", async () => {
    const f = setup(); const event = { target: f.form, defaultPrevented: false };
    f.events.submit(event); event.defaultPrevented = true; await flush();
    f.responses.push(reply("succeeded")); await f.tick();
    assert(f.reloads === 1, "Cancelled submission left pending navigation protection forever");
  });
  await test("async prevented and new-tab forms do not fence the current page", async () => {
    for (const kind of ["prevented", "new-tab", "dialog"]) {
      const f = setup(); if (kind === "new-tab") f.form.target = "_blank"; if (kind === "dialog") f.form.method = "dialog";
      f.events.submit({ target: f.form, defaultPrevented: kind === "prevented" }); await flush();
      f.responses.push(reply("succeeded")); await f.tick();
      assert(f.reloads === 1, "Non-navigation form blocked clean completion: " + kind);
    }
  });
  await test("pageshow clears stale native intent without resetting editor state", async () => {
    const f = setup(); f.events.submit({ target: f.form, defaultPrevented: false }); await flush();
    f.events.pageshow(); f.responses.push(reply("succeeded")); await f.tick();
    assert(f.reloads === 1 && f.draft.value === "new unsent settings", "Restoration retained native intent or changed field values");
  });
  await test("network cancellation failure does not retry POST", async () => {
    const f = setup({ dirty: true }); f.responses.push(() => { throw new TypeError("Network failed"); }, reply("running"));
    await f.form.events.submit({ preventDefault() {} }); await flush();
    assert(f.form.afterElement.textContent.includes("could not be confirmed"), "Uncertain network cancellation was hidden");
    assert(f.calls.filter(x => x.options.method === "POST").length === 1 && !f.reloads, "Uncertain network cancellation repeated or lost draft");
  });
  await test("timed-out cancellation does not retry POST", async () => {
    const f = setup({ dirty: true }); f.responses.push(() => { throw Object.assign(new Error("Timed out"), { name: "TimeoutError" }); }, reply("running"));
    await f.form.events.submit({ preventDefault() {} }); await flush();
    assert(f.form.afterElement.textContent.includes("never retried automatically"), "Timeout cancellation message unclear");
    assert(f.calls.filter(x => x.options.method === "POST").length === 1 && f.draft.value === "new unsent settings", "Timed-out cancellation repeated or lost draft");
  });
  await test("unknown cancellation response remains uncertain and never replays", async () => {
    for (const response of [{ ok: true, redirected: false }, { ok: true, redirected: true, url: "https://fixture.test/owned/old?job=different" }]) {
      const f = setup({ dirty: true }); f.responses.push(response, reply("running"));
      await f.form.events.submit({ preventDefault() {} }); await flush();
      assert(f.form.afterElement.textContent.includes("could not be confirmed"), "Unexpected response claimed cancellation");
      assert(f.calls.filter(x => x.options.method === "POST").length === 1 && !f.reloads, "Unknown cancellation response repeated POST or discarded draft");
    }
  });
  return results;
};
