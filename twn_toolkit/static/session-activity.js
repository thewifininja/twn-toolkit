(function () {
  const notice = document.getElementById("session-expiry-notice");
  if (!notice || !notice.dataset.activityUrl) return;
  const interval = 5000;
  let lastSignal = -Infinity;
  let inFlight = false;
  let pendingActivity = false;
  let timer = null;

  function schedule(seconds) {
    clearTimeout(timer);
    // Even with expiry disabled, periodically observe logout or a policy change.
    timer = setTimeout(() => check(false), seconds === null ? 60000 : Math.max(1000, Math.min(60000, seconds * 1000 + 1000)));
  }

  async function check(active) {
    if (inFlight) return;
    inFlight = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(notice.dataset.activityUrl, {
        method: active ? "POST" : "GET",
        headers: active ? {"Accept": "application/json", "X-TWN-User-Activity": "1"} : {"Accept": "application/json"},
        cache: "no-store",
        signal: controller.signal,
      });
      if (response.status === 401 || response.redirected) {
        notice.hidden = false;
        schedule(30);
        return;
      }
      if (!response.ok) throw new Error("Session check unavailable");
      const data = await response.json();
      notice.hidden = true;
      schedule(data.remaining_seconds);
    } catch (_error) {
      // A network failure does not prove expiry and must not discard a draft.
      schedule(5);
    } finally {
      clearTimeout(timeout);
      inFlight = false;
      if (pendingActivity) {
        pendingActivity = false;
        if (!document.hidden && performance.now() - lastSignal >= interval) {
          lastSignal = performance.now();
          check(notice.hidden);
        }
      }
    }
  }

  function activity(event) {
    if (!event.isTrusted || document.hidden) return;
    // Signing out must not race a last activity update from the sign-out control.
    const form = event.target.closest && event.target.closest("form");
    if (form && new URL(form.action, location.href).pathname.endsWith("/logout")) {
      pendingActivity = false;
      return;
    }
    const now = performance.now();
    if (now - lastSignal < interval) return;
    if (inFlight) {
      pendingActivity = true;
      return;
    }
    lastSignal = now;
    check(notice.hidden);
  }

  for (const name of ["keydown", "pointerdown", "pointermove", "input", "wheel", "touchmove"]) {
    document.addEventListener(name, activity, {capture: true, passive: true});
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) check(false);
  });
  window.addEventListener("pageshow", () => check(false));
  check(false);
})();
