(function () {
  window.__INFISICAL_RRWEB_EVENTS = window.__INFISICAL_RRWEB_EVENTS || [];

  const startRecorder = () => {
    if (typeof window.rrwebRecord !== "function") return false;
    if (window.__INFISICAL_RRWEB_STOP) return true;

    window.__INFISICAL_RRWEB_STOP = window.rrwebRecord({
      emit(event) {
        window.__INFISICAL_RRWEB_EVENTS.push(event);
      }
    });

    if (typeof window.rrwebRecord.takeFullSnapshot === "function") {
      window.rrwebRecord.takeFullSnapshot(true);
    }

    return true;
  };

  if (!startRecorder()) {
    const interval = window.setInterval(() => {
      if (startRecorder()) {
        window.clearInterval(interval);
      }
    }, 25);

    window.addEventListener("load", () => {
      if (startRecorder()) {
        window.clearInterval(interval);
      }
    }, { once: true });
  }

  window.addEventListener("pagehide", () => {
    try {
      if (typeof window.__infisicalFlushRRWebEvents === "function") {
        const events = window.__INFISICAL_RRWEB_EVENTS || [];
        window.__infisicalFlushRRWebEvents(events, "pagehide");
        window.__INFISICAL_RRWEB_EVENTS = [];
      }
    } catch {}

    if (typeof window.__INFISICAL_RRWEB_STOP === "function") {
      window.__INFISICAL_RRWEB_STOP();
      window.__INFISICAL_RRWEB_STOP = null;
    }
  });
})();
