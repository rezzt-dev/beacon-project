// the live connection: server-sent events with resume, growing backoff and a stall watchdog.

const MAX_BACKOFF = 30000;
const STALL = 45000; // the server sends something at least every 15 s
const MAX_PENDING = 500; // past this, a paused screen reloads everything on resume instead

export class Live {
  constructor({ onChange, onStatus, onReset, onState }) {
    this.onChange = onChange;
    this.onStatus = onStatus;
    this.onReset = onReset;
    this.onState = onState;
    this.lastId = null;
    this.attempt = 0;
    this.source = null;
    this.timer = null;
    this.watchdog = null;
    this.lastMessage = 0;
    this.paused = false;
    this.pending = [];
    this.overflow = false;
    this.state = "connecting";
    window.addEventListener("online", () => this.reconnect(0));
    window.addEventListener("offline", () => this.setState("offline"));
  }

  connect() {
    this.close();
    const url = "/api/v1/stream" + (this.lastId !== null ? "?after=" + encodeURIComponent(this.lastId) : "");
    const source = new EventSource(url, { withCredentials: true });
    this.source = source;
    this.setState(this.attempt ? "reconnecting" : "connecting");
    const seen = (event) => {
      this.lastMessage = Date.now();
      if (event.lastEventId) this.lastId = Number(event.lastEventId);
    };
    source.addEventListener("open", () => { this.lastMessage = Date.now(); });
    source.addEventListener("hello", (event) => {
      seen(event);
      this.attempt = 0;
      this.setState("live");
      this.onStatus(JSON.parse(event.data).status);
    });
    source.addEventListener("reset", (event) => {
      seen(event);
      this.attempt = 0;
      this.setState("live");
      this.pending = [];
      this.onReset();
    });
    source.addEventListener("change", (event) => {
      seen(event);
      if (this.state !== "live") { this.attempt = 0; this.setState("live"); }
      const change = JSON.parse(event.data);
      if (!this.paused) this.onChange([change]);
      else {
        if (this.pending.length < MAX_PENDING) this.pending.push(change);
        else this.overflow = true;
        this.setState(this.state);
      }
    });
    source.addEventListener("status", (event) => {
      seen(event);
      if (this.state !== "live") { this.attempt = 0; this.setState("live"); }
      this.onStatus(JSON.parse(event.data));
    });
    source.onerror = () => {
      // the browser would retry on its own at a fixed pace; we back off instead
      if (source.readyState === EventSource.CLOSED || this.state !== "offline") this.reconnect();
    };
    clearInterval(this.watchdog);
    this.watchdog = setInterval(() => {
      if (this.lastMessage && Date.now() - this.lastMessage > STALL) this.reconnect();
    }, 5000);
  }

  reconnect(delay) {
    this.close();
    if (!navigator.onLine) { this.setState("offline"); return; }
    const wait = delay ?? Math.min(MAX_BACKOFF, 1000 * 2 ** this.attempt) * (0.75 + Math.random() * 0.5);
    this.attempt += 1;
    this.setState("reconnecting", Math.round(wait / 1000));
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.connect(), wait);
  }

  close() {
    if (this.source) {
      this.source.close();
      this.source = null;
    }
    clearInterval(this.watchdog);
  }

  setState(state, retryIn) {
    this.state = state;
    this.onState(state, { retryIn, attempt: this.attempt, pending: this.pending.length, paused: this.paused });
  }

  /** stop repainting the screen; data keeps arriving and is applied on resume. the monitor is untouched. */
  pause() {
    this.paused = true;
    this.setState(this.state);
  }

  resume() {
    this.paused = false;
    const queued = this.pending;
    this.pending = [];
    if (this.overflow) { this.overflow = false; this.onReset(); }
    else if (queued.length) this.onChange(queued);
    this.setState(this.state);
  }
}
