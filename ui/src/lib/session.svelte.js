import { invoke, listen } from "./bridge.js";
import { addOutput, clearOutput } from "./output.svelte.js";

const RUNS_KEY = "zendo.runs";

function loadRuns() {
  try {
    const raw = JSON.parse(localStorage.getItem(RUNS_KEY) || "[]");
    return Array.isArray(raw) ? raw.slice(0, 8) : [];
  } catch {
    return [];
  }
}

export const session = $state({
  phase: "idle", // idle | running | done | failed
  note: "",
  client: null,
  profile: null,
  elevated: null,
  ms: 0,
  chunk: 0,
  errorLine: 0,
  streamed: "",
  runId: 0,
  stage: null,
  stageAge: 0,
  loopMark: null,
  mutex: null,
  mutexAge: 0,
  log: null,
  runs: loadRuns(),
});

export function lampClass(s) {
  if (s.phase === "failed") return "bad";
  if (s.phase === "running") return "busy";
  if (s.client) return "live";
  return "idle";
}

export function statusText(s) {
  if (s.phase === "running") return s.note || "starting";
  if (s.phase === "failed") return "failed — see output";
  if (s.phase === "done") return "ready";
  return s.client ? "ready" : "no client";
}

export function fmtAge(ms) {
  if (!ms || ms < 1000) return (ms || 0) + "ms";
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return sec + "s";
  const min = Math.floor(sec / 60);
  if (min < 60) return min + "m " + (sec % 60) + "s";
  return Math.floor(min / 60) + "h " + (min % 60) + "m";
}

export function stageFresh(s) {
  return s.stage && s.stageAge < 8000;
}

export function scanError(text) {
  const m = /([\w.-]+\.luau):(\d+)/.exec(text) || /\bline (\d+)\b/i.exec(text);
  if (!m) return 0;
  const n = Number(m[2] || m[1]);
  return n > 0 ? n : 0;
}

function pushRun(ok) {
  session.runs = [{ t: Date.now(), ms: session.ms, chunk: session.chunk, ok }, ...session.runs].slice(0, 8);
  localStorage.setItem(RUNS_KEY, JSON.stringify(session.runs));
}

export async function runScript(source) {
  if (session.phase === "running") return;
  session.phase = "running";
  session.note = "starting";
  session.ms = 0;
  session.chunk = 0;
  session.errorLine = 0;
  session.streamed = "";
  clearOutput();

  // The command returns as soon as the run thread exists. Completion arrives as
  // a `zendo://run` event, so a wedged pipe cannot pin the button: the host's
  // watchdog emits the same event on its own clock.
  try {
    session.runId = await invoke("start_run", { code: source, steps: "defer" });
    clearTimeout(runTimer);
    runTimer = setTimeout(() => {
      if (session.phase !== "running") return;
      addOutput("run did not report back; releasing the button\n");
      session.phase = "failed";
      session.note = "no response";
      pushRun(false);
    }, 45000);
  } catch (err) {
    addOutput(String(err));
    session.phase = "failed";
    session.note = "failed";
    pushRun(false);
  }
}

let runTimer = 0;

function finishRun(ev) {
  if (!ev || ev.id !== session.runId) return;
  if (session.phase !== "running") return;
  clearTimeout(runTimer);
  if (ev.output) {
    if (ev.output.startsWith(session.streamed)) {
      addOutput(ev.output.slice(session.streamed.length));
    } else if (!session.streamed) {
      addOutput(ev.output);
    }
  }
  session.ms = ev.ms;
  session.chunk = ev.chunk;
  if (ev.ok) {
    session.phase = "done";
    session.note = "done";
    session.errorLine = scanError(ev.output || "");
    pushRun(true);
  } else {
    if (ev.error) addOutput(ev.error + "\n");
    session.phase = "failed";
    session.note = ev.timeout ? "timed out" : "failed";
    pushRun(false);
  }
  refreshTelemetry();
}

export async function saveScript(source) {
  const path = await invoke("save_script", { code: source });
  return path;
}

export async function refreshTelemetry() {
  try {
    const t = await invoke("telemetry");
    session.stage = t.stage || null;
    session.stageAge = t.stage ? t.stage.age : 0;
    session.loopMark = t.loop ? t.loop.text : null;
    session.mutex = t.mutex || null;
    session.mutexAge = t.mutex ? t.mutex.age : 0;
    session.log = t.log || null;
  } catch {
    /* the rail is a convenience; a failed read must not disturb a run */
  }
}

let started = false;

export function startSession() {
  if (started) return;
  started = true;

  listen("zendo://run", (e) => finishRun(e.payload));

  const client = async () => {
    try {
      const pid = await invoke("client_pid");
      session.client = pid || null;
      if (pid) {
        const p = await invoke("profile").catch(() => null);
        session.profile = p || null;
      } else {
        session.profile = null;
      }
    } catch {
      session.client = null;
      session.profile = null;
    }
    setTimeout(client, 2000);
  };

  const telemetry = async () => {
    await refreshTelemetry();
    setTimeout(telemetry, 2000);
  };

  invoke("elevated")
    .then((on) => {
      session.elevated = !!on;
    })
    .catch(() => {});

  client();
  telemetry();
}
