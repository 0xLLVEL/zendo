const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const code = $("code");
const hl = $("hl");
const gutter = $("gutter");
const log = $("log");
const dot = $("dot");
const statusEl = $("status");
const stageEl = $("stage");
const stampEl = $("stamp");
const timingEl = $("timing");
const clientEl = $("client");
const integrityEl = $("integrity");
const runBtn = $("run");
const cursorEl = $("cursor");
const linesEl = $("lines");
const dirtyEl = $("dirty");
const errline = $("errline");
const splitEl = $("split");
const workEl = document.querySelector(".work");
const noiseEl = $("noise");

const LINE = 21;
const PAD = 14;
const MAX_LINES = 4000;

const SAMPLE = `-- ctrl+enter runs · ctrl+s saves
local players = game:GetService("Players")
local lp = players.LocalPlayer
print("local player:", lp and lp.Name or "none")
print("identity", getthreadidentity())
`;

// ── state ──────────────────────────────────────────────────────────────────

const state = {
  phase: "idle",     // idle | running | done | failed
  note: "",
  client: null,
  elevated: null,
  ms: 0,
  chunk: 0,
};

function lampClass() {
  if (state.phase === "failed") return "bad";
  if (state.phase === "running") return "busy";
  if (state.client) return "live";
  return "idle";
}

function statusText() {
  if (state.phase === "running") return state.note || "compiling";
  if (state.phase === "failed") return "failed — see output";
  if (state.phase === "done") return "ready";
  return state.client ? "ready" : "no client";
}

function render() {
  dot.className = "lamp " + lampClass();
  statusEl.textContent = statusText();
  statusEl.className = state.phase === "running" ? "running"
    : state.phase === "done" ? "done"
    : state.phase === "failed" ? "failed" : "";
  runBtn.disabled = state.phase === "running";

  clientEl.textContent = state.client ? `pid ${state.client}` : "no client";
  clientEl.className = "chip" + (state.client ? "" : " warn");

  if (state.elevated === null) {
    integrityEl.textContent = "integrity ?";
    integrityEl.className = "chip";
  } else if (state.elevated) {
    integrityEl.textContent = "elevated";
    integrityEl.className = "chip";
  } else {
    integrityEl.textContent = "medium";
    integrityEl.className = "chip warn";
    integrityEl.title = "client runs elevated — inject needs an elevated UI";
  }

  $("r-client").textContent = state.client ? String(state.client) : "—";
  $("r-integrity").textContent = state.elevated === null ? "—" : state.elevated ? "elevated" : "medium";
  $("r-phase").textContent = state.phase;
  stageEl.textContent = state.note || state.phase;
  stageEl.className = "chip" + (state.phase === "running" ? " fresh" : "");
  timingEl.textContent = state.ms ? `${state.ms} ms · ${state.chunk} bytes` : "";
  $("r-phase").className = state.phase === "failed" ? "bad" : state.phase === "running" ? "warn" : "";
}

// ── highlight ──────────────────────────────────────────────────────────────

const KEYWORDS = new Set(("and break continue do else elseif end export false for " +
  "function if in local nil not or repeat return then true type until while").split(" "));

const BUILTINS = new Set(("game workspace script shared plugin task print warn error " +
  "assert pcall xpcall select type typeof tostring tonumber pairs ipairs next rawget rawset " +
  "rawequal rawlen getmetatable setmetatable require tick time wait spawn delay settings " +
  "getgenv getrenv hookfunction hookmetamethod newcclosure").split(" "));

const esc = (s) => s.replace(/[&<>]/g, (c) => (c === "&" ? "&amp;" : c === "<" ? "&lt;" : "&gt;"));
const span = (cls, text) => `<span class="${cls}">${esc(text)}</span>`;

function longEnd(src, at) {
  let j = at + 1, eq = 0;
  while (src[j] === "=") { eq++; j++; }
  if (src[j] !== "[") return 0;
  const close = "]" + "=".repeat(eq) + "]";
  const e = src.indexOf(close, j + 1);
  return e < 0 ? src.length : e + close.length;
}

function highlight(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];

    if (c === "-" && src[i + 1] === "-") {
      let end = 0;
      if (src[i + 2] === "[") end = longEnd(src, i + 2);
      if (!end) {
        const nl = src.indexOf("\n", i);
        end = nl < 0 ? n : nl;
      }
      out += span("com", src.slice(i, end));
      i = end;
      continue;
    }

    if (c === "[") {
      const end = longEnd(src, i);
      if (end) { out += span("str", src.slice(i, end)); i = end; continue; }
    }

    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== "\n") {
        if (src[j] === "\\") j++;
        j++;
      }
      if (j < n && src[j] === c) j++;
      out += span("str", src.slice(i, j));
      i = j;
      continue;
    }

    if (c >= "0" && c <= "9") {
      const m = /^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/.exec(src.slice(i, i + 64));
      const t = m ? m[0] : c;
      out += span("num", t);
      i += t.length;
      continue;
    }

    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      if (KEYWORDS.has(word)) out += span("kw", word);
      else if (BUILTINS.has(word)) out += span("bi", word);
      else {
        let k = j;
        while (src[k] === " " || src[k] === "\t") k++;
        out += src[k] === "(" ? span("fn", word) : esc(word);
      }
      i = j;
      continue;
    }

    const op = /^(?:\.\.\.|\.\.|==|~=|<=|>=|::|[-+*/%^#<>=~&|])/.exec(src.slice(i, i + 3));
    if (op) { out += span("op", op[0]); i += op[0].length; continue; }

    if ("{}()[].,:;".includes(c)) { out += span("punct", c); i++; continue; }

    out += esc(c);
    i++;
  }
  return out;
}

let lastCount = -1;
let painting = false;

function paint() {
  painting = false;
  const value = code.value;
  hl.innerHTML = highlight(value) + "\n";
  document.body.classList.add("hl-on");
  const count = value.split("\n").length;
  if (count !== lastCount) {
    lastCount = count;
    let nums = "";
    for (let i = 1; i <= count; i++) nums += i + "\n";
    gutter.textContent = nums;
    linesEl.textContent = count + (count === 1 ? " line" : " lines");
  }
  syncScroll();
  placeErrline();
}

function schedulePaint() {
  if (painting) return;
  painting = true;
  requestAnimationFrame(paint);
}

function syncScroll() {
  hl.scrollTop = code.scrollTop;
  hl.scrollLeft = code.scrollLeft;
  gutter.scrollTop = code.scrollTop;
}

// ── console ────────────────────────────────────────────────────────────────

const NOISE = [
  /^chunk \d+ bytes, injecting\s*$/,
  /^zendo-inject\b/,
  /^ {2}(remote image|reloc dir|resolved|wrote|DllMain|hijack)/,
  /^\[z\] /,
  /^\[pipe\] /,
  /^(REPL|ZEND1|RDY|END|EXITCODE)\b/,
  /^(capi|flush|raw dyn|probe|cap)\b.*\b(load ret|PROTO80|raw|done|st=|ci=|r\d|err)\b/,
  /^(ca|ra) r\d /,
  /^err tt=/,
  /^RUN\b/,
  /^f=0x[0-9a-f]+$/,
  /^len=\d+/,
];

const isNoise = (line) => NOISE.some((re) => re.test(line));

function classify(s) {
  if (/^warn:|warning/i.test(s)) return "warn";
  if (/error|attempt to|traceback|stack begin|invalid argument|cannot/i.test(s)) return "err";
  if (/^»/.test(s)) return "ok";
  if (/^(RUN|END|PRE-CLOSE|POST|EXIT)\b/.test(s)) return "meta";
  return "";
}

let logLines = [];

function addNode(item) {
  const div = document.createElement("div");
  div.className = "line " + item.cls;
  div.textContent = item.text === "" ? " " : item.text;
  log.appendChild(div);
}

function rebuildLog() {
  log.textContent = "";
  const frag = document.createDocumentFragment();
  for (const item of logLines) {
    if (!noiseEl.checked && item.noise) continue;
    const div = document.createElement("div");
    div.className = "line " + item.cls;
    div.textContent = item.text === "" ? " " : item.text;
    frag.appendChild(div);
  }
  log.appendChild(frag);
}

function addText(text) {
  if (!text) return;
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
  const parts = text.split("\n");
  if (parts[parts.length - 1] === "") parts.pop();
  for (const line of parts) {
    const item = { text: line, cls: classify(line), noise: isNoise(line) };
    logLines.push(item);
    if (noiseEl.checked || !item.noise) addNode(item);
  }
  if (logLines.length > MAX_LINES) {
    logLines.splice(0, logLines.length - MAX_LINES);
    rebuildLog();
  }
  if (atBottom) log.scrollTop = log.scrollHeight;
  stampEl.textContent = new Date().toLocaleTimeString();
}

function clearLog() {
  logLines = [];
  log.textContent = "";
  stampEl.textContent = "";
}

// ── editor helpers ─────────────────────────────────────────────────────────

function cursorPos() {
  const p = code.selectionStart;
  const before = code.value.slice(0, p);
  const line = before.split("\n").length;
  const col = p - (before.lastIndexOf("\n") + 1) + 1;
  cursorEl.textContent = `Ln ${line}, Col ${col}`;
}

function placeErrline() {
  const line = Number(errline.dataset.line || 0);
  if (!line) { errline.hidden = true; return; }
  const top = PAD + (line - 1) * LINE - code.scrollTop;
  if (top < PAD - LINE || top > code.clientHeight - PAD) {
    errline.hidden = true;
    return;
  }
  errline.hidden = false;
  errline.style.top = top + "px";
}

function markError(line) {
  errline.dataset.line = line ? String(line) : "";
  placeErrline();
}

function indentSelection(outdent) {
  const start = code.selectionStart;
  const end = code.selectionEnd;
  const value = code.value;
  const from = value.lastIndexOf("\n", start - 1) + 1;
  const to = end + (value.slice(end).indexOf("\n") === -1 ? value.length - end : value.slice(end).indexOf("\n"));

  const block = value.slice(from, to);
  const shifted = block.split("\n").map((line) => {
    if (outdent) return line.replace(/^ {1,4}/, "");
    return "    " + line;
  }).join("\n");

  code.setRangeText(shifted, from, to, "select");
  schedulePaint();
  persist();
}

function toggleComment() {
  const start = code.selectionStart;
  const end = code.selectionEnd;
  const value = code.value;
  const from = value.lastIndexOf("\n", start - 1) + 1;
  let to = value.indexOf("\n", end);
  if (to === -1) to = value.length;

  const lines = value.slice(from, to).split("\n");
  const live = lines.filter((l) => l.trim().length > 0);
  const commented = live.length > 0 && live.every((l) => /^\s*-- /.test(l));

  const next = lines.map((l) => {
    if (!l.trim()) return l;
    if (commented) return l.replace(/^(\s*)-- /, "$1");
    return l.replace(/^(\s*)/, "$1-- ");
  }).join("\n");

  code.setRangeText(next, from, to, "select");
  schedulePaint();
  persist();
}

// ── persistence ────────────────────────────────────────────────────────────

const LS = {
  script: "zendo.script",
  console: "zendo.console",
  noise: "zendo.noise",
  runs: "zendo.runs",
};

function persist() {
  localStorage.setItem(LS.script, code.value);
  dirtyEl.hidden = false;
}

function saveLocal() {
  localStorage.setItem(LS.script, code.value);
}

function loadRuns() {
  try { return JSON.parse(localStorage.getItem(LS.runs) || "[]"); } catch { return []; }
}

function pushRun(ok) {
  const runs = loadRuns();
  runs.unshift({ t: Date.now(), ms: state.ms, chunk: state.chunk, ok });
  localStorage.setItem(LS.runs, JSON.stringify(runs.slice(0, 8)));
  renderRuns();
}

function renderRuns() {
  const list = $("runs");
  list.textContent = "";
  const runs = loadRuns();
  if (!runs.length) {
    const li = document.createElement("li");
    li.textContent = "none yet";
    list.appendChild(li);
    return;
  }
  for (const r of runs) {
    const li = document.createElement("li");
    const when = new Date(r.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const mark = document.createElement("span");
    mark.className = r.ok ? "ok" : "no";
    mark.textContent = r.ok ? "ok" : "fail";
    const time = document.createElement("span");
    time.textContent = when;
    const ms = document.createElement("b");
    ms.textContent = `${r.ms} ms`;
    li.append(mark, time, ms);
    list.appendChild(li);
  }
}

// ── split ──────────────────────────────────────────────────────────────────

function setConsoleHeight(px) {
  const h = workEl.clientHeight;
  const clamped = Math.max(120, Math.min(h - 140, px));
  document.documentElement.style.setProperty("--console-h", clamped + "px");
  return clamped;
}

function initSplit() {
  const saved = Number(localStorage.getItem(LS.console) || 0);
  if (saved) setConsoleHeight(saved);
  let dragging = false;
  const onMove = (e) => {
    if (!dragging) return;
    const rect = workEl.getBoundingClientRect();
    const px = setConsoleHeight(rect.bottom - e.clientY);
    localStorage.setItem(LS.console, String(px));
  };
  splitEl.addEventListener("pointerdown", (e) => {
    dragging = true;
    splitEl.setPointerCapture(e.pointerId);
    e.preventDefault();
  });
  splitEl.addEventListener("pointermove", onMove);
  splitEl.addEventListener("pointerup", () => { dragging = false; });
  splitEl.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
    e.preventDefault();
    const current = workEl.querySelector(".console").clientHeight;
    const next = setConsoleHeight(current + (e.key === "ArrowUp" ? 24 : -24));
    localStorage.setItem(LS.console, String(next));
  });
}

// ── telemetry ──────────────────────────────────────────────────────────────

function fmtAge(ms) {
  if (!ms || ms < 1000) return (ms || 0) + "ms";
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m " + (s % 60) + "s";
  return Math.floor(m / 60) + "h " + (m % 60) + "m";
}

function setWire(id, text, age, warnAfter) {
  const el = $(id);
  el.textContent = text || "—";
  el.className = text ? (age < 8000 ? "val fresh" : age > warnAfter ? "val warn" : "val") : "val";
}

async function refreshTelemetry() {
  try {
    const t = await invoke("telemetry");
    setWire("r-stage", t.stage && t.stage.text, t.stage ? t.stage.age : 0, 600000);
    $("r-age").textContent = t.stage ? fmtAge(t.stage.age) : "—";
    $("r-loop").textContent = t.loop && t.loop.text ? t.loop.text : "—";
    setWire("r-mutex", t.mutex && t.mutex.text, t.mutex ? t.mutex.age : 0, 600000);
    if (t.log) {
      const short = t.log.name.replace(/^0\.\d+\.\d+_/, "").replace(/_last\.log$/, "");
      $("r-log").textContent = short;
      $("r-log").title = `${t.log.name} · ${t.log.size} bytes`;
      setWire("r-log", short, t.log.age, 600000);
    } else {
      $("r-log").textContent = "—";
    }
  } catch {
    /* the rail is a convenience; a failed read must not disturb a run */
  }
}

function tickTelemetry() {
  refreshTelemetry();
  setTimeout(tickTelemetry, 2000);
}

async function pollClient() {
  try {
    const pid = await invoke("client_pid");
    if (pid !== state.client) {
      state.client = pid || null;
      render();
    }
  } catch {
    state.client = null;
    render();
  }
  setTimeout(pollClient, 2000);
}

// ── run ────────────────────────────────────────────────────────────────────

let streamed = "";

async function run() {
  if (state.phase === "running") return;
  if (!code.value.trim()) return;
  state.phase = "running";
  state.note = "compiling";
  state.ms = 0;
  state.chunk = 0;
  streamed = "";
  clearLog();
  markError(0);
  render();

  try {
    const res = await invoke("run_script", { code: code.value, steps: "chunk" });
    if (res.output) {
      if (res.output.startsWith(streamed)) addText(res.output.slice(streamed.length));
      else if (!streamed) addText(res.output);
    }
    state.ms = res.ms;
    state.chunk = res.chunk;
    state.phase = "done";
    state.note = "done";
    scanError(res.output || "");
    pushRun(true);
  } catch (err) {
    addText(String(err));
    state.phase = "failed";
    state.note = "failed";
    pushRun(false);
  }
  render();
  refreshTelemetry();
}

function scanError(text) {
  const m = /([\w.-]+\.luau):(\d+)/.exec(text) || /\bline (\d+)\b/i.exec(text);
  if (m) {
    const line = Number(m[2] || m[1]);
    if (line > 0) {
      markError(line);
      const top = PAD + (line - 7) * LINE;
      code.scrollTop = Math.max(0, top);
      syncScroll();
      placeErrline();
    }
  }
}

// ── wiring ─────────────────────────────────────────────────────────────────

code.addEventListener("input", () => {
  schedulePaint();
  cursorPos();
  clearTimeout(saveLocal.timer);
  saveLocal.timer = setTimeout(persist, 250);
});

code.addEventListener("scroll", () => { syncScroll(); placeErrline(); });

document.addEventListener("selectionchange", () => {
  if (document.activeElement === code) cursorPos();
});
code.addEventListener("click", cursorPos);
code.addEventListener("keyup", cursorPos);

code.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;

  if (e.key === "Enter" && mod) {
    e.preventDefault();
    run();
    return;
  }
  if (e.key === "s" && mod) {
    e.preventDefault();
    invoke("save_script", { code: code.value })
      .then((path) => {
        dirtyEl.hidden = true;
        state.note = "saved";
        render();
        stampEl.textContent = "saved " + path;
      })
      .catch((err) => addText(String(err)));
    return;
  }
  if (e.key === "/" && mod) {
    e.preventDefault();
    toggleComment();
    return;
  }
  if (e.key === "Tab") {
    e.preventDefault();
    if (e.shiftKey) indentSelection(true);
    else if (code.selectionStart === code.selectionEnd) {
      code.setRangeText("    ", code.selectionStart, code.selectionEnd, "end");
      schedulePaint();
      persist();
    } else {
      indentSelection(false);
    }
    return;
  }
  if (e.key === "Enter") {
    // keep the current indentation on a fresh line, nothing clever beyond it
    const p = code.selectionStart;
    const lineStart = code.value.lastIndexOf("\n", p - 1) + 1;
    const indent = /^[ \t]*/.exec(code.value.slice(lineStart, p))[0];
    if (indent) {
      e.preventDefault();
      code.setRangeText("\n" + indent, p, code.selectionEnd, "end");
      schedulePaint();
      persist();
    }
  }
});

runBtn.addEventListener("click", run);

noiseEl.checked = localStorage.getItem(LS.noise) === "1";
noiseEl.addEventListener("change", () => {
  localStorage.setItem(LS.noise, noiseEl.checked ? "1" : "0");
  rebuildLog();
});

$("clear").addEventListener("click", clearLog);
$("copy").addEventListener("click", async () => {
  const text = logLines.map((l) => l.text).join("\n");
  try {
    await navigator.clipboard.writeText(text);
    stampEl.textContent = "copied";
  } catch {
    stampEl.textContent = "clipboard denied";
  }
});

listen("zendo://out", (e) => {
  streamed += e.payload;
  addText(e.payload);
});
listen("zendo://stage", (e) => {
  state.note = String(e.payload);
  render();
});

// ── boot ───────────────────────────────────────────────────────────────────

const saved = localStorage.getItem(LS.script);
code.value = saved !== null ? saved : SAMPLE;
dirtyEl.hidden = saved !== null;

invoke("elevated").then((on) => { state.elevated = !!on; render(); }).catch(() => render());

paint();
cursorPos();
renderRuns();
initSplit();
render();
pollClient();
tickTelemetry();
