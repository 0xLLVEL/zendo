const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const code = $("code");
const gutter = $("gutter");
const log = $("log");
const dot = $("dot");
const statusEl = $("status");
const stageEl = $("stage");
const timingEl = $("timing");
const clientEl = $("client");
const runBtn = $("run");

let running = false;

const SAMPLE = `-- ctrl+enter to run
local players = game:GetService("Players")
print("local player:", players.LocalPlayer and players.LocalPlayer.Name or "none")
print("identity ok", 5050)
return "dyn";`;

function setDot(state) {
  dot.className = "dot " + state;
}

function lineCount() {
  const lines = code.value.split("\n").length;
  $("lines").textContent = lines + (lines === 1 ? " line" : " lines");
  let out = "";
  for (let i = 1; i <= lines; i++) out += i + "\n";
  gutter.textContent = out;
  gutter.scrollTop = code.scrollTop;
}

// The pipe carries the payload's bring-up noise next to the script's own
// output. Only the script's lines (» …) and real errors are worth showing.
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

function clean(text) {
  return text
    .split("\n")
    .filter((line) => line.length === 0 || !NOISE.some((re) => re.test(line)))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
}

function append(text, cls) {
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
  text = clean(text);
  if (!text) return;
  if (cls) {
    const span = document.createElement("span");
    span.className = cls;
    span.textContent = text;
    log.appendChild(span);
  } else {
    log.appendChild(document.createTextNode(text));
  }
  if (atBottom) log.scrollTop = log.scrollHeight;
}

function setRunning(on) {
  running = on;
  runBtn.disabled = on;
  if (on) {
    setDot("busy");
    statusEl.textContent = "running";
  } else {
    setDot("live");
    statusEl.textContent = "ready";
  }
}

async function run() {
  if (running) return;
  if (!code.value.trim()) return;
  setRunning(true);
  log.textContent = "";
  stageEl.textContent = "compiling";
  timingEl.textContent = "";
  try {
    const res = await invoke("run_script", { code: code.value, steps: "chunk" });
    if (res.output) append(res.output);
    stageEl.textContent = "done";
    timingEl.textContent = `${res.ms} ms · ${res.chunk} bytes`;
    setDot("live");
  } catch (err) {
    append(String(err), "err");
    append("\n", "err");
    stageEl.textContent = "failed";
    setDot("dead");
  } finally {
    setRunning(false);
  }
}

async function pollClient() {
  try {
    const pid = await invoke("client_pid");
    if (pid) {
      clientEl.textContent = `client pid ${pid}`;
      if (!running) setDot("live");
    } else {
      clientEl.textContent = "no client — open Roblox";
      if (!running) setDot("dead");
    }
  } catch {
    clientEl.textContent = "client lookup failed";
  }
  setTimeout(pollClient, 3000);
}

code.addEventListener("input", lineCount);
code.addEventListener("scroll", () => (gutter.scrollTop = code.scrollTop));
code.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    run();
    return;
  }
  if (e.key === "Tab") {
    e.preventDefault();
    const start = code.selectionStart;
    const end = code.selectionEnd;
    code.setRangeText("    ", start, end, "end");
    lineCount();
  }
});
runBtn.addEventListener("click", run);

listen("zendo://out", (e) => append(e.payload));
listen("zendo://stage", (e) => (stageEl.textContent = e.payload));

code.value = SAMPLE;
lineCount();
pollClient();
