const MAX_LINES = 4000;

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

export const output = $state({
  lines: [],
  noise: false,
  stamp: "",
  stick: true,
});

export function addOutput(text) {
  if (!text) return;
  const parts = text.split("\n");
  if (parts[parts.length - 1] === "") parts.pop();
  const t = Date.now();
  for (const line of parts) {
    output.lines.push({ text: line, cls: classify(line), noise: isNoise(line), t });
  }
  if (output.lines.length > MAX_LINES) {
    output.lines.splice(0, output.lines.length - MAX_LINES);
  }
  output.stamp = new Date().toLocaleTimeString();
}

export function clearOutput() {
  output.lines = [];
  output.stamp = "";
}

export function setNoise(on) {
  output.noise = on;
  localStorage.setItem("zendo.noise", on ? "1" : "0");
}

export function plainText() {
  return output.lines.map((l) => l.text).join("\n");
}

export function restoreNoise() {
  output.noise = localStorage.getItem("zendo.noise") === "1";
}
