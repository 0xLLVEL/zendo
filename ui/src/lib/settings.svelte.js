const KEY = "zendo.settings.v2";

const DEFAULTS = {
  font: 13,
  wrap: false,
  noise: false,
  autoscroll: true,
  accent: "sky",
  console: 240,
};

const ACCENTS = {
  sky: { wave: "#aac1d5", ink: "#0a1016" },
  mint: { wave: "#9fcfc2", ink: "#08140f" },
  iris: { wave: "#b3b8d4", ink: "#0c0e18" },
  rose: { wave: "#d3aab8", ink: "#170a10" },
};

function load() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) || "{}");
    return { ...DEFAULTS, ...raw };
  } catch {
    return { ...DEFAULTS };
  }
}

export const settings = $state(load());

export function paint() {
  const accent = ACCENTS[settings.accent] ?? ACCENTS.mint;
  document.documentElement.style.setProperty("--accent", accent.wave);
  document.documentElement.style.setProperty("--accent-ink", accent.ink);
}

export function update(patch) {
  Object.assign(settings, patch);
  localStorage.setItem(KEY, JSON.stringify({ ...settings }));
  paint();
}

export function reset() {
  Object.assign(settings, DEFAULTS);
  localStorage.setItem(KEY, JSON.stringify({ ...settings }));
  paint();
}

paint();
