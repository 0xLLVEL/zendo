const KEY = "zendo.tabs.v2";

const SAMPLE = `-- ctrl+enter runs, ctrl+s saves
local players = game:GetService("Players")
local lp = players.LocalPlayer
print("local player:", lp and lp.Name or "none")
print("identity", getthreadidentity())
`;

let seq = 0;
const uid = () => `t${Date.now().toString(36)}${(seq++).toString(36)}`;

function load() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) || "null");
    if (raw && Array.isArray(raw.list) && raw.list.length) {
      return {
        list: raw.list.map((t) => ({ id: t.id, name: t.name, source: t.source ?? "", saved: t.source ?? "", error: 0 })),
        active: raw.list.some((t) => t.id === raw.active) ? raw.active : raw.list[0].id,
      };
    }
  } catch {
    /* a corrupt tab file is not worth a broken start */
  }
  const id = uid();
  return { list: [{ id, name: "script.luau", source: SAMPLE, saved: SAMPLE, error: 0 }], active: id };
}

const fresh = load();

export const tabs = $state({
  list: fresh.list,
  active: fresh.active,
});

export function persist() {
  localStorage.setItem(
    KEY,
    JSON.stringify({
      list: tabs.list.map((t) => ({ id: t.id, name: t.name, source: t.source })),
      active: tabs.active,
    })
  );
}

let timer;
function schedule() {
  clearTimeout(timer);
  timer = setTimeout(persist, 300);
}

export function current() {
  return tabs.list.find((t) => t.id === tabs.active) ?? tabs.list[0];
}

export function select(id) {
  tabs.active = id;
  schedule();
}

export function add(name, source) {
  const id = uid();
  let n = 1;
  let label = name || "untitled.luau";
  if (!name) {
    while (tabs.list.some((t) => t.name === label)) label = `untitled ${++n}.luau`;
  }
  const body = source ?? "";
  tabs.list.push({ id, name: label, source: body, saved: body, error: 0 });
  tabs.active = id;
  schedule();
  return id;
}

export function close(id) {
  if (tabs.list.length === 1) {
    // Never leave an empty strip: clear the last one instead of closing it.
    const only = tabs.list[0];
    only.source = "";
    only.saved = "";
    return;
  }
  const at = tabs.list.findIndex((t) => t.id === id);
  tabs.list.splice(at, 1);
  if (tabs.active === id) {
    tabs.active = tabs.list[Math.max(0, at - 1)].id;
  }
  schedule();
}

export function rename(id, name) {
  const tab = tabs.list.find((t) => t.id === id);
  if (!tab) return;
  const trimmed = name.trim();
  if (!trimmed) return;
  tab.name = trimmed.endsWith(".luau") ? trimmed : `${trimmed}.luau`;
  schedule();
}

export function setSource(id, source) {
  const tab = tabs.list.find((t) => t.id === id);
  if (!tab) return;
  tab.source = source;
  schedule();
}

export function markSaved(id) {
  const tab = tabs.list.find((t) => t.id === id);
  if (!tab) return;
  tab.saved = tab.source;
  schedule();
}
