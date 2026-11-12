const core = window.__TAURI__?.core;
const events = window.__TAURI__?.event;

export const invoke = core
  ? core.invoke
  : async () => {
      throw new Error("zendo: not running inside Tauri");
    };

export const listen = events?.listen ?? (() => Promise.resolve(() => {}));
