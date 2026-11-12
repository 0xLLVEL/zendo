<script>
  import { settings, update, reset } from "../lib/settings.svelte.js";
  import { session } from "../lib/session.svelte.js";
  import { output, setNoise, clearOutput } from "../lib/output.svelte.js";
  import { invoke } from "../lib/bridge.js";

  let { onclose, onsetheight } = $props();
  let killing = $state(false);
  let killed = $state("");

  async function killClient() {
    killing = true;
    try {
      const pids = await invoke("kill_client");
      killed = pids.length ? `killed ${pids.join(", ")}` : "nothing to kill";
      if (pids.length) {
        session.client = null;
        session.profile = null;
      }
    } catch (err) {
      killed = String(err);
    }
    killing = false;
  }

  const accents = [
    { id: "sky", color: "#aac1d5" },
    { id: "mint", color: "#9fcfc2" },
    { id: "iris", color: "#b3b8d4" },
    { id: "rose", color: "#d3aab8" },
  ];

  function toggle(key) {
    if (key === "noise") {
      setNoise(!output.noise);
      update({ noise: !output.noise });
      return;
    }
    update({ [key]: !settings[key] });
  }

  function font(delta) {
    update({ font: Math.min(18, Math.max(11, settings.font + delta)) });
  }
</script>

<div
  class="fixed inset-0 z-40 flex justify-end bg-black/20 backdrop-blur-[2px]"
  role="presentation"
  onclick={(e) => e.target === e.currentTarget && onclose()}
>
  <div
    class="sheet lens flex h-full w-[360px] flex-col overflow-y-auto rounded-l-2xl p-5"
    role="dialog"
    aria-modal="true"
    aria-label="Settings"
  >
    <div class="mb-5 flex items-center justify-between">
      <h2 class="text-[16px] font-semibold tracking-[-0.02em]">Settings</h2>
      <button class="btn btn-quiet h-7 w-7 !px-0" aria-label="Close settings" onclick={onclose}>
        <svg width="11" height="11" viewBox="0 0 10 10" stroke="currentColor" stroke-width="1.7">
          <path d="M1.5 1.5l7 7M8.5 1.5l-7 7" />
        </svg>
      </button>
    </div>

    <p class="mb-2 text-[12.5px] font-medium text-faint">Editor</p>
    <div class="mb-5 rounded-xl border border-white/8 bg-white/[0.03] px-3">
      <div class="flex h-12 items-center justify-between border-b border-white/6">
        <span class="text-[14.5px]">Font size</span>
        <span class="flex items-center gap-2">
          <button class="stepper" aria-label="Smaller" onclick={() => font(-1)}>−</button>
          <span class="w-6 text-center font-mono text-[13px] text-dim">{settings.font}</span>
          <button class="stepper" aria-label="Larger" onclick={() => font(1)}>+</button>
        </span>
      </div>
      <button class="flex h-12 w-full items-center justify-between" onclick={() => toggle("wrap")}>
        <span class="text-[14.5px]">Wrap long lines</span>
        <span class="switch" class:on={settings.wrap}></span>
      </button>
    </div>

    <p class="mb-2 text-[12.5px] font-medium text-faint">Console</p>
    <div class="mb-5 rounded-xl border border-white/8 bg-white/[0.03] px-3">
      <button class="flex h-12 w-full items-center justify-between border-b border-white/6" onclick={() => toggle("noise")}>
        <span class="text-[14.5px]">Show engine noise</span>
        <span class="switch" class:on={output.noise}></span>
      </button>
      <button class="flex h-12 w-full items-center justify-between border-b border-white/6" onclick={() => toggle("autoscroll")}>
        <span class="text-[14.5px]">Follow output</span>
        <span class="switch" class:on={settings.autoscroll}></span>
      </button>
      <div class="flex h-12 items-center justify-between gap-2">
        <span class="text-[14.5px]">Height</span>
        <span class="flex gap-2">
          <button class="btn h-7" onclick={() => onsetheight(240)}>Reset</button>
          <button class="btn h-7" onclick={clearOutput}>Clear log</button>
        </span>
      </div>
    </div>

    <p class="mb-2 text-[12.5px] font-medium text-faint">Accent</p>
    <div class="mb-5 flex gap-2 rounded-xl border border-white/8 bg-white/[0.03] p-3">
      {#each accents as a}
        <button
          class="h-8 flex-1 rounded-lg border transition-transform {settings.accent === a.id
            ? 'border-white/60'
            : 'border-white/10'}"
          style={`background:linear-gradient(180deg, ${a.color}55, ${a.color}22)`}
          aria-label={a.id}
          onclick={() => update({ accent: a.id })}
        >
          <span class="mx-auto block h-2.5 w-2.5 rounded-full" style={`background:${a.color}`}></span>
        </button>
      {/each}
    </div>

    <p class="mb-2 text-[12.5px] font-medium text-faint">Session</p>
    <div class="mb-6 space-y-1.5 rounded-xl border border-white/8 bg-white/[0.03] p-3 font-mono text-[13px]">
      <div class="flex justify-between"><span class="text-faint">client</span><span>{session.client ?? "—"}</span></div>
      <div class="flex justify-between"><span class="text-faint">identity</span><span>{session.profile?.name ?? "—"}</span></div>
      <div class="flex justify-between"><span class="text-faint">integrity</span><span>{session.elevated === null ? "—" : session.elevated ? "elevated" : "medium"}</span></div>
      <div class="flex justify-between"><span class="text-faint">stage</span><span>{session.stage?.text ?? "—"}</span></div>
      <div class="flex justify-between"><span class="text-faint">build</span><span>v4080</span></div>
      <div class="flex items-center justify-between pt-1">
        <span class="text-faint">recovery</span>
        <button class="btn h-7" onclick={killClient} disabled={killing}>
          {killing ? "killing" : "Force kill client"}
        </button>
      </div>
      {#if killed}
        <div class="flex justify-between"><span class="text-faint">result</span><span>{killed}</span></div>
      {/if}
    </div>

    <span class="flex-1"></span>
    <button class="btn h-8 w-full justify-center" onclick={reset}>Reset all settings</button>
  </div>
</div>

<style>
  .stepper {
    width: 22px;
    height: 22px;
    border-radius: 6px;
    border: 1px solid rgb(255 255 255 / 0.1);
    background: rgb(255 255 255 / 0.05);
    color: var(--color-dim);
    font: 500 13px/1 var(--font-ui);
  }
  .stepper:hover {
    color: var(--color-ink);
    background: rgb(255 255 255 / 0.1);
  }

  .switch {
    width: 32px;
    height: 18px;
    border-radius: 999px;
    background: rgb(255 255 255 / 0.1);
    border: 1px solid rgb(255 255 255 / 0.08);
    position: relative;
    transition: background 160ms;
  }
  .switch::after {
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #b8bfd0;
    transition: transform 160ms, background 160ms;
  }
  .switch.on {
    background: color-mix(in srgb, var(--accent) 32%, transparent);
    border-color: color-mix(in srgb, var(--accent) 45%, transparent);
  }
  .switch.on::after {
    transform: translateX(14px);
    background: var(--accent);
  }
</style>
