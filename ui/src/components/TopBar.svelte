<script>
  import { session } from "../lib/session.svelte.js";

  let { onrun, onsettings, onhub, view = "workbench" } = $props();

  let profile = $derived(session.profile);
  let busy = $derived(session.phase === "running");
  const appWindow = globalThis.__TAURI__?.window?.getCurrentWindow?.() ?? null;

  function beginDrag(event) {
    if (!appWindow || event.button !== 0) return;
    const target = event.target;
    if (target instanceof Element && target.closest("button, a, input, select, textarea, [data-no-drag]")) return;
    appWindow.startDragging();
  }

  function toggleMax(event) {
    if (!appWindow) return;
    const target = event.target;
    if (target instanceof Element && target.closest("button, a, input, select, textarea, [data-no-drag]")) return;
    appWindow.toggleMaximize();
  }
  let initials = $derived(
    profile ? profile.name.slice(0, 2).toUpperCase() : session.client ? "··" : "—"
  );
</script>

<header
  class="relative z-20 flex h-[68px] shrink-0 items-center gap-4 px-4"
  data-tauri-drag-region
  onpointerdown={beginDrag}
  ondblclick={toggleMax}
>
  <div class="flex items-center gap-3" data-tauri-drag-region>
    <svg class="logo" width="30" height="30" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <rect x="0.75" y="0.75" width="18.5" height="18.5" rx="5.5" stroke="rgb(255 255 255 / 0.2)" />
      <path
        d="M6.4 6.6h7.2L6.4 13.4h7.2"
        stroke="var(--accent)"
        stroke-width="1.7"
        stroke-linecap="square"
        stroke-linejoin="miter"
      />
    </svg>
    <span class="brand">zendo</span>
  </div>

  <nav class="absolute left-1/2 flex -translate-x-1/2 items-center gap-0.5 rounded-lg border border-white/10 bg-s2 p-0.5">
    <button class="nav" class:on={view === "workbench"} onclick={() => onrun === null}>Workbench</button>
    <button class="nav" onclick={onhub}>Script Hub</button>
    <button class="nav" onclick={onsettings}>Settings</button>
  </nav>

  <span class="flex-1" data-tauri-drag-region></span>

  <span
    class="dot"
    data-state={busy ? "running" : session.client ? "live" : "idle"}
    role="status"
    aria-label={busy ? "running" : session.client ? `connected, pid ${session.client}` : "not connected"}
    title={busy ? "running" : session.client ? `pid ${session.client}` : "not connected"}
  ></span>

  <div class="flex h-10 items-center gap-3 rounded-full border border-white/10 bg-s2 pl-1 pr-3.5">
    {#if profile?.avatar}
      <img src={profile.avatar} alt="" class="h-8 w-8 rounded-full object-cover" draggable="false" />
    {:else}
      <span
        class="grid h-8 w-8 place-items-center rounded-full text-[12px] font-semibold {profile
          ? 'text-[#0a1016]'
          : 'bg-s3 text-faint'}"
        style={profile ? "background:linear-gradient(140deg,#aac1d5,#cfdae6);color:#0a1016" : ""}
      >
        {initials}
      </span>
    {/if}
    <span class="max-w-[200px] truncate text-[15.5px]">{profile?.name ?? (session.client ? `pid ${session.client}` : "guest")}</span>
  </div>

  {#if appWindow}
    <div class="ml-1 flex items-center gap-0.5">
      <button class="winbtn" aria-label="Minimize" onclick={() => appWindow.minimize()}>
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
          <path d="M2 5h6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
        </svg>
      </button>
      <button class="winbtn" aria-label="Maximize" onclick={() => appWindow.toggleMaximize()}>
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
          <rect x="2.2" y="2.2" width="5.6" height="5.6" rx="1" fill="none" stroke="currentColor" stroke-width="1.1" />
        </svg>
      </button>
      <button class="winbtn close" aria-label="Close" onclick={() => appWindow.close()}>
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
          <path d="M2.4 2.4l5.2 5.2M7.6 2.4L2.4 7.6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
        </svg>
      </button>
    </div>
  {/if}
</header>

<style>
  .logo {
    flex-shrink: 0;
  }

  .brand {
    font: 600 26px/30px var(--font-ui);
    letter-spacing: -0.04em;
  }

  .nav {
    height: 32px;
    padding: 0 14px;
    border-radius: 7px;
    color: var(--color-dim);
    font: 500 15px/1 var(--font-ui);
  }
  .nav:hover {
    color: var(--color-ink);
  }
  .nav.on {
    background: var(--color-s4);
    color: var(--color-ink);
  }

  .dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: #ff5a6e;
    box-shadow: inset 0 0 0 1px rgb(0 0 0 / 0.25);
  }
  .dot[data-state="live"] {
    background: #5ee08d;
  }
  .dot[data-state="running"] {
    background: #5ee08d;
    animation: pulse 1.6s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.35;
    }
  }
</style>
