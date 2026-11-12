<script>
  import { onMount } from "svelte";
  import TopBar from "./components/TopBar.svelte";
  import TabStrip from "./components/TabStrip.svelte";
  import Explorer from "./components/Explorer.svelte";
  import Editor from "./components/Editor.svelte";
  import Console from "./components/Console.svelte";
  import Settings from "./components/Settings.svelte";
  import Hub from "./components/Hub.svelte";
  import { listen } from "./lib/bridge.js";
  import { session, startSession, runScript, saveScript } from "./lib/session.svelte.js";
  import { output, addOutput, setNoise } from "./lib/output.svelte.js";
  import { settings, update } from "./lib/settings.svelte.js";
  import { tabs, current, setSource, markSaved, add } from "./lib/tabs.svelte.js";

  let cursor = $state({ line: 1, col: 1 });
  let open = $state(false);
  let hub = $state(false);

  let tab = $derived(current());
  let lines = $derived(tab.source.split("\n").length);
  let split = $derived(settings.console);
  let running = $derived(session.phase === "running");

  function clamp(px) {
    const max = Math.max(180, window.innerHeight - 48 - 26 - 180);
    return Math.max(120, Math.min(max, px));
  }

  function setSplit(px) {
    update({ console: clamp(px) });
  }

  function startDrag(event) {
    event.preventDefault();
    const handle = event.currentTarget;
    handle.setPointerCapture(event.pointerId);
    const move = (e) => setSplit(window.innerHeight - 26 - 12 - e.clientY);
    const up = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
  }

  function splitKeys(event) {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
    event.preventDefault();
    setSplit(split + (event.key === "ArrowUp" ? 24 : -24));
  }

  async function run() {
    if (session.phase === "running") return;
    tab.error = 0;
    await runScript(tab.source);
  }

  async function save() {
    try {
      const path = await saveScript(tab.source);
      markSaved(tab.id);
      output.stamp = "saved " + path.split("\\").pop();
    } catch (err) {
      addOutput(String(err));
    }
  }

  onMount(() => {
    setNoise(settings.noise);
    startSession();

    listen("zendo://out", (e) => {
      session.streamed += e.payload;
      addOutput(e.payload);
    });
    listen("zendo://stage", (e) => {
      session.note = String(e.payload);
    });

    const onKey = (e) => {
      const mod = e.ctrlKey || e.metaKey;
      if (!mod) return;
      if (e.key === "Enter") {
        e.preventDefault();
        run();
      } else if (e.key === "s") {
        e.preventDefault();
        save();
      } else if (e.key === "n") {
        e.preventDefault();
        add();
      } else if (e.key === ",") {
        e.preventDefault();
        open = !open;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });
</script>

<div class="field" aria-hidden="true"></div>

<div class="shell relative z-10 grid h-full grid-rows-[68px_minmax(0,1fr)_28px]">
  <TopBar onrun={run} onsettings={() => (open = true)} onhub={() => (hub = true)} />

  <main class="grid min-h-0 min-w-0 grid-cols-[248px_minmax(0,1fr)] gap-2 px-3 pb-2 max-[820px]:grid-cols-1">
    <Explorer />

    <section
      class="grid h-full min-h-0 min-w-0"
      style="grid-template-rows:minmax(0,1fr) 10px {split}px"
    >
      <div class="panel relative flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl">
        <TabStrip {cursor} {lines} {running} />

        <Editor
          value={tab.source}
          errorLine={session.errorLine}
          font={settings.font}
          wrap={settings.wrap}
          onchange={(v) => setSource(tab.id, v)}
          onsave={save}
          onrun={run}
          oncursor={(line, col) => (cursor = { line, col })}
        />

        <div class="raised pointer-events-auto absolute bottom-3 right-3 flex items-center gap-1 rounded-lg p-1">
          <button class="btn h-7 !bg-transparent !border-transparent hover:!bg-white/8" onclick={save}>
            Save
          </button>
          <button class="btn btn-run h-7 !px-3" onclick={run} disabled={running}>
            {running ? "Running" : "Execute"}
          </button>
        </div>
      </div>

      <button
        type="button"
        class="group grid cursor-row-resize place-items-center border-0 bg-transparent p-0 outline-none"
        aria-label="Resize console"
        title="Drag to resize console"
        onpointerdown={startDrag}
        onkeydown={splitKeys}
      >
        <span class="h-[3px] w-9 rounded-full bg-white/12 transition-colors group-hover:bg-[var(--accent)]"></span>
      </button>

      <Console onheight={(px) => setSplit(px)} />
    </section>
  </main>

  <footer class="flex items-center gap-4 px-4 font-mono text-[12.5px] text-faint">
    <span>{tab.name}</span>
    <span class="flex-1"></span>
    <span>{session.ms ? `${session.ms} ms · ${session.chunk} bytes` : ""}</span>
    <span>ctrl+↵ run · ctrl+s save · ctrl+n new</span>
  </footer>
</div>

{#if hub}
  <Hub onclose={() => (hub = false)} />
{/if}

{#if open}
  <Settings onclose={() => (open = false)} onsetheight={(px) => setSplit(px)} />
{/if}
