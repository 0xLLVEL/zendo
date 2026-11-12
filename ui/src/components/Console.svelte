<script>
  import { output, clearOutput, setNoise, plainText } from "../lib/output.svelte.js";
  import { settings } from "../lib/settings.svelte.js";

  let { onheight } = $props();

  let scroller = $state(null);
  let collapsed = $state(false);

  let visible = $derived(output.lines.filter((l) => output.noise || !l.noise));
  let errors = $derived(visible.filter((l) => l.cls === "err").length);
  let warns = $derived(visible.filter((l) => l.cls === "warn").length);

  $effect(() => {
    visible.length;
    output.noise;
    settings.autoscroll;
    if (scroller && settings.autoscroll && output.stick) scroller.scrollTop = scroller.scrollHeight;
  });

  function onscroll() {
    if (!scroller) return;
    output.stick = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 24;
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(plainText());
      output.stamp = "copied";
    } catch {
      output.stamp = "clipboard denied";
    }
  }

  function toggle() {
    collapsed = !collapsed;
    onheight?.(collapsed ? 34 : 240);
  }

  function clock(t) {
    return t ? new Date(t).toLocaleTimeString([], { hour12: false }) : "";
  }
</script>

<section class="panel flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl">
  <div class="flex h-9 shrink-0 items-center gap-2.5 border-b border-white/8 px-3">
    <span class="text-[13.5px] font-medium">Console</span>
    <span class="font-mono text-[12px] text-faint">{visible.length} lines</span>

    <span class="ml-2 flex items-center gap-3 font-mono text-[12px]">
      <span class="text-[var(--color-danger)]">{errors} err</span>
      <span class="text-[var(--color-amber)]">{warns} warn</span>
    </span>

    <span class="flex-1"></span>

    <label class="flex cursor-pointer items-center gap-1.5 text-[12.5px] text-faint hover:text-dim">
      <input
        type="checkbox"
        class="h-[12px] w-[12px] accent-[var(--accent)]"
        checked={output.noise}
        onchange={(e) => setNoise(e.currentTarget.checked)}
      />
      noise
    </label>
    <button class="btn btn-quiet h-6 !px-2 text-[12.5px]" onclick={copy}>Copy</button>
    <button class="btn btn-quiet h-6 !px-2 text-[12.5px]" onclick={clearOutput}>Clear</button>
    <button class="btn btn-quiet h-7 w-7 !px-0" aria-label="Collapse console" onclick={toggle}>
      <svg width="10" height="10" viewBox="0 0 12 12" stroke="currentColor" stroke-width="1.7" class={collapsed ? "rotate-180" : ""}>
        <path d="M2.5 4.5L6 8l3.5-3.5" />
      </svg>
    </button>
  </div>

  {#if !collapsed}
    <div
      id="log"
      bind:this={scroller}
      {onscroll}
      class="min-h-0 flex-1 overflow-auto px-3 py-2 font-mono text-[13.5px] leading-[1.75] text-[#c6ccd6]"
    >
      {#each visible as line}
        <div class="line {line.cls}">
          <span class="mr-2 select-none text-faint">{clock(line.t)}</span>{line.text === "" ? " " : line.text}
        </div>
      {:else}
        <div class="flex h-full items-center justify-center text-[13.5px] text-faint">Run a script to see its output.</div>
      {/each}
    </div>
  {/if}
</section>
