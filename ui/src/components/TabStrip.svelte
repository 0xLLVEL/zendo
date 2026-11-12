<script>
  import { tabs, select, close, add } from "../lib/tabs.svelte.js";

  let { cursor = { line: 1, col: 1 }, lines = 1, running = false } = $props();

  let editing = $state(null);
  let draft = $state("");

  function beginEdit(tab) {
    editing = tab.id;
    draft = tab.name.replace(/\.luau$/, "");
  }
</script>

<div class="flex h-10 shrink-0 items-center gap-1 border-b border-white/8 bg-s1 px-2">
  <div class="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
    {#each tabs.list as tab (tab.id)}
      {@const dirty = tab.source !== tab.saved}
      <div
        class="group flex h-7 shrink-0 items-center gap-1.5 rounded-md border px-2.5 {tabs.active === tab.id
          ? 'border-white/10 bg-s3'
          : 'border-transparent hover:bg-s2'}"
      >
        <button
          class="max-w-[170px] truncate font-mono text-[13.5px] {tabs.active === tab.id ? 'text-ink' : 'text-dim'}"
          onclick={() => select(tab.id)}
          title={tab.name}
        >
          {tab.name}
        </button>
        {#if dirty}
          <span class="h-1.5 w-1.5 rounded-full" style="background:var(--accent)"></span>
        {/if}
        <button
          class="grid h-[18px] w-[18px] place-items-center rounded text-faint opacity-0 transition-opacity hover:bg-white/10 hover:text-ink group-hover:opacity-100"
          class:opacity-100={tabs.active === tab.id}
          aria-label={`Close ${tab.name}`}
          onclick={() => close(tab.id)}
        >
          <svg width="8" height="8" viewBox="0 0 10 10" stroke="currentColor" stroke-width="1.6">
            <path d="M1.5 1.5l7 7M8.5 1.5l-7 7" />
          </svg>
        </button>
      </div>
    {/each}

    <button
      class="grid h-7 w-7 shrink-0 place-items-center rounded-md text-faint transition-colors hover:bg-s3 hover:text-ink"
      aria-label="New script"
      title="New script (ctrl+n)"
      onclick={() => add()}
    >
      <svg width="11" height="11" viewBox="0 0 12 12" stroke="currentColor" stroke-width="1.7">
        <path d="M6 1.5v9M1.5 6h9" />
      </svg>
    </button>
  </div>

  <span class="shrink-0 font-mono text-[12.5px] text-faint">Ln {cursor.line}, Col {cursor.col} · {lines} lines</span>

  {#if running}
    <span class="ml-2 flex shrink-0 items-center gap-1.5 rounded-md border border-white/10 bg-s2 px-2 py-0.5 text-[12.5px] text-dim">
      <span class="h-1.5 w-1.5 rounded-full" style="background:var(--accent)"></span>
      running
    </span>
  {/if}
</div>
