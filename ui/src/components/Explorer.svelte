<script>
  import { tabs, select, add, close } from "../lib/tabs.svelte.js";
</script>

<aside class="flex min-h-0 flex-col gap-2">
  <section class="panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl">
    <div class="flex h-11 shrink-0 items-center gap-2 border-b border-white/8 px-3.5">
      <span class="text-[14px] font-medium">Scripts</span>
      <span class="rounded border border-white/10 px-1.5 font-mono text-[11.5px] text-faint">{tabs.list.length}</span>
      <span class="flex-1"></span>
      <button class="btn btn-quiet h-7 w-7 !px-0" aria-label="New script" onclick={() => add()}>
        <svg width="12" height="12" viewBox="0 0 12 12" stroke="currentColor" stroke-width="1.7">
          <path d="M6 1.5v9M1.5 6h9" />
        </svg>
      </button>
    </div>

    <ol class="min-h-0 flex-1 overflow-y-auto px-2 py-2">
      {#each tabs.list as tab (tab.id)}
        {@const dirty = tab.source !== tab.saved}
        <li>
          <div
            class="group flex h-9 items-center gap-2 rounded-md px-2.5 text-[14px] {tabs.active === tab.id
              ? 'bg-s4 text-ink'
              : 'text-dim hover:bg-s3'}"
          >
            <button class="min-w-0 flex-1 truncate text-left font-mono" onclick={() => select(tab.id)}>
              {tab.name}
            </button>
            {#if dirty}
              <span class="h-1.5 w-1.5 shrink-0 rounded-full" style="background:var(--accent)"></span>
            {/if}
            <button
              class="grid h-5 w-5 shrink-0 place-items-center rounded text-faint opacity-0 hover:bg-white/10 hover:text-ink group-hover:opacity-100"
              aria-label={`Close ${tab.name}`}
              onclick={() => close(tab.id)}
            >
              <svg width="8" height="8" viewBox="0 0 10 10" stroke="currentColor" stroke-width="1.6">
                <path d="M1.5 1.5l7 7M8.5 1.5l-7 7" />
              </svg>
            </button>
          </div>
        </li>
      {/each}
    </ol>

    <div class="flex h-9 shrink-0 items-center gap-1.5 border-t border-white/8 px-3.5 font-mono text-[12px] text-faint">
      {tabs.list.length} {tabs.list.length === 1 ? "script" : "scripts"}
      <span class="flex-1"></span>
      <span>ctrl+n</span>
    </div>
  </section>

  <section class="panel rounded-xl px-3.5 py-3">
    <p class="mb-2 text-[12.5px] font-medium text-faint">Shortcuts</p>
    <div class="space-y-1.5 font-mono text-[12.5px] text-dim">
      <div class="flex justify-between"><span class="text-faint">run</span><span>ctrl+↵</span></div>
      <div class="flex justify-between"><span class="text-faint">save</span><span>ctrl+s</span></div>
      <div class="flex justify-between"><span class="text-faint">settings</span><span>ctrl+,</span></div>
    </div>
  </section>
</aside>
