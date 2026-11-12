<script>
  import { session, fmtAge, statusText } from "../lib/session.svelte.js";

  let profile = $derived(session.profile);
  let initials = $derived(
    profile ? profile.name.slice(0, 2).toUpperCase() : session.client ? "··" : "—"
  );
  let runs = $derived(session.runs.slice(0, 5));

  function clock(t) {
    return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
</script>

<aside class="flex min-h-0 flex-col gap-3 overflow-y-auto py-1 pr-1">
  <section class="glass rounded-xl p-3">
    <div class="flex items-center gap-2.5">
      {#if profile?.avatar}
        <img
          src={profile.avatar}
          alt=""
          class="h-9 w-9 rounded-full object-cover ring-1 ring-white/12"
          draggable="false"
        />
      {:else}
        <span
          class="grid h-9 w-9 place-items-center rounded-full text-[10px] font-semibold {profile
            ? 'text-[#100a1d]'
            : 'bg-white/5 text-faint ring-1 ring-white/8'}"
          style={profile ? "background:linear-gradient(140deg,#b9a2ff,#7df0d8)" : ""}
        >
          {initials}
        </span>
      {/if}

      <div class="min-w-0 flex-1">
        <div class="truncate text-[12.5px] font-medium leading-tight">
          {profile?.name ?? (session.client ? "resolving…" : "no client")}
        </div>
        <div class="truncate text-[10.5px] text-faint">
          {profile?.display && profile.display !== profile.name
            ? profile.display
            : session.client
              ? `pid ${session.client}`
              : "waiting for Roblox"}
        </div>
      </div>
    </div>

    <div class="mt-3 flex items-center gap-1.5">
      <span class="chip">{session.elevated === null ? "integrity ?" : session.elevated ? "elevated" : "medium"}</span>
      <span class="chip">{session.client ? `pid ${session.client}` : "offline"}</span>
    </div>
  </section>

  <section class="glass rounded-xl p-3">
    <p class="mb-2 text-[10.5px] font-medium text-faint">Wire</p>
    <div class="space-y-1.5 font-mono text-[10.5px]">
      <div class="flex justify-between gap-2">
        <span class="text-faint">stage</span>
        <span class="truncate text-right">{session.stage?.text ?? "—"}</span>
      </div>
      <div class="flex justify-between gap-2">
        <span class="text-faint">age</span>
        <span>{session.stage ? fmtAge(session.stageAge) : "—"}</span>
      </div>
      <div class="flex justify-between gap-2">
        <span class="text-faint">loop</span>
        <span class="truncate text-right">{session.loopMark ?? "—"}</span>
      </div>
      <div class="flex justify-between gap-2">
        <span class="text-faint">mutex</span>
        <span class="truncate text-right">{session.mutex?.text ?? "—"}</span>
      </div>
    </div>
  </section>

  <section class="glass min-h-0 rounded-xl p-3">
    <p class="mb-2 text-[10.5px] font-medium text-faint">Runs</p>
    <ol class="space-y-1 font-mono text-[10.5px]">
      {#each runs as r}
        <li class="flex items-center gap-2">
          <span class={r.ok ? "text-[var(--color-mint)]" : "text-[var(--color-danger)]"}>
            {r.ok ? "ok" : "fail"}
          </span>
          <span class="text-faint">{clock(r.t)}</span>
          <span class="flex-1"></span>
          <span class="text-dim">{r.ms} ms</span>
        </li>
      {:else}
        <li class="text-faint">none yet</li>
      {/each}
    </ol>
  </section>

  <section class="glass rounded-xl p-3">
    <p class="mb-2 text-[10.5px] font-medium text-faint">Status</p>
    <p class="text-[11.5px] text-dim">{statusText(session)}</p>
  </section>
</aside>

<style>
  .chip {
    border: 1px solid rgb(255 255 255 / 0.08);
    border-radius: 5px;
    padding: 1px 6px;
    font: 500 10px/1.6 var(--font-mono);
    color: var(--color-dim);
    white-space: nowrap;
  }
</style>
