<script>
  import { add } from "../lib/tabs.svelte.js";

  let { onclose } = $props();

  let query = $state("");

  const entries = [
    {
      name: "server-info.luau",
      tag: "diagnostic",
      blurb: "Place, job id, and every player currently in the server.",
      source: `local players = game:GetService("Players")
local lp = players.LocalPlayer

print("place", game.PlaceId, "job", game.JobId)
print("players", #players:GetPlayers(), "/", players.MaxPlayers)

for _, p in ipairs(players:GetPlayers()) do
    print(string.format("%-20s id=%d ping=%d", p.Name, p.UserId, p:GetNetworkPing() * 1000))
end

print("local", lp.Name, "char", lp.Character and lp.Character.Name or "none")
`,
    },
    {
      name: "walkspeed.luau",
      tag: "character",
      blurb: "Set WalkSpeed and JumpPower on the local humanoid, with restore.",
      source: `local lp = game:GetService("Players").LocalPlayer
local humanoid = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
if not humanoid then return warn("no humanoid") end

local SPEED, JUMP = 42, 78
local oldSpeed, oldJump = humanoid.WalkSpeed, humanoid.UseJumpPower and humanoid.JumpPower or nil

humanoid.WalkSpeed = SPEED
if humanoid.UseJumpPower then humanoid.JumpPower = JUMP end

task.delay(30, function()
    if humanoid.Parent then
        humanoid.WalkSpeed = oldSpeed
        if oldJump then humanoid.JumpPower = oldJump end
    end
end)
`,
    },
    {
      name: "anti-afk.luau",
      tag: "utility",
      blurb: "Keeps the idle timer from dropping the client.",
      source: `local vu = game:GetService("VirtualUser")
local players = game:GetService("Players")
local lp = players.LocalPlayer

print("anti-afk armed")

lp.Idled:Connect(function()
    vu:CaptureController()
    vu:ClickButton2(Vector2.new())
end)
`,
    },
    {
      name: "esp.luau",
      tag: "visual",
      blurb: "Highlight every other player through walls with name and health.",
      source: `local players = game:GetService("Players")
local lp = players.LocalPlayer

local function paint(model)
    local highlight = Instance.new("Highlight")
    highlight.Name = "zendo-esp"
    highlight.FillColor = Color3.fromRGB(170, 193, 213)
    highlight.FillTransparency = 0.65
    highlight.OutlineColor = Color3.fromRGB(210, 228, 240)
    highlight.OutlineTransparency = 0.15
    highlight.Adornee = model
    highlight.Parent = model
end

local function watch(player)
    if player == lp then return end
    local function hook(char)
        if char and not char:FindFirstChild("zendo-esp") then paint(char) end
    end
    if player.Character then hook(player.Character) end
    player.CharacterAdded:Connect(hook)
end

for _, p in ipairs(players:GetPlayers()) do watch(p) end
players.PlayerAdded:Connect(watch)
`,
    },
    {
      name: "teleport-part.luau",
      tag: "movement",
      blurb: "Snap the character to a nearby part by name.",
      source: `local lp = game:GetService("Players").LocalPlayer
local target = "Part"

local part = workspace:FindFirstChild(target, true)
if not part then return warn("no part named " .. target) end

local hrp = lp.Character and lp.Character:FindFirstChild("HumanoidRootPart")
if not hrp then return warn("no root") end

hrp.CFrame = part.CFrame + Vector3.new(0, 4, 0)
print("moved to", part:GetFullName())
`,
    },
    {
      name: "fly.luau",
      tag: "movement",
      blurb: "BodyVelocity steering with WASD and space, shift to descend.",
      source: `local uis = game:GetService("UserInputService")
local lp = game:GetService("Players").LocalPlayer
local char = lp.Character or lp.CharacterAdded:Wait()
local hrp = char:WaitForChild("HumanoidRootPart")
local humanoid = char:WaitForChild("Humanoid")

local bv = Instance.new("BodyVelocity")
bv.MaxForce = Vector3.new(1, 1, 1) * 1e5
bv.Velocity = Vector3.zero
bv.Parent = hrp

local speed = 70
local conn = game:GetService("RunService").Heartbeat:Connect(function()
    local cam = workspace.CurrentCamera.CFrame
    local dir = Vector3.zero
    if uis:IsKeyDown(Enum.KeyCode.W) then dir += cam.LookVector end
    if uis:IsKeyDown(Enum.KeyCode.S) then dir -= cam.LookVector end
    if uis:IsKeyDown(Enum.KeyCode.D) then dir += cam.RightVector end
    if uis:IsKeyDown(Enum.KeyCode.A) then dir -= cam.RightVector end
    if uis:IsKeyDown(Enum.KeyCode.Space) then dir += Vector3.yAxis end
    if uis:IsKeyDown(Enum.KeyCode.LeftShift) then dir -= Vector3.yAxis end
    bv.Velocity = dir.Unit * speed * (dir.Magnitude > 0 and 1 or 0)
    humanoid.PlatformStand = true
end)

task.delay(45, function()
    conn:Disconnect()
    bv:Destroy()
    if humanoid.Parent then humanoid.PlatformStand = false end
end)
`,
    },
    {
      name: "infinite-jump.luau",
      tag: "character",
      blurb: "Resets the jump state every time the player touches ground.",
      source: `local lp = game:GetService("Players").LocalPlayer

local humanoid = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
if not humanoid then return warn("no humanoid") end

humanoid.StateChanged:Connect(function(_, next)
    if next == Enum.HumanoidStateType.Landed then
        humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
    end
end)
print("infinite jump on")
`,
    },
    {
      name: "rejoin.luau",
      tag: "session",
      blurb: "Teleport back into the same job, keeping the server alive.",
      source: `local ts = game:GetService("TeleportService")
local players = game:GetService("Players")

local options = Instance.new("TeleportOptions")
options.ServerInstanceId = game.JobId

print("rejoining", game.JobId)
ts:TeleportAsync(game.PlaceId, { players.LocalPlayer }, options)
`,
    },
  ];

  let shown = $derived(
    query.trim()
      ? entries.filter(
          (e) =>
            e.name.includes(query.trim().toLowerCase()) ||
            e.tag.includes(query.trim().toLowerCase()) ||
            e.blurb.toLowerCase().includes(query.trim().toLowerCase())
        )
      : entries
  );

  function insert(entry) {
    add(entry.name, entry.source);
    onclose();
  }
</script>

<div
  class="fixed inset-0 z-40 flex justify-end bg-black/30"
  role="presentation"
  onclick={(e) => e.target === e.currentTarget && onclose()}
>
  <div
    class="sheet flex h-full w-[430px] flex-col overflow-hidden rounded-l-2xl"
    role="dialog"
    aria-modal="true"
    aria-label="Script hub"
  >
    <div class="flex h-16 shrink-0 items-center justify-between px-5">
      <div>
        <h2 class="text-[16px] font-semibold tracking-[-0.02em]">Script Hub</h2>
        <p class="text-[12px] text-faint">{entries.length} bundled scripts</p>
      </div>
      <button class="btn btn-quiet h-8 w-8 !px-0" aria-label="Close script hub" onclick={onclose}>
        <svg width="12" height="12" viewBox="0 0 10 10" stroke="currentColor" stroke-width="1.7">
          <path d="M1.5 1.5l7 7M8.5 1.5l-7 7" />
        </svg>
      </button>
    </div>

    <div class="px-5 pb-3">
      <input
        bind:value={query}
        placeholder="Search scripts"
        class="h-9 w-full rounded-lg border border-white/10 bg-s1 px-3 font-mono text-[12.5px] text-ink outline-none placeholder:text-faint focus:border-white/25"
      />
    </div>

    <div class="min-h-0 flex-1 space-y-2 overflow-y-auto px-5 pb-5">
      {#each shown as entry}
        <article class="rounded-xl border border-white/8 bg-s3/60 p-3">
          <div class="flex items-center gap-2">
            <span class="font-mono text-[12.5px] text-ink">{entry.name}</span>
            <span class="rounded border border-white/10 px-1.5 font-mono text-[10.5px] text-faint">{entry.tag}</span>
            <span class="flex-1"></span>
            <button class="btn h-7" onclick={() => insert(entry)}>Add</button>
          </div>
          <p class="mt-1.5 text-[12.5px] leading-snug text-dim">{entry.blurb}</p>
        </article>
      {:else}
        <p class="pt-6 text-center text-[12.5px] text-faint">Nothing matches that.</p>
      {/each}
    </div>
  </div>
</div>
