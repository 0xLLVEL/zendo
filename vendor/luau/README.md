# luau-compile.exe

Bytecode compiler for the Luau VM that ships inside the Roblox client. The host
shells out to it and injects whatever it emits, so this binary is part of the
trust boundary: a compiler from a different Luau revision can emit a bytecode
version the client's VM rejects, or accept syntax it does not.

Pinned, not vendored from a random build:

| | |
|---|---|
| source | https://github.com/luau-lang/luau/releases/tag/0.746 |
| asset | `luau-windows.zip` (3280763 bytes) |
| asset sha256 | `E149FDB4FE78A52CE457FBD40741484EAAB1DBF9907E7F878C6D8A9A3DAC2DDD` |
| `luau-compile.exe` sha256 | `870665FDC7E751EB266EA8BEEC2CDA64762C9B6B689E8A466FEEDAAEEFC8DD3D` |
| license | MIT, see `LICENSE.txt` |

0.746 is the revision the client we test against runs (`0.746.0.7461267`), so
`--binary` output loads without a version poke. Re-pin together with the client
version, never separately:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\luau.ps1 -Tag 0.747 -Sha256 <zip hash>
```

`ZENDO_COMPILER` overrides the search for one run; `zendo_core::compiler()`
otherwise looks for `vendor/luau/luau-compile.exe` walking up from the running
executable, then from the working directory, then falls back to the old
`D:\zend\test\luau` path so an existing checkout keeps working.
