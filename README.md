# L4D2 Proton VAC Fix

This is a workaround for an issue that prevents the Windows version of
Left 4 Dead 2 running under Proton from joining VAC-secure dedicated servers.

A request to remove plugins is displayed because Windows PE files are
rejected by Linux Steam's ELF signature checker, disabling secure connections.

Loaded through `LD_PRELOAD`, this library forwards signature requests unchanged
and tracks their asynchronous handles. For L4D2 (AppID 550), it changes a
successfully retrieved `InvalidSignature` result to `ValidSignature` for
`left4dead2/bin/server.dll` and `bin/engine.dll`. It skips signature verification
for these checks. Other verdicts, unrelated files and apps, and failed API calls
pass through unchanged.

## Build

Make, GCC, and 32-bit glibc development support are required: `make` and
`gcc-multilib` on Debian; `make`, `gcc`, and `lib32-gcc-libs` on Arch Linux.

```sh
make
```

## Use

The 32-bit shared library `steam-signature-fix32.so` is produced in the source
directory by `make`. It can be left there or placed anywhere else; its full
path is specified through `LD_PRELOAD`. For example, it can be copied to:

```sh
cp steam-signature-fix32.so ~/.local/share/Steam/
```

Proton should be selected in L4D2's Compatibility settings, and the following
launch options should be set, with the path adjusted to the `.so` location:

```text
LD_PRELOAD="$HOME/.local/share/Steam/steam-signature-fix32.so" %command%
```
