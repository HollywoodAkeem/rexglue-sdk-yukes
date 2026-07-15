#pragma once

#include <cstdint>
#include <filesystem>

namespace rex {

class Runtime;

namespace system {

// Applies `[[patches]]` entries from a project TOML to guest memory, once the
// XEX image is resident but before the module runs. A reusable, per-title
// code/data patch facility (Xenia-canary style) so mods that must alter the
// executable image or its .rodata do not require editing default.xex or
// re-touching the generated recompiler output.
//
// TOML schema (array-of-tables in the project's `<name>.toml`):
//
//   [[patches]]
//   name     = "roster grid: enable 5th row widget bases"  # optional label
//   title_id = "545408B2"        # optional filter; skipped if != running title
//   enabled  = true              # optional (default true)
//   address  = 0x82037504        # guest virtual address of the first byte
//   bytes    = "00 00 02 BD"     # replacement bytes, verbatim (whitespace ok)
//   expect   = "FF FF FF FF"     # optional guard bytes; patch aborts on mismatch
//
// `bytes` is written exactly as given — the caller controls byte order, so
// this works for big-endian guest data as-is. `title_id` accepts a hex string
// ("545408B2") or an integer. `expect`, when present, must equal the current
// memory contents or the individual patch is skipped and logged as an error
// (guards against a wrong address or a differently-built game image).
//
// Every span is bounds-checked with IsValidGuestAddress before any write.
// Read-only guest pages (XEX .text/.rodata) are temporarily made writable
// and restored around the write.
//
// IMPORTANT — this patches guest DATA, not guest CODE. rexglue is a STATIC
// recompiler: the generated C++ runs as native x64; guest .text bytes are
// never decoded/executed. So a patch only changes behavior if recompiled
// code READS the patched bytes from guest memory at runtime (e.g. a .rodata
// lookup table accessed via REX_LOAD_U32, or .data the game reads). Poking a
// guest instruction's immediate has no effect — that constant was baked into
// the generated source at codegen time and must be changed there instead.
//
// Returns the number of patches successfully applied.
uint32_t ApplyMemoryPatches(Runtime* runtime,
                            const std::filesystem::path& config_path,
                            uint32_t title_id);

}  // namespace system
}  // namespace rex
