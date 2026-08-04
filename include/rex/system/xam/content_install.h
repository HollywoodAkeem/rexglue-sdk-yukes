#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include <rex/system/xtypes.h>

namespace rex {
namespace system {

class KernelState;

namespace xam {

// Installs `[[content_install]]` STFS packages listed in a project TOML into
// the ContentManager content tree, once the XEX image is resident (title_id
// known) but before the guest module runs. The DLC on-ramp counterpart to
// ApplyMemoryPatches: reusable, per-project, default-off (absent section =
// silent no-op).
//
// TOML schema (array-of-tables in the project's `<name>.toml`):
//
//   [[content_install]]
//   name      = "Add-On 2 unlock-all"   # optional label for receipts
//   title_id  = "545408B2"  # optional filter; skipped if != running title
//   enabled   = true        # optional (default true)
//   path      = 'V:/dlc/267E5576...DE54'  # host path to the LIVE/PIRS package
//   overwrite = false       # optional; default false = one-shot (skip when
//                           # the package dir + .header already exist)
//   dlc_guard = true        # optional; default true = run the title's
//                           # [DLC-GUARD] rules on the extracted tree (set
//                           # false ONLY to debug unguarded DLC behavior)
//
// Every entry logs a [CONTENT-INSTALL] receipt. Receipts use warn level so
// project consoles running at [log.levels] sys = "warn" still show them; the
// lines only ever appear when a [[content_install]] section exists.
// Returns the number of packages newly installed (one-shot skips excluded).
uint32_t InstallContentFromConfig(KernelState* kernel_state,
                                  const std::filesystem::path& config_path,
                                  uint32_t title_id);

// [DLC-GUARD] rule engine. Applies title-specific, size-preserving byte
// patches to a freshly extracted content package (called by
// ContentManager::InstallContent between extraction and the .header write)
// so retail DLC can never clobber recomp-added content. Per rule:
//   - target file absent       -> silent skip (pack doesn't carry it)
//   - expect bytes match       -> patch + [DLC-GUARD] WARN receipt logging
//                                 offset + ORIGINAL bytes (hand-revert info)
//   - already in patched state -> "already guarded" receipt, no write
//   - expect mismatch          -> structural fallback re-locate (catalog
//                                 record scan / EPK8->MSC1->PACH walk); if
//                                 that fails too: [DLC-GUARD] SKIP warning,
//                                 file left byte-identical (never corrupt)
// Returns non-success ONLY on a real I/O failure (open/read/write error) so
// the caller can abort pre-header and retry next boot. Titles without a
// rule set are a silent no-op.
X_RESULT ApplyDlcGuardRules(const std::filesystem::path& install_path,
                            const std::string& package_file_name,
                            uint32_t title_id);

}  // namespace xam
}  // namespace system
}  // namespace rex
