/**
 * @file        codegen/codegen_flags.cpp
 * @brief       CVar definitions for the codegen pipeline
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <rex/cvar.h>

// clang-format off

//=============================================================================
// Codegen/Output
//=============================================================================

REXCVAR_DEFINE_UINT32(max_file_size_bytes, 2097152, "Codegen",
                      "Target maximum source file size in bytes")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(65536, 67108864);

REXCVAR_DEFINE_UINT32(progress_log_frequency, 100, "Codegen",
                      "Log progress every N functions")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

//=============================================================================
// Codegen/Analysis
//=============================================================================

REXCVAR_DEFINE_UINT32(max_discovery_iterations, 1000, "Codegen",
                      "Max iterations for function discovery convergence")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_vtable_iterations, 100, "Codegen",
                      "Max iterations for vtable discovery")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_resolve_iterations, 100, "Codegen",
                      "Max iterations for call target resolution")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_eh_states, 100, "Codegen",
                      "Max C++ EH states before rejecting handler")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_eh_try_blocks, 50, "Codegen",
                      "Max try blocks before rejecting handler")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_eh_ip_map_entries, 200, "Codegen",
                      "Max IP-to-state map entries")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_seh_scope_entries, 100, "Codegen",
                      "Max SEH scope table entries")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

//=============================================================================
// Codegen/Discovery
//=============================================================================

REXCVAR_DEFINE_UINT32(backward_scan_limit, 64, "Codegen",
                      "Max instructions to scan backward for jump table patterns")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 10000);

REXCVAR_DEFINE_UINT32(max_jump_table_entries, 512, "Codegen",
                      "Max entries per detected jump table")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 100000);

REXCVAR_DEFINE_UINT32(max_blocks_per_function, 10000, "Codegen",
                      "Safety limit on blocks per function")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly)
    .range(1, 1000000);

// HollywoodAkeem: scan .rdata/.data sections for 32-bit values that point
// to function prologues (mflr r12 / mflr r0) and register them as
// functions. Catches functions that are only reachable via indirect call
// through data-resident pointer tables (vtables, function-pointer arrays,
// etc.) — the Xbox 360 Yukes engine (WWE 2K14, SVR07/08) uses these
// heavily and rexglue's existing vtableScanner only catches MSVC RTTI
// vtables which Xbox 360 binaries usually don't have. Disabled by default
// to avoid changing behavior for projects that don't need it.
REXCVAR_DEFINE_BOOL(data_pointer_scan, false, "Codegen",
                    "Scan .rdata/.data for code pointers (vtables, fn ptr arrays)")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly);

// clang-format on
