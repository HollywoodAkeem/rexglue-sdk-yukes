/**
 * @file        codegen/phase_discover.cpp
 * @brief       Discover phase: iterative function block discovery
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include "codegen_flags.h"
#include "decoded_binary.h"
#include <rex/codegen/function_scanner.h>

#include <array>
#include <bitset>
#include <unordered_set>

#include <rex/codegen/phases.h>
#include "phase_helpers.h"

#include <rex/codegen/vtable_scanner.h>
#include <rex/logging.h>

#include "codegen_logging.h"
#include <rex/memory/utils.h>

#include <ppc.h>

using rex::codegen::ppc::Opcode;
using rex::memory::load_and_swap;

namespace rex::codegen {

namespace {

//=============================================================================
// Discover Phase: iterative function block discovery
//=============================================================================

void discoverFunction(CodegenContext& ctx, uint32_t funcAddr,
                      const std::unordered_set<uint32_t>& knownFunctions) {
  auto& graph = ctx.graph;
  auto& binary = ctx.binary();
  auto& decoded = ctx.decoded();

  auto* node = graph.getFunction(funcAddr);
  if (!node)
    return;

  // Skip if already discovered
  if (!node->canDiscover()) {
    REXCODEGEN_TRACE("Analyze: function 0x{:08X} already discovered, skipping", funcAddr);
    return;
  }

  // Imports don't need block discovery
  if (node->isImport()) {
    node->discoverAsImport();
    return;
  }

  REXCODEGEN_TRACE("Analyze: discovering function 0x{:08X} ({})", funcAddr, node->name());

  // Lookup pdataSize for exception handler boundary
  uint32_t pdataSize = 0;

  // For CONFIG functions: use only the explicitly declared size (if any)
  // If no size specified (size=0), let discovery find natural boundaries via region
  // Don't inherit PDATA sizes for CONFIG functions - they're user hints for entry points
  if (node->authority() == FunctionAuthority::CONFIG) {
    pdataSize = node->size();  // 0 if not specified, which is correct
    REXCODEGEN_TRACE("Analyze: 0x{:08X} is CONFIG, using declared size={}", funcAddr, pdataSize);
  } else {
    // For non-CONFIG functions, use PDATA size if available
    auto pdataIt = ctx.scan.pdataSizes.find(funcAddr);
    if (pdataIt != ctx.scan.pdataSizes.end()) {
      pdataSize = pdataIt->second;
      REXCODEGEN_TRACE("Analyze: 0x{:08X} using PDATA size={}", funcAddr, pdataSize);
    }
  }

  // Find the code region containing this function
  const CodeRegion* region = nullptr;
  for (const auto& r : ctx.scan.codeRegions) {
    if (r.contains(funcAddr)) {
      region = &r;
      break;
    }
  }
  if (!region) {
    REXCODEGEN_WARN("Analyze: function 0x{:08X} not in any code region", funcAddr);
    return;
  }

  // Pass pdataSize so forward branches within function extent are correctly identified
  auto result = discoverBlocks(decoded, funcAddr, *region, knownFunctions, pdataSize);

  if (result.blocks.empty()) {
    REXCODEGEN_WARN("Analyze: no blocks found for function 0x{:08X}", funcAddr);
    return;
  }

  // snooper the function with the discovered blocks and instructions
  node->discover(std::move(result.blocks), std::move(result.instructions),
                 std::move(result.labels));

  // Add jump tables (targets become labels in the function)
  for (const auto& jt : result.jumpTables) {
    graph.addJumpTableToFunction(funcAddr, jt);
  }

  // Register external call targets as new functions (bl only, not b)
  for (uint32_t target : result.externalCalls) {
    if (!graph.isEntryPoint(target) && !graph.isImport(target)) {
      if (binary.isInImportExportRange(target)) {
        continue;
      }
      graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
    }
  }

  // HollywoodAkeem: register tail-call targets AND wire up their callsite
  // edges. Upstream skipped this on the assumption that tail-call targets are
  // also reachable via a regular `bl` elsewhere — but the Xbox 360 Yukes-
  // engine pattern of alternate-entry chunks tail-calling to other alternate
  // entries breaks that assumption.
  //
  // Two-part fix: (1) addFunction so the target gets a FunctionNode + body;
  // (2) addUnresolvedJumpToFunction so the merge phase wires up the
  // callsite→callee edge. Without (2), codegen sees the b instruction, looks
  // up the FunctionNode's calls/tailCalls for the site, finds nothing, and
  // emits REX_FATAL("Unresolved call from X to Y").
  //
  // We don't know the per-site address for each tail-call target from
  // result.tailCalls alone (the BlockDiscoveryResult collapses them to a flat
  // vector of unique targets), so we mine result.unresolvedBranches for any
  // non-call branch whose target matches a tailCalls entry and add it there.
  // Anything not matched falls back to just the addFunction (target gets
  // recompiled, but the specific callsite may still need manual review).
  //
  // Gated by the same cvar as the data-pointer scan so projects without that
  // pattern keep upstream behavior.
  if (REXCVAR_GET(data_pointer_scan)) {
    std::unordered_set<uint32_t> tail_targets(result.tailCalls.begin(), result.tailCalls.end());
    for (uint32_t target : result.tailCalls) {
      if (!graph.isEntryPoint(target) && !graph.isImport(target)) {
        if (binary.isInImportExportRange(target)) {
          continue;
        }
        graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
      }
    }
    // For each branch the discovery walked but classified as "external"
    // (tail-call), also queue an unresolvedJump so the merge phase will
    // record the callsite edge once the target function is registered.
    // The walker records these in result.tailCalls but doesn't attach a
    // site, so we scan the function's blocks for `b` instructions whose
    // target is in our tail_targets set.
    for (const auto& block : result.blocks) {
      // Walk the block's instructions to find tail-call branches.
      for (uint32_t addr = block.base; addr + 4 <= block.base + block.size; addr += 4) {
        const uint8_t* insn_bytes = binary.translate(addr);
        if (!insn_bytes) continue;
        uint32_t insn = rex::memory::load_and_swap<uint32_t>(insn_bytes);
        // Unconditional b (op=18), no link bit, PC-relative
        if ((insn >> 26) != 18) continue;
        if (insn & 1) continue;  // link bit set = bl (call, handled by externalCalls)
        bool absolute = (insn >> 1) & 1;
        int32_t li = static_cast<int32_t>(insn & 0x03FFFFFC);
        if (li & 0x02000000) li -= 0x04000000;
        uint32_t target = absolute ? static_cast<uint32_t>(li) : addr + li;
        if (!tail_targets.count(target)) continue;
        // Queue as unresolved jump (isCall=false, isConditional=false). The
        // merge phase's tryResolveAgainst will call addTailCall once the
        // target FunctionNode is created and registered.
        graph.addUnresolvedJumpToFunction(funcAddr, addr, target, false, false);
      }
    }
  }

  // Add unresolved branches for later resolution
  for (const auto& branch : result.unresolvedBranches) {
    graph.addUnresolvedJumpToFunction(funcAddr, branch.site, branch.target, branch.isCall,
                                      branch.isConditional);
  }

  // Scan exception handler regions for branches not in discovered blocks
  if (pdataSize > 0) {
    std::unordered_set<uint32_t> discoveredAddrs;
    for (const auto& block : result.blocks) {
      for (uint32_t addr = block.base; addr < block.base + block.size; addr += 4) {
        discoveredAddrs.insert(addr);
      }
    }

    uint32_t pdataEnd = funcAddr + pdataSize;
    const uint8_t* funcData = binary.translate(funcAddr);
    if (funcData) {
      for (uint32_t offset = 0; offset < pdataSize; offset += 4) {
        uint32_t site = funcAddr + offset;

        // Skip if already discovered by normal control flow
        if (discoveredAddrs.count(site))
          continue;

        // Skip if marked invalid
        auto invalidIt = ctx.analysisState().invalidInstructions.find(site);
        if (invalidIt != ctx.analysisState().invalidInstructions.end()) {
          continue;
        }

        uint32_t insn = load_and_swap<uint32_t>(funcData + offset);
        uint32_t opcode = PPC_OP(insn);

        if (opcode != PPC_OP_B && opcode != PPC_OP_BC)
          continue;

        uint32_t target = 0;
        bool isCall = PPC_BL(insn);
        bool isAbsolute = PPC_BA(insn);

        if (opcode == PPC_OP_B) {
          int32_t branchOffset = PPC_BI(insn);
          target = isAbsolute ? static_cast<uint32_t>(branchOffset) : site + branchOffset;
        } else {
          int32_t branchOffset = PPC_BD(insn);
          target = isAbsolute ? static_cast<uint32_t>(branchOffset) : site + branchOffset;
        }

        // Skip internal jumps within pdata region
        if (!isCall && target >= funcAddr && target < pdataEnd) {
          continue;
        }

        graph.addUnresolvedJumpToFunction(funcAddr, site, target, isCall, false);

        // Register call targets as new functions
        if (isCall && !graph.isEntryPoint(target) && !graph.isImport(target)) {
          if (binary.isInImportExportRange(target)) {
            continue;
          }
          graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
        }
      }
    }
  }
}

void discoverAllFunctions(CodegenContext& ctx) {
  REXCODEGEN_TRACE("Analyze: starting iterative discovery...");

  auto& graph = ctx.graph;
  auto& binary = ctx.binary();

  // Iterative discovery
  size_t iteration = 0;
  size_t lastFunctionCount = 0;
  const size_t maxIterations = REXCVAR_GET(max_discovery_iterations);

  while (iteration < maxIterations) {
    iteration++;

    size_t currentFunctionCount = graph.functionCount();
    if (currentFunctionCount == lastFunctionCount && iteration > 1) {
      REXCODEGEN_DEBUG("Analyze: fixed point at iteration {} ({} functions)", iteration,
                       currentFunctionCount);
      break;
    }

    lastFunctionCount = currentFunctionCount;

    auto knownFunctions = buildKnownFunctions(graph);
    if (discoverPendingFunctions(ctx, knownFunctions) == 0) {
      break;
    }
  }

  REXCODEGEN_TRACE("Analyze: {} functions after call graph expansion", graph.functionCount());

  // VTable scanning
  {
    VTableScanner vtScanner(binary);
    auto vtables = vtScanner.scan();

    size_t newFunctions = 0;

    for (const auto& vt : vtables) {
      for (size_t i = 0; i < vt.slots.size(); i++) {
        uint32_t funcAddr = vt.slots[i];

        if (graph.isEntryPoint(funcAddr))
          continue;
        if (binary.isInImportExportRange(funcAddr))
          continue;

        graph.addFunction(funcAddr, 4, FunctionAuthority::VTABLE, true);
        newFunctions++;
      }
    }

    REXCODEGEN_TRACE("Analyze: VTable scan found {} vtables, {} new functions", vtables.size(),
                     newFunctions);

    // Continue discovery for vtable functions
    if (newFunctions > 0) {
      size_t vtableIteration = 0;
      const size_t maxVtableIterations = REXCVAR_GET(max_vtable_iterations);

      while (vtableIteration < maxVtableIterations) {
        vtableIteration++;

        auto knownFunctions = buildKnownFunctions(graph);
        if (discoverPendingFunctions(ctx, knownFunctions) == 0)
          break;

        if (graph.functionCount() == lastFunctionCount)
          break;
        lastFunctionCount = graph.functionCount();
      }
    }
  }

  REXCODEGEN_TRACE("Analyze: {} total functions after vtable scan", graph.functionCount());

  //=============================================================================
  // HollywoodAkeem: Data-Section Code Pointer Scan
  //
  // Scan .rdata and .data for 32-bit big-endian values that point to code
  // addresses with a recognizable PowerPC function prologue (mflr r12 / mflr r0).
  // Catches functions reachable only via data-resident pointer tables — the
  // Xbox 360 Yukes engine (WWE 2K14, SVR07/08) and similar games heavily use
  // these, and the existing vtableScanner only finds MSVC RTTI-style vtables
  // which Xbox 360 binaries usually don't have.
  //
  // Conservative filter: target must START WITH mflr r12 or mflr r0 (a real
  // function prologue). Addresses that point INTO existing function bodies
  // (alternate entry points used by some compiler optimizations) are logged
  // for manual `[entrypoint.functions]` review but NOT auto-registered — they
  // require chunk handling that this simple scan can't do safely.
  //=============================================================================
  if (REXCVAR_GET(data_pointer_scan)) {
    REXCODEGEN_TRACE("Analyze: starting data-section code-pointer scan...");
    constexpr uint32_t MFLR_R12 = 0x7D8802A6u;
    constexpr uint32_t MFLR_R0  = 0x7C0802A6u;

    // Terminator opcodes that end a function's reachable range.
    constexpr uint32_t BLR  = 0x4E800020u;
    constexpr uint32_t BCTR = 0x4E800420u;
    // Max bytes to walk forward from a candidate looking for a terminator.
    constexpr uint32_t MAX_CHUNK_SCAN = 0x1000u;  // 4 KB

    size_t scanned_pointers = 0;
    size_t registered_prologue = 0;
    size_t registered_safe_alt = 0;
    size_t skipped_unsafe = 0;
    // Dedupe across the scan — many tables reference the same address repeatedly.
    std::unordered_set<uint32_t> seen_candidates;

    for (const auto& sec : binary.sections()) {
      // Only scan non-executable data sections (.rdata, .data, etc.). Skip
      // executable sections (we already discover those by control flow) and
      // sections with no backing data.
      if (sec.executable || !sec.data || sec.size < 4) {
        continue;
      }
      // .pdata is exception-handler RVAs, not function pointers — skip it.
      if (sec.name == ".pdata") {
        continue;
      }

      for (uint32_t offset = 0; offset + 4 <= sec.size; offset += 4) {
        // Big-endian 32-bit load (matches PowerPC byte order in the binary)
        uint32_t candidate = rex::memory::load_and_swap<uint32_t>(sec.data + offset);
        scanned_pointers++;

        // Quick rejects
        if (candidate == 0) continue;
        if (candidate & 0x3) continue;                              // PPC is 4-byte aligned
        if (!binary.isExecutable(candidate)) continue;              // must point at code
        if (binary.isInImportExportRange(candidate)) continue;     // skip import thunks
        if (graph.isEntryPoint(candidate)) continue;                // already registered
        if (!seen_candidates.insert(candidate).second) continue;   // already evaluated

        const uint8_t* target_bytes = binary.translate(candidate);
        if (!target_bytes) continue;
        uint32_t first_insn = rex::memory::load_and_swap<uint32_t>(target_bytes);

        // Case 1: HIGH CONFIDENCE — real function prologue. Register and move on.
        if (first_insn == MFLR_R12 || first_insn == MFLR_R0) {
          graph.addFunction(candidate, 4, FunctionAuthority::VTABLE, true);
          registered_prologue++;
          REXCODEGEN_TRACE("data_pointer_scan: 0x{:08X} (prologue) via pointer at 0x{:08X}+{}",
                           candidate, sec.baseAddress, offset);
          continue;
        }

        // Case 2: non-prologue target. Walk forward looking for a terminator
        // (blr / bctr / unconditional b). While walking, check for backward
        // branches that escape [candidate, terminator). If any escape, this
        // is a loop-body / alternate-entry pattern that the recompiler's
        // chunk model can't represent safely — log and skip.
        uint32_t walk_addr = candidate;
        uint32_t terminator_addr = 0;
        bool has_escape_branch = false;
        uint32_t max_walk_addr = candidate + MAX_CHUNK_SCAN;
        while (walk_addr < max_walk_addr) {
          const uint8_t* walk_bytes = binary.translate(walk_addr);
          if (!walk_bytes) break;                                   // crossed section boundary
          uint32_t insn = rex::memory::load_and_swap<uint32_t>(walk_bytes);
          uint32_t op = insn >> 26;

          // Conditional branch (bc family): 16-bit signed displacement at bits 16..31, mask 0xFFFC
          if (op == 16) {
            int32_t bd = static_cast<int32_t>(insn & 0xFFFC);
            if (bd & 0x8000) bd -= 0x10000;
            uint32_t target = walk_addr + bd;
            if (target < candidate) {                               // backward escape
              has_escape_branch = true;
              break;
            }
          }
          // Unconditional branch (b family): 26-bit signed displacement at bits 6..31, mask 0x03FFFFFC
          else if (op == 18) {
            int32_t li = static_cast<int32_t>(insn & 0x03FFFFFC);
            if (li & 0x02000000) li -= 0x04000000;
            bool absolute = (insn >> 1) & 1;
            bool link = insn & 1;
            uint32_t target = absolute ? static_cast<uint32_t>(li) : walk_addr + li;
            if (!link) {
              // Non-link branch = tail-call or escape. Becomes the terminator.
              if (target < candidate || target >= max_walk_addr) {
                // Targets outside our walk range are fine as tail-calls.
              }
              terminator_addr = walk_addr;
              break;
            }
            // Link branch (bl) = call. Backward call is fine (calls another func), no escape.
          }
          // Plain blr / bctr — clean terminator.
          else if (insn == BLR || insn == BCTR) {
            terminator_addr = walk_addr;
            break;
          }
          walk_addr += 4;
        }

        if (has_escape_branch || terminator_addr == 0) {
          // Unsafe to register: chunk has a backward branch into untracked
          // code, OR we never found a terminator within the scan window.
          // The user can still add a manual [entrypoint.functions] entry
          // after deciding what to do.
          skipped_unsafe++;
          REXCODEGEN_TRACE("data_pointer_scan: 0x{:08X} skipped (insn=0x{:08X}, "
                           "{}backward-escape) via pointer at 0x{:08X}+{}",
                           candidate, first_insn,
                           has_escape_branch ? "has " : "no terminator, ",
                           sec.baseAddress, offset);
          continue;
        }

        // Case 3: SAFE alternate entry — self-contained chunk with no
        // backward escape. Register as standalone function; the generated
        // code will be a partial body that runs from candidate to terminator,
        // using whatever register state the caller set up.
        graph.addFunction(candidate, 4, FunctionAuthority::VTABLE, true);
        registered_safe_alt++;
        REXCODEGEN_TRACE("data_pointer_scan: 0x{:08X} (safe alt-entry, end~0x{:08X}) via "
                         "pointer at 0x{:08X}+{}",
                         candidate, terminator_addr + 4, sec.baseAddress, offset);
      }
    }

    REXCODEGEN_DEBUG("data_pointer_scan: scanned {} 32-bit words, registered {} "
                     "(prologue) + {} (safe alt-entry) functions, skipped {} unsafe",
                     scanned_pointers, registered_prologue, registered_safe_alt,
                     skipped_unsafe);

    size_t registered = registered_prologue + registered_safe_alt;

    // Re-run discovery for the newly registered functions so we get their
    // control flow (which may reveal more transitively-reachable functions).
    if (registered > 0) {
      size_t dpsIteration = 0;
      const size_t maxDpsIterations = REXCVAR_GET(max_vtable_iterations);
      while (dpsIteration < maxDpsIterations) {
        dpsIteration++;
        auto knownFunctions = buildKnownFunctions(graph);
        if (discoverPendingFunctions(ctx, knownFunctions) == 0) break;
        if (graph.functionCount() == lastFunctionCount) break;
        lastFunctionCount = graph.functionCount();
      }
      REXCODEGEN_TRACE("Analyze: {} total functions after data-pointer scan",
                       graph.functionCount());
    }
  }
}

//=============================================================================
// Function Pointer Scan: find lis/addi pairs loading code addresses
// TODO(tomc): THIS IS WIP AND PROB A BAD IDEA LOL LETS SEE
//=============================================================================
void functionPointerScan(CodegenContext& ctx) {
  if (!ctx.hasDecoded()) {
    REXCODEGEN_WARN("functionPointerScan: DecodedBinary not initialized, skipping");
    return;
  }

  auto& graph = ctx.graph;
  auto& decoded = ctx.decoded();
  const auto& codeRegions = decoded.codeRegions();

  if (codeRegions.empty()) {
    REXCODEGEN_WARN("functionPointerScan: no code regions, skipping");
    return;
  }

  // Build set of existing functions to avoid duplicates
  std::unordered_set<uint32_t> existingFunctions;
  for (const auto& [addr, node] : graph.functions()) {
    existingFunctions.insert(addr);
  }

  // Track lis values: register -> (high_value, lis_address)
  // We scan linearly and track the most recent lis for each register
  // PPC has exactly 32 GPRs, so a fixed-size array is more efficient than a map
  std::array<std::pair<uint32_t, uint32_t>, 32> lisValues{};
  std::bitset<32> lisValid;

  size_t foundCount = 0;

  for (const auto& region : codeRegions) {
    lisValid.reset();  // Reset tracking at region boundaries

    for (uint32_t addr = region.start; addr < region.end; addr += 4) {
      auto* insn = decoded.get(addr);
      if (!insn)
        continue;

      // Track lis rD, IMM
      if (isLis(*insn)) {
        uint8_t rd = static_cast<uint8_t>(insn->D.RT);
        uint32_t hi = static_cast<uint32_t>(static_cast<int16_t>(insn->D.d)) << 16;
        lisValues[rd] = {hi, addr};
        lisValid.set(rd);
        continue;
      }

      // Check for addi rD, rA, IMM where rA was set by lis
      if (insn->opcode == rex::codegen::ppc::Opcode::addi) {
        uint8_t ra = static_cast<uint8_t>(insn->D.RA);
        if (ra == 0)
          continue;  // li pseudo-op, not addi

        if (!lisValid.test(ra))
          continue;

        uint32_t hi = lisValues[ra].first;
        int16_t lo = static_cast<int16_t>(insn->D.d);
        uint32_t fullAddr = hi + lo;  // Sign-extended add

        // PPC instructions are 4-byte aligned
        if (fullAddr & 0x3)
          continue;

        // Check if this address is in a code region
        const CodeRegion* targetRegion = decoded.regionContaining(fullAddr);
        if (!targetRegion)
          continue;

        // Skip if already a known function
        if (existingFunctions.contains(fullAddr))
          continue;

        // Skip if it's an internal address (within same function's likely range)
        // Heuristic: if target is very close to current address, probably internal label
        int32_t distance = static_cast<int32_t>(fullAddr) - static_cast<int32_t>(addr);
        if (distance > -0x1000 && distance < 0x1000) {
          // Could be local label, skip for now
          continue;
        }

        // Register as function with DISCOVERED authority and hasXrefs=true
        graph.addFunction(fullAddr, 4, FunctionAuthority::DISCOVERED, true);
        existingFunctions.insert(fullAddr);
        foundCount++;

        REXCODEGEN_TRACE("functionPointerScan: found 0x{:08X} via lis/addi at 0x{:08X}", fullAddr,
                         addr);
      }

      // Also check ori rD, rA, IMM (alternative to addi for unsigned)
      if (insn->opcode == rex::codegen::ppc::Opcode::ori) {
        uint8_t ra = static_cast<uint8_t>(insn->D.RA);
        if (!lisValid.test(ra))
          continue;

        uint32_t hi = lisValues[ra].first;
        uint16_t lo = static_cast<uint16_t>(insn->D.d);
        uint32_t fullAddr = hi | lo;  // Unsigned OR

        // PPC instructions are 4-byte aligned
        if (fullAddr & 0x3)
          continue;

        const CodeRegion* targetRegion = decoded.regionContaining(fullAddr);
        if (!targetRegion)
          continue;

        if (existingFunctions.contains(fullAddr))
          continue;

        int32_t distance = static_cast<int32_t>(fullAddr) - static_cast<int32_t>(addr);
        if (distance > -0x1000 && distance < 0x1000)
          continue;

        graph.addFunction(fullAddr, 4, FunctionAuthority::DISCOVERED, true);
        existingFunctions.insert(fullAddr);
        foundCount++;

        REXCODEGEN_TRACE("functionPointerScan: found 0x{:08X} via lis/ori at 0x{:08X}", fullAddr,
                         addr);
      }

      // Clear lis tracking if register is overwritten by other instruction
      // (Simplified: we clear on any write to the register)
      // This is conservative - could miss some patterns but avoids false positives
    }
  }

  REXCODEGEN_TRACE("functionPointerScan: found {} new function pointer targets", foundCount);
}

}  // anonymous namespace

/// Discover blocks for all pending functions (shared helper, declared in phase_helpers.h).
size_t discoverPendingFunctions(CodegenContext& ctx,
                                const std::unordered_set<uint32_t>& knownFunctions) {
  std::vector<uint32_t> pending;
  for (const auto& [addr, node] : ctx.graph.functions()) {
    if (node->canDiscover()) {
      pending.push_back(addr);
    }
  }
  for (uint32_t funcAddr : pending) {
    discoverFunction(ctx, funcAddr, knownFunctions);
  }
  return pending.size();
}

namespace phases {

VoidResult Discover(CodegenContext& ctx, ProgressReporter* reporter) {
  (void)reporter;
  discoverAllFunctions(ctx);
  return Ok();
}

}  // namespace phases

}  // namespace rex::codegen
