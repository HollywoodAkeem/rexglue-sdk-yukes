#include <rex/system/xam/content_install.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <toml++/toml.hpp>

#include <rex/filesystem.h>
#include <rex/logging.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/content_manager.h>

namespace rex {
namespace system {
namespace xam {

namespace {

// Same convention as memory_patch.cpp: hex string ("545408B2") or integer.
std::optional<uint32_t> ParseTitleId(const toml::node& node) {
  if (auto v = node.value<int64_t>())
    return static_cast<uint32_t>(*v);
  if (auto s = node.value<std::string>()) {
    try {
      return static_cast<uint32_t>(std::stoul(*s, nullptr, 16));
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

}  // namespace

// ===========================================================================
// [DLC-GUARD] rule engine
// ===========================================================================

namespace {

enum class GuardFallback {
  kNone,          // expect-at-offset only
  kScanFile,      // search the file for the unique expect window (small files)
  kEpk8Msc1Walk,  // EPK8 dir walk -> MSC1 chunk -> front PACH (misc pacs)
};

// One size-preserving byte patch inside one extracted package file. `expect`
// is verified before any write; `patch` overlays the window at +patch_delta.
// `candidates` are the known-good offsets (clean packs); `fallback`
// re-locates the record structurally when offsets have shifted.
struct DlcGuardRule {
  const char* rel_path;  // forward-slash path under the package root
  const uint8_t* expect;
  uint32_t expect_len;
  uint32_t patch_delta;  // patch position within the expect window
  const uint8_t* patch;
  uint32_t patch_len;
  const uint32_t* candidates;
  uint32_t candidate_count;
  GuardFallback fallback;
  const char* desc;
};

// ===== WWE 2K14 (545408B2) — recon wf_ad3f9e6f, byte-verified on the clean
// redrooster Add-Ons 3/4/5. =====
// 1) misc_dlc0N.pac: the MSC1 chunk (EPK8 data base 0x4000) opens with a
//    front PACH dir (count 9 LE, ids {2,20,118,400-404,600}); entry[0] id 2
//    dispatches sub_822C54E8 = wholesale runtime STG-table replace with a
//    verbatim retail 73-record table — it would erase the recomp arena-57
//    record. Flip the id to 0x7FFF: the dispatcher (sub_83427E20) is a
//    sorted merge-join that silently skips unmatched ids, so ids
//    20/400-404/600 keep dispatching exactly as retail.
// 2) catalog_{hd,sd}.arc: dir records 'CSDT' and 'SDB ' register DLC chunk
//    dirs that PREPEND to the runtime lookup ring and shadow the modified
//    base evtdata CSDT (arena-57 rows) and all 136 base string chunks (37
//    recomp-edited). One-byte 4CC rename -> dead ring entry; lookups fall
//    through to base. Cost until merge-upgrade (logged): DLC loses its ~11
//    CSDT announce-row tweaks + 64 updated string chunks.
// Reversibility: every receipt logs the original bytes; hand-revert = write
// them back (or wipe the package dir + .header and re-install).

constexpr uint8_t kMsc1PachId2[12] = {0x50, 0x41, 0x43, 0x48,   // 'PACH'
                                      0x09, 0x00, 0x00, 0x00,   // count 9 LE
                                      0x02, 0x00, 0x00, 0x00};  // entry0 id 2
constexpr uint8_t kIdFlip[4] = {0xFF, 0x7F, 0x00, 0x00};        // id 0x7FFF
constexpr uint8_t kCsdtRecord[8] = {0x43, 0x53, 0x44, 0x54,     // 'CSDT'
                                    0x00, 0x30, 0x00, 0x00};    // dir flags
constexpr uint8_t kSdbRecord[8] = {0x53, 0x44, 0x42, 0x20,      // 'SDB '
                                   0x19, 0x80, 0x00, 0x00};     // dir flags
constexpr uint8_t kRenameX[1] = {0x78};                         // 'x'

constexpr uint32_t kMsc1At[] = {0x4000};
constexpr uint32_t kCsdtAt[] = {0x0D00, 0x08C0};         // AO3/AO5, AO4
constexpr uint32_t kSdbAt[] = {0x0F70, 0x1010, 0x0C0C};  // AO5, AO3, AO4

constexpr const char* kStgDesc =
    "MSC1 PACH entry id 2 -> 0x7FFF (wholesale STG-replace neutralized; "
    "arena-57 record protected)";
constexpr const char* kCsdtDesc =
    "dir 'CSDT' -> 'CSDx' (evtdata shadow off; DLC announce-row tweaks "
    "deferred to merge-upgrade)";
constexpr const char* kSdbDesc =
    "dir 'SDB ' -> 'SDBx' (string shadow off; DLC string updates deferred "
    "to merge-upgrade)";

constexpr DlcGuardRule kWwe2k14Rules[] = {
    {"pac/misc_dlc03.pac", kMsc1PachId2, 12, 8, kIdFlip, 4, kMsc1At, 1,
     GuardFallback::kEpk8Msc1Walk, kStgDesc},
    {"pac/misc_dlc04.pac", kMsc1PachId2, 12, 8, kIdFlip, 4, kMsc1At, 1,
     GuardFallback::kEpk8Msc1Walk, kStgDesc},
    {"pac/misc_dlc05.pac", kMsc1PachId2, 12, 8, kIdFlip, 4, kMsc1At, 1,
     GuardFallback::kEpk8Msc1Walk, kStgDesc},
    {"info/catalog_hd.arc", kCsdtRecord, 8, 3, kRenameX, 1, kCsdtAt, 2,
     GuardFallback::kScanFile, kCsdtDesc},
    {"info/catalog_sd.arc", kCsdtRecord, 8, 3, kRenameX, 1, kCsdtAt, 2,
     GuardFallback::kScanFile, kCsdtDesc},
    {"info/catalog_hd.arc", kSdbRecord, 8, 3, kRenameX, 1, kSdbAt, 3,
     GuardFallback::kScanFile, kSdbDesc},
    {"info/catalog_sd.arc", kSdbRecord, 8, 3, kRenameX, 1, kSdbAt, 3,
     GuardFallback::kScanFile, kSdbDesc},
};

std::string GuardHex(const uint8_t* p, size_t n) {
  std::string s;
  for (size_t i = 0; i < n; ++i)
    s += fmt::format("{}{:02X}", i ? " " : "", p[i]);
  return s;
}

bool GuardReadAt(std::fstream& f, uint64_t off, uint8_t* buf, size_t len) {
  f.clear();
  f.seekg(static_cast<std::streamoff>(off));
  f.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(len));
  return f.good();
}

bool GuardWriteAt(std::fstream& f, uint64_t off, const uint8_t* buf,
                  size_t len) {
  f.clear();
  f.seekp(static_cast<std::streamoff>(off));
  f.write(reinterpret_cast<const char*>(buf), static_cast<std::streamsize>(len));
  f.flush();
  return f.good();
}

enum class GuardMatch { kNo, kExpect, kAlreadyPatched };

GuardMatch GuardClassify(const DlcGuardRule& rule, const uint8_t* window) {
  if (!std::memcmp(window, rule.expect, rule.expect_len))
    return GuardMatch::kExpect;
  // Already-patched = expect with the patch overlaid (idempotent re-run).
  std::vector<uint8_t> after(rule.expect, rule.expect + rule.expect_len);
  std::memcpy(after.data() + rule.patch_delta, rule.patch, rule.patch_len);
  if (!std::memcmp(window, after.data(), rule.expect_len))
    return GuardMatch::kAlreadyPatched;
  return GuardMatch::kNo;
}

// Fallback 1: bounded whole-file scan (catalog arcs are a few KiB and the
// 8-byte dir records are unique per the recon census).
bool GuardScanFile(std::fstream& f, const DlcGuardRule& rule,
                   uint64_t file_size, uint64_t* out_off,
                   GuardMatch* out_state) {
  constexpr uint64_t kScanCap = 4ull * 1024 * 1024;
  uint64_t limit = std::min(file_size, kScanCap);
  if (limit < rule.expect_len) return false;
  std::vector<uint8_t> data(static_cast<size_t>(limit));
  if (!GuardReadAt(f, 0, data.data(), data.size())) return false;
  for (size_t off = 0; off + rule.expect_len <= data.size(); ++off) {
    GuardMatch m = GuardClassify(rule, data.data() + off);
    if (m != GuardMatch::kNo) {
      *out_off = off;
      *out_state = m;
      return true;
    }
  }
  return false;
}

// Fallback 2: structural EPK8 walk for misc pacs — dir @0x800 (28-byte LE
// entries, fname8 @+0xC, sector u32 @+0x14, unit 0x800 from data base
// 0x4000); find "MSC1", verify its chunk opens with 'PACH' and entry[0]'s
// id field (dir+8, u32 LE) is 2 (or already 0x7FFF).
bool GuardEpk8Msc1Walk(std::fstream& f, const DlcGuardRule& rule,
                       uint64_t* out_off, GuardMatch* out_state) {
  uint8_t magic[4];
  if (!GuardReadAt(f, 0, magic, 4) || std::memcmp(magic, "EPK8", 4))
    return false;
  for (uint64_t e = 0x800; e + 28 <= 0x4000; e += 28) {
    uint8_t entry[28];
    if (!GuardReadAt(f, e, entry, 28)) return false;
    if (std::memcmp(entry + 0xC, "MSC1", 4)) continue;
    uint32_t sector = entry[0x14] | (entry[0x15] << 8) | (entry[0x16] << 16) |
                      (static_cast<uint32_t>(entry[0x17]) << 24);
    uint64_t chunk = 0x4000ull + static_cast<uint64_t>(sector) * 0x800;
    uint8_t window[12];
    if (!GuardReadAt(f, chunk, window, 12)) return false;
    if (std::memcmp(window, "PACH", 4)) return false;
    if (!std::memcmp(window + 8, rule.expect + 8, 4)) {
      *out_off = chunk;
      *out_state = GuardMatch::kExpect;
      return true;
    }
    if (!std::memcmp(window + 8, rule.patch, 4)) {
      *out_off = chunk;
      *out_state = GuardMatch::kAlreadyPatched;
      return true;
    }
    return false;  // PACH found but entry0 id is neither 2 nor 0x7FFF
  }
  return false;
}

}  // namespace

X_RESULT ApplyDlcGuardRules(const std::filesystem::path& install_path,
                            const std::string& package_file_name,
                            uint32_t title_id) {
  std::span<const DlcGuardRule> rules;
  if (title_id == 0x545408B2u) rules = kWwe2k14Rules;  // WWE 2K14
  if (rules.empty()) return X_ERROR_SUCCESS;           // unknown title: no-op

  uint32_t applied = 0, already = 0, mismatched = 0, touched = 0;

  for (const auto& rule : rules) {
    auto path = install_path / rule.rel_path;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) continue;  // silent skip
    ++touched;

    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!f.is_open()) {
      REXSYS_ERROR("[DLC-GUARD] {}: cannot open for patching", path.string());
      return X_ERROR_ACCESS_DENIED;  // pre-header abort => clean retry
    }
    uint64_t file_size = std::filesystem::file_size(path, ec);
    if (ec) file_size = 0;

    // 1) Known-good candidate offsets (clean redrooster packs).
    uint64_t hit_off = 0;
    GuardMatch state = GuardMatch::kNo;
    for (uint32_t c = 0; c < rule.candidate_count && state == GuardMatch::kNo;
         ++c) {
      uint64_t off = rule.candidates[c];
      if (off + rule.expect_len > file_size) continue;
      uint8_t window[16];
      if (!GuardReadAt(f, off, window, rule.expect_len)) {
        REXSYS_ERROR("[DLC-GUARD] {}: read failed @0x{:X}", path.string(), off);
        return X_ERROR_ACCESS_DENIED;
      }
      GuardMatch m = GuardClassify(rule, window);
      if (m != GuardMatch::kNo) {
        hit_off = off;
        state = m;
      }
    }

    // 2) Structural fallback for shifted (community-modified) packs.
    bool relocated = false;
    if (state == GuardMatch::kNo && rule.fallback == GuardFallback::kScanFile)
      relocated = GuardScanFile(f, rule, file_size, &hit_off, &state);
    if (state == GuardMatch::kNo &&
        rule.fallback == GuardFallback::kEpk8Msc1Walk)
      relocated = GuardEpk8Msc1Walk(f, rule, &hit_off, &state);

    if (state == GuardMatch::kNo) {
      REXSYS_WARN("[DLC-GUARD] SKIP {}: expect bytes not found (candidates + "
                  "fallback) - file left untouched; unknown/modified pack?",
                  rule.rel_path);
      ++mismatched;
      continue;  // never corrupt
    }

    uint64_t patch_off = hit_off + rule.patch_delta;
    if (state == GuardMatch::kAlreadyPatched) {
      REXSYS_WARN("[DLC-GUARD] {} @0x{:X}: already guarded ({})",
                  rule.rel_path, patch_off, rule.desc);
      ++already;
      continue;
    }

    uint8_t orig[8];
    if (!GuardReadAt(f, patch_off, orig, rule.patch_len) ||
        !GuardWriteAt(f, patch_off, rule.patch, rule.patch_len)) {
      REXSYS_ERROR("[DLC-GUARD] {}: write failed @0x{:X}", path.string(),
                   patch_off);
      return X_ERROR_ACCESS_DENIED;  // pre-header abort => clean retry
    }
    REXSYS_WARN("[DLC-GUARD] {} @0x{:X}: {}{} [was {} -> now {}]",
                rule.rel_path, patch_off, rule.desc,
                relocated ? " (RELOCATED offset)" : "",
                GuardHex(orig, rule.patch_len),
                GuardHex(rule.patch, rule.patch_len));
    ++applied;
  }

  if (touched)
    REXSYS_WARN("[DLC-GUARD] '{}': {} patched, {} already-guarded, {} skipped "
                "(mismatch) - retail DLC neutralized against recomp content",
                package_file_name, applied, already, mismatched);
  return X_ERROR_SUCCESS;
}

uint32_t InstallContentFromConfig(KernelState* kernel_state,
                                  const std::filesystem::path& config_path,
                                  uint32_t title_id) {
  if (!kernel_state || !kernel_state->content_manager())
    return 0;
  if (config_path.empty() || !std::filesystem::is_regular_file(config_path))
    return 0;

  toml::table root;
  try {
    root = toml::parse_file(config_path.string());
  } catch (const toml::parse_error&) {
    return 0;  // cvar loader already reports parse errors
  }

  auto* installs = root["content_install"].as_array();
  if (!installs || installs->empty())
    return 0;

  uint32_t installed = 0;
  uint32_t index = 0;

  for (auto&& node : *installs) {
    ++index;
    auto* entry = node.as_table();
    if (!entry) {
      REXSYS_WARN("[CONTENT-INSTALL] entry #{}: not a table, skipped", index);
      continue;
    }

    std::string name = (*entry)["name"].value_or<std::string>(fmt::format("#{}", index));

    if (auto enabled = (*entry)["enabled"].value<bool>(); enabled && !*enabled) {
      REXSYS_INFO("[CONTENT-INSTALL] '{}' disabled, skipped", name);
      continue;
    }

    if (auto* tid = (*entry)["title_id"].node()) {
      auto want = ParseTitleId(*tid);
      if (!want) {
        REXSYS_WARN("[CONTENT-INSTALL] '{}': bad title_id, skipped", name);
        continue;
      }
      if (*want != title_id) {
        REXSYS_DEBUG("[CONTENT-INSTALL] '{}': title {:08X} != running {:08X}, skipped",
                     name, *want, title_id);
        continue;
      }
    }

    auto path_str = (*entry)["path"].value<std::string>();
    if (!path_str || path_str->empty()) {
      REXSYS_WARN("[CONTENT-INSTALL] '{}': missing 'path', skipped", name);
      continue;
    }
    auto package_path = rex::to_path(*path_str);

    bool overwrite = (*entry)["overwrite"].value_or(false);
    // Per-entry guard off-switch (default ON = automatic; design law).
    bool dlc_guard = (*entry)["dlc_guard"].value_or(true);

    auto result = kernel_state->content_manager()->InstallContent(package_path, overwrite,
                                                                  dlc_guard);
    if (result == X_ERROR_SUCCESS) {
      ++installed;
    } else if (result != X_ERROR_ALREADY_EXISTS) {
      REXSYS_ERROR("[CONTENT-INSTALL] '{}': install failed ({:08X}) for '{}'", name,
                   result, package_path.string());
    }
    // X_ERROR_ALREADY_EXISTS = one-shot skip; InstallContent already logged it.
  }

  if (installed)
    REXSYS_WARN("[CONTENT-INSTALL] {} package(s) installed from {}", installed,
                config_path.filename().string());
  return installed;
}

}  // namespace xam
}  // namespace system
}  // namespace rex
