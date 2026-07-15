#include <rex/system/memory_patch.h>

#include <cctype>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <toml++/toml.hpp>

#include <rex/logging.h>
#include <rex/runtime.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xmemory.h>

namespace rex {
namespace system {

namespace {

// Parse a run of hex digits (whitespace / "0x" / commas ignored) into bytes.
std::optional<std::vector<uint8_t>> ParseHexBytes(std::string_view s) {
  std::vector<uint8_t> out;
  int hi = -1;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == ' ' || c == '\t' || c == ',' || c == '_' || c == '\n' || c == '\r')
      continue;
    // tolerate a "0x" / "0X" prefix between byte groups
    if (c == '0' && i + 1 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
      ++i;
      continue;
    }
    int v;
    if (c >= '0' && c <= '9')
      v = c - '0';
    else if (c >= 'a' && c <= 'f')
      v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      v = c - 'A' + 10;
    else
      return std::nullopt;
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(static_cast<uint8_t>((hi << 4) | v));
      hi = -1;
    }
  }
  if (hi >= 0)
    return std::nullopt;  // odd number of nibbles
  return out;
}

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

std::string BytesToHex(const uint8_t* p, size_t n) {
  static const char* kHex = "0123456789ABCDEF";
  std::string s;
  s.reserve(n * 3);
  for (size_t i = 0; i < n; ++i) {
    if (i)
      s.push_back(' ');
    s.push_back(kHex[p[i] >> 4]);
    s.push_back(kHex[p[i] & 0xF]);
  }
  return s;
}

}  // namespace

uint32_t ApplyMemoryPatches(Runtime* runtime,
                            const std::filesystem::path& config_path,
                            uint32_t title_id) {
  if (!runtime || !runtime->memory())
    return 0;
  if (config_path.empty() || !std::filesystem::is_regular_file(config_path))
    return 0;

  toml::table root;
  try {
    root = toml::parse_file(config_path.string());
  } catch (const toml::parse_error&) {
    return 0;  // cvar loader already reports parse errors
  }

  auto* patches = root["patches"].as_array();
  if (!patches || patches->empty())
    return 0;

  auto* memory = runtime->memory();
  uint32_t applied = 0;
  uint32_t index = 0;

  for (auto&& node : *patches) {
    ++index;
    auto* entry = node.as_table();
    if (!entry) {
      REXSYS_WARN("Patch #{}: not a table, skipped", index);
      continue;
    }

    std::string name = (*entry)["name"].value_or<std::string>(fmt::format("#{}", index));

    if (auto enabled = (*entry)["enabled"].value<bool>(); enabled && !*enabled) {
      REXSYS_INFO("Patch '{}' disabled, skipped", name);
      continue;
    }

    if (auto* tid = (*entry)["title_id"].node()) {
      auto want = ParseTitleId(*tid);
      if (!want) {
        REXSYS_WARN("Patch '{}': bad title_id, skipped", name);
        continue;
      }
      if (*want != title_id) {
        REXSYS_DEBUG("Patch '{}': title {:08X} != running {:08X}, skipped", name,
                     *want, title_id);
        continue;
      }
    }

    auto addr64 = (*entry)["address"].value<int64_t>();
    if (!addr64) {
      REXSYS_WARN("Patch '{}': missing/invalid 'address', skipped", name);
      continue;
    }
    uint32_t address = static_cast<uint32_t>(*addr64);

    auto bytes_str = (*entry)["bytes"].value<std::string>();
    if (!bytes_str) {
      REXSYS_WARN("Patch '{}': missing 'bytes', skipped", name);
      continue;
    }
    auto bytes = ParseHexBytes(*bytes_str);
    if (!bytes || bytes->empty()) {
      REXSYS_WARN("Patch '{}': malformed 'bytes' (need whole hex bytes), skipped", name);
      continue;
    }
    uint32_t len = static_cast<uint32_t>(bytes->size());

    // Bounds-check the entire span (both ends, in case it straddles a page).
    if (!rex::memory::IsValidGuestAddress(address) ||
        !rex::memory::IsValidGuestAddress(address + len - 1)) {
      REXSYS_ERROR("Patch '{}': address range {:08X}..{:08X} not committed guest "
                   "memory, skipped", name, address, address + len - 1);
      continue;
    }

    uint8_t* host = memory->TranslateVirtual<uint8_t*>(address);

    // Optional guard: refuse to patch unless current bytes match `expect`.
    // (Reads are safe even on read-only guest pages.)
    if (auto expect_str = (*entry)["expect"].value<std::string>()) {
      auto expect = ParseHexBytes(*expect_str);
      if (!expect || expect->size() != bytes->size()) {
        REXSYS_ERROR("Patch '{}': 'expect' malformed or wrong length ({} vs {} "
                     "bytes), skipped", name, expect ? expect->size() : 0, len);
        continue;
      }
      if (std::memcmp(host, expect->data(), len) != 0) {
        REXSYS_ERROR("Patch '{}': guard mismatch at {:08X} — have [{}], expected "
                     "[{}]. Wrong address or game build? Skipped.", name, address,
                     BytesToHex(host, len), BytesToHex(expect->data(), len));
        continue;
      }
    }

    // XEX .text/.rodata sections are mapped host-READ-ONLY (xex_module.cpp
    // Protect() on XEX_SECTION_CODE / XEX_SECTION_READONLY_DATA). A raw write
    // to such a page faults the host, so temporarily add write access to the
    // covering pages, apply, then restore the original protection.
    auto* heap = memory->LookupHeap(address);
    if (!heap) {
      REXSYS_ERROR("Patch '{}': no heap for {:08X}, skipped", name, address);
      continue;
    }
    rex::memory::HeapAllocationInfo info{};
    if (!heap->QueryRegionInfo(address, &info)) {
      REXSYS_ERROR("Patch '{}': cannot query protection at {:08X}, skipped", name, address);
      continue;
    }
    bool made_writable = false;
    uint32_t saved_protect = info.protect;
    if (!(info.protect & rex::memory::kMemoryProtectWrite)) {
      if (!heap->Protect(address, len,
                         info.protect | rex::memory::kMemoryProtectWrite,
                         &saved_protect)) {
        REXSYS_ERROR("Patch '{}': failed to unprotect {:08X}, skipped", name, address);
        continue;
      }
      made_writable = true;
    }

    std::string before = BytesToHex(host, len);
    std::memcpy(host, bytes->data(), len);
    std::string after = BytesToHex(host, len);

    if (made_writable)
      heap->Protect(address, len, saved_protect);  // restore original protection

    REXSYS_INFO("Patch '{}': {:08X} [{}] -> [{}]", name, address, before, after);
    ++applied;
  }

  if (applied)
    REXSYS_INFO("Applied {} memory patch(es) from {}", applied,
                config_path.filename().string());
  return applied;
}

}  // namespace system
}  // namespace rex
