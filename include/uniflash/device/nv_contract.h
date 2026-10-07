#pragma once
#include <array>
#include <string_view>
#include <cstdint>

namespace uniflash::device {
enum class NvDialect { Unknown, Signed7MiB };
struct NvPair { std::string_view primary, backup; };
inline constexpr std::array nv_pairs{
    NvPair{"fixnv1","fixnv2"}, NvPair{"runtimenv1","runtimenv2"},
    NvPair{"tdfixnv1","tdfixnv2"}, NvPair{"tdruntimenv1","tdruntimenv2"},
    NvPair{"g_fixnv1","g_fixnv2"}, NvPair{"g_runtimenv1","g_runtimenv2"},
    NvPair{"nr_fixnv1","nr_fixnv2"}, NvPair{"nr_runtimenv1","nr_runtimenv2"},
    NvPair{"l_fixnv1","l_fixnv2"}, NvPair{"l_runtimenv1","l_runtimenv2"},
    NvPair{"tl_fixnv1","tl_fixnv2"}, NvPair{"tl_runtimenv1","tl_runtimenv2"},
    NvPair{"lf_fixnv1","lf_fixnv2"}, NvPair{"lf_runtimenv1","lf_runtimenv2"},
    NvPair{"wfixnv1","wfixnv2"}, NvPair{"wruntimenv1","wruntimenv2"},
    NvPair{"w_fixnv1","w_fixnv2"}, NvPair{"w_runtimenv1","w_runtimenv2"},
    NvPair{"wl_fixnv1","wl_fixnv2"}, NvPair{"wl_runtimenv1","wl_runtimenv2"},
    NvPair{"wcnfixnv1","wcnfixnv2"}, NvPair{"wcnruntimenv1","wcnruntimenv2"}
};
inline const NvPair* nv_pair(std::string_view name) {
    for (const auto& pair : nv_pairs) if (pair.primary==name || pair.backup==name) return &pair;
    return nullptr;
}
inline uint32_t nv_payload_size(NvDialect dialect) {
    return dialect==NvDialect::Signed7MiB ? 0x700000 : 0;
}
}
