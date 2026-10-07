/*
 * UniFlash-Core / PAC Archive
 *
 * Archive entry classification and the local PAC reader interface.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/io/image.h>
#include <string>
#include <vector>
#include <uniflash/session/nv_image.h>
#include <uniflash/session/pac_parser.h>

namespace uniflash::session {
inline bool pac_address_operation(std::string_view type) {
    return type=="CODE" || type=="UBOOT_LOADER" || type=="BOOT_LOADER" || type=="YAFFS_IMG" || type=="MiscDataCode" ||
        type=="ReadFlash" || type=="ReadFlashAndSave" || type=="ReadFlashAndDirectSave" || type=="EraseFlash" || type=="NV" || type=="NV_NAND" || type=="CHECK_NV" || type=="Soft_SIM";
}
inline bool pac_address_read(std::string_view type) {
    return type=="ReadFlash" || type=="ReadFlashAndSave" || type=="ReadFlashAndDirectSave" || type=="CHECK_NV";
}
inline bool pac_control_operation(std::string_view type) {
    return type=="DONOTHING" || type=="EndProcess" || type=="Reset" || type=="PowerOff" || type=="EXTTABLE" ||
        type=="READFLASHTYPE" || type=="CHECK_MCPTYPE" || type=="READ_FLASHINFO" || type=="READ_RF_CHIP_TYPE" ||
        type=="ReadPartitionInfo" || type=="WriteEfuse" || type=="ReadVpac" || type=="WriteVpac";
}
inline bool pac_read_operation(std::string_view type) {
    return type=="ReadFlash2" || type=="CHECK_NV2" || type=="ReadFlashAndSave2" || type=="ReadFlashAndDirectSave2" ||
        type=="ReadFlashAndSave2_64" || type=="ReadFlashAndDirectSave2_64";
}
struct PacAction {
    std::string id, partition, type;
    uint64_t offset = 0, length = 0;
    bool erase = false;
    uint32_t load_address = 0;
    std::vector<NvMergeItem> nv_items{};
    uint64_t declared_size = 0;
    uint64_t read_offset = 0;
};
// A frozen, CRC-checked archive. Entries are bounded views, never filesystem paths.
class PacArchive {
public:
    // Zero defers storage selection; nonzero validates selected operations
    // after parsing, including address-only packages for NAND/unknown storage.
    static std::expected<PacArchive, std::errc> open(const std::filesystem::path&,
        uint32_t storage, std::stop_token = {}, const io::PrepareObserver& = {});
    const std::vector<PacAction>& actions() const { return actions_; }
    const std::string& product() const { return product_; }
    const std::vector<PacAction>& loaders() const { return loaders_; }
    const PacImage& partition_layout() const { return partition_layout_; }
    const std::vector<std::string>& backup_targets() const { return backup_targets_; }
    uint32_t repartition_strategy() const { return repartition_strategy_; }
    std::expected<std::vector<PacAction>,std::errc> selected_actions(uint32_t storage) const;
    std::expected<std::vector<uint8_t>,std::errc> loader_bytes(const PacAction&,std::stop_token = {}) const;
    std::expected<io::Image, std::errc> image(const PacAction&, uint64_t capacity,
        std::stop_token = {}, const io::PrepareObserver& = {}) const;
    // Validate sparse structure/expanded capacity but retain the original
    // bytes for DownloadByID. The loader owns sparse expansion and signed ABI.
    std::expected<io::Image,std::errc> transfer_image(const PacAction&,uint64_t capacity,
        std::stop_token = {},const io::PrepareObserver& = {},uint64_t* expanded_size = nullptr) const;
private:
    explicit PacArchive(io::Image image) : container_(std::move(image)) {}
    io::Image container_;
    std::vector<PacAction> actions_;
    std::vector<PacAction> loaders_;
    std::string product_;
    PacImage partition_layout_;
    uint32_t repartition_strategy_ = 1;
    std::vector<std::string> backup_targets_;
};
}
