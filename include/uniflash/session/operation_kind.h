/*
 * UniFlash-Core / Operation Description
 *
 * Address targets, write actions and plan steps.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <cstdint>
#include <optional>
#include <memory>
#include <uniflash/io/image.h>
#include <uniflash/device/address.h>
namespace uniflash::session {
class NvRestorePlan;
struct AddressTarget {
    uint32_t address=0;
    device::AddressWordOrder order=device::AddressWordOrder::Little;
    size_t chunk=0x800;
};
struct WriteAction {
    explicit WriteAction(io::Image source,bool erase=false):image(std::move(source)),erase_first(erase) {}
    io::Image image;
    bool erase_first=false,wide=false;
    uint64_t expanded_size=0,verify_size=0;
    std::vector<std::string> verify_targets;
    std::optional<AddressTarget> address;
    std::optional<uint32_t> timestamp;
    std::vector<uint8_t> softsim_eid;
};
struct EraseAction { std::optional<AddressTarget> address;uint64_t size=0; };
struct ReadAction { uint64_t offset=0,length=0; bool wide=false;std::optional<AddressTarget> address{}; };
struct LogicalNvAction { std::vector<uint8_t> payload,before;std::optional<AddressTarget> address; };
class PhysicalNvAction {
public:
    explicit PhysicalNvAction(std::shared_ptr<NvRestorePlan> plan):plan_(std::move(plan)) {}
    const NvRestorePlan* plan() const {return plan_.get();}
private:
    friend class Operations;
    friend class PacRecoveryStore;
    friend class PlanExecutor;
    std::shared_ptr<NvRestorePlan> plan_;
};
struct CheckNvAction { std::vector<uint8_t> expected;std::optional<AddressTarget> address{}; };
enum class ControlCommand {
    Noop,EndProcess,Reset,PowerOff,WriteEfuse,ReadVpac,ReadFlashType,
    CheckMcpType,ReadFlashInfo,ReadRfChipType,ReadPartitionInfo
};
struct VpacWrite { std::vector<uint8_t> bytes; };
struct ExtTableWrite { io::Image image; };
struct ControlAction {
    std::variant<ControlCommand,VpacWrite,ExtTableWrite> payload;
};
inline std::optional<ControlCommand> control_command(std::string_view name) {
    if(name=="DONOTHING")return ControlCommand::Noop;
    if(name=="EndProcess")return ControlCommand::EndProcess;
    if(name=="Reset")return ControlCommand::Reset;
    if(name=="PowerOff")return ControlCommand::PowerOff;
    if(name=="WriteEfuse")return ControlCommand::WriteEfuse;
    if(name=="ReadVpac")return ControlCommand::ReadVpac;
    if(name=="READFLASHTYPE")return ControlCommand::ReadFlashType;
    if(name=="CHECK_MCPTYPE")return ControlCommand::CheckMcpType;
    if(name=="READ_FLASHINFO")return ControlCommand::ReadFlashInfo;
    if(name=="READ_RF_CHIP_TYPE")return ControlCommand::ReadRfChipType;
    if(name=="ReadPartitionInfo")return ControlCommand::ReadPartitionInfo;
    return {};
}
inline std::string control_name(const ControlAction& action) {
    if(std::holds_alternative<VpacWrite>(action.payload))return "WriteVpac";
    if(std::holds_alternative<ExtTableWrite>(action.payload))return "EXTTABLE";
    switch(std::get<ControlCommand>(action.payload)) {
    case ControlCommand::Noop:return "DONOTHING";
    case ControlCommand::EndProcess:return "EndProcess";
    case ControlCommand::Reset:return "Reset";
    case ControlCommand::PowerOff:return "PowerOff";
    case ControlCommand::WriteEfuse:return "WriteEfuse";
    case ControlCommand::ReadVpac:return "ReadVpac";
    case ControlCommand::ReadFlashType:return "READFLASHTYPE";
    case ControlCommand::CheckMcpType:return "CHECK_MCPTYPE";
    case ControlCommand::ReadFlashInfo:return "READ_FLASHINFO";
    case ControlCommand::ReadRfChipType:return "READ_RF_CHIP_TYPE";
    case ControlCommand::ReadPartitionInfo:return "ReadPartitionInfo";
    }
    return {};
}
using OperationAction=std::variant<WriteAction,EraseAction,ReadAction,LogicalNvAction,PhysicalNvAction,CheckNvAction,ControlAction>;
inline std::string operation_name(const OperationAction& action) {
    if(const auto* control=std::get_if<ControlAction>(&action))return control_name(*control);
    if(std::holds_alternative<ReadAction>(action))return "read";
    if(std::holds_alternative<EraseAction>(action))return "erase";
    if(std::holds_alternative<LogicalNvAction>(action))return "logical NV merge/write";
    if(std::holds_alternative<PhysicalNvAction>(action))return "physical NV merge/write";
    if(std::holds_alternative<CheckNvAction>(action))return "CHECK_NV";
    return "write";
}
}
