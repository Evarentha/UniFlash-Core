#pragma once
#include <uniflash/layout/disk_layout.h>

namespace uniflash::session {
// Compatibility names: disk evidence and parsing belong below device/session.
using layout::GptHeader;
using layout::GptPartition;
using layout::GptLayout;
using layout::parse_gpt_header;
using layout::read_primary_gpt;
using layout::read_partition_layout;
using layout::matching_gpt_headers;
using layout::verify_backup_gpt;
using layout::make_layout_xml;
}
