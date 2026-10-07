#include <uniflash/session/sparse.h>
#include <uniflash/session/sparse_memory_sink.h>
#include <uniflash/io/sparse_index.h>
#include <algorithm>
#include <new>
#include <stdexcept>

namespace uniflash::session {
bool SparseDecoder::is_sparse(std::span<const uint8_t> data) {
    return data.size()>=4 && data[0]==0x3a && data[1]==0xff && data[2]==0x26 && data[3]==0xed;
}
namespace {
io::Reader memory_reader(std::span<const uint8_t> bytes) {
    return [bytes](uint64_t at,std::span<uint8_t> out,std::stop_token stop)->std::expected<void,std::errc> {
        if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
        if(at>bytes.size() || out.size()>bytes.size()-at)return std::unexpected(std::errc::message_size);
        std::copy_n(bytes.begin()+at,out.size(),out.begin());return {};
    };
}
std::expected<void,std::errc> emit(std::span<const uint8_t> data,const io::SparseIndex& index,SparseDecoder::Sink& sink) {
    for(const auto& e:index.extents) {
        std::expected<void,std::errc> result;
        if(e.type==CHUNK_TYPE_RAW)result=sink.write_raw(e.start,data.subspan(static_cast<size_t>(e.source),static_cast<size_t>(e.length)));
        else if(e.type==CHUNK_TYPE_FILL) {
            uint32_t word=0;for(unsigned i=0;i<4;++i)word|=uint32_t(e.pattern[i])<<(8*i);
            result=sink.write_fill(e.start,static_cast<uint32_t>(e.length/index.block_size),word,index.block_size);
        } else result=sink.skip_dont_care(e.start,static_cast<uint32_t>(e.length/index.block_size),index.block_size);
        if(!result)return result;
    }
    return {};
}
}
std::expected<void,std::errc> SparseDecoder::decode(std::span<const uint8_t> data,Sink& sink) try {
    // Freeze caller memory so a sink cannot modify later source extents after
    // the shared engine has validated all declared checksums.
    const std::vector<uint8_t> frozen(data.begin(),data.end());
    auto index=io::index_sparse(memory_reader(frozen),frozen.size(),UINT64_MAX);
    if(!index)return std::unexpected(index.error());
    if(!index->sparse)return std::unexpected(std::errc::invalid_argument);
    return emit(frozen,*index,sink);
} catch(const std::bad_alloc&) {return std::unexpected(std::errc::not_enough_memory);}
  catch(const std::length_error&) {return std::unexpected(std::errc::file_too_large);}
std::expected<std::vector<uint8_t>,std::errc> expand_sparse(const std::vector<uint8_t>& data) {
    try {
        auto index=io::index_sparse(memory_reader(data),data.size(),UINT64_MAX);
        if(!index)return std::unexpected(index.error());
        if(!index->sparse)return std::unexpected(std::errc::invalid_argument);
        std::vector<uint8_t> out;
        if(index->length>out.max_size())return std::unexpected(std::errc::file_too_large);
        out.reserve(static_cast<size_t>(index->length));MemorySink sink(out,index->length);
        auto result=emit(data,*index,sink);if(!result)return std::unexpected(result.error());return out;
    } catch(const std::bad_alloc&) {return std::unexpected(std::errc::not_enough_memory);}
      catch(const std::length_error&) {return std::unexpected(std::errc::file_too_large);}
}
}
