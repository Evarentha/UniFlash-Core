#include <uniflash/session/pac_config.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/io/authentication.h>
#include <uniflash/platform.h>
#include <charconv>
#include <set>
namespace uniflash::session {
class PacConfigReader {
public:
static std::expected<PacPrepareOptions,std::errc> read(const std::filesystem::path& path,std::string_view product,std::stop_token stop) {
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    auto frozen=io::Image::prepare_blob(path,65536,stop);if(!frozen)return std::unexpected(frozen.error());
    std::string text(static_cast<size_t>(frozen->size()),'\0');
    auto got=frozen->reader()(0,std::span(reinterpret_cast<uint8_t*>(text.data()),text.size()),stop);
    if(!got)return std::unexpected(got.error());
    auto document=PacParser::parse_document(std::move(text),65536);
    if(!document)return std::unexpected(document.error());
    auto root=std::move(*document);
    if(!root||root->tag!="PacHostConfig"||!root->text.empty()||!root->attrs.contains("product")||root->attrs.at("product")!=product)
        return std::unexpected(std::errc::invalid_argument);
    const auto number=[](const std::string& text)->std::expected<uint32_t,std::errc> {
        std::string_view s=text;int radix=10;if(s.starts_with("0x")){s.remove_prefix(2);radix=16;}
        uint32_t n=0;auto [end,ec]=std::from_chars(s.data(),s.data()+s.size(),n,radix);
        if(ec!=std::errc{}||end!=s.data()+s.size()||s.empty())return std::unexpected(std::errc::invalid_argument);
        return n;
    };
    const auto order=[](std::string_view s)->std::expected<NvByteOrder,std::errc> {
        if(s=="little")return NvByteOrder::Little;
        if(s=="big-items")return NvByteOrder::BigItemHeaders;
        if(s=="reversed-words")return NvByteOrder::ReversedWords;
        if(s=="little-index-big-items")return NvByteOrder::LittleIndexBigItemHeaders;
        return std::unexpected(std::errc::invalid_argument);
    };
    PacPrepareOptions options;
    for(const auto& [name,value]:root->attrs) {
        if(name=="product")continue;
        if(name=="address-word-order") {
            if(value=="little")options.address_word_order=device::AddressWordOrder::Little;
            else if(value=="big")options.address_word_order=device::AddressWordOrder::Big;
            else return std::unexpected(std::errc::invalid_argument);
        } else if(name=="factory-timestamp") {
            auto n=number(value);if(!n)return std::unexpected(n.error());options.factory_timestamp=*n;
        } else if(name=="write-efuse") {
            if(value!="0"&&value!="1")return std::unexpected(std::errc::invalid_argument);
            options.factory_write_efuse=value=="1";
        } else return std::unexpected(std::errc::not_supported);
    }
    bool auth=false,vpac=false,softsim=false;std::set<std::string> nv;
    for(const auto& node:root->children) {
        if(!node->children.empty()||!node->text.empty())return std::unexpected(std::errc::bad_message);
        if(node->tag=="NV") {
            if(!node->attrs.contains("target"))return std::unexpected(std::errc::bad_message);
            PacNvRepresentation r;r.partition=node->attrs.at("target");
            if(r.partition.empty()||!nv.insert(r.partition).second)return std::unexpected(std::errc::bad_message);
            for(const auto& [name,value]:node->attrs) {
                if(name=="target")continue;
                if(name=="protocol") {
                    if(value!="r27-named")return std::unexpected(std::errc::not_supported);
                    r.r27_named_protocol=true;
                }
                else if(name=="logical-size") {auto n=number(value);if(!n||*n<8||(*n&1)||*n>16*1024*1024)return std::unexpected(std::errc::message_size);r.logical_size=*n;}
                else if(name=="device-order"||name=="template-order") {
                    auto o=order(value);if(!o)return std::unexpected(o.error());
                    if(name=="device-order")r.device_order=*o;else r.template_order=*o;
                } else return std::unexpected(std::errc::not_supported);
            }
            options.nv_representations.push_back(std::move(r));
        } else if(node->tag=="SoftSim") {
            if(softsim||node->attrs.size()!=1||!node->attrs.contains("expected-eid-hex"))return std::unexpected(std::errc::bad_message);
            softsim=true;const auto& hex=node->attrs.at("expected-eid-hex");if(hex.size()!=20)return std::unexpected(std::errc::message_size);
            for(size_t i=0;i<20;i+=2){unsigned n=0;auto [end,ec]=std::from_chars(hex.data()+i,hex.data()+i+2,n,16);
                if(ec!=std::errc{}||end!=hex.data()+i+2)return std::unexpected(std::errc::bad_message);
                options.softsim_expected_eid.push_back(static_cast<uint8_t>(n));}
        } else if(node->tag=="Vpac") {
            if(vpac||node->attrs.size()!=1||!node->attrs.contains("utf16le-hex"))return std::unexpected(std::errc::bad_message);
            vpac=true;const auto& hex=node->attrs.at("utf16le-hex");
            if(hex.size()<8||hex.size()>1024||hex.size()%4)return std::unexpected(std::errc::message_size);
            for(size_t i=0;i<hex.size();i+=2){unsigned n=0;auto [end,ec]=std::from_chars(hex.data()+i,hex.data()+i+2,n,16);
                if(ec!=std::errc{}||end!=hex.data()+i+2)return std::unexpected(std::errc::bad_message);
                options.vpac_utf16le.push_back(static_cast<uint8_t>(n));}
            const auto& data=options.vpac_utf16le;
            if(data[data.size()-1]||data[data.size()-2])return std::unexpected(std::errc::bad_message);
            for(size_t i=0;i+2<data.size();i+=2)if(!data[i]&&!data[i+1])return std::unexpected(std::errc::bad_message);
        } else if(node->tag=="Auth41") {
            if(auth||node->attrs.size()!=2||!node->attrs.contains("key")||!node->attrs.contains("project-hex"))return std::unexpected(std::errc::bad_message);
            auth=true;const auto& hex=node->attrs.at("project-hex");if(hex.size()!=64)return std::unexpected(std::errc::bad_message);
            std::array<uint8_t,32> project_bytes{};
            for(size_t i=0;i<32;++i) {unsigned n=0;auto [end,ec]=std::from_chars(hex.data()+2*i,hex.data()+2*i+2,n,16);
                if(ec!=std::errc{}||end!=hex.data()+2*i+2)return std::unexpected(std::errc::bad_message);
                project_bytes[i]=static_cast<uint8_t>(n);}
            auto key_path=platform::path(node->attrs.at("key"));if(key_path.empty())return std::unexpected(std::errc::invalid_argument);
            if(key_path.is_relative())key_path=path.parent_path()/key_path;
            auto responder=io::r27_authenticator(key_path,project_bytes,stop);if(!responder)return std::unexpected(responder.error());
            options.authentication=std::move(*responder);
        } else return std::unexpected(std::errc::not_supported);
    }
    return options;
}
};
std::expected<PacPrepareOptions,std::errc> read_pac_config(const std::filesystem::path& path,std::string_view product,std::stop_token stop) {
    return PacConfigReader::read(path,product,stop);
}
}
