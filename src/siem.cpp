#include "ai_shield/siem.hpp"

#include <algorithm>

namespace ai_shield::siem {
namespace {

std::string escape(std::string value, char separator) {
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char character) {
        return character < 0x20U || character == 0x7fU;
    }), value.end());
    std::string result;
    for (const char character : value) {
        if (character == '\\' || character == separator || character == '=') result.push_back('\\');
        result.push_back(character);
    }
    return result;
}

std::string fields(const Event& event, char separator) {
    const std::string delimiter(1U, separator);
    return "act=" + escape(event.action, separator) + delimiter + "risk=" + std::to_string(event.risk_score) +
           delimiter + "reason=" + std::to_string(event.reason_mask) + delimiter +
           "flow=" + std::to_string(event.correlation.flow_id) + delimiter +
           "file=" + std::to_string(event.correlation.file_id) + delimiter +
           "process=" + std::to_string(event.correlation.process_id) + delimiter +
           "policy=" + std::to_string(event.correlation.policy_version) + delimiter +
           "model=" + std::to_string(event.correlation.model_version);
}

}  // namespace

std::string format(const Event& event, Format output_format) {
    if (output_format == Format::cef)
        return "CEF:0|AI Shield|AI Shield|2.0|" + std::to_string(event.reason_mask) +
               "|Security decision|" + std::to_string((std::min)(10U, event.risk_score / 26U)) + "|" + fields(event, ' ');
    if (output_format == Format::leef)
        return "LEEF:2.0|AI Shield|AI Shield|2.0|" + std::to_string(event.reason_mask) + "|" + fields(event, '\t');
    return "{\"schema\":2,\"time_ns\":" + std::to_string(event.monotonic_ns) +
           ",\"action\":\"" + escape(event.action, '|') + "\",\"risk\":" + std::to_string(event.risk_score) +
           ",\"reason\":" + std::to_string(event.reason_mask) + ",\"flow_id\":" +
           std::to_string(event.correlation.flow_id) + ",\"file_id\":" +
           std::to_string(event.correlation.file_id) + ",\"process_id\":" +
           std::to_string(event.correlation.process_id) + ",\"policy_version\":" +
           std::to_string(event.correlation.policy_version) + ",\"model_version\":" +
           std::to_string(event.correlation.model_version) + "}";
}

}  // namespace ai_shield::siem
