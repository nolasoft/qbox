#pragma once
#include <filesystem>
namespace qbox {
void embed_payload(const std::filesystem::path &base,
                   const std::filesystem::path &payload,
                   const std::filesystem::path &destination);
}
