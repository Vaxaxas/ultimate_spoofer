#pragma once
#include <string>
#include <optional>
#include <memory>
#include <cstdint>

namespace pdb
{
    struct download_info_t {
        std::string path;
    };

    struct type_entry_t {
        void add_member(const std::string& name, uint32_t* out) {
            (void)name;
            if (out) *out = 0;
        }
    };

    struct pdb_entry_t {
        void add_symbol(const std::string& name, uint32_t* out) {
            (void)name;
            if (out) *out = 0;
        }
        std::shared_ptr<type_entry_t> add_type(const std::string& name) {
            (void)name;
            return std::make_shared<type_entry_t>();
        }
    };

    struct request_t {
        std::shared_ptr<pdb_entry_t> add_entry(const download_info_t& info) {
            (void)info;
            return std::make_shared<pdb_entry_t>();
        }
    };

    inline std::optional<download_info_t> get_download_info(const std::string& path) {
        return download_info_t{ path };
    }

    inline std::shared_ptr<request_t> create_request() {
        return std::make_shared<request_t>();
    }

    inline bool get(std::shared_ptr<request_t> request) {
        (void)request;
        return true;
    }
}
