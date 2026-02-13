#include "utils/file_mapping.hpp"
#include <windows.h>
#include <stdexcept>

namespace dlltools::utils {

FileMapping::FileMapping(FileMapping&& other) noexcept
    : data_(other.data_)
    , size_(other.size_)
    , file_handle_(other.file_handle_)
    , map_handle_(other.map_handle_)
{
    other.data_ = nullptr;
    other.size_ = 0;
    other.file_handle_ = nullptr;
    other.map_handle_ = nullptr;
}

FileMapping& FileMapping::operator=(FileMapping&& other) noexcept {
    if (this != &other) {
        // Clean up current resources
        if (map_handle_) {
            ::UnmapViewOfFile(data_);
            ::CloseHandle(map_handle_);
        }
        if (file_handle_) {
            ::CloseHandle(file_handle_);
        }

        // Move from other
        data_ = other.data_;
        size_ = other.size_;
        file_handle_ = other.file_handle_;
        map_handle_ = other.map_handle_;

        // Reset other
        other.data_ = nullptr;
        other.size_ = 0;
        other.file_handle_ = nullptr;
        other.map_handle_ = nullptr;
    }
    return *this;
}

FileMapping::~FileMapping() noexcept {
    if (map_handle_) {
        ::UnmapViewOfFile(data_);
        ::CloseHandle(map_handle_);
    }
    if (file_handle_) {
        ::CloseHandle(file_handle_);
    }
}

Result<FileMapping> FileMapping::map(const std::filesystem::path& path) {
    // Check if file exists
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return std::unexpected(Error::file_not_found(path));
    }

    // Open file with GENERIC_READ access
    HANDLE file = ::CreateFileW(
        path.wstring().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = ::GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            return std::unexpected(Error::access_denied(path));
        }
        return std::unexpected(Error::mapping_failed(
            path,
            "Failed to open file"
        ));
    }

    // Get file size
    LARGE_INTEGER file_size;
    if (!::GetFileSizeEx(file, &file_size)) {
        ::CloseHandle(file);
        return std::unexpected(Error::mapping_failed(
            path,
            "Failed to get file size"
        ));
    }

    // Check for empty file
    if (file_size.QuadPart == 0) {
        ::CloseHandle(file);
        return std::unexpected(Error::mapping_failed(
            path,
            "File is empty"
        ));
    }

    // Create file mapping object
    HANDLE mapping = ::CreateFileMappingW(
        file,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );

    if (!mapping) {
        ::CloseHandle(file);
        return std::unexpected(Error::mapping_failed(
            path,
            "Failed to create file mapping"
        ));
    }

    // Map view of file
    const uint8_t* data = static_cast<const uint8_t*>(
        ::MapViewOfFile(
            mapping,
            FILE_MAP_READ,
            0,
            0,
            0
        )
    );

    if (!data) {
        ::CloseHandle(mapping);
        ::CloseHandle(file);
        return std::unexpected(Error::mapping_failed(
            path,
            "Failed to map view of file"
        ));
    }

    return FileMapping(data, static_cast<size_t>(file_size.QuadPart), file, mapping);
}

const uint8_t& FileMapping::at(size_t index) const {
    if (index >= size_) {
        throw std::out_of_range("FileMapping::at() - index out of range");
    }
    return data_[index];
}

} // namespace dlltools::utils
