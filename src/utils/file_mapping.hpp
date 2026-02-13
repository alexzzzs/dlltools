#pragma once

#include "core/error.hpp"
#include <filesystem>
#include <span>
#include <memory>

namespace dlltools::utils {

/// RAII wrapper for Windows memory-mapped files
class FileMapping {
public:
    /// Default constructor - creates an empty mapping
    FileMapping() noexcept = default;

    /// Move constructor
    FileMapping(FileMapping&& other) noexcept;

    /// Move assignment
    FileMapping& operator=(FileMapping&& other) noexcept;

    /// Non-copyable
    FileMapping(const FileMapping&) = delete;
    FileMapping& operator=(const FileMapping&) = delete;

    /// Destructor - unmaps and closes handles
    ~FileMapping() noexcept;

    /// Create a read-only file mapping
    /// @param path Path to the file to map
    /// @return Result containing FileMapping or Error
    [[nodiscard]] static Result<FileMapping> map(const std::filesystem::path& path);

    /// Check if mapping is valid
    [[nodiscard]] bool is_valid() const noexcept { return data_ != nullptr; }

    /// Get pointer to mapped data
    [[nodiscard]] const uint8_t* data() const noexcept { return data_; }

    /// Get size of mapped data
    [[nodiscard]] size_t size() const noexcept { return size_; }

    /// Get mapped data as a span
    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return { data_, size_ };
    }

    /// Get byte at index with bounds checking
    [[nodiscard]] const uint8_t& operator[](size_t index) const noexcept {
        return data_[index];
    }

    /// Get byte at index with bounds checking
    /// @throws std::out_of_range if index >= size
    [[nodiscard]] const uint8_t& at(size_t index) const;

    /// Check if offset + length is within bounds
    [[nodiscard]] bool in_bounds(size_t offset, size_t length) const noexcept {
        // Empty mapping or null data always fails bounds check
        if (data_ == nullptr || size_ == 0) return false;
        return offset + length <= size_;
    }

    /// Get a pointer at offset with bounds checking
    /// @return nullptr if out of bounds
    [[nodiscard]] const uint8_t* ptr_at(size_t offset) const noexcept {
        if (offset >= size_) return nullptr;
        return data_ + offset;
    }

    /// Get a pointer at offset with bounds checking for length
    /// @return nullptr if out of bounds
    [[nodiscard]] const uint8_t* ptr_at(size_t offset, size_t length) const noexcept {
        if (!in_bounds(offset, length)) return nullptr;
        return data_ + offset;
    }

    /// Read a value at offset with bounds checking
    /// @tparam T Type to read
    /// @param offset Byte offset in the file
    /// @return Pointer to value or nullptr if out of bounds
    template<typename T>
    [[nodiscard]] const T* read_at(size_t offset) const noexcept {
        if (!in_bounds(offset, sizeof(T))) return nullptr;
        return reinterpret_cast<const T*>(data_ + offset);
    }

    /// Read a value at offset, returning Result
    /// @tparam T Type to read
    /// @param offset Byte offset in the file
    /// @return Result containing pointer to value or Error
    template<typename T>
    [[nodiscard]] Result<const T*> read_checked(size_t offset) const noexcept {
        if (!in_bounds(offset, sizeof(T))) {
            return std::unexpected(Error::out_of_bounds(offset, sizeof(T), size_));
        }
        return reinterpret_cast<const T*>(data_ + offset);
    }

    /// Explicit bool conversion for validity check
    explicit operator bool() const noexcept { return is_valid(); }

private:
    FileMapping(const uint8_t* data, size_t size, void* file_handle, void* map_handle) noexcept
        : data_(data), size_(size), file_handle_(file_handle), map_handle_(map_handle) {}

    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    void* file_handle_ = nullptr;   // HANDLE for file
    void* map_handle_ = nullptr;    // HANDLE for file mapping
};

} // namespace dlltools::utils
