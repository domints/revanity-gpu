#include <cuda_runtime.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace {
__device__ __forceinline__ int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// out layout: [byte_pattern_len, byte_offset, nibble_check, nibble_idx, nibble_mask, nibble_value, byte_pattern...]
__global__ void match_prefix_suffix_kernel(
    const uint8_t* hashes,
    size_t n,
    const uint8_t* desc,
    int* flags
) {
    size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n) return;

    const uint8_t* h = hashes + i * 16;
    const int byte_pattern_len = static_cast<int>(desc[0]);
    const int byte_offset = static_cast<int>(desc[1]);
    const int nibble_check = static_cast<int>(desc[2]);
    const int nibble_idx = static_cast<int>(desc[3]);
    const int nibble_mask = static_cast<int>(desc[4]);
    const int nibble_value = static_cast<int>(desc[5]);
    const uint8_t* byte_pattern = desc + 6;

    int ok = 1;
    for (int j = 0; j < byte_pattern_len; ++j) {
        if (h[byte_offset + j] != byte_pattern[j]) {
            ok = 0;
            break;
        }
    }

    if (ok && nibble_check) {
        if ((h[nibble_idx] & nibble_mask) != nibble_value) {
            ok = 0;
        }
    }

    flags[i] = ok;
}

bool parse_pattern_desc(const char* pattern_hex, size_t pattern_len, int mode, uint8_t* out_desc, size_t out_desc_len) {
    if (!pattern_hex || pattern_len == 0 || pattern_len > 32 || !out_desc || out_desc_len < 22) {
        return false;
    }

    // 0 prefix, 1 suffix
    const int is_prefix = (mode == 0);
    if (!is_prefix && mode != 1) return false;

    const int n = static_cast<int>(pattern_len);
    const int n_full = n / 2;
    int byte_pattern_len = 0;
    int byte_offset = 0;
    int nibble_check = 0;
    int nibble_idx = 0;
    int nibble_mask = 0;
    int nibble_value = 0;

    uint8_t bytes[16] = {0};

    if (is_prefix) {
        byte_pattern_len = n_full;
        byte_offset = 0;
        for (int i = 0; i < n_full; ++i) {
            int hi = hex_nibble(pattern_hex[i * 2]);
            int lo = hex_nibble(pattern_hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        if (n % 2 == 1) {
            int nib = hex_nibble(pattern_hex[n - 1]);
            if (nib < 0) return false;
            nibble_check = 1;
            nibble_idx = n_full;
            nibble_mask = 0xF0;
            nibble_value = nib << 4;
        }
    } else {
        if (n % 2 == 1) {
            int nib = hex_nibble(pattern_hex[0]);
            if (nib < 0) return false;
            nibble_check = 1;
            nibble_idx = 16 - n_full - 1;
            nibble_mask = 0x0F;
            nibble_value = nib;
            byte_pattern_len = n_full;
            byte_offset = 16 - n_full;
            for (int i = 0; i < n_full; ++i) {
                int hi = hex_nibble(pattern_hex[1 + i * 2]);
                int lo = hex_nibble(pattern_hex[1 + i * 2 + 1]);
                if (hi < 0 || lo < 0) return false;
                bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
            }
        } else {
            byte_pattern_len = n_full;
            byte_offset = 16 - n_full;
            for (int i = 0; i < n_full; ++i) {
                int hi = hex_nibble(pattern_hex[i * 2]);
                int lo = hex_nibble(pattern_hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return false;
                bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
            }
        }
    }

    out_desc[0] = static_cast<uint8_t>(byte_pattern_len);
    out_desc[1] = static_cast<uint8_t>(byte_offset);
    out_desc[2] = static_cast<uint8_t>(nibble_check);
    out_desc[3] = static_cast<uint8_t>(nibble_idx);
    out_desc[4] = static_cast<uint8_t>(nibble_mask);
    out_desc[5] = static_cast<uint8_t>(nibble_value);
    for (int i = 0; i < 16; ++i) out_desc[6 + i] = bytes[i];
    return true;
}
}  // namespace

extern "C" __declspec(dllexport) int revanity_scan_prefix_suffix(
    const void* x_scalars,
    size_t n,
    const void* pattern_hex,
    size_t pattern_len,
    int mode,
    uint8_t out_scalar[32],
    uint64_t* out_checked
) {
    if (!x_scalars || !pattern_hex || !out_scalar || !out_checked) return -1;
    *out_checked = 0;
    if (n == 0) return 0;

    // NOTE: Current native function expects `x_scalars` to contain 16-byte hashes
    // packed as n*16 bytes. This is a temporary bridge contract while GPU curve
    // derivation is being implemented.
    const uint8_t* hashes_host = reinterpret_cast<const uint8_t*>(x_scalars);

    uint8_t desc_host[22] = {0};
    if (!parse_pattern_desc(reinterpret_cast<const char*>(pattern_hex), pattern_len, mode, desc_host, sizeof(desc_host))) {
        return -2;
    }

    uint8_t* d_hashes = nullptr;
    uint8_t* d_desc = nullptr;
    int* d_flags = nullptr;
    cudaError_t err = cudaSuccess;

    err = cudaMalloc(&d_hashes, n * 16);
    if (err != cudaSuccess) return -3;
    err = cudaMalloc(&d_desc, sizeof(desc_host));
    if (err != cudaSuccess) {
        cudaFree(d_hashes);
        return -4;
    }
    err = cudaMalloc(&d_flags, n * sizeof(int));
    if (err != cudaSuccess) {
        cudaFree(d_hashes);
        cudaFree(d_desc);
        return -5;
    }

    err = cudaMemcpy(d_hashes, hashes_host, n * 16, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) goto cleanup;
    err = cudaMemcpy(d_desc, desc_host, sizeof(desc_host), cudaMemcpyHostToDevice);
    if (err != cudaSuccess) goto cleanup;

    {
        constexpr int threads = 256;
        int blocks = static_cast<int>((n + threads - 1) / threads);
        match_prefix_suffix_kernel<<<blocks, threads>>>(d_hashes, n, d_desc, d_flags);
        err = cudaGetLastError();
        if (err != cudaSuccess) goto cleanup;
    }

    {
        int* flags_host = new int[n];
        err = cudaMemcpy(flags_host, d_flags, n * sizeof(int), cudaMemcpyDeviceToHost);
        if (err != cudaSuccess) {
            delete[] flags_host;
            goto cleanup;
        }

        for (size_t i = 0; i < n; ++i) {
            if (flags_host[i]) {
                // Compatibility output: caller expects a 32-byte "candidate". For now,
                // we return the first 16 bytes of matched hash and zero-pad.
                std::memset(out_scalar, 0, 32);
                std::memcpy(out_scalar, hashes_host + i * 16, 16);
                *out_checked = static_cast<uint64_t>(i + 1);
                delete[] flags_host;
                goto cleanup_success;
            }
        }
        *out_checked = static_cast<uint64_t>(n);
        delete[] flags_host;
    }

cleanup:
    cudaFree(d_hashes);
    cudaFree(d_desc);
    cudaFree(d_flags);
    return (err == cudaSuccess) ? 0 : -6;

cleanup_success:
    cudaFree(d_hashes);
    cudaFree(d_desc);
    cudaFree(d_flags);
    return 1;
}
