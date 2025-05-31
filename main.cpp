#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fstream>

constexpr uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

int main() {
    const uint32_t file_alignment = 0x200;
    const uint32_t section_alignment = 0x1000;

    const uint32_t code_rva = align_up(0x400, section_alignment);
    const uint32_t code_offset = align_up(0x400, file_alignment);

    const uint32_t code_size = 1;
    const uint32_t code_virtual_size = align_up(code_size, section_alignment);
    const uint32_t code_raw_size = align_up(code_size, file_alignment);

    const uint32_t image_size = code_rva + code_virtual_size;
    const uint32_t headers_size = align_up(0x400, file_alignment); // assume headers take 0x400 bytes

    uint32_t total_size = code_offset + code_raw_size;
    char* exe = (char*)std::calloc(total_size, 1);
    if (!exe) {
        std::perror("Allocation failed");
        return 1;
    }

    // === DOS Header ===
    exe[0x00] = 'M';
    exe[0x01] = 'Z';
    *(uint32_t*)(exe + 0x3C) = 0x80;  // PE header offset

    // === PE Signature ===
    char* pe = exe + 0x80;
    pe[0] = 'P';
    pe[1] = 'E';
    pe[2] = 0;
    pe[3] = 0;

    // === COFF Header ===
    *(uint16_t*)(pe + 4) = 0x8664; // Machine: AMD64
    *(uint16_t*)(pe + 6) = 1;      // Number of sections
    *(uint32_t*)(pe + 8) = 0;      // TimeDateStamp
    *(uint32_t*)(pe + 12) = 0;     // PointerToSymbolTable
    *(uint32_t*)(pe + 16) = 0;     // NumberOfSymbols
    *(uint16_t*)(pe + 20) = 0xF0;  // Size of optional header
    *(uint16_t*)(pe + 22) = 0x0222; // Characteristics: executable, 64bit

    // === Optional Header (PE32+) ===
    char* opt = pe + 24;
    *(uint16_t*)(opt + 0) = 0x20B;       // Magic = PE32+
    *(uint8_t*)(opt + 2) = 0;            // Linker version
    *(uint8_t*)(opt + 3) = 0;
    *(uint32_t*)(opt + 4) = align_up(code_size, file_alignment); // SizeOfCode
    *(uint32_t*)(opt + 8) = 0;           // SizeOfInitializedData
    *(uint32_t*)(opt + 12) = 0;          // SizeOfUninitializedData
    *(uint32_t*)(opt + 16) = code_rva;   // AddressOfEntryPoint
    *(uint32_t*)(opt + 20) = code_rva;   // BaseOfCode
    *(uint64_t*)(opt + 24) = 0x140000000; // ImageBase
    *(uint32_t*)(opt + 32) = section_alignment;
    *(uint32_t*)(opt + 36) = file_alignment;
    *(uint16_t*)(opt + 40) = 6;           // OS Version
    *(uint16_t*)(opt + 42) = 0;
    *(uint16_t*)(opt + 44) = 0;           // Image version
    *(uint16_t*)(opt + 46) = 0;
    *(uint16_t*)(opt + 48) = 6;           // Subsystem version
    *(uint16_t*)(opt + 50) = 0;
    *(uint32_t*)(opt + 52) = 0;           // Win32VersionValue
    *(uint32_t*)(opt + 56) = image_size;  // SizeOfImage
    *(uint32_t*)(opt + 60) = headers_size; // SizeOfHeaders
    *(uint32_t*)(opt + 64) = 0;           // Checksum
    *(uint16_t*)(opt + 68) = 3;           // Subsystem (console)
    *(uint16_t*)(opt + 70) = 0;           // DllCharacteristics
    *(uint64_t*)(opt + 72) = 0x100000;    // SizeOfStackReserve
    *(uint64_t*)(opt + 80) = 0x1000;      // SizeOfStackCommit
    *(uint64_t*)(opt + 88) = 0x100000;    // SizeOfHeapReserve
    *(uint64_t*)(opt + 96) = 0x1000;      // SizeOfHeapCommit
    *(uint32_t*)(opt + 104) = 0;          // LoaderFlags
    *(uint32_t*)(opt + 108) = 0x10;       // NumberOfRvaAndSizes

    // === Section Header ===
    char* section = opt + 0xF0;
    std::memcpy(section + 0, ".text", 5);
    *(uint32_t*)(section + 8) = code_virtual_size;
    *(uint32_t*)(section + 12) = code_rva;
    *(uint32_t*)(section + 16) = code_raw_size;
    *(uint32_t*)(section + 20) = code_offset;
    *(uint32_t*)(section + 24) = 0; // reloc
    *(uint32_t*)(section + 28) = 0; // lineno
    *(uint16_t*)(section + 32) = 0; // num reloc
    *(uint16_t*)(section + 34) = 0; // num lineno
    *(uint32_t*)(section + 36) = 0x60000020; // flags: code + exec + read

    // === Code: RET ===
    exe[code_offset] = (char)0xC3;

    std::ofstream out("minimal.exe", std::ios::binary);
    out.write(exe, total_size);
    out.close();
    std::free(exe);
    return 0;
}
