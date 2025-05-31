#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>

constexpr uint16_t FILE_ALIGNMENT = 0x200;
constexpr uint16_t SECTION_ALIGNMENT = 0x1000;
constexpr uint64_t IMAGE_BASE = 0x140000000;

// Ручной код: GetStdHandle -> WriteConsoleA
// Этот кусок кода использует системные вызовы Windows API
const uint8_t code[] = {
    0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28 (align stack)
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx, -1 (STD_OUTPUT_HANDLE)
    0x48, 0xB8,                               // mov rax, address of GetStdHandle
    // 8 байт адреса GetStdHandle (заполним позже)
    0,0,0,0,0,0,0,0,
    0xFF, 0xD0,                               // call rax

    0x48, 0x89, 0xC1,                         // mov rcx, rax (handle)
    0x48, 0x8D, 0x15,                         // lea rdx, [rip+offset]
    // 4 байта смещения до строки
    0,0,0,0,
    0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00, // mov rdx, length
    0x48, 0x31, 0xC0,                         // xor rax, rax (lpNumberOfBytesWritten)
    0x48, 0xB8,                               // mov rax, address of WriteConsoleA
    // 8 байт адреса WriteConsoleA (заполним позже)
    0,0,0,0,0,0,0,0,
    0xFF, 0xD0,                               // call rax

    0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
    0xC3                                      // ret
};

// Наша строка
const char message[] = "Hello, World!\n";

int align(int size, int alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

int main() {
    std::ofstream f("hello.exe", std::ios::binary);

    // DOS заголовок
    uint8_t mz[0x40] = {};
    mz[0] = 'M'; mz[1] = 'Z';
    *reinterpret_cast<uint32_t*>(&mz[0x3C]) = 0x80; // e_lfanew

    // NT-заголовок
    uint8_t pe[0xF8] = {};
    std::memcpy(pe, "PE\0\0", 4);
    *reinterpret_cast<uint16_t*>(&pe[4]) = 0x8664; // machine x64
    *reinterpret_cast<uint16_t*>(&pe[6]) = 2;      // NumberOfSections
    *reinterpret_cast<uint16_t*>(&pe[20]) = 0xF0;  // SizeOfOptionalHeader

    // Optional Header
    pe[24] = 0x20; pe[25] = 0x0B; // PE32+
    *reinterpret_cast<uint64_t*>(&pe[24+24]) = IMAGE_BASE;
    *reinterpret_cast<uint32_t*>(&pe[24+32]) = SECTION_ALIGNMENT;
    *reinterpret_cast<uint32_t*>(&pe[24+36]) = FILE_ALIGNMENT;
    *reinterpret_cast<uint16_t*>(&pe[24+40]) = 6; // OS version
    *reinterpret_cast<uint16_t*>(&pe[24+42]) = 0;
    *reinterpret_cast<uint16_t*>(&pe[24+44]) = 6; // Subsystem version
    *reinterpret_cast<uint16_t*>(&pe[24+46]) = 0;
    *reinterpret_cast<uint32_t*>(&pe[24+56]) = 0x400; // SizeOfHeaders
    *reinterpret_cast<uint32_t*>(&pe[24+60]) = 0x2000; // SizeOfImage
    *reinterpret_cast<uint32_t*>(&pe[24+64]) = 0x1000; // EntryPoint RVA
    *reinterpret_cast<uint32_t*>(&pe[24+68]) = 0x1000; // BaseOfCode RVA
    *reinterpret_cast<uint16_t*>(&pe[24+92]) = 3; // Subsystem (Windows CUI)
    *reinterpret_cast<uint64_t*>(&pe[24+112]) = 0x100000; // SizeOfStackReserve
    *reinterpret_cast<uint64_t*>(&pe[24+120]) = 0x1000;   // SizeOfStackCommit
    *reinterpret_cast<uint64_t*>(&pe[24+128]) = 0x100000; // SizeOfHeapReserve
    *reinterpret_cast<uint64_t*>(&pe[24+136]) = 0x1000;   // SizeOfHeapCommit
    *reinterpret_cast<uint32_t*>(&pe[24+148]) = 1;        // NumberOfRvaAndSizes

    // Section headers
    uint8_t text_section[40] = {};
    std::memcpy(text_section, ".text\0\0\0", 8);
    *reinterpret_cast<uint32_t*>(&text_section[8]) = align(sizeof(code), SECTION_ALIGNMENT); // VirtualSize
    *reinterpret_cast<uint32_t*>(&text_section[12]) = 0x1000; // RVA
    *reinterpret_cast<uint32_t*>(&text_section[16]) = align(sizeof(code), FILE_ALIGNMENT); // RawSize
    *reinterpret_cast<uint32_t*>(&text_section[20]) = 0x400;  // RawOffset
    *reinterpret_cast<uint32_t*>(&text_section[36]) = 0x60000020; // characteristics (CODE | EXECUTE | READ)

    // Пишем DOS, NT, Section
    f.write((char*)mz, sizeof(mz));
    f.seekp(0x80);
    f.write((char*)pe, sizeof(pe));
    f.write((char*)text_section, sizeof(text_section));

    // Выравнивание до 0x400
    f.seekp(0x400);
    // Пишем код
    f.write((char*)code, sizeof(code));
    // Можно добавить строку (если используем lea rdx, [rip+offset])
    // и скорректировать offset.

    f.close();
    return 0;
}
