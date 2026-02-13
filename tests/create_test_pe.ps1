# Create a minimal valid PE32 file for testing
# Fixed version with correct DOS header structure

$outputPath = "tests\test_data\test_pe32.dll"

# PE file structure (minimal)
$peData = New-Object System.Collections.Generic.List[byte]

# === DOS HEADER (64 bytes at offset 0x00) ===
# e_magic = "MZ" (0x5A4D)
$peData.AddRange([byte[]](0x4D, 0x5A))  # e_magic at offset 0x00
# e_cblp = 0x90 
$peData.AddRange([byte[]](0x90, 0x00))  # e_cblp at offset 0x02
# e_cp = 3
$peData.AddRange([byte[]](0x03, 0x00))  # e_cp at offset 0x04
# e_crlc = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_crlc at offset 0x06
# e_cparhdr = 4 (size of header in paragraphs)
$peData.AddRange([byte[]](0x04, 0x00))  # e_cparhdr at offset 0x08
# e_minalloc = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_minalloc at offset 0x0A
# e_maxalloc = 0xFFFF
$peData.AddRange([byte[]](0xFF, 0xFF))  # e_maxalloc at offset 0x0C
# e_ss = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_ss at offset 0x0E
# e_sp = 0xB8
$peData.AddRange([byte[]](0xB8, 0x00))  # e_sp at offset 0x10
# e_csum = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_csum at offset 0x12
# e_ip = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_ip at offset 0x14
# e_cs = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_cs at offset 0x16
# e_lfarlc = 0x40 (offset to relocation table)
$peData.AddRange([byte[]](0x40, 0x00))  # e_lfarlc at offset 0x18
# e_ovno = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_ovno at offset 0x1A
# e_res (4 reserved words) - zeros
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))  # e_res at offset 0x1C
# e_oemid = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_oemid at offset 0x24
# e_oeminfo = 0
$peData.AddRange([byte[]](0x00, 0x00))  # e_oeminfo at offset 0x26
# e_res2 (10 reserved words) - zeros
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))  # e_res2 at offset 0x28
# e_lfanew = 0x80 (offset to PE header) - THIS IS THE KEY FIELD AT OFFSET 0x3C
$peData.AddRange([byte[]](0x80, 0x00, 0x00, 0x00))  # e_lfanew at offset 0x3C

# === DOS STUB (remainder to reach e_lfanew = 0x80) ===
# Pad from offset 0x40 to 0x80 (64 bytes to 128 bytes)
while ($peData.Count -lt 0x80) {
    $peData.Add(0x00)
}

# === PE SIGNATURE (4 bytes at offset 0x80) ===
# "PE\0\0"
$peData.AddRange([byte[]](0x50, 0x45, 0x00, 0x00))  # PE signature at offset 0x80

# === FILE HEADER (20 bytes at offset 0x84) ===
# Machine = IMAGE_FILE_MACHINE_I386 (0x014C)
$peData.AddRange([byte[]](0x4C, 0x01))  # Machine at offset 0x84
# NumberOfSections = 1
$peData.AddRange([byte[]](0x01, 0x00))  # NumberOfSections at offset 0x86
# TimeDateStamp = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # TimeDateStamp at offset 0x88
# PointerToSymbolTable = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # PointerToSymbolTable at offset 0x8C
# NumberOfSymbols = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # NumberOfSymbols at offset 0x90
# SizeOfOptionalHeader = 0xE0 (for PE32)
$peData.AddRange([byte[]](0xE0, 0x00))  # SizeOfOptionalHeader at offset 0x94
# Characteristics = IMAGE_FILE_DLL (0x2000)
$peData.AddRange([byte[]](0x00, 0x20))  # Characteristics at offset 0x96

# === OPTIONAL HEADER (224 bytes for PE32 at offset 0x98) ===
# Magic = PE32 (0x10B)
$peData.AddRange([byte[]](0x0B, 0x01))  # Magic at offset 0x98
# MajorLinkerVersion = 14
$peData.Add(0x0E)  # MajorLinkerVersion at offset 0x9A
# MinorLinkerVersion = 0
$peData.Add(0x00)  # MinorLinkerVersion at offset 0x9B
# SizeOfCode = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # SizeOfCode at offset 0x9C
# SizeOfInitializedData = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # SizeOfInitializedData at offset 0xA0
# SizeOfUninitializedData = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # SizeOfUninitializedData at offset 0xA4
# AddressOfEntryPoint = 0x1000 (RVA)
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # AddressOfEntryPoint at offset 0xA8
# BaseOfCode = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # BaseOfCode at offset 0xAC
# BaseOfData = 0x2000
$peData.AddRange([byte[]](0x00, 0x20, 0x00, 0x00))  # BaseOfData at offset 0xB0
# ImageBase = 0x10000000
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x10))  # ImageBase low at offset 0xB4
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # ImageBase high at offset 0xB8
# SectionAlignment = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # SectionAlignment at offset 0xBC
# FileAlignment = 0x200
$peData.AddRange([byte[]](0x00, 0x02, 0x00, 0x00))  # FileAlignment at offset 0xC0
# MajorOSVersion = 5
$peData.AddRange([byte[]](0x05, 0x00))  # MajorOSVersion at offset 0xC4
# MinorOSVersion = 0
$peData.AddRange([byte[]](0x00, 0x00))  # MinorOSVersion at offset 0xC6
# MajorImageVersion = 0
$peData.AddRange([byte[]](0x00, 0x00))  # MajorImageVersion at offset 0xC8
# MinorImageVersion = 0
$peData.AddRange([byte[]](0x00, 0x00))  # MinorImageVersion at offset 0xCA
# MajorSubsystemVersion = 5
$peData.AddRange([byte[]](0x05, 0x00))  # MajorSubsystemVersion at offset 0xCC
# MinorSubsystemVersion = 0
$peData.AddRange([byte[]](0x00, 0x00))  # MinorSubsystemVersion at offset 0xCE
# Win32VersionValue = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # Win32VersionValue at offset 0xD0
# SizeOfImage = 0x3000
$peData.AddRange([byte[]](0x00, 0x30, 0x00, 0x00))  # SizeOfImage at offset 0xD4
# SizeOfHeaders = 0x400
$peData.AddRange([byte[]](0x00, 0x04, 0x00, 0x00))  # SizeOfHeaders at offset 0xD8
# CheckSum = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # CheckSum at offset 0xDC
# Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI (3)
$peData.AddRange([byte[]](0x03, 0x00))  # Subsystem at offset 0xE0
# DllCharacteristics = 0x8160
$peData.AddRange([byte[]](0x60, 0x81))  # DllCharacteristics at offset 0xE2
# SizeOfStackReserve = 0x100000
$peData.AddRange([byte[]](0x00, 0x00, 0x10, 0x00))  # SizeOfStackReserve low at offset 0xE4
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # SizeOfStackReserve high at offset 0xE8
# SizeOfStackCommit = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # SizeOfStackCommit low at offset 0xEC
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # SizeOfStackCommit high at offset 0xF0
# SizeOfHeapReserve = 0x100000
$peData.AddRange([byte[]](0x00, 0x00, 0x10, 0x00))  # SizeOfHeapReserve low at offset 0xF4
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # SizeOfHeapReserve high at offset 0xF8
# SizeOfHeapCommit = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # SizeOfHeapCommit low at offset 0xFC
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # SizeOfHeapCommit high at offset 0x100
# LoaderFlags = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # LoaderFlags at offset 0x104
# NumberOfRvaAndSizes = 16
$peData.AddRange([byte[]](0x10, 0x00, 0x00, 0x00))  # NumberOfRvaAndSizes at offset 0x108

# === DATA DIRECTORIES (16 * 8 = 128 bytes at offset 0x10C) ===
for ($i = 0; $i -lt 16; $i++) {
    $peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # VirtualAddress
    $peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # Size
}

# === SECTION HEADER (40 bytes per section, 1 section at offset 0x18C) ===
# Name = ".text" (8 bytes)
$peData.AddRange([System.Text.Encoding]::ASCII.GetBytes(".text"))  # Name at offset 0x18C
# Pad remaining 8 bytes of name with zeros
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

# VirtualSize = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # VirtualSize at offset 0x194
# VirtualAddress = 0x1000
$peData.AddRange([byte[]](0x00, 0x10, 0x00, 0x00))  # VirtualAddress at offset 0x198
# SizeOfRawData = 0x200
$peData.AddRange([byte[]](0x00, 0x02, 0x00, 0x00))  # SizeOfRawData at offset 0x19C
# PointerToRawData = 0x400
$peData.AddRange([byte[]](0x00, 0x04, 0x00, 0x00))  # PointerToRawData at offset 0x1A0
# PointerToRelocations = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # PointerToRelocations at offset 0x1A4
# PointerToLinenumbers = 0
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # PointerToLinenumbers at offset 0x1A8
# NumberOfRelocations = 0
$peData.AddRange([byte[]](0x00, 0x00))  # NumberOfRelocations at offset 0x1AC
# NumberOfLinenumbers = 0
$peData.AddRange([byte[]](0x00, 0x00))  # NumberOfLinenumbers at offset 0x1AE
# Characteristics = 0x60000020 (CODE | EXECUTE | READ)
$peData.AddRange([byte[]](0x20, 0x00, 0x00, 0x60))  # Characteristics at offset 0x1B0

# === SECTION DATA (aligned to 0x200 = 512) ===
# Pad to 0x400 (start of section data)
while ($peData.Count -lt 0x400) {
    $peData.Add(0x00)
}

# Add some minimal code (simple RET instruction)
$peData.Add(0xC3)  # RET instruction

# Pad section to 0x200 bytes
while ($peData.Count -lt 0x600) {
    $peData.Add(0x00)
}

# Write to file
[System.IO.File]::WriteAllBytes($outputPath, $peData.ToArray())

Write-Host "Created test PE32 file: $outputPath"
Write-Host "File size: $((Get-Item $outputPath).Length) bytes"
Write-Host "e_lfanew at offset 0x3C: $('{0:X2} {1:X2} {2:X2} {3:X2}' -f (Get-Content $outputPath -Raw)[60..63])"
Write-Host "PE sig at offset 0x80: $('{0:X2} {1:X2} {2:X2} {3:X2}' -f (Get-Content $outputPath -Raw)[128..131])"
