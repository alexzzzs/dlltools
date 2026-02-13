# Create invalid PE files for testing error handling

# === 1. Invalid DOS signature (not "MZ") ===
$invalidDosSig = "tests\test_data\invalid_dos_sig.dll"
$peData = New-Object System.Collections.Generic.List[byte]
$peData.AddRange([byte[]](0x00, 0x00))  # Invalid signature (not "MZ")
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
$peData.Add(0x80)  # e_lfanew
$peData.AddRange([byte[]](0x00, 0x00, 0x00))
while ($peData.Count -lt 128) { $peData.Add(0x00) }
$peData.AddRange([byte[]](0x50, 0x45, 0x00, 0x00))  # PE signature
$peData.AddRange([byte[]](0x4C, 0x01))  # Machine = i386
$peData.AddRange([byte[]](0x01, 0x00))  # NumberOfSections
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
$peData.AddRange([byte[]](0xE0, 0x00))  # SizeOfOptionalHeader
$peData.AddRange([byte[]](0x00, 0x20))  # Characteristics
[System.IO.File]::WriteAllBytes($invalidDosSig, $peData.ToArray())
Write-Host "Created: $invalidDosSig"

# === 2. Invalid PE signature (not "PE\0\0") ===
$invalidPeSig = "tests\test_data\invalid_pe_sig.dll"
$peData = New-Object System.Collections.Generic.List[byte]
$peData.AddRange([byte[]](0x4D, 0x5A))  # Valid MZ
$peData.AddRange([byte[]](0x90, 0x00))
$peData.AddRange([byte[]](0x03, 0x00))
$peData.AddRange([byte[]](0x00, 0x00))
$peData.AddRange([byte[]](0x04, 0x00))
$peData.AddRange([byte[]](0x00, 0x00))
$peData.AddRange([byte[]](0xFF, 0xFF))
$peData.AddRange([byte[]](0x00, 0x00))
$peData.AddRange([byte[]](0xB8, 0x00))
$peData.AddRange([byte[]](0x00, 0x00))
$peData.AddRange([byte[]](0x00, 0x00))
$peData.AddRange([byte[]](0x00, 0x00))
$peData.AddRange([byte[]](0x80, 0x00, 0x00, 0x00))
while ($peData.Count -lt 128) { $peData.Add(0x00) }
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))  # Invalid PE signature
[System.IO.File]::WriteAllBytes($invalidPeSig, $peData.ToArray())
Write-Host "Created: $invalidPeSig"

# === 3. Truncated file (too short) ===
$truncated = "tests\test_data\truncated.dll"
$peData = New-Object System.Collections.Generic.List[byte]
$peData.AddRange([byte[]](0x4D, 0x5A))  # Just MZ header
[System.IO.File]::WriteAllBytes($truncated, $peData.ToArray())
Write-Host "Created: $truncated"

# === 4. Invalid optional header magic (not 0x10B or 0x20B) ===
$invalidOptMagic = "tests\test_data\invalid_opt_magic.dll"
$peData = New-Object System.Collections.Generic.List[byte]
$peData.AddRange([byte[]](0x4D, 0x5A))
$peData.AddRange([byte[]](0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00))
$peData.AddRange([byte[]](0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00))
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00))
while ($peData.Count -lt 128) { $peData.Add(0x00) }
$peData.AddRange([byte[]](0x50, 0x45, 0x00, 0x00))  # PE
$peData.AddRange([byte[]](0x4C, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00))
$peData.AddRange([byte[]](0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x20))
$peData.AddRange([byte[]](0xFF, 0xFF))  # Invalid optional header magic
while ($peData.Count -lt 256) { $peData.Add(0x00) }
[System.IO.File]::WriteAllBytes($invalidOptMagic, $peData.ToArray())
Write-Host "Created: $invalidOptMagic"

Write-Host "All invalid PE test files created!"
