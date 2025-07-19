# goldsrc-buildnumber-extractor

I use this python scripts when figuring out the build numbers and build dates of old GoldSrc builds.

Usage:

```powershell
python .\main.py ".\CS1.5\"
```

Output:

```
searching for pattern None in 27 file(s)...
[*] Processing: .\CS1.5\a3dapi.dll
[!] Pattern not found in .\CS1.5\a3dapi.dll
[*] Processing: .\CS1.5\cstrike.exe
found at .\CS1.5\cstrike.exe!0x00000000000D4654: 'Jun  5 2002' -> build 2050
[*] Processing: .\CS1.5\hl_res.dll
[!] Pattern not found in .\CS1.5\hl_res.dll
[*] Processing: .\CS1.5\hw.dll
[INFO] '.\CS1.5\hw.dll' appears to be Valve blob-encrypted. Decrypting...
[INFO] Decryption finished. Scanning decrypted image...
found at .\CS1.5\hw.dll!0x00000000000F4FFD: '13:25:04 Jun 11 2002' -> build 2056
[*] Processing: .\CS1.5\Mss32.dll
[!] Pattern not found in .\CS1.5\Mss32.dll
...

--- Summary ---
Total files processed : 27
Encrypted files       : 3
Build numbers found   : 5
No match              : 22

Matches:
  .\CS1.5\cstrike.exe!0x00000000000D4654 -> 'Jun  5 2002' -> build 2050
  .\CS1.5\hw.dll!0x00000000000F4FFD -> '13:25:04 Jun 11 2002' -> build 2056
  .\CS1.5\hw_dec.dll!0x00000000000F72E7 -> '13:25:04 Jun 11 2002' -> build 2056
  .\CS1.5\sw.dll!0x00000000000DDE5C -> '13:22:19 Jun 11 2002' -> build 2056
  .\CS1.5\swds.dll!0x00000000000ED797 -> '13:27:08 Jun 11 2002' -> build 2056
```