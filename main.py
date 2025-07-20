"""
MIT License

Copyright (c) 2025 oxiKKK

-------------------------------------------------------------------------------
Build-number extractor for Valve GoldSrc/Source binaries.

This script traverses the file and directory paths passed on the command line,
recursively scanning every Windows executable (.exe / .dll).  For each file it:

1. Detects Valve's classic blob encryption and transparently decrypts the
   buffer when necessary.
2. Searches the binary data for build-date strings in either of two formats:
      • "HH:MM:SS Mon DD YYYY" (preferred, includes time)
      • "Mon DD YYYY" (fallback)
3. Converts the date to the engine's build number (days since 24 Oct 1996)
   using the `build_number()` routine.
4. Prints per-file results while scanning and, at the end, a summary that lists
   total/encrypted/matched files plus the exact offsets, strings and build
   numbers for all matches.

Example usage:
    python main.py C:\Path\To\GameDir
-------------------------------------------------------------------------------
"""

import os
import re
import argparse
import struct

# -----------------------------------------------------------------------------
# argument parsing helpers
# -----------------------------------------------------------------------------


def _parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        description="Extract build number from GoldSrc/Source2 executables.",
    )

    parser.add_argument(
        "paths",
        nargs="+",
        help="File and/or directory paths to scan. Directories will be searched recursively.",
    )

    return parser.parse_args()


# -----------------------------------------------------------------------------
# file discovery helpers
# -----------------------------------------------------------------------------


def _is_executable(path):
    """Return True if *path* ends with a known executable extension."""
    return os.path.splitext(path)[1].lower() in (".dll", ".exe")


def _gather_files(paths):
    """Return a list of executable files (.exe/.dll) discovered under *paths*.

    *paths* may contain individual files or directories. Directories are scanned
    recursively. Non-executable files are ignored.
    """

    candidate_files = []

    # Normalize incoming paths so that separators like '\\' or mixed usage are
    # handled consistently across platforms. This also transparently converts
    # paths such as "C:\\some\\dir\\" and "C:/some/dir/" to the canonical
    # representation expected by os.path utilities.

    for raw_path in paths:
        # On Windows, a trailing backslash in a quoted path argument escapes
        # the closing quote. This results in the argument being passed with a
        # literal quote at the end (e.g., "C:\path\" -> C:\path").
        # We strip any trailing quotes to handle this common shell issue.
        p = os.path.normpath(raw_path.rstrip('"'))

        if os.path.isfile(p):
            if _is_executable(p):
                candidate_files.append(p)
        elif os.path.isdir(p):
            for root, _, files_in_dir in os.walk(p):
                for fname in files_in_dir:
                    fpath = os.path.join(root, fname)
                    if _is_executable(fpath):
                        candidate_files.append(fpath)
        else:
            print(f"warning: path '{raw_path}' is not a valid file or directory, skipping.")

    return candidate_files


# -----------------------------------------------------------------------------
# blob encryption handling (Valve classic blob algorithm)
# -----------------------------------------------------------------------------

CLASSIC_BLOB_SIG = 0x12345678  # magic number located at offset 64 if encrypted
_FAKECOFF_SIZE = 60 + 4 + 4    # sizeof(FakeCOFFHeader_t) -> 68 bytes
_XOR_SEED = ord('W')


def _is_encrypted_blob(data: bytes) -> bool:
    """Return True if *data* looks like a Valve blob-encrypted module."""
    if len(data) < _FAKECOFF_SIZE:
        return False

    sig = struct.unpack_from('<I', data, 64)[0]  # nSignature field
    return sig == CLASSIC_BLOB_SIG


def _decrypt_blob(data: bytes) -> bytes:
    """Decrypt Valve blob-encrypted buffer *data* in-place and return bytes object."""
    # Work on mutable copy
    buf = bytearray(data)

    xor_char = _XOR_SEED
    for i in range(_FAKECOFF_SIZE, len(buf)):
        buf[i] ^= xor_char
        xor_char = (xor_char + buf[i] + _XOR_SEED) & 0xFF

    # Additional header field fixes (not strictly required for pattern search)
    # Decode certain header fields so that a rebuilt PE could be produced later
    # if desired. We still apply them for completeness, but errors are ignored
    # on malformed files.
    try:
        # Read BlobHeader_t (6 ints, 24 bytes) right after FakeCOFF
        nRandom, cblobunit, nAddressF, nImageBase, nEntryPoint, nImportDir = struct.unpack_from(
            '<6I', buf, _FAKECOFF_SIZE)

        # Apply Valve transformations (same as C++ reference).
        nAddressF ^= 0x7A32BC85
        nImageBase ^= 0x49C042D1
        nEntryPoint = (nEntryPoint - 0x0000000C) & 0xFFFFFFFF
        nImportDir ^= 0x872C3D47

        # Write back patched values (keep nRandom and cblobunit, but increment cblobunit like original code)
        struct.pack_into('<6I', buf, _FAKECOFF_SIZE,
                         nRandom,
                         (cblobunit + 1) & 0xFFFF_FFFF,
                         nAddressF,
                         nImageBase,
                         nEntryPoint,
                         nImportDir)
    except struct.error:
        # Not enough data – ignore silently, since pattern search will still work
        pass

    return bytes(buf)


# -----------------------------------------------------------------------------
# processing helpers
# -----------------------------------------------------------------------------


def _process_file(file_path):
    """Try to extract and print build number from *file_path*.
    Returns tuple (found, encrypted):
        found (bool)      - True if build number pattern was detected.
        encrypted (bool)  - True if file was recognised as a Valve blob-encrypted module.
    """

    # Show progress to the user
    print(f"[*] Processing: {file_path}")

    encrypted = False
    match_info = None  # will hold tuple (offset, full_str, date_part, buildnum)

    try:
        with open(file_path, "rb") as exe_file:
            binary_data = exe_file.read()
    except FileNotFoundError:
        print(f"error: file '{file_path}' not found.")
        return False, encrypted, None
    except OSError as err:
        print(f"error: could not read '{file_path}': {err}")
        return False, encrypted, None

    if not binary_data:
        return False, encrypted, None

    # Detect and decrypt Valve blob-encrypted DLLs / EXEs automatically.
    if _is_encrypted_blob(binary_data):
        print(f"[INFO] '{file_path}' appears to be Valve blob-encrypted. Decrypting...")
        binary_data = _decrypt_blob(binary_data)
        encrypted = True
        print(f"[INFO] Decryption finished. Scanning decrypted image...")

    # ------------------------------------------------------------------
    # Regex search for build date/time strings within binary data
    # ------------------------------------------------------------------

    # Decode the binary blob using latin-1 so that every byte maps 1:1 to a char
    text_blob = binary_data.decode("latin-1", errors="ignore")

    # Preferred pattern: HH:MM:SS <Mon> <DD> <YYYY>
    time_date_regex = re.compile(r"(\d{2}:\d{2}:\d{2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4})")
    date_only_regex = re.compile(r"((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4})")

    m = time_date_regex.search(text_blob)
    if m:
        full_str = m.group(1)
        date_only = " ".join(full_str.split()[1:])  # drop time component
        offset = m.start(1)
    else:
        m2 = date_only_regex.search(text_blob)
        if not m2:
            print(f"[!] Pattern not found in {file_path}")
            return False, encrypted, None
        full_str = date_only = m2.group(1)
        offset = m2.start(1)

    # Validate date_only via regex again (ensures parse reliability)
    if not re.match(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}$", date_only):
        print(f"[!] Extracted date string '{date_only}' from {file_path} is invalid, skipping.")
        return False, encrypted, None

    try:
        buildnum = build_number(date_only)
    except Exception as e:
        print(f"[!] Failed to compute build number for '{date_only}' in {file_path}: {e}")
        return False, encrypted, None

    print(f"found at {file_path}!0x{offset:016X}: '{full_str}' -> build {buildnum}")

    match_info = (file_path, offset, full_str, buildnum)

    return True, encrypted, match_info


# HL1 release date. Valve uses this as a starting point to calculate the amount of days from this particular
# date u till now as a build number for their engine-
RELEASE_DATE = 34995  # Oct 24 1996


# List of month abbreviations
months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Days in each month
month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def build_number(date_utf8):  # expected 9842 for 'Oct  5 2023'
    """
    converts a date-like string into a goldsrc/source2-like build number.
    expects date_utf8 to be MMM DD YYYY
    """

    # Extract month, day, and year
    current_month, current_day, current_year = date_utf8.split()

    # Unpack as integers
    m = months.index(current_month)
    d = 0
    y = 0

    for i in range(m):
        d += month_days[i]

    d += int(current_day) - 1
    y = int(current_year) - 1900

    d = d + int((y - 1) * 365.25)

    # Adjust for leap years
    if ((y % 4) == 0) and m > 1:
        d += 1

    # Adjust for the base date
    d -= RELEASE_DATE

    return d


def main():
    args = _parse_arguments()

    candidate_files = _gather_files(args.paths)

    if not candidate_files:
        print("No matching files found. Nothing to do.")
        return

    total_files = len(candidate_files)
    found_count = 0
    encrypted_count = 0
    found_entries = []

    for fp in candidate_files:
        found, encrypted, info = _process_file(fp)

        if encrypted:
            encrypted_count += 1
        if found:
            found_count += 1
            if info:
                found_entries.append(info)

    print("\n--- Summary ---")
    print(f"Total files processed : {total_files}")
    print(f"Encrypted files       : {encrypted_count}")
    print(f"Build numbers found   : {found_count}")
    print(f"No match              : {total_files - found_count}")

    if found_entries:
        print("\nMatches:")
        for (fpath, off, dstr, bnum) in found_entries:
            print(f"  {fpath}!0x{off:016X} -> '{dstr}' -> build {bnum}")


if __name__ == "__main__":
    main()
