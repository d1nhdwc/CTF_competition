import binascii
import struct
from pathlib import Path


def main() -> None:
    line = Path("hash.txt").read_text().strip()
    prefix, rest = line.split(":$pkzip2$", 1)
    archive_name, member_name = prefix.split("/", 1)
    body = rest.split("$/pkzip2$:", 1)[0]
    parts = body.split("*")

    comp_method = int(parts[3], 16)
    comp_size = int(parts[4], 16)
    uncomp_size = int(parts[5], 16)
    crc32 = int(parts[6], 16)
    data_offset = int(parts[8], 16)
    checksum_crc = int(parts[11], 16)
    checksum_time = int(parts[12], 16)
    blob = bytes.fromhex(parts[13])

    filename = member_name.encode()
    assert len(blob) == comp_size
    assert data_offset >= 30 + len(filename)

    def build(out_name: str, flag_bits: int, mod_time: int) -> None:
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flag_bits,
            comp_method,
            mod_time,
            0,
            crc32,
            comp_size,
            uncomp_size,
            len(filename),
            data_offset - 30 - len(filename),
        )
        local_blob = local + filename + b"\x00" * (data_offset - 30 - len(filename)) + blob

        central = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            flag_bits,
            comp_method,
            mod_time,
            0,
            crc32,
            comp_size,
            uncomp_size,
            len(filename),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        central += filename

        eocd = struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            1,
            1,
            len(central),
            len(local_blob),
            0,
        )

        Path(out_name).write_bytes(local_blob + central + eocd)
        print(f"wrote {out_name}")

    # Variant 1: password check byte comes from CRC high byte.
    build("flag_crc.zip", 0x0001, 0)
    # Variant 2: password check byte comes from timestamp high byte.
    build("flag_time.zip", 0x0009, checksum_time)
    print(f"member={member_name} method={comp_method} comp={comp_size} uncomp={uncomp_size}")
    print(f"crc32={crc32:08x} cs={checksum_crc:04x} tc={checksum_time:04x} blob_crc32={binascii.crc32(blob) & 0xffffffff:08x}")


if __name__ == "__main__":
    main()
