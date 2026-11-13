"""Small PNG/BMP decoder for dHash. Alpha is composited onto a white background."""
from pathlib import Path
import platform
import re
import struct
import subprocess
import tempfile
import zlib
from storage import safe_path

MAX_IMAGE_FILE_BYTES = 25 * 1024 * 1024
MAX_IMAGE_PIXELS = 4096 * 4096
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def _luma(r, g, b, alpha=255):
    if alpha != 255:
        r, g, b = ((v * alpha + 255 * (255 - alpha) + 127) // 255 for v in (r, g, b))
    return (299 * r + 587 * g + 114 * b) // 1000


def _decode_png_luma(raw: bytes):
    if not raw.startswith(b'\x89PNG\r\n\x1a\n') or len(raw) > MAX_IMAGE_FILE_BYTES:
        raise ValueError('Invalid or oversized PNG')
    pos = 8
    width = height = color_type = 0
    palette = b''
    transparency = b''
    idat = []
    seen = set()
    ended = False
    idat_closed = False
    chunks = 0
    while pos < len(raw):
        chunks += 1
        if chunks > 4096 or pos + 12 > len(raw):
            raise ValueError('Truncated PNG or excessive chunk count')
        length = struct.unpack_from('>I', raw, pos)[0]
        kind = raw[pos + 4:pos + 8]
        end = pos + 8 + length
        if end + 4 > len(raw) or not re.fullmatch(b'[A-Za-z]{2}[A-Z][A-Za-z]', kind):
            raise ValueError('Invalid PNG chunk')
        data = raw[pos + 8:end]
        expected_crc = struct.unpack_from('>I', raw, end)[0]
        if zlib.crc32(data, zlib.crc32(kind)) & 0xffffffff != expected_crc:
            raise ValueError('PNG chunk CRC mismatch')
        pos = end + 4
        if not seen and kind != b'IHDR':
            raise ValueError('PNG must start with IHDR')
        if kind in (b'IHDR', b'PLTE', b'tRNS', b'IEND') and kind in seen:
            raise ValueError('Duplicate PNG structure chunk')
        if idat and kind != b'IDAT':
            idat_closed = True
        if kind == b'IHDR':
            if len(data) != 13:
                raise ValueError('Invalid PNG IHDR length')
            width, height, depth, color_type, comp, flt, interlace = struct.unpack('>IIBBBBB', data)
            if not width or not height or width * height > MAX_IMAGE_PIXELS:
                raise ValueError('PNG dimensions out of budget')
            if depth != 8 or comp or flt or interlace or color_type not in (0, 2, 3, 4, 6):
                raise ValueError('Only 8-bit non-interlaced PNG is supported')
        elif kind == b'PLTE':
            if idat or b'tRNS' in seen or color_type in (0, 4) or not data or len(data) % 3 or len(data) > 768:
                raise ValueError('Invalid PNG palette')
            palette = data
        elif kind == b'tRNS':
            if idat or color_type not in (0, 2, 3):
                raise ValueError('Invalid PNG transparency ordering or type')
            if (color_type == 0 and len(data) != 2) or (color_type == 2 and len(data) != 6):
                raise ValueError('Invalid PNG transparent color')
            if color_type == 3 and (not palette or not data or len(data) > len(palette) // 3):
                raise ValueError('Invalid PNG palette transparency')
            if color_type in (0, 2) and any(v > 255 for v in struct.unpack('>' + 'H' * (len(data) // 2), data)):
                raise ValueError('PNG transparent sample exceeds bit depth')
            transparency = data
        elif kind == b'IDAT':
            if idat_closed or (color_type == 3 and not palette):
                raise ValueError('Invalid PNG image stream ordering')
            idat.append(data)
        elif kind == b'IEND':
            if data or not idat or pos != len(raw):
                raise ValueError('Invalid PNG IEND or trailing data')
            ended = True
            break
        elif kind[:1].isupper():
            raise ValueError('Unsupported critical PNG chunk')
        seen.add(kind)
    if not ended:
        raise ValueError('PNG is missing IEND')
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    stride = width * channels
    expected = height * (1 + stride)
    if expected > MAX_DECOMPRESSED_BYTES:
        raise ValueError('Decompressed PNG exceeds budget')
    decoder = zlib.decompressobj()
    try:
        inflated = decoder.decompress(b''.join(idat), expected + 1)
    except zlib.error as exc:
        raise ValueError('Invalid PNG compressed stream') from exc
    if len(inflated) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('Incomplete or excessive PNG compressed stream')
    transparent_color = None
    if transparency and color_type in (0, 2):
        transparent_color = struct.unpack('>' + 'H' * (len(transparency) // 2), transparency)
    luma = bytearray(width * height)
    previous = bytearray(stride)
    for y in range(height):
        start = y * (1 + stride)
        filter_type = inflated[start]
        if filter_type > 4:
            raise ValueError('Invalid PNG filter')
        src = inflated[start + 1:start + 1 + stride]
        current = bytearray(stride)
        for i, value in enumerate(src):
            a = current[i - channels] if i >= channels else 0
            b = previous[i]
            c = previous[i - channels] if i >= channels else 0
            predictor = 0 if filter_type == 0 else a if filter_type == 1 else b if filter_type == 2 else (a + b) // 2 if filter_type == 3 else _paeth(a, b, c)
            current[i] = (value + predictor) & 255
        previous = current
        for x in range(width):
            i = x * channels
            alpha = 255
            if color_type in (0, 4):
                r = g = b = current[i]
                alpha = current[i + 1] if color_type == 4 else 0 if transparent_color == (r,) else 255
            elif color_type in (2, 6):
                r, g, b = current[i:i + 3]
                alpha = current[i + 3] if color_type == 6 else 0 if transparent_color == (r, g, b) else 255
            else:
                index = current[i]
                if index >= len(palette) // 3:
                    raise ValueError('PNG palette index out of range')
                r, g, b = palette[index * 3:index * 3 + 3]
                alpha = transparency[index] if index < len(transparency) else 255
            luma[y * width + x] = _luma(r, g, b, alpha)
    return width, height, luma


def _decode_bmp_luma(raw: bytes):
    if len(raw) < 54 or len(raw) > MAX_IMAGE_FILE_BYTES or raw[:2] != b'BM':
        raise ValueError('Invalid or oversized BMP')
    file_size = struct.unpack_from('<I', raw, 2)[0]
    offset, dib_size = struct.unpack_from('<II', raw, 10)
    if dib_size < 40 or 14 + dib_size > len(raw) or file_size != len(raw):
        raise ValueError('Invalid BMP header length')
    width, signed_height, planes, bpp, compression = struct.unpack_from('<iiHHI', raw, 18)
    height = abs(signed_height)
    if planes != 1 or width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS or compression or bpp not in (8, 24, 32):
        raise ValueError('Only uncompressed 8/24/32-bit BMP within limits is supported')
    stride = ((bpp * width + 31) // 32) * 4
    palette = []
    minimum_offset = 14 + dib_size
    if bpp == 8:
        colors_used = struct.unpack_from('<I', raw, 46)[0] or 256
        if not 1 <= colors_used <= 256:
            raise ValueError('Invalid BMP palette size')
        palette_end = minimum_offset + colors_used * 4
        if palette_end > len(raw):
            raise ValueError('Truncated BMP palette')
        for i in range(minimum_offset, palette_end, 4):
            b, g, r, _ = raw[i:i + 4]
            palette.append(_luma(r, g, b))
        minimum_offset = palette_end
    if offset < minimum_offset or offset + stride * height > len(raw):
        raise ValueError('Invalid BMP pixel offset or truncated pixels')
    luma = bytearray(width * height)
    for y in range(height):
        row = offset + (y if signed_height < 0 else height - 1 - y) * stride
        for x in range(width):
            p = row + x * (bpp // 8)
            if bpp == 8:
                if raw[p] >= len(palette):
                    raise ValueError('BMP palette index out of range')
                luma[y * width + x] = palette[raw[p]]
            else:
                b, g, r = raw[p:p + 3]
                # BI_RGB 32-bit uses the fourth byte as reserved data, not alpha.
                luma[y * width + x] = _luma(r, g, b)
    return width, height, luma


def _read_image(path: Path) -> bytes:
    path = safe_path(path)
    if not path.is_file() or path.stat().st_size > MAX_IMAGE_FILE_BYTES:
        raise ValueError('Image must be a regular file up to 25 MiB')
    with path.open('rb') as stream:
        raw = stream.read(MAX_IMAGE_FILE_BYTES + 1)
    if not raw or len(raw) > MAX_IMAGE_FILE_BYTES:
        raise ValueError('Empty or oversized image')
    return raw


def _decode_image_luma(path: Path):
    path = safe_path(path)
    raw = _read_image(path)
    if raw.startswith(b'\x89PNG\r\n\x1a\n'):
        return _decode_png_luma(raw)
    if raw.startswith(b'BM'):
        return _decode_bmp_luma(raw)
    if platform.system() == 'Darwin' and Path('/usr/bin/sips').is_file():
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'converted.png'
            try:
                subprocess.run(['/usr/bin/sips', '-s', 'format', 'png', str(path), '--out', str(output)],
                               check=True, capture_output=True, timeout=15)
                return _decode_png_luma(_read_image(output))
            except (subprocess.SubprocessError, OSError) as exc:
                raise ValueError('Native image conversion failed') from exc
    raise ValueError('Unsupported encoding; convert to PNG or BMP')


def compute_image_dhash(path: Path) -> str:
    width, height, luma = _decode_image_luma(path)
    grid = []
    for gy in range(8):
        y0 = (gy * height) // 8
        y1 = max(y0 + 1, ((gy + 1) * height) // 8)
        row = []
        for gx in range(9):
            x0 = (gx * width) // 9
            x1 = max(x0 + 1, ((gx + 1) * width) // 9)
            total = count = 0
            for y in range(min(y0, height - 1), min(y1, height)):
                for x in range(min(x0, width - 1), min(x1, width)):
                    total += luma[y * width + x]
                    count += 1
            row.append(total // max(1, count))
        grid.append(row)
    bits = 0
    for row in grid:
        for x in range(8):
            bits = (bits << 1) | int(row[x] < row[x + 1])
    return f'{bits:016x}'


def dhash_hamming_distance(hash_a: str, hash_b: str) -> int:
    if not re.fullmatch(r'[0-9a-fA-F]{16}', hash_a) or not re.fullmatch(r'[0-9a-fA-F]{16}', hash_b):
        raise ValueError('Expected 16-hex-character dHash values')
    return (int(hash_a, 16) ^ int(hash_b, 16)).bit_count()


def compare_images_dhash(original_path: Path, suspect_path: Path, threshold: int = 10) -> dict:
    if type(threshold) is not int or not 0 <= threshold <= 64:
        raise ValueError('dHash threshold must be between 0 and 64')
    h1, h2 = compute_image_dhash(original_path), compute_image_dhash(suspect_path)
    distance = dhash_hamming_distance(h1, h2)
    return {'algorithm': 'dhash-64', 'alpha_background': '#ffffff',
            'original_dhash': h1, 'suspect_dhash': h2, 'hamming_distance': distance,
            'max_bits': 64, 'threshold': threshold, 'candidate_similar': distance <= threshold,
            'use': 'VISUAL_SIMILARITY_HINT_NOT_PROOF_OF_INFRINGEMENT', 'trusted_as_instructions': False}
