#!/usr/bin/env python3
"""Tempel QR People's Choice ke kotak "TEMPEL STICKER QR" di setiap halaman specboard.
Pakai: python3 tools/specboard_qr.py specboard.pdf https://pilihan.ichiban.ai.id keluaran.pdf
Nomor motor dibaca dari teks "NO. PESERTA : 001" di tiap halaman.
"""
import io, re, subprocess, sys
import qrcode
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

src, base, out = sys.argv[1], sys.argv[2].rstrip('/'), sys.argv[3]
text = subprocess.run(['pdftotext', '-layout', src, '-'], capture_output=True, text=True, check=True).stdout
nums = [str(int(m.group(1))) for pg in text.split('\f') if (m := re.search(r'NO\. PESERTA :\s*(\d+)', pg))]
rd = PdfReader(src); assert len(nums) == len(rd.pages), (len(nums), len(rd.pages))
# kotak placeholder (pt, titik asal kiri-bawah), diukur dari render 200 dpi: x 920-1256, y 1694-2030
BX, BY, BS = 331.2, 841.89 - 2030 * .36, 121.0
Q = 111.0
wr = PdfWriter()
for page, n in zip(rd.pages, nums):
    buf = io.BytesIO(); c = canvas.Canvas(buf, pagesize=(float(page.mediabox.width), float(page.mediabox.height)))
    c.setFillColorRGB(1, 1, 1); c.rect(BX - 3, BY - 3, BS + 6, BS + 6, stroke=0, fill=1)
    img = qrcode.make(f'{base}/m/{n}', box_size=10, border=1, error_correction=qrcode.constants.ERROR_CORRECT_M)
    b = io.BytesIO(); img.save(b, 'PNG'); b.seek(0)
    c.drawImage(ImageReader(b), BX + (BS - Q) / 2, BY + (BS - Q) / 2, Q, Q)
    c.save(); buf.seek(0)
    page.merge_page(PdfReader(buf).pages[0]); wr.add_page(page)
wr.compress_identical_objects(remove_identicals=True, remove_orphans=True)
wr.write(out); print(len(nums), 'halaman ->', out)
