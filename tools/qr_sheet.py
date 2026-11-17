#!/usr/bin/env python3
"""Buat PDF lembar QR People's Choice (kartu 6,5 x 4,5 cm, 18 kartu per A4).
Pakai:  python3 tools/qr_sheet.py import_motor.json https://pilihan.ichiban.ai.id keluaran.pdf [jumlah_cadangan]
"""
import json, sys, io
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

src, base, out = sys.argv[1], sys.argv[2].rstrip('/'), sys.argv[3]
spare = int(sys.argv[4]) if len(sys.argv) > 4 else 15
rows = json.load(open(src, encoding='utf-8'))
merged = {}
for r in rows:
    m = merged.setdefault(r['number'], dict(r, category=[]))
    if r['category'] and r['category'] not in m['category']: m['category'].append(r['category'])
rows = [dict(m, category=' / '.join(m['category'])) for m in merged.values()]
def key(r):
    n = r['number']; return (0, int(n)) if n.isdigit() else (1, n)
rows.sort(key=key)
top = max([int(r['number']) for r in rows if r['number'].isdigit()] + [0])
for i in range(1, spare + 1): rows.append({'number': str(top + i), 'category': '', 'owner': '', 'name': ''})

pdfmetrics.registerFont(TTFont('B', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'))
pdfmetrics.registerFont(TTFont('R', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
W, H = A4; CW, CH = 6.5 * cm, 4.5 * cm; COLS, ROWS = 3, 6
mx, my = (W - COLS * CW) / 2, (H - ROWS * CH) / 2

def fit(c, t, font, size, maxw):
    while size > 5 and c.stringWidth(t, font, size) > maxw: size -= .5
    return size
def wrap(c, t, font, size, maxw, lines):
    words, cur, res = t.split(), '', []
    for w in words:
        if c.stringWidth((cur + ' ' + w).strip(), font, size) <= maxw: cur = (cur + ' ' + w).strip()
        else: res.append(cur); cur = w
    if cur: res.append(cur)
    if len(res) > lines: res = res[:lines]; res[-1] = res[-1][:-1] + '…'
    return res

c = canvas.Canvas(out, pagesize=A4)
c.setTitle("QR Motor - People's Choice")
for i, r in enumerate(rows):
    k = i % (COLS * ROWS)
    if i and k == 0: c.showPage()
    x = mx + (k % COLS) * CW; y = H - my - (k // COLS + 1) * CH
    c.setStrokeColorRGB(.6, .6, .6); c.setDash(2, 2); c.setLineWidth(.4); c.rect(x, y, CW, CH); c.setDash()
    img = qrcode.make(f"{base}/m/{r['number']}", box_size=10, border=1, error_correction=qrcode.constants.ERROR_CORRECT_M)
    buf = io.BytesIO(); img.save(buf, 'PNG'); buf.seek(0)
    q = 3.5 * cm
    c.drawImage(ImageReader(buf), x + .35 * cm, y + (CH - q) / 2, q, q)
    tx = x + .35 * cm + q + .3 * cm; tw = CW - (tx - x) - .3 * cm
    c.setFillColorRGB(.88, .11, .16); c.setFont('B', 8); c.drawString(tx, y + CH - .8 * cm, 'NO. MOTOR')
    c.setFillColorRGB(0, 0, 0); s = fit(c, r['number'], 'B', 40, tw); c.setFont('B', s); c.drawString(tx, y + CH - 2.0 * cm, r['number'])
    yy = y + CH - 2.6 * cm
    c.setFont('B', 7.5)
    for ln in wrap(c, r['category'] or 'Cadangan', 'B', 7.5, tw, 2): c.drawString(tx, yy, ln.upper()); yy -= .33 * cm
    c.setFont('R', 7); c.setFillColorRGB(.25, .25, .25)
    for ln in wrap(c, r['owner'].split(' • ')[0] if r['owner'] else '', 'R', 7, tw, 1): c.drawString(tx, yy - .05 * cm, ln)
    c.setFont('R', 6); c.setFillColorRGB(.4, .4, .4); c.drawString(tx, y + .3 * cm, 'Scan untuk memilih')
c.save()
print(len(rows), 'kartu ->', out)
