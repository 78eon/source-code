"""Offline document layout for curated assessment sections. No data-store access."""
from . import static_graph
from dataclasses import dataclass, field
from html import escape
import textwrap


@dataclass
class Section:
    title: str
    blocks: list = field(default_factory=list)

    def prose(self, *paragraphs):
        self.blocks.extend(("p", paragraph) for paragraph in paragraphs)

    def heading(self, title):
        self.blocks.append(("h", title))

    def table(self, headers, rows):
        self.blocks.append(("table", (headers, list(rows))))

    def figure(self, caption, items):
        self.blocks.append(("figure", (caption, list(items))))


@dataclass
class Document:
    title: str
    classification: str
    subject: str
    reference: str
    sections: list = field(default_factory=list)
    graph_presentation: dict = field(default_factory=dict)

    def section(self, title):
        section = Section(title)
        self.sections.append(section)
        return section


def html(doc):
    graph_positions = static_graph.positions(doc)
    e = lambda s: escape(str(s))
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
             f'<title>{e(doc.title)} | Security-RL</title><style>',
             'body{font:15px/1.58 system-ui;color:#182f42;max-width:64rem;margin:auto;padding:4vw}header{border-top:9px solid #167568;background:#edf5f4;padding:2rem}h1{font-size:2.4rem}h2{border-top:2px solid #167568;padding-top:1em}h3,caption{color:#16675d}p{max-width:80ch}table{width:100%;border-collapse:collapse;margin:1em 0;font-size:.92rem}td,th{padding:.55em;text-align:left;vertical-align:top;border-bottom:1px solid #cddbdc;overflow-wrap:anywhere}th{background:#e5efef}figure{margin:1em 0;background:#eff5f5;padding:1em}figure ol{display:flex;flex-wrap:wrap;gap:1em;list-style-position:inside;padding:0}figure li{background:white;padding:.6em}section{margin:2em 0}a{color:#126459}@media print{header,section{break-before:page}tr,figure{break-inside:avoid}}.link{display:grid;grid-template-columns:1fr minmax(7em,.7fr) 1fr;align-items:center;margin:.55em 0}.link span,.link strong{background:white;padding:.5em;border:1px solid #b3c8c4;border-radius:4px;overflow-wrap:anywhere}.link small{text-align:center;border-bottom:2px solid #147468}.discovery small{border-color:#82aaa2}.structural small{border-color:#667782}.time small{border-bottom:1px dashed #667782}.objective strong{background:#ffedbb}.unreached strong{border:2px dashed #926c31}.unreached span,.unreached small{visibility:hidden}.zones{display:grid;grid-template-columns:repeat(auto-fit,minmax(13em,1fr));gap:.65em}.zones>div{background:white;border-left:3px solid #167568;padding:.75em}</style>',
             f'<header><p>Security-RL / Assessment briefing</p><h1>{e(doc.title)}</h1><h2>{e(doc.subject)}</h2><strong>{e(doc.classification)}</strong><p>{e(doc.reference)}</p></header><nav aria-label="Contents"><ol>']
    parts.extend(f'<li><a href="#s{i}">{e(s.title)}</a></li>' for i,s in enumerate(doc.sections,1))
    parts.append('</ol></nav>')
    for i,s in enumerate(doc.sections,1):
        parts.append(f'<section id="s{i}"><h2>{i:02} · {e(s.title)}</h2>')
        for kind,v in s.blocks:
            if kind in ("p","h"):
                tag = "p" if kind=="p" else "h3"
                parts.append(f'<{tag}>{e(v)}</{tag}>')
            elif kind == "zones":
                caption, zones = v
                parts.append('<figure><figcaption>'+e(caption)+'</figcaption><div class="zones">')
                for name, role, members in zones:
                    parts.append(f'<div><strong>{e(name)}</strong><br>{e(role)}<br>{e(members)}</div>')
                parts.append('</div></figure>')
            elif kind in {"graph", "topology_graph"}:
                caption, links = v
                parts.append('<figure class="progression"><figcaption>' + e(caption) + '</figcaption>')
                parts.append(static_graph.svg(links, graph_positions, kind == "topology_graph", s.title == "Observed Attack / Provenance Graph"))
                parts.append('</figure>')
            elif kind=="figure":
                caption,items=v
                parts.append('<figure><figcaption>'+e(caption)+'</figcaption><ol>'+''.join('<li>'+e(t)+'</li>' for t in items)+'</ol></figure>')
            else:
                headers,rows=v
                parts.append('<table><thead><tr>'+''.join('<th>'+e(t)+'</th>' for t in headers)+'</tr></thead><tbody>')
                parts.extend('<tr>'+''.join('<td>'+e(t)+'</td>' for t in row)+'</tr>' for row in rows)
                parts.append('</tbody></table>')
        parts.append('</section>')
    return ''.join(parts)+'</html>'


def pdf(doc):
    pages=[]
    graph_positions = static_graph.positions(doc)
    def draw(value,x,y,size=10,bold=False):
        literal=str(value).replace('—','-').replace('→','>').encode('cp1252','replace').decode('latin1')
        literal=literal.replace('\\','\\\\').replace('(','\\(').replace(')','\\)').replace('\r',' ').replace('\n',' ')
        pages[-1].append(f"BT /F{2 if bold else 1} {size} Tf 0.08 0.18 0.24 rg {x} {y} Td ({literal}) Tj ET")
    def page(title):
        pages.append(["0.08 0.43 0.39 rg 36 776 523 4 re f"])
        draw("SECURITY-RL   /   ASSESSMENT BRIEFING",36,795,9,True)
        draw(title,36,748,16,True)
        return 720
    y=page(doc.title)
    for value in [doc.subject,doc.classification,doc.reference]:
        for line in textwrap.wrap(value,80):
            draw(line,36,y,11,True); y-=17
        y-=12
    draw("Contents",36,y,14,True)
    for i,s in enumerate(doc.sections,1):
        y-=20;draw(f"{i:02}    {s.title}",36,y)
    for i,s in enumerate(doc.sections,1):
        title=f"{i:02}   {s.title}"
        y=page(title)
        def space(height):
            nonlocal y
            if y-height<53:
                y=page(title+" (continued)")
        def lines(v,width):
            return textwrap.wrap(str(v),width=width) or ['']
        def cells(row,header=False):
            nonlocal y
            w=523/len(row)
            # Conservative character width for Helvetica, including uppercase identifiers.
            columns=[lines(v,max(7,int((w-14)/5.8))) for v in row]
            height=max(map(len,columns))*12+10
            if header:
                pages[-1].append(f'0.88 0.94 0.93 rg 36 {y-height+5} 523 {height} re f')
            for j,col in enumerate(columns):
                for n,line in enumerate(col):
                    draw(line,round(41+j*w),y-5-12*n,8.5,header)
            y-=height
            pages[-1].append(f'0.8 0.85 0.86 RG 0.4 w 36 {y+4} m 559 {y+4} l S')
        def graph_height(links):
            return 28 + sum(21 + 11 * max(len(lines(item.left, 32)), len(lines(item.right, 32))) for item in links)

        for block_index, (kind, v) in enumerate(s.blocks):
            if kind == "h":
                needed = 22
                for following, content in s.blocks[block_index + 1:]:
                    if following == "p":
                        needed += 15 * len(lines(content, 88)) + 7
                    elif following == "graph":
                        space(min(needed + graph_height(content[1]) + 16, 640))
                        break
                    else:
                        break
            if kind in ("p","h"):
                for line in lines(v,78 if kind=="h" else 88):
                    space(21);draw(line,36,y,11 if kind=="h" else 10,kind=="h");y-=15
                y-=7
            elif kind == "zones":
                caption, zones = v
                pairs = []
                for start in range(0, len(zones), 2):
                    cards = [[*lines(name, 32), *lines(role, 39), *lines(members, 39)]
                             for name, role, members in zones[start:start + 2]]
                    pairs.append((cards, 18 + 13 * max(map(len, cards))))
                space(min(640, 32 + sum(height + 7 for _, height in pairs)))
                draw(caption, 36, y, 12, True)
                y -= 15
                for cards, height in pairs:
                    space(height + 8)
                    for col, card in enumerate(cards):
                        x = 36 + col * 265
                        pages[-1].append(f'0.91 0.95 0.94 rg {x} {y-height} 254 {height} re f')
                        pages[-1].append(f'0.09 0.43 0.39 rg {x} {y-height} 3 {height} re f')
                        for row, line in enumerate(card):
                            draw(line, x + 9, y - 15 - row * 13, 10, row == 0)
                    y -= height + 7
                y -= 9
            elif kind in {"graph", "topology_graph"}:
                caption, links = v
                _, height, _ = static_graph.geometry(links, graph_positions, kind == "topology_graph")
                space(height + 40)
                draw(caption, 36, y, 10, True)
                y -= 20
                used = static_graph.pdf_commands(links, graph_positions, y, draw, pages[-1], kind == "topology_graph", s.title == "Observed Attack / Provenance Graph")
                y -= used + 12
            elif kind=="figure":
                caption,items=v
                space(50);draw(caption,36,y,10,True);y-=22
                for j,t in enumerate(items,1):
                    for line in lines(f"{j:02}     {t}",80):
                        space(24)
                        pages[-1].append(f'0.91 0.95 0.94 rg 36 {y-6} 523 19 re f')
                        draw(line,45,y,10);y-=22
                y-=7
            else:
                headers,rows=v
                space(73);cells(headers,True)
                for row in rows:
                    width=max(7,int((523/len(row)-14)/5.8))
                    height=max(len(lines(t,width)) for t in row)*12+10
                    if y-height<53:
                        y=page(title+" (continued)");cells(headers,True)
                    cells(row)
                y-=8
    objects=[b'',b'',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>']
    ids=[]
    for i,commands in enumerate(pages,1):
        commands.append(f'BT /F1 9 Tf 36 28 Td (Security-RL   /   {i} of {len(pages)}) Tj ET')
        stream='\n'.join(commands).encode('latin1')
        pid=len(objects)+1;ids.append(pid)
        objects.extend([f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {pid+1} 0 R >>'.encode(),b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream'])
    objects[0]=b'<< /Type /Catalog /Pages 2 0 R >>'
    objects[1]=f'<< /Type /Pages /Count {len(ids)} /Kids [{" ".join(str(i)+" 0 R" for i in ids)}] >>'.encode()
    out=bytearray(b'%PDF-1.4\n'); offsets=[]
    for i,obj in enumerate(objects,1):
        offsets.append(len(out));out.extend(f'{i} 0 obj\n'.encode()+obj+b'\nendobj\n')
    start=len(out);out.extend(f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode())
    for offset in offsets:out.extend(f'{offset:010d} 00000 n \n'.encode())
    out.extend(f'trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n'.encode())
    return bytes(out)
