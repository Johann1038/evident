"""Helpers that write into the conference template while preserving its styles.

Inline markup in text: **bold**, *italic*, `code` (monospace), [n] citations are plain text.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt

M_NS = "http://schemas.openxmlformats.org/officeDocument/2006/math"
TEXT_WIDTH_TWIPS = 7031


class Paper:
    def __init__(self, template: Path):
        self.doc = Document(str(template))
        self.body = self.doc.element.body
        self.fig_n = 0
        self.tab_n = 0
        self.eq_n = 0
        ps = self.doc.paragraphs
        self.title, self.author = ps[0], ps[1]
        self.abstract = next(p for p in ps if p.style.name == "Abstract")
        self.keywords = next(p for p in ps if p.style.name == "Keywords")
        # drop everything after the keywords paragraph (keep sectPr)
        kw = self.keywords._p
        drop, seen = [], False
        for el in list(self.body):
            if el is kw:
                seen = True
                continue
            if seen and el.tag != qn("w:sectPr"):
                drop.append(el)
        for el in drop:
            self.body.remove(el)
        self.sect = self.body.find(qn("w:sectPr"))

    # ------------------------------------------------------------- basics
    def _new_p(self, style: str):
        p = OxmlElement("w:p")
        ppr = OxmlElement("w:pPr")
        ps = OxmlElement("w:pStyle")
        ps.set(qn("w:val"), style)
        ppr.append(ps)
        p.append(ppr)
        self.sect.addprevious(p)
        from docx.text.paragraph import Paragraph
        return Paragraph(p, self.doc._body)

    @staticmethod
    def _runs(par, text: str, size: float | None = None):
        tokens = re.split(r"(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)", text)
        for t in tokens:
            if not t:
                continue
            if t.startswith("**"):
                r = par.add_run(t[2:-2])
                r.bold = True
            elif t.startswith("*"):
                r = par.add_run(t[1:-1])
                r.italic = True
            elif t.startswith("`"):
                r = par.add_run(t[1:-1])
                r.font.name = "Courier New"
                r.font.size = Pt(8.5)
            else:
                r = par.add_run(t)
            if size and not t.startswith("`"):
                r.font.size = Pt(size)
        return par

    def set_front(self, title: str, abstract: str, keywords: str):
        for r in list(self.title.runs):
            r._r.getparent().remove(r._r)
        self.title.add_run(title)
        for p, label, text in ((self.abstract, "Abstract.", abstract), (self.keywords, "Keywords.", keywords)):
            for r in list(p.runs):
                r._r.getparent().remove(r._r)
            b = p.add_run(label)
            b.bold = True
            self._runs(p, " " + text)

    def set_authors(self, authors: list[str], affiliation: str, footnote: str, corresponding: int = 0):
        """All authors share one affiliation; the template's footnote 1 marks the corresponding author."""
        p = self.author._p
        fn_run = next(r for r in p.findall(qn("w:r")) if r.find(qn("w:footnoteReference")) is not None)
        for r in p.findall(qn("w:r")):
            p.remove(r)
        for i, a in enumerate(authors):
            sep = "" if i == 0 else (" and " if i == len(authors) - 1 else ", ")
            if sep:
                self.author.add_run(sep)
            self.author.add_run(a)
            if i == corresponding:
                p.append(fn_run)
        affs = [q for q in self.doc.paragraphs if q.style.name == "Affiliation"]
        for q in affs[1:]:
            q._p.getparent().remove(q._p)
        a = affs[0]
        for r in list(a.runs):
            r._r.getparent().remove(r._r)
        a.add_run(affiliation)
        # footnote 1 text
        from docx.opc.constants import RELATIONSHIP_TYPE as RT
        part = self.doc.part.part_related_by(RT.FOOTNOTES)
        from lxml import etree
        root = etree.fromstring(part.blob)
        W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        fn = root.find(f"{{{W}}}footnote[@{{{W}}}id='1']")
        par = fn.find(f"{{{W}}}p")
        for r in par.findall(f"{{{W}}}r")[1:]:
            par.remove(r)
        r = etree.SubElement(par, f"{{{W}}}r")
        t = etree.SubElement(r, f"{{{W}}}t")
        t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        t.text = " " + footnote
        part._blob = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    def h1(self, text):
        self._runs(self._new_p("Heading1"), text)
        self._first = True

    def h2(self, text):
        self._runs(self._new_p("Heading2"), text)
        self._first = True

    def h_unnumbered(self, text):
        self._runs(self._new_p("HeadingUnn1"), text)

    def para(self, text):
        style = "NoindentNormal" if getattr(self, "_first", False) else "Normal"
        self._first = False
        return self._runs(self._new_p(style), text)

    def bullets(self, items):
        for it in items:
            self._runs(self._new_p("Listbul"), it)
        self._first = True

    def numbered(self, items):
        for i, it in enumerate(items, 1):
            p = self._new_p("NoindentNormal")
            p.paragraph_format.left_indent = Cm(0.6)
            p.paragraph_format.first_line_indent = Cm(-0.6)
            self._runs(p, f"({i}) " + it)
        self._first = True

    # ------------------------------------------------------------- figures & tables
    def figure(self, path: Path, caption: str, width_cm: float = 11.5):
        self.fig_n += 1
        p = self._new_p("NoindentNormal")
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.keep_with_next = True
        p.add_run().add_picture(str(path), width=Cm(width_cm))
        c = self._new_p("CaptionShort")
        r = c.add_run(f"Figure {self.fig_n}.")
        r.bold = True
        self._runs(c, " " + caption)
        self._first = False
        return self.fig_n

    def table(self, header: list[str], rows: list[list[str]], caption: str, widths: list[int] | None = None,
              align: list[str] | None = None, font_pt: float = 8):
        self.tab_n += 1
        c = self._new_p("CaptionLong")
        c.paragraph_format.keep_with_next = True
        r = c.add_run(f"Table {self.tab_n}.")
        r.bold = True
        self._runs(c, " " + caption)
        n = len(header)
        widths = widths or [TEXT_WIDTH_TWIPS // n] * n
        scale = TEXT_WIDTH_TWIPS / sum(widths)
        widths = [int(w * scale) for w in widths]
        align = align or (["left"] + ["center"] * (n - 1))
        tbl = OxmlElement("w:tbl")
        tpr = OxmlElement("w:tblPr")
        tw = OxmlElement("w:tblW")
        tw.set(qn("w:w"), str(sum(widths)))
        tw.set(qn("w:type"), "dxa")
        jc = OxmlElement("w:jc")
        jc.set(qn("w:val"), "center")
        lay = OxmlElement("w:tblLayout")
        lay.set(qn("w:type"), "fixed")
        cm = OxmlElement("w:tblCellMar")
        for side in ("left", "right"):
            e = OxmlElement(f"w:{side}")
            e.set(qn("w:w"), "57")
            e.set(qn("w:type"), "dxa")
            cm.append(e)
        tpr.extend([tw, jc, lay, cm])
        grid = OxmlElement("w:tblGrid")
        for w in widths:
            g = OxmlElement("w:gridCol")
            g.set(qn("w:w"), str(w))
            grid.append(g)
        tbl.extend([tpr, grid])
        allrows = [header] + rows
        for i, row in enumerate(allrows):
            tr = OxmlElement("w:tr")
            trpr = OxmlElement("w:trPr")
            cs = OxmlElement("w:cantSplit")
            trpr.append(cs)
            if i == 0:
                trpr.append(OxmlElement("w:tblHeader"))
            tr.append(trpr)
            for j, cell in enumerate(row):
                tc = OxmlElement("w:tc")
                tcpr = OxmlElement("w:tcPr")
                w = OxmlElement("w:tcW")
                w.set(qn("w:w"), str(widths[j]))
                w.set(qn("w:type"), "dxa")
                tcpr.append(w)
                b = OxmlElement("w:tcBorders")
                edges = []
                if i == 0:
                    edges = ["top", "bottom"]
                if i == len(allrows) - 1:
                    edges.append("bottom")
                for e in edges:
                    el = OxmlElement(f"w:{e}")
                    el.set(qn("w:val"), "single")
                    el.set(qn("w:sz"), "4")
                    el.set(qn("w:space"), "0")
                    el.set(qn("w:color"), "auto")
                    b.append(el)
                tcpr.append(b)
                tc.append(tcpr)
                p = OxmlElement("w:p")
                ppr = OxmlElement("w:pPr")
                ind = OxmlElement("w:ind")
                ind.set(qn("w:firstLine"), "0")
                sp = OxmlElement("w:spacing")
                sp.set(qn("w:before"), "10")
                sp.set(qn("w:after"), "10")
                jcp = OxmlElement("w:jc")
                jcp.set(qn("w:val"), "center" if align[j] == "center" else ("right" if align[j] == "right" else "left"))
                ppr.extend([sp, ind, jcp])
                p.append(ppr)
                tc.append(p)
                tr.append(tc)
                from docx.text.paragraph import Paragraph
                para = Paragraph(p, self.doc._body)
                txt = str(cell)
                if i == 0:
                    txt = f"**{txt}**" if not txt.startswith("**") else txt
                self._runs(para, txt, size=font_pt)
            tbl.append(tr)
        self.sect.addprevious(tbl)
        spacer = self._new_p("NoindentNormal")
        spacer.paragraph_format.space_after = Pt(2)
        self._first = False
        return self.tab_n

    # ------------------------------------------------------------- equations (OMML)
    def equation(self, parts) -> int:
        """parts: list of OMML elements built with the m_* helpers."""
        self.eq_n += 1
        p = self._new_p("Equation")
        om = _m("oMath")
        for el in parts:
            om.append(el)
        p._p.append(om)
        r = p.add_run(f"\t({self.eq_n})")
        self._first = True
        return self.eq_n

    def references(self, refs: list[str]):
        self.h_unnumbered("References")
        for ref in refs:
            p = self._new_p("References")
            p.paragraph_format.left_indent = Pt(357 / 20)
            p.paragraph_format.first_line_indent = Pt(-357 / 20)
            self._runs(p, ref)

    def save(self, path: Path):
        self.doc.save(str(path))


# ------------------------------------------------------------- OMML builders
def _m(tag):
    return OxmlElement(f"m:{tag}")


def mr(text: str, plain: bool = False):
    r = _m("r")
    if plain:
        rpr = _m("rPr")
        sty = _m("sty")
        sty.set(qn("m:val"), "p")
        rpr.append(sty)
        r.append(rpr)
    t = _m("t")
    t.text = text
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    r.append(t)
    return r


def _wrap(tag, items):
    e = _m(tag)
    for it in items if isinstance(items, list) else [items]:
        e.append(it)
    return e


def msub(base, sub):
    e = _m("sSub")
    e.append(_wrap("e", base))
    e.append(_wrap("sub", sub))
    return e


def msup(base, sup):
    e = _m("sSup")
    e.append(_wrap("e", base))
    e.append(_wrap("sup", sup))
    return e


def mfrac(num, den):
    e = _m("f")
    e.append(_wrap("num", num))
    e.append(_wrap("den", den))
    return e


def mnary(chr_: str, sub, sup, body):
    e = _m("nary")
    pr = _m("naryPr")
    c = _m("chr")
    c.set(qn("m:val"), chr_)
    pr.append(c)
    lim = _m("limLoc")
    lim.set(qn("m:val"), "undOvr")
    pr.append(lim)
    if not sup:
        h = _m("supHide")
        h.set(qn("m:val"), "1")
        pr.append(h)
    e.append(pr)
    e.append(_wrap("sub", sub or []))
    e.append(_wrap("sup", sup or []))
    e.append(_wrap("e", body))
    return e


def mtext(s: str):
    """Quick linear text: tokens like x_{i} handled by msub."""
    out = []
    for tok in re.split(r"(\w+_\{[^}]+\}|\w+_\w)", s):
        if not tok:
            continue
        m = re.fullmatch(r"(\w+)_\{([^}]+)\}|(\w+)_(\w)", tok)
        if m:
            base = m.group(1) or m.group(3)
            sub = m.group(2) or m.group(4)
            out.append(msub(mr(base), mr(sub)))
        else:
            out.append(mr(tok))
    return out
