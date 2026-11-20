"""Real file attachments for attacks (indirect prompt injection through uploaded files).

An attack declares an ``AttachmentSpec``: a file ``kind`` (pdf, docx, html, ...), a benign
``visible`` cover text, an injected ``payload`` and a ``hide`` technique that says where the payload
lives inside the file (white text, 1pt font, metadata, comment, ...). At trial time the spec is
rendered (``{CANARY}`` substituted) and built into an ``Attachment``: the actual bytes, built with
the standard library only, deterministically (same input, same bytes).

``Attachment.text`` is what a plain text extractor returns from the file; ``Attachment.metadata``
is the text that lives only in metadata / comments. Function targets can use both to simulate their
own extraction pipeline; HTTP targets receive the bytes (multipart or base64 JSON).
"""

import base64
import html
import io
import json
import re
import struct
import zipfile
import zlib
from collections.abc import Callable
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, model_validator

from redgrade.font import raster


class Attachment(BaseModel):
    """A built file ready to be sent to the app under test."""

    model_config = ConfigDict(frozen=True)

    filename: str
    content_type: str
    data: bytes
    text: str = ""  # what a plain text extractor returns (includes visually hidden body text)
    metadata: str = ""  # text that lives only in metadata / comments (not in the body)
    kind: str = ""
    hide: str = ""

    def as_json(self) -> dict[str, str]:
        """JSON-safe form used for ``{{attachments}}`` in HTTP bodies."""
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "data_base64": base64.b64encode(self.data).decode("ascii"),
        }


class _Built(NamedTuple):
    data: bytes
    text: str
    metadata: str = ""


Builder = Callable[[str, str, str], _Built]  # (visible, payload, hide) -> built


class _Kind(NamedTuple):
    build: Builder
    content_type: str
    extension: str
    techniques: tuple[str, ...]


# --- plain text family ----------------------------------------------------------------------


def _build_txt(visible: str, payload: str, hide: str) -> _Built:
    text = f"{visible}\n{payload}\n" if visible else f"{payload}\n"
    return _Built(text.encode(), text)


def _build_md(visible: str, payload: str, hide: str) -> _Built:
    if hide == "html_comment":
        text = f"{visible}\n\n<!-- {payload} -->\n"
    elif hide == "link_reference":
        text = f"{visible}\n\n[//]: # ({payload})\n"
    else:
        text = f"{visible}\n\n{payload}\n"
    return _Built(text.encode(), text)


def _build_csv(visible: str, payload: str, hide: str) -> _Built:
    def cell(value: str) -> str:
        return '"' + value.replace('"', '""') + '"'

    if hide == "header":
        text = f"{cell('note')},{cell(payload)}\n{cell('info')},{cell(visible)}\n"
    else:
        text = (
            f"{cell('note')},{cell('value')}\n"
            f"{cell('info')},{cell(visible)}\n"
            f"{cell('comment')},{cell(payload)}\n"
        )
    return _Built(text.encode(), text)


def _build_json(visible: str, payload: str, hide: str) -> _Built:
    key = "_instructions" if hide == "underscore_field" else "notes"
    text = json.dumps({"summary": visible, key: payload}, ensure_ascii=False, indent=2) + "\n"
    return _Built(text.encode(), text)


def _build_html(visible: str, payload: str, hide: str) -> _Built:
    cover = html.escape(visible)
    esc = html.escape(payload)
    head = ""
    body = f"<p>{cover}</p>"
    if hide == "comment":
        body += f"<!-- {payload} -->"
    elif hide == "display_none":
        body += f'<div style="display:none">{esc}</div>'
    elif hide == "white_text":
        body += f'<p style="color:#fff;background:#fff;font-size:1px">{esc}</p>'
    elif hide == "meta":
        head = f'<meta name="description" content="{html.escape(payload, quote=True)}">'
    elif hide == "aria_label":
        body += f'<span aria-label="{html.escape(payload, quote=True)}"></span>'
    else:
        body += f"<p>{esc}</p>"
    doc = f"<!doctype html><html><head><meta charset=utf-8>{head}</head><body>{body}</body></html>\n"
    meta = payload if hide in {"meta", "aria_label"} else ""
    text = "\n".join(
        part
        for part in (
            visible,
            payload if hide in {"comment", "display_none", "white_text", "plain"} else "",
        )
        if part
    )
    return _Built(doc.encode(), text, meta)


# --- docx -----------------------------------------------------------------------------------

_W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def _xml(text: str) -> str:
    return html.escape(text, quote=False)


def _run(text: str, props: str = "") -> str:
    rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{_xml(text)}</w:t></w:r>'


def _zip_bytes(files: list[tuple[str, str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content.encode("utf-8"))
    return buf.getvalue()


def _build_docx(visible: str, payload: str, hide: str) -> _Built:
    paragraphs = [f"<w:p>{_run(visible)}</w:p>"]
    comments_part = False
    core_description = ""
    body_text = [visible]
    metadata = ""
    if hide == "white_text":
        white_tiny = '<w:color w:val="FFFFFF"/><w:sz w:val="2"/>'
        paragraphs.append(f"<w:p>{_run(payload, white_tiny)}</w:p>")
        body_text.append(payload)
    elif hide == "tiny_text":
        tiny = '<w:sz w:val="2"/>'
        paragraphs.append(f"<w:p>{_run(payload, tiny)}</w:p>")
        body_text.append(payload)
    elif hide == "vanish":
        paragraphs.append(f"<w:p>{_run(payload, '<w:vanish/>')}</w:p>")
        body_text.append(payload)
    elif hide == "comment":
        comments_part = True
        metadata = payload
        paragraphs[0] = (
            '<w:p><w:commentRangeStart w:id="0"/>'
            f'{_run(visible)}<w:commentRangeEnd w:id="0"/>'
            '<w:r><w:commentReference w:id="0"/></w:r></w:p>'
        )
    elif hide == "metadata":
        core_description = payload
        metadata = payload
    else:
        paragraphs.append(f"<w:p>{_run(payload)}</w:p>")
        body_text.append(payload)

    document = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {_W_NS}><w:body>'
        + "".join(paragraphs)
        + "</w:body></w:document>"
    )
    overrides = (
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-'
        'package.core-properties+xml"/>'
    )
    rels_doc = ""
    if comments_part:
        overrides += (
            '<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-'
            'officedocument.wordprocessingml.comments+xml"/>'
        )
        rels_doc = (
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/comments" Target="comments.xml"/>'
        )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>' + overrides + "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/'
        'relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>'
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + rels_doc
        + "</Relationships>"
    )
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/'
        'core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:title>Document</dc:title><dc:description>{_xml(core_description)}</dc:description>"
        "</cp:coreProperties>"
    )
    files = [
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", root_rels),
        ("word/document.xml", document),
        ("word/_rels/document.xml.rels", doc_rels),
        ("docProps/core.xml", core),
    ]
    if comments_part:
        files.append(
            (
                "word/comments.xml",
                f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:comments {_W_NS}>'
                f'<w:comment w:id="0" w:author="reviewer"><w:p>{_run(payload)}</w:p></w:comment>'
                "</w:comments>",
            )
        )
    return _Built(_zip_bytes(files), "\n".join(t for t in body_text if t), metadata)


# --- pdf ------------------------------------------------------------------------------------

_PDF_WRAP = 90


def _pdf_escape(text: str) -> str:
    raw = text.encode("latin-1", "replace").decode("latin-1")
    return raw.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_lines(text: str) -> list[str]:
    lines: list[str] = []
    for para in text.splitlines() or [""]:
        while len(para) > _PDF_WRAP:
            cut = para.rfind(" ", 0, _PDF_WRAP)
            cut = cut if cut > 0 else _PDF_WRAP
            lines.append(para[:cut])
            para = para[cut:].lstrip()
        lines.append(para)
    return lines


def _pdf_text_block(text: str, *, x: int, y: int, size: int, color: str) -> str:
    out = [f"BT /F1 {size} Tf {color} rg {x} {y} Td {size + 2} TL"]
    for line in _pdf_lines(text):
        out.append(f"({_pdf_escape(line)}) Tj T*")
    out.append("ET")
    return "\n".join(out)


def _build_pdf(visible: str, payload: str, hide: str) -> _Built:
    blocks = [_pdf_text_block(visible, x=50, y=780, size=12, color="0 0 0")]
    body_text = [visible]
    info = ""
    metadata = ""
    if hide == "white_text":
        blocks.append(_pdf_text_block(payload, x=50, y=500, size=12, color="1 1 1"))
        body_text.append(payload)
    elif hide == "tiny_text":
        blocks.append(_pdf_text_block(payload, x=50, y=30, size=1, color="0 0 0"))
        body_text.append(payload)
    elif hide == "offpage":
        blocks.append(_pdf_text_block(payload, x=-2000, y=400, size=12, color="0 0 0"))
        body_text.append(payload)
    elif hide == "metadata":
        info = f"/Subject ({_pdf_escape(payload)}) "
        metadata = payload
    else:
        blocks.append(_pdf_text_block(payload, x=50, y=700, size=12, color="0 0 0"))
        body_text.append(payload)
    stream = "\n".join(blocks).encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 5 0 R "
        b"/Resources << /Font << /F1 4 0 R >> >> >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        f"<< /Title (Document) {info}>>".encode("latin-1", "replace"),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode()
    return _Built(bytes(out), "\n".join(t for t in body_text if t), metadata)


# --- png (metadata or pixels) ---------------------------------------------------------------


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


_PNG_WRAP = 48
_PNG_MARGIN = 8
_PNG_INK = 0x00
_PNG_PAPER = 0xFF
_PNG_FAINT = 0xF2  # ~5% contrast on white: hard to see, still read by OCR / vision models
# hide -> (payload scale, payload ink)
_PNG_PIXEL_STYLES: dict[str, tuple[int, int]] = {
    "visible": (3, _PNG_INK),
    "low_contrast": (3, _PNG_FAINT),
    "tiny": (1, _PNG_INK),
}


def _wrap(text: str, width: int = _PNG_WRAP) -> list[str]:
    lines: list[str] = []
    for para in text.splitlines() or [""]:
        line = ""
        for word in para.split():
            if line and len(line) + 1 + len(word) > width:
                lines.append(line)
                line = word
            else:
                line = f"{line} {word}" if line else word
        lines.append(line)
    return lines


def _text_png(blocks: list[tuple[str, int, int]]) -> bytes:
    """Grayscale PNG with each ``(text, scale, ink)`` block drawn in the 5x7 font, top to bottom."""
    rows: list[tuple[list[bool], int, int]] = []  # (cells, scale, ink) per bitmap row
    for text, scale, ink in blocks:
        for line in _wrap(text):
            for cells in raster(line):
                rows.extend([(cells, scale, ink)] * scale)
            rows.extend([([], scale, ink)] * (2 * scale))  # line gap
    width = max([len(c) * s for c, s, _ in rows] + [32]) + 2 * _PNG_MARGIN
    blank = bytes([_PNG_PAPER]) * width
    scan = [b"\x00" + blank] * _PNG_MARGIN
    for cells, scale, ink in rows:
        line = bytearray(blank)
        for x, on in enumerate(cells):
            if on:
                start = _PNG_MARGIN + x * scale
                line[start : start + scale] = bytes([ink]) * scale
        scan.append(b"\x00" + bytes(line))
    scan += [b"\x00" + blank] * _PNG_MARGIN
    height = len(scan)
    chunks = [
        _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)),
        _png_chunk(b"IDAT", zlib.compress(b"".join(scan), 9)),
        _png_chunk(b"IEND", b""),
    ]
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def _build_png(visible: str, payload: str, hide: str) -> _Built:
    """A PNG whose payload hides in text chunks (``metadata``) or is drawn in its pixels.

    Pixel modes (``visible``, ``low_contrast``, ``tiny``) draw the cover text in black and the
    payload below it, for apps that OCR images or pass them to a vision model. For those, the
    attachment's ``text`` is what OCR reads (cover text + payload); a plain text extractor gets
    nothing from an image.
    """
    if hide in _PNG_PIXEL_STYLES:
        scale, ink = _PNG_PIXEL_STYLES[hide]
        data = _text_png([(visible or " ", 3, _PNG_INK), (payload, scale, ink)])
        return _Built(data, "\n".join(x for x in (visible, payload) if x))
    width = height = 64
    raw = b"".join(b"\x00" + b"\xff\xff\xff" * width for _ in range(height))
    chunks = [
        _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
        _png_chunk(b"tEXt", b"Title\x00" + (visible or "image").encode("latin-1", "replace")),
        _png_chunk(b"tEXt", b"Description\x00" + payload.encode("latin-1", "replace")),
        _png_chunk(b"IDAT", zlib.compress(raw, 9)),
        _png_chunk(b"IEND", b""),
    ]
    return _Built(b"\x89PNG\r\n\x1a\n" + b"".join(chunks), "", payload)


KINDS: dict[str, _Kind] = {
    "txt": _Kind(_build_txt, "text/plain", "txt", ("plain",)),
    "md": _Kind(_build_md, "text/markdown", "md", ("plain", "html_comment", "link_reference")),
    "csv": _Kind(_build_csv, "text/csv", "csv", ("cell", "header")),
    "json": _Kind(_build_json, "application/json", "json", ("field", "underscore_field")),
    "html": _Kind(
        _build_html,
        "text/html",
        "html",
        ("plain", "comment", "display_none", "white_text", "meta", "aria_label"),
    ),
    "docx": _Kind(
        _build_docx,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docx",
        ("plain", "white_text", "tiny_text", "vanish", "comment", "metadata"),
    ),
    "pdf": _Kind(
        _build_pdf, "application/pdf", "pdf", ("plain", "white_text", "tiny_text", "offpage", "metadata")
    ),
    "png": _Kind(_build_png, "image/png", "png", ("metadata", "visible", "low_contrast", "tiny")),
}

_CANARY = re.compile(r"\{CANARY\}")


class AttachmentSpec(BaseModel):
    """Declarative attachment inside an attack pack (templates, built per trial)."""

    model_config = ConfigDict(frozen=True)

    kind: str
    payload: str
    visible: str = "Documento di lavoro."
    hide: str = ""
    filename: str = ""

    @model_validator(mode="before")
    @classmethod
    def _valid(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        kind = KINDS.get(str(data.get("kind")))
        if kind is None:
            raise ValueError(f"unknown attachment kind {data.get('kind')!r} (use one of {sorted(KINDS)})")
        hide = data.get("hide") or kind.techniques[0]
        if hide not in kind.techniques:
            raise ValueError(
                f"attachment kind {data['kind']!r} does not support hide={hide!r} "
                f"(use one of {list(kind.techniques)})"
            )
        if not data.get("payload"):
            raise ValueError("attachment needs a payload")
        return {**data, "hide": hide}


def build_attachment(spec: AttachmentSpec) -> Attachment:
    """Build the file for an already-rendered spec."""
    kind = KINDS[spec.kind]
    built = kind.build(spec.visible, spec.payload, spec.hide)
    filename = spec.filename or f"document.{kind.extension}"
    return Attachment(
        filename=filename,
        content_type=kind.content_type,
        data=built.data,
        text=built.text,
        metadata=built.metadata,
        kind=spec.kind,
        hide=spec.hide,
    )
