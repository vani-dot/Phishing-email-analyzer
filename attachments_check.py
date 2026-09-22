# attachments_check.py
# Signals derived from attached files.
#
# Reasoning model: an attachment is the attacker's second delivery option, and
# a more committed one — the payload travels inside the message instead of
# waiting on a server. Because mail gateways have blocked bare executables for
# two decades, almost everything here is about DISGUISE: making a file that
# runs look like a file that opens.
#
# Nothing in this module writes, extracts or executes anything. Files are
# identified by their first bytes and hashed. A hash is the useful artefact
# anyway — it is what gets looked up in VirusTotal or a threat feed later,
# without ever handling the sample.

import re
from typing import List

import intel
from models import Category, ParsedEmail, Severity, Signal

# Filename shapes that are deception by construction.
DOUBLE_EXT = re.compile(
    r"(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|mp4|csv|zip)"
    r"\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|jar|msi|hta|lnk|ps1)$"
)
BIDI_CHARS = "‪‫‬‭‮⁦⁧⁨⁩"


def _sig(code, title, severity, detail, evidence=None) -> Signal:
    return Signal(code=code, title=title, category=Category.ATTACHMENT,
                  severity=severity, detail=detail, evidence=evidence)


def analyse_attachments(email: ParsedEmail) -> List[Signal]:
    signals: List[Signal] = []
    attachments = email.attachments
    if not attachments:
        return signals

    for att in attachments:
        name = att.filename or "(unnamed)"
        ext = att.declared_ext
        detected = att.detected_type or ""

        # ---- 1. it simply executes --------------------------------------
        if ext in intel.DANGEROUS_EXTENSIONS:
            signals.append(_sig(
                "ATT_EXECUTABLE", f"Executable attachment ({ext})", Severity.CRITICAL,
                f"'{name}' carries the extension {ext}, which runs code on open rather than "
                f"displaying a document. No routine business correspondence delivers an "
                f"executable by mail.",
                evidence=f"{name}  ({att.size:,} bytes, sha256 {att.sha256[:16]}...)",
            ))

        # ---- 2. it is disguised -----------------------------------------
        if DOUBLE_EXT.search(name):
            signals.append(_sig(
                "ATT_DOUBLE_EXTENSION", "Attachment uses a double extension",
                Severity.CRITICAL,
                f"'{name}' ends in two extensions. Windows hides known extensions by "
                f"default, so the recipient sees only the harmless first one while the "
                f"second decides what actually runs. This is disguise, not a naming quirk.",
                evidence=name,
            ))

        if any(ch in name for ch in BIDI_CHARS):
            signals.append(_sig(
                "ATT_RLO_FILENAME", "Filename contains a direction override",
                Severity.CRITICAL,
                f"'{name}' embeds a right-to-left override character, which reverses how the "
                f"rest of the name displays. It is used to show 'invoice.pdf' for a file "
                f"that is really an executable, and has no legitimate use in a filename.",
                evidence=repr(name)[:200],
            ))

        # ---- 3. the name and the content disagree -----------------------
        # The strongest attachment check: the extension is the attacker's
        # claim, the magic bytes are the fact.
        if detected and ext:
            claim_map = {
                "PDF document": {".pdf"},
                "PE executable (.exe/.dll)": {".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".msi"},
                "ELF executable": {".so", ".bin", ".elf", ""},
                "ZIP archive (also .docx/.xlsx/.jar/.apk)": {
                    ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods",
                    ".docm", ".xlsm", ".pptm", ".epub", ".xpi", ".war",
                },
                "OLE2 / legacy Office document": {".doc", ".xls", ".ppt", ".msg", ".vsd", ".db"},
                "RAR archive": {".rar"}, "7-Zip archive": {".7z"}, "GZIP archive": {".gz", ".tgz"},
                "JPEG image": {".jpg", ".jpeg"}, "PNG image": {".png"}, "GIF image": {".gif"},
                "RTF document": {".rtf", ".doc"}, "HTML document": {".html", ".htm"},
            }
            allowed = claim_map.get(detected)
            if allowed is not None and ext not in allowed:
                severity = (Severity.CRITICAL if "executable" in detected.lower()
                            else Severity.HIGH)
                signals.append(_sig(
                    "ATT_TYPE_MISMATCH", "File content does not match its extension",
                    severity,
                    f"'{name}' is named {ext} but its first bytes identify it as "
                    f"{detected}. The extension is what the sender claims; the file header "
                    f"is what the file is. A mismatch this specific is deliberate.",
                    evidence=f"{name}: declared {ext}, actually {detected}",
                ))

        if "executable" in detected.lower() and ext not in intel.DANGEROUS_EXTENSIONS:
            signals.append(_sig(
                "ATT_HIDDEN_EXECUTABLE", "Attachment is an executable under a benign name",
                Severity.CRITICAL,
                f"'{name}' does not look dangerous, but its header identifies it as "
                f"{detected}. Whatever the recipient believes they are opening, this file "
                f"runs code.",
                evidence=f"{name}  ({detected})",
            ))

        # ---- 4. macro-bearing documents ---------------------------------
        if ext in intel.MACRO_EXTENSIONS:
            signals.append(_sig(
                "ATT_MACRO_DOCUMENT", f"Macro-enabled document ({ext})", Severity.HIGH,
                f"'{name}' is a macro-enabled Office format. These carry embedded code, and "
                f"the accompanying 'Enable Content' instruction is one of the most durable "
                f"malware delivery techniques in use.",
                evidence=name,
            ))
        elif ext in intel.LEGACY_OFFICE:
            signals.append(_sig(
                "ATT_LEGACY_OFFICE", f"Legacy Office format ({ext})", Severity.MEDIUM,
                f"'{name}' uses the pre-2007 Office format, which can contain macros without "
                f"declaring it in the extension. Modern senders have little reason to use it; "
                f"attackers prefer it precisely because it is ambiguous.",
                evidence=name,
            ))

        # ---- 5. containers ----------------------------------------------
        if ext in (".iso", ".img", ".vhd", ".vhdx"):
            signals.append(_sig(
                "ATT_DISK_IMAGE", f"Disk image attachment ({ext})", Severity.CRITICAL,
                f"'{name}' is a disk image. When mounted, files inside lose the "
                f"mark-of-the-web that normally triggers a security warning — this format is "
                f"chosen specifically to strip that protection from the payload.",
                evidence=name,
            ))
        elif ext in intel.ARCHIVE_EXTENSIONS:
            signals.append(_sig(
                "ATT_ARCHIVE", f"Archive attachment ({ext})", Severity.MEDIUM,
                f"'{name}' is a compressed archive. Contents cannot be inspected by this "
                f"analyser and are frequently password-protected — with the password in the "
                f"message body — specifically so that gateway scanners cannot read them.",
                evidence=name,
            ))

        if ext in (".html", ".htm", ".shtml", ".svg"):
            signals.append(_sig(
                "ATT_HTML_ATTACHMENT", f"HTML attachment ({ext})", Severity.HIGH,
                f"'{name}' is a web page delivered as a file. Opening it renders a login "
                f"form from the local disk, so there is no malicious URL for a filter or "
                f"proxy to block — the phishing page arrives inside the mail.",
                evidence=name,
            ))

        if ext == ".lnk":
            signals.append(_sig(
                "ATT_SHORTCUT", "Windows shortcut attachment (.lnk)", Severity.CRITICAL,
                f"'{name}' is a shortcut file. It displays whatever icon it likes and runs an "
                f"arbitrary command line on double-click — a favoured replacement for macros "
                f"since Office began blocking them by default.",
                evidence=name,
            ))

        # ---- 6. size tells ----------------------------------------------
        if att.size and att.size < 1500 and ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx"):
            signals.append(_sig(
                "ATT_STUB_DOCUMENT", "Document is suspiciously small", Severity.MEDIUM,
                f"'{name}' is only {att.size:,} bytes. A real invoice or statement is larger; "
                f"a file this size is usually a stub whose only content is a link or a "
                f"remote-template reference that pulls the real payload on open.",
                evidence=f"{name} ({att.size:,} bytes)",
            ))

    # ---- 7. message-level -----------------------------------------------
    if len(attachments) >= 6:
        signals.append(_sig(
            "ATT_MANY_FILES", f"{len(attachments)} attachments", Severity.LOW,
            f"The message carries {len(attachments)} files. Bulk attachment is sometimes used "
            f"to bury one malicious file among harmless ones.",
            evidence=", ".join(a.filename for a in attachments[:6]),
        ))

    return signals
