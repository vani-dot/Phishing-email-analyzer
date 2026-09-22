"""Parsing: structure extraction, encodings, and hostile input."""

import pytest
from conftest import GENUINE_EML, PHISHING_EML

import parser
from config import config


def test_parses_standard_headers():
    email = parser.parse_email(PHISHING_EML)
    assert email.headers_present
    assert email.from_address == "service@paypa1-secure.tk"
    assert email.from_display == "PayPal Security"
    assert email.reply_to == "harvest@mail.ru"
    assert "spf=fail" in email.auth_results


def test_decodes_rfc2047_subject():
    raw = ("From: a@b.com\nTo: c@d.com\n"
           "Subject: =?utf-8?B?VXJnZW50OiBBY2NvdW50IFN1c3BlbmRlZA==?=\n"
           "Date: Mon, 1 Jan 2024 00:00:00 +0000\n\nbody")
    assert parser.parse_email(raw).subject == "Urgent: Account Suspended"


def test_malformed_encoded_header_does_not_raise():
    raw = "From: a@b.com\nTo: c@d.com\nSubject: =?utf-8?B?!!!not-base64!!!?=\nDate: x\n\nbody"
    email = parser.parse_email(raw)          # must not raise
    assert email.headers_present


def test_body_only_paste_is_flagged_not_assumed_clean():
    email = parser.parse_email("Just text with http://evil.tk/login in it")
    assert email.headers_present is False
    assert email.parse_notes, "a body-only paste must say so in the report"
    assert any("header" in note.lower() for note in email.parse_notes)
    assert len(email.links) == 1


def test_extracts_anchor_text_for_mismatch_detection():
    raw = ('From: a@b.com\nTo: c@d.com\nSubject: s\nContent-Type: text/html\n\n'
           '<a href="http://evil.tk/x">https://www.paypal.com</a>')
    email = parser.parse_email(raw)
    link = email.links[0]
    assert link.domain == "evil.tk"
    assert link.display_text == "https://www.paypal.com"


def test_registered_domain_ignores_subdomains():
    assert parser.domain_of("x@mail.corp.paypal.com") == "paypal.com"
    assert parser.domain_of("x@foo.co.uk") == "foo.co.uk"
    assert parser.domain_of("not-an-address") == ""


def test_null_bytes_are_stripped():
    email = parser.parse_email("From: a@b.com\nTo: c@d.com\nSubject: te\x00st\n\nbo\x00dy")
    assert "\x00" not in email.subject
    assert "\x00" not in email.body_text


def test_oversized_input_is_truncated_not_rejected():
    huge = "From: a@b.com\nTo: c@d.com\nSubject: s\n\n" + ("A" * (config.MAX_BODY_CHARS + 50_000))
    email = parser.parse_email(huge)
    assert len(email.body_text) <= config.MAX_BODY_CHARS
    assert any("truncat" in note.lower() for note in email.parse_notes)


def test_link_count_is_capped():
    links = "\n".join(f"http://example{i}.com/page" for i in range(config.MAX_URLS_SCANNED + 200))
    email = parser.parse_email(f"From: a@b.com\nTo: c@d.com\nSubject: s\n\n{links}")
    assert len(email.links) <= config.MAX_URLS_SCANNED


def test_attachment_is_hashed_and_typed_not_written():
    raw = (
        'From: a@b.com\nTo: c@d.com\nSubject: s\n'
        'Content-Type: multipart/mixed; boundary="X"\n\n'
        '--X\nContent-Type: text/plain\n\nbody\n'
        '--X\nContent-Type: application/octet-stream; name="a.pdf"\n'
        'Content-Transfer-Encoding: base64\n'
        'Content-Disposition: attachment; filename="a.pdf"\n\n'
        'TVqQAAMAAAAEAAAA//8AALgAAAAA\n'
        '--X--\n'
    )
    email = parser.parse_email(raw)
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.sha256 and len(att.sha256) == 64
    # MZ magic bytes: named .pdf, actually a Windows executable.
    assert att.detected_type and "executable" in att.detected_type.lower()


def test_path_traversal_in_filename_is_not_normalised_away():
    raw = (
        'From: a@b.com\nTo: c@d.com\nSubject: s\n'
        'Content-Type: multipart/mixed; boundary="X"\n\n'
        '--X\nContent-Type: application/octet-stream\n'
        'Content-Disposition: attachment; filename="../../etc/passwd"\n\nZGF0YQ==\n'
        '--X--\n'
    )
    email = parser.parse_email(raw)
    assert email.attachments, "attachment must still be reported"


@pytest.mark.parametrize("raw", [
    "", "   ", "\x00\x00", "From:", "Subject: only-a-subject",
    "From: a@b\nTo: c@d\nSubject: s\nContent-Type: multipart/mixed; boundary=X\n\n--X\n",
])
def test_pathological_inputs_never_raise(raw):
    parser.parse_email(raw)
