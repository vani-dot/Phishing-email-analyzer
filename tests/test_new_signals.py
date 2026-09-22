"""Rules added after the eval50 review: each must fire on its attack and stay
quiet on the benign wording that shares its vocabulary."""

import pytest

import analyzer
import content_check as cc
import parser
import scoring


def raw(body, subject="Notice", frm="Support <help@example-sender.test>", extra=""):
    return (
        "Return-Path: <help@example-sender.test>\n"
        f"From: {frm}\nTo: user@company.test\nSubject: {subject}\n"
        "Date: Mon, 07 Sep 2026 10:00:00 +0000\n"
        f"{extra}Content-Type: text/plain; charset=utf-8\n\n{body}\n"
    )


def codes(text):
    return {s.code for s in analyzer.analyse(text, use_llm=False).signals}


# ---- parser keeps the headers the rules need -------------------------------

def test_parser_keeps_thread_and_list_headers():
    e = parser.parse_email(raw("hi", extra="In-Reply-To: <a@orig.test>\nReferences: <a@orig.test>\nList-Id: <l.test>\n"))
    assert "orig.test" in e.headers["in-reply-to"]
    assert "orig.test" in e.headers["references"]
    assert e.headers["list-id"]


def test_thread_hijack_detected_from_a_real_eml():
    text = raw("Please continue.", frm="Vendor <ap@lookalike-vendor.com>",
               extra="In-Reply-To: <inv1@real-vendor.com>\nReferences: <inv1@real-vendor.com>\n")
    assert "HDR_THREAD_DOMAIN_MISMATCH" in codes(text)


def test_same_domain_thread_is_not_a_hijack():
    text = raw("Please continue.", frm="Vendor <ap@real-vendor.com>",
               extra="In-Reply-To: <inv1@real-vendor.com>\n")
    assert "HDR_THREAD_DOMAIN_MISMATCH" not in codes(text)


# ---- phone numbers ---------------------------------------------------------

@pytest.mark.parametrize("number", [
    "+91 80 4471 2288", "+1 (800) 555-0199", "080-44712288",
    "1800 123 4567", "9876543210", "+44 20 7946 0958",
])
def test_phone_formats_recognised(number):
    assert cc.PHONE_NUMBER.search(f"call {number} now")


@pytest.mark.parametrize("not_phone", [
    "39104471288", "50100447128834", "NRT-88213409", "12,499", "card ending 4412",
])
def test_bank_and_order_numbers_are_not_phones(not_phone):
    assert not cc.PHONE_NUMBER.search(f"ref {not_phone} done")


def test_callback_phishing_with_indian_number():
    assert "CNT_CALLBACK_PHISH" in codes(raw(
        "Your plan renewed for INR 12,499. To cancel call our helpline +91 80 4471 2288 "
        "within 24 hours."))


# ---- seed phrase -----------------------------------------------------------

@pytest.mark.parametrize("text", [
    "You will be asked to enter your 24-word recovery phrase to continue.",
    "Please provide your seed phrase so we can verify ownership.",
    "Submit the twelve-word backup words to restore access.",
])
def test_seed_phrase_request_detected(text):
    assert "CNT_SEED_PHRASE_REQUEST" in codes(raw(text))


@pytest.mark.parametrize("text", [
    "Never share your seed phrase with anyone, including our staff.",
    "We will never ask you to enter your recovery phrase.",
    "Do not type your 24-word recovery phrase into any website.",
])
def test_seed_phrase_warning_is_not_a_request(text):
    assert "CNT_SEED_PHRASE_REQUEST" not in codes(raw(text))


def test_seed_phrase_request_is_a_theft_vector():
    r = analyzer.analyse(raw("Enter your 24-word recovery phrase to restore the wallet."), use_llm=False)
    assert "credential_request" in r.theft_vectors


# ---- MFA fatigue -----------------------------------------------------------

@pytest.mark.parametrize("text", [
    "If you get more than one prompt, please approve them all.",
    "Approve every notification we send to confirm your device.",
])
def test_mfa_approval_lure_detected(text):
    assert "CNT_MFA_APPROVAL_LURE" in codes(raw(text))


@pytest.mark.parametrize("text", [
    "If you did not request this, do not approve any prompts.",
    "Never approve a sign-in request you did not start.",
])
def test_mfa_warning_is_not_a_lure(text):
    assert "CNT_MFA_APPROVAL_LURE" not in codes(raw(text))


# ---- bank details in the body ---------------------------------------------

def test_bank_details_in_body_count_as_payment_instruction():
    body = ("Please send the payment to this account instead.\n"
            "Account number: 39104471288\nIFSC: UTIB0001234")
    r = analyzer.analyse(raw(body), use_llm=False)
    assert "CNT_PAYMENT_INSTRUCTION" in {s.code for s in r.signals}
    assert "payment_redirection" in r.theft_vectors


def test_ordinary_text_is_not_bank_details():
    assert "CNT_PAYMENT_INSTRUCTION" not in codes(raw("Thanks for the update, see you Monday."))
