"""Content parsing and sanitization: email is untrusted input."""

from __future__ import annotations

import base64

import pytest

from gmail_mcp_gateway.gmail.parse import (
    decode_base64url,
    decode_mime_header,
    extract_body,
    html_to_text,
    parse_addresses,
    parse_message,
    parse_timestamp,
    sanitize_filename,
    sanitize_text,
)

from .conftest import make_message


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #


def test_script_content_is_dropped_not_escaped():
    text = html_to_text("<p>Hello</p><script>alert('xss');fetch('/steal')</script><p>Bye</p>")
    assert "Hello" in text and "Bye" in text
    assert "alert" not in text
    assert "fetch" not in text
    assert "<" not in text and ">" not in text


def test_style_and_head_are_dropped():
    text = html_to_text("<head><style>body{display:none}</style></head><body>Visible</body>")
    assert text.strip() == "Visible"
    assert "display" not in text


def test_unterminated_script_does_not_leak_source():
    text = html_to_text("<p>Before</p><script>secret_payload_marker")
    assert "Before" in text
    assert "secret_payload_marker" not in text


def test_nested_droppable_elements_are_removed():
    text = html_to_text("<div><noscript><iframe src=x><script>bad()</script></iframe></noscript>ok</div>")
    assert "bad()" not in text
    assert "ok" in text


def test_output_is_never_markup():
    text = html_to_text('<a href="javascript:alert(1)" onclick="steal()">click</a>')
    assert "javascript:" not in text
    assert "onclick" not in text
    assert text.strip() == "click"


def test_block_elements_become_line_breaks():
    text = html_to_text("<p>one</p><p>two</p><br>three")
    assert text.splitlines()[0].strip() == "one"
    assert "two" in text and "three" in text


def test_entities_are_decoded_after_tags_are_stripped():
    # &lt;script&gt; must decode to visible text, not to a live tag.
    text = html_to_text("<p>5 &lt; 6 &amp;&amp; 7 &gt; 6</p>")
    assert text == "5 < 6 && 7 > 6"


# --------------------------------------------------------------------------- #
# Invisible characters
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "hidden",
    [
        "​",  # zero-width space
        "‎",  # left-to-right mark
        "‮",  # right-to-left override
        "⁦",  # left-to-right isolate
        "﻿",  # BOM
        "\U000e0041",  # tag character
    ],
)
def test_invisible_characters_are_stripped_and_counted(hidden):
    result = sanitize_text(f"Pay{hidden} Bob")
    assert hidden not in result.text
    assert result.removed_characters >= 1


def test_control_characters_are_removed_but_newlines_survive():
    result = sanitize_text("line one\nline two\x07\x00\ttabbed")
    assert "\x07" not in result.text and "\x00" not in result.text
    assert "\n" in result.text and "\t" in result.text


def test_carriage_returns_are_normalised():
    assert sanitize_text("a\r\nb\rc").text == "a\nb\nc"


# --------------------------------------------------------------------------- #
# Headers and addresses
# --------------------------------------------------------------------------- #


def test_encoded_words_are_decoded():
    assert decode_mime_header("=?utf-8?B?SGVsbG8gV29ybGQ=?=") == "Hello World"


def test_header_decoding_never_yields_a_line_break():
    # A folded/encoded header must not produce something that looks like a new header.
    assert "\n" not in decode_mime_header("=?utf-8?B?QQpCY2M6IGV2aWxAZXhhbXBsZS5jb20=?=")


def test_addresses_are_split_into_name_and_email():
    parsed = parse_addresses('"Smith, Alice" <alice@example.com>, bob@example.com')
    assert parsed[0]["email"] == "alice@example.com"
    assert "Alice" in parsed[0]["name"]
    assert parsed[1]["email"] == "bob@example.com"


def test_malformed_address_header_does_not_raise():
    assert isinstance(parse_addresses("<<<>>> not an address"), list)


def test_internal_date_wins_over_the_date_header():
    stamp = parse_timestamp({"date": "Tue, 12 Aug 2025 10:04:00 +0000"}, "1755000240000")
    assert stamp["source"] == "internal_date"
    assert stamp["epoch_ms"] == 1755000240000


def test_date_header_is_the_fallback():
    stamp = parse_timestamp({"date": "Tue, 12 Aug 2025 10:04:00 +0000"}, None)
    assert stamp["source"] == "date_header"
    assert stamp["iso"].startswith("2025-08-12")


def test_unparseable_timestamps_degrade_to_null():
    stamp = parse_timestamp({"date": "not a date"}, "not-a-number")
    assert stamp["iso"] is None


# --------------------------------------------------------------------------- #
# Filenames
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "forbidden"),
    [
        ("../../../etc/passwd", ".."),
        ("/etc/shadow", "/"),
        ("..\\..\\windows\\system32\\cmd.exe", "\\"),
        ("report.pdf\x00.exe", "\x00"),
        ("a/b/c.txt", "/"),
    ],
)
def test_filenames_cannot_carry_a_path(raw, forbidden):
    cleaned = sanitize_filename(raw)
    assert forbidden not in cleaned
    assert not cleaned.startswith(".")


def test_reserved_windows_names_are_defused():
    assert sanitize_filename("CON.txt").lower().startswith("file_")


def test_empty_filename_falls_back():
    assert sanitize_filename("") == "attachment"
    assert sanitize_filename("...") == "attachment"


def test_filename_length_is_bounded():
    assert len(sanitize_filename("x" * 500 + ".pdf")) <= 128


# --------------------------------------------------------------------------- #
# Bodies and messages
# --------------------------------------------------------------------------- #


def test_plain_text_is_preferred_over_html():
    message = make_message(body_text="plain version", body_html="<p>html version</p>")
    body = extract_body(message["payload"], max_chars=1000)
    assert body["text"] == "plain version"
    assert body["source"] == "text/plain"


def test_html_only_message_is_converted():
    payload = {
        "mimeType": "text/html",
        "filename": "",
        "headers": [{"name": "Content-Type", "value": "text/html; charset=UTF-8"}],
        "body": {"data": _b64("<p>Hi <b>there</b></p><script>bad()</script>")},
    }
    body = extract_body(payload, max_chars=1000)
    assert "Hi there" in body["text"]
    assert "bad()" not in body["text"]
    assert "converted" in body["source"]


def test_body_is_truncated_with_a_flag():
    message = make_message(body_text="x" * 5000)
    body = extract_body(message["payload"], max_chars=100)
    assert len(body["text"]) == 100
    assert body["truncated"] is True
    assert body["total_characters"] == 5000


def test_message_view_reports_state_and_metadata():
    message = make_message(
        subject="Invoice 42",
        cc="carol@example.com",
        labels=["INBOX", "UNREAD", "STARRED", "Label_7"],
        attachments=[{"filename": "invoice.pdf", "attachment_id": "att0", "size": 900}],
    )
    view = parse_message(message, max_body_chars=1000, label_names={"Label_7": "Receipts"})

    assert view["subject"] == "Invoice 42"
    assert view["from"]["email"] == "alice@example.com"
    assert view["cc"][0]["email"] == "carol@example.com"
    assert view["is_unread"] is True
    assert view["is_starred"] is True
    assert view["in_inbox"] is True
    assert "Receipts" in view["labels"]["names"]
    assert view["has_attachments"] is True
    assert view["attachments"][0]["filename"] == "invoice.pdf"
    assert view["content_is_untrusted"] is True


def test_attachment_inventory_never_includes_content():
    message = make_message(
        attachments=[{"filename": "secret.pdf", "attachment_id": "att0", "size": 10}]
    )
    view = parse_message(message, max_body_chars=0, include_body=False)
    entry = view["attachments"][0]
    assert "data" not in entry and "content" not in entry
    assert entry["size_bytes"] == 10


def test_attachment_with_a_traversal_filename_is_sanitized_in_the_view():
    message = make_message(
        attachments=[{"filename": "../../../etc/passwd", "attachment_id": "att0"}]
    )
    view = parse_message(message, max_body_chars=0, include_body=False)
    assert ".." not in view["attachments"][0]["filename"]
    assert view["attachments"][0]["original_filename_differs"] is True


def test_base64url_decoding_handles_missing_padding():
    assert decode_base64url(_b64("abcde")) == b"abcde"


def test_deeply_nested_payload_terminates():
    payload: dict = {"mimeType": "multipart/mixed", "body": {}, "headers": []}
    node = payload
    for _ in range(60):
        child: dict = {"mimeType": "multipart/mixed", "body": {}, "headers": []}
        node["parts"] = [child]
        node = child
    node["mimeType"] = "text/plain"
    node["body"] = {"data": _b64("deep")}
    # Must not recurse without bound; content past the depth limit is simply lost.
    assert extract_body(payload, max_chars=100)["text"] == ""
