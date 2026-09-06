"""One literal redactor for live diagnostics and recognized historical records."""
import base64
import json
import re
import unicodedata
from urllib.parse import quote, quote_plus


class Redactor:
    def __init__(self, values):
        forms = set()
        for raw in values:
            if not raw:
                continue
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            text = raw.decode("utf-8", errors="replace")
            forms.update([text, raw.hex(), raw.hex().upper(), base64.b64encode(raw).decode(), " ".join(f"{value:02x}" for value in raw), ":".join(f"{value:02x}" for value in raw), json.dumps(text)[1:-1], quote(text, safe=""), quote_plus(text, safe="")])
            forms.update(part for part in text.splitlines() if part.strip())
            forms.add(text.encode("utf-16le").hex())
            forms.add(text.encode("utf-16le").hex().upper())
            forms.add(" ".join(f"{value:02X}" for value in raw))
            forms.add(":".join(f"{value:02X}" for value in raw))
            forms.add(base64.urlsafe_b64encode(raw).decode())
        self.forms = sorted((value for value in forms if value), key=len, reverse=True)

    def text(self, value):
        # Match against original text before preserving existing markers. Matches
        # may span a marker; output is assembled once and is never reprocessed.
        markers = [(match.start(), match.end()) for match in re.finditer(re.escape("[redacted]"), value)]
        hidden = bytearray(len(value))
        for secret in self.forms:
            offset = 0
            while True:
                start = value.find(secret, offset)
                if start < 0:
                    break
                end = start + len(secret)
                offset = start + 1
                if any(left <= start and end <= right for left, right in markers):
                    continue
                for left, right in markers:
                    if start < right and end > left:
                        start, end = min(start, left), max(end, right)
                hidden[start:end] = b"\x01" * (end - start)
        output = []
        offset = 0
        while offset < len(value):
            if hidden[offset]:
                output.append("[redacted]")
                while offset < len(value) and hidden[offset]:
                    offset += 1
            else:
                char = value[offset]
                output.append("?" if unicodedata.category(char) in {"Cc", "Cf"} and char not in "\n\t" else char)
                offset += 1
        return "".join(output)

    def object(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.object(item) for item in value]
        if isinstance(value, dict):
            return {key: self.object(item) for key, item in value.items() if not key.startswith("_")}
        return value

    def line(self, value):
        if value in {"[sensitive diagnostic suppressed]", "[RADIUS or binary diagnostic suppressed]", "[overlong diagnostic suppressed]", "[overlong sanitized diagnostic suppressed]"}:
            return value
        if re.search(r"(?i)(hexdump|password|passwd|private[_ -]?key|shared[_ -]?secret|master[_ -]?key|\bmppe\b|\bmsk\b|\bemsk\b|challenge|response authenticator|authenticator:|keying material|encryption key|tls secret)", value):
            return "[sensitive diagnostic suppressed]"
        if re.match(r"(?i)^\s*(?:RADIUS message:|Attribute [0-9]+|Type:|Length:|Value:|Vendor-|User-Password|CHAP-|MS-CHAP|Tunnel-Password|EAP-Message|Message-Authenticator)", value) or re.match(r"(?i)^\s*(?:[0-9a-f]{2}[ :]){4,}", value):
            return "[RADIUS or binary diagnostic suppressed]"
        return self.text(value)

