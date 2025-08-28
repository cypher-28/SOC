import csv
import json
import re
import sys

# quick regex helpers
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\b\d{10}\b")
AADHAR_RE = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
PASSPORT_RE = re.compile(r"\b[A-Z][0-9]{7}\b")
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)

# categories
NAME_KEYS = {"name", "first_name", "last_name"}
EMAIL_KEYS = {"email", "email_id"}
PHONE_KEYS = {"phone", "mobile", "contact", "whatsapp"}
AADHAR_KEYS = {"aadhar", "aadhaar"}
PASSPORT_KEYS = {"passport"}
UPI_KEYS = {"upi", "upi_id"}
ADDR_KEYS = {"address", "city", "pin", "pincode", "zipcode"}
DEVICE_KEYS = {"device_id", "ip", "ip_address"}


def mask_phone(x):
    return x[:2] + "XXXXXX" + x[-2:] if len(x) >= 4 else "X" * len(x)


def mask_aadhar(x):
    digits = re.sub(r"\D", "", x)
    return "XXXX-XXXX-" + digits[-4:] if len(digits) == 12 else "XXXX"


def mask_passport(x):
    return x[0] + "XXXXXX"


def mask_upi(x):
    try:
        name, dom = x.split("@", 1)
        return name[:2] + "XXXXXX@" + dom
    except Exception:
        return "[REDACTED_UPI]"


def mask_email(x):
    try:
        user, dom = x.split("@", 1)
        return user[:2] + "XXXX@" + dom
    except Exception:
        return "[REDACTED_EMAIL]"


def mask_name(x):
    parts = x.split()
    out = []
    for p in parts:
        if len(p) > 1:
            out.append(p[0] + "X" * (len(p) - 1))
        else:
            out.append("X")
    return " ".join(out)


def mask_ip(x):
    if IPV4_RE.fullmatch(x):
        return "***.***.***.***"
    if IPV6_RE.fullmatch(x):
        return "****:****:****:****"
    return "[REDACTED_IP]"


def mask_addr(x):
    return "[REDACTED_ADDRESS]"


def mask_device(x):
    return "[REDACTED_DEVICE]"


def detect_and_mask(record):
    has_a = False
    b_cats = set()

    masked = {}

    for k, v in record.items():
        if not isinstance(v, str):
            masked[k] = v
            continue

        lowk = k.lower().strip()
        newv = v

        # --- standalone PII (always triggers) ---
        if lowk in PHONE_KEYS and PHONE_RE.search(v):
            newv, has_a = mask_phone(v), True
        elif lowk in AADHAR_KEYS and AADHAR_RE.search(v):
            newv, has_a = mask_aadhar(v), True
        elif lowk in PASSPORT_KEYS and PASSPORT_RE.search(v):
            newv, has_a = mask_passport(v), True
        elif (lowk in UPI_KEYS or UPI_RE.search(v)):
            newv, has_a = mask_upi(v), True

        # --- category checks (B) ---
        elif lowk in NAME_KEYS and len(v.split()) >= 2:
            b_cats.add("name")
        elif lowk in EMAIL_KEYS and EMAIL_RE.search(v):
            b_cats.add("email")
        elif lowk in ADDR_KEYS:
            # check if we have full addr combo later
            b_cats.add("address")
        elif lowk in DEVICE_KEYS and (IPV4_RE.search(v) or IPV6_RE.search(v)):
            b_cats.add("device")

        masked[k] = newv

    # check address combo (need at least addr+city+pin)
    addr_keys_present = sum(1 for k in record if k.lower() in {"address", "city", "pin_code", "pincode", "zipcode"})
    if addr_keys_present >= 3:
        b_cats.add("address")

    is_pii = has_a or (len(b_cats) >= 2)

    if is_pii:
        # actually redact B cats
        for k, v in list(masked.items()):
            lowk = k.lower()
            if lowk in NAME_KEYS:
                masked[k] = mask_name(str(v))
            elif lowk in EMAIL_KEYS and EMAIL_RE.search(str(v)):
                masked[k] = mask_email(str(v))
            elif lowk in ADDR_KEYS:
                masked[k] = mask_addr(str(v))
            elif lowk in DEVICE_KEYS:
                if IPV4_RE.search(str(v)) or IPV6_RE.search(str(v)):
                    masked[k] = mask_ip(str(v))
                else:
                    masked[k] = mask_device(str(v))

    return masked, is_pii


def main(infile, outfile):
    with open(infile, newline="", encoding="utf-8") as f, open(outfile, "w", newline="", encoding="utf-8") as out:
        reader = csv.DictReader(f)
        writer = csv.writer(out)
        writer.writerow(["record_id", "redacted_data_json", "is_pii"])

        for row in reader:
            try:
                data = json.loads(row["Data_json"].replace("'", '"'))
            except Exception:
                data = {}

            masked, is_pii = detect_and_mask(data)
            writer.writerow([row["record_id"], json.dumps(masked, ensure_ascii=False), str(is_pii)])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector.py input.csv [output.csv]")
        sys.exit(1)

    inp = sys.argv[1]
    outp = sys.argv[2] if len(sys.argv) > 2 else "redacted_output.csv"
    main(inp, outp)
