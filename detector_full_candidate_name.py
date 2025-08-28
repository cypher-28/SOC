
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector_full_candidate_name.py

Usage:
    python3 detector_full_candidate_name.py input.csv [output.csv]

Input CSV must have: record_id, Data_json
Output CSV columns: record_id, redacted_data_json, is_pii

Rules implemented from challenge prompt:
- PII Standalone (A): phone (10-digit), aadhar (12-digit), passport (Indian), UPI id
- PII Combinatorial (B): name (full), email, physical address (street+city+pin), device/ip (only in user context)
- Non-PII: single elements from B on their own should not trigger is_pii=True (e.g., only email)
- Redaction: redact A always; redact B only when the record qualifies as PII (>=2 distinct B categories present)
"""
import csv, json, re, sys, typing

# --------- Regex helpers ---------
EMAIL_RE = re.compile(r'''(?ix)
\b
[A-Z0-9._%+-]+
@
[A-Z0-9.-]+\.[A-Z]{2,}
\b
''')

UPI_RE = re.compile(r'''(?ix)\b
[0-9A-Z._\-]{2,}@[A-Z]{2,}
\b''')

# Indian passport: 1 letter + 7 digits (some older series may have formats, we stick to common case)
PASSPORT_RE = re.compile(r'\b([A-Za-z])[0-9]{7}\b')

# Strict 10-digit run, not part of longer run
TEN_DIGIT_RE = re.compile(r'(?<!\d)(\d{10})(?!\d)')

# Aadhar: 12 digits; allow spaces between groups
AADHAR_RE = re.compile(r'(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)')

# IPv4 simple; IPv6 very basic catch
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
IPV6_RE = re.compile(r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b', re.I)

PINCODE_RE = re.compile(r'(?<!\d)(\d{6})(?!\d)')

# --------- Field name normalization ---------
def norm_key(k: str) -> str:
    return (k or '').strip().lower()

# Keys we consider likely "phone-ish"
PHONE_KEYS = {'phone','mobile','contact','alt_phone','alternate_phone','whatsapp','phone_number'}
# Keys that are known non-personal numeric-like to avoid false positives
NON_PII_NUMERIC_KEYS = {'transaction_id','order_id','product_id','ticket_id','filters'}

AADHAR_KEYS = {'aadhar','aadhaar','aadhar_number','aadhaar_number'}
PASSPORT_KEYS = {'passport','passport_number'}
UPI_KEYS = {'upi','upi_id'}
EMAIL_KEYS = {'email','email_id'}
NAME_KEYS = {'name','full_name'}
FIRST_NAME_KEYS = {'first_name','firstname'}
LAST_NAME_KEYS = {'last_name','lastname'}
ADDRESS_KEYS = {'address','street_address'}
CITY_KEYS = {'city'}
PINCODE_KEYS = {'pin_code','pincode','postal_code','zip'}
DEVICE_KEYS = {'device_id'}
IP_KEYS = {'ip_address','ip'}

# --------- Maskers ---------
def mask_phone(s: str) -> str:
    digits = re.sub(r'\D','', s)
    if len(digits) >= 10:
        d = digits[-10:]  # last 10 digits
        masked = d[:2] + 'X'*6 + d[-2:]
        return masked
    return '[REDACTED_PHONE]'

def format_like_value(original: str, masked_digits: str) -> str:
    # Try to keep non-digit separators layout length if possible; otherwise return digits
    return masked_digits

def mask_aadhar(s: str) -> str:
    digits = re.sub(r'\D','', s)
    if len(digits) >= 12:
        d = digits[-12:]
        return 'XXXX-XXXX-' + d[-4:]
    return '[REDACTED_AADHAR]'

def mask_passport(s: str) -> str:
    m = PASSPORT_RE.search(s)
    if not m:
        return '[REDACTED_PASSPORT]'
    pref = m.group(1).upper()
    return pref + 'XXXXXX'  # keep series letter

def mask_upi(s: str) -> str:
    # keep domain; mask most of handle
    try:
        user, domain = s.split('@',1)
        if len(user) <= 2:
            masked_user = user[0] + 'X'*(len(user)-1)
        else:
            masked_user = user[:2] + 'X'*(max(0, len(user)-2))
        return masked_user + '@' + domain
    except Exception:
        return '[REDACTED_UPI]'

def mask_email(s: str) -> str:
    try:
        local, domain = s.split('@', 1)
        if len(local) <= 2:
            masked_local = local[0] + 'X'*(len(local)-1)
        else:
            masked_local = local[:2] + 'X'*(len(local)-2)
        return masked_local + '@' + domain
    except Exception:
        return '[REDACTED_EMAIL]'

def mask_name_full(s: str) -> str:
    parts = re.split(r'(\s+)', s or '')
    out = []
    for token in parts:
        if token.strip() == '':
            out.append(token)
        else:
            out.append(token[0] + 'X'*(max(0,len(token)-1)))
    return ''.join(out)

def mask_address(s: str) -> str:
    return '[REDACTED_ADDRESS]'

def mask_ip(s: str) -> str:
    ss = s.strip()
    if IPV4_RE.fullmatch(ss):
        return '***.***.***.***'
    if IPV6_RE.fullmatch(ss):
        return '****:****:****:****'
    return '[REDACTED_IP]'
    
def mask_device(s: str) -> str:
    return '[REDACTED_DEVICE]'

# --------- Detection logic ---------
def detect_and_redact(record: dict):
    """Returns (redacted_record_dict, is_pii_boolean)"""
    # Track B categories present
    B_present = {
        'name': False,
        'email': False,
        'address': False,
        'device_or_ip': False,
    }
    # Track fields in A we will redact regardless
    standalone_pii_hits = set()
    # Store redactions for B; we will apply only if >=2 true
    b_field_hits = []  # list of (key, value, mask_func)

    redacted = dict(record)  # shallow copy

    # First pass: normalize keys and detect patterns
    # Also construct helper presence flags for address components
    has_address_key = any(norm_key(k) in ADDRESS_KEYS for k in record.keys())
    has_city = any(norm_key(k) in CITY_KEYS and str(record[k]).strip() for k in record.keys())
    has_pin_key = any(norm_key(k) in PINCODE_KEYS and str(record[k]).strip() for k in record.keys())

    # Detect name presence (full)
    # If 'name' key has two+ words -> B name present
    for k, v in record.items():
        nk = norm_key(k)
        sval = '' if v is None else str(v)

        # --- Standalone A checks ---
        if nk in PHONE_KEYS:
            # try to harvest 10-digit number in this field
            m = TEN_DIGIT_RE.search(sval)
            if m:
                standalone_pii_hits.add((k, 'phone'))
                redacted[k] = format_like_value(sval, mask_phone(sval))

        if nk in AADHAR_KEYS:
            if AADHAR_RE.search(sval):
                standalone_pii_hits.add((k, 'aadhar'))
                redacted[k] = mask_aadhar(sval)

        if nk in PASSPORT_KEYS:
            if PASSPORT_RE.search(sval):
                standalone_pii_hits.add((k, 'passport'))
                redacted[k] = mask_passport(sval)

        if nk in UPI_KEYS or UPI_RE.search(sval):
            if UPI_RE.search(sval):
                standalone_pii_hits.add((k, 'upi'))
                # Mask only the first upi-like in the value
                redacted[k] = UPI_RE.sub(lambda m: mask_upi(m.group(0)), sval)

        # --- Combinatorial B checks ---
        if nk in NAME_KEYS:
            # consider full name only if two or more tokens
            tokens = [t for t in re.split(r'\s+', sval.strip()) if t]
            if len(tokens) >= 2:
                B_present['name'] = True
                b_field_hits.append((k, sval, mask_name_full))
        # We'll combine first_name and last_name below

        if nk in EMAIL_KEYS:
            if EMAIL_RE.search(sval):
                B_present['email'] = True
                b_field_hits.append((k, sval, mask_email))

        # Address line itself
        if nk in ADDRESS_KEYS and sval.strip():
            # We'll set address present later if city & pin exist
            b_field_hits.append((k, sval, mask_address))  # candidate for redaction

        if nk in DEVICE_KEYS and sval.strip():
            B_present['device_or_ip'] = True
            b_field_hits.append((k, sval, mask_device))

        if nk in IP_KEYS and (IPV4_RE.search(sval) or IPV6_RE.search(sval)):
            B_present['device_or_ip'] = True
            b_field_hits.append((k, sval, mask_ip))

        # Avoid counting numeric-looking in non-PII keys
        if nk in NON_PII_NUMERIC_KEYS:
            pass

    # Handle first_name + last_name combo as Name
    has_first = any(norm_key(k) in FIRST_NAME_KEYS and str(record[k]).strip() for k in record.keys())
    has_last  = any(norm_key(k) in LAST_NAME_KEYS and str(record[k]).strip() for k in record.keys())
    if has_first and has_last:
        B_present['name'] = True
        # enqueue both for redaction with mask_name_full
        for k in record.keys():
            nk = norm_key(k)
            if nk in FIRST_NAME_KEYS or nk in LAST_NAME_KEYS:
                sval = '' if record[k] is None else str(record[k])
                b_field_hits.append((k, sval, mask_name_full))

    # Decide if "Physical Address" present
    if has_address_key and has_city and has_pin_key:
        B_present['address'] = True

    # Record-level is_pii
    is_pii = False
    if standalone_pii_hits:
        is_pii = True
    else:
        # count distinct True in B categories
        if sum(1 for flag in B_present.values() if flag) >= 2:
            is_pii = True

    # Apply B redactions only if is_pii via B rules
    if is_pii:
        # If is_pii due only to standalone A, we still want to avoid masking B fields unless B threshold met
        # However it's safe to mask B fields if they exist because the record is already PII.
        for k, val, masker in b_field_hits:
            try:
                redacted[k] = masker(val)
            except Exception:
                redacted[k] = val

    return redacted, bool(is_pii)


def safe_json_loads(s: str):
    # Best-effort: handle both proper JSON and relaxed JSON with single quotes
    try:
        return json.loads(s)
    except Exception:
        try:
            # replace single quotes with double quotes, but be conservative
            s2 = s.replace("'", '"')
            return json.loads(s2)
        except Exception:
            # fallback: try to parse as key=value pairs (very rough)
            return {}

def process(input_csv: str, output_csv: str):
    with open(input_csv, newline='', encoding='utf-8') as f_in,          open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ['record_id','redacted_data_json','is_pii']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            rid = row.get('record_id')
            data_json_raw = row.get('Data_json') or row.get('data_json') or ''
            data_obj = safe_json_loads(data_json_raw)
            if not isinstance(data_obj, dict):
                data_obj = {}
            redacted_obj, is_pii = detect_and_redact(data_obj)

            # Output compact json
            redacted_str = json.dumps(redacted_obj, ensure_ascii=False)
            writer.writerow({'record_id': rid, 'redacted_data_json': redacted_str, 'is_pii': str(bool(is_pii))})

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py input.csv [output.csv]")
        sys.exit(2)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else 'redacted_output_candidate_full_name.csv'
    process(inp, out)
    print(f"Wrote {out}")
