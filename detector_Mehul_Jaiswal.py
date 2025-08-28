import csv, json, re, sys, ast

# regexes
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\b\d{10}\b")
AADHAR_RE = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
PASSPORT_RE = re.compile(r"\b[A-Z][0-9]{7}\b")
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)

# field buckets
NAME_KEYS = {"name", "first_name", "last_name"}
EMAIL_KEYS = {"email", "email_id"}
PHONE_KEYS = {"phone", "mobile", "contact", "whatsapp"}
AADHAR_KEYS = {"aadhar", "aadhaar"}
PASSPORT_KEYS = {"passport"}
UPI_KEYS = {"upi", "upi_id"}
ADDR_KEYS = {"address", "city", "pin", "pincode", "zipcode"}
DEVICE_KEYS = {"device_id", "ip", "ip_address"}

# --- maskers ---
def hide_phone(x): return x[:2] + "XXXXXX" + x[-2:] if len(x) >= 4 else "X"*len(x)
def hide_aadhar(x): 
    digits = re.sub(r"\D","",x)
    return "XXXX-XXXX-" + digits[-4:] if len(digits)==12 else "XXXX"
def hide_passport(x): return x[0] + "XXXXXX"
def hide_upi(x):
    try: u,d=x.split("@",1); return u[:2]+"XXXXXX@"+d
    except: return "[REDACTED_UPI]"
def hide_email(x):
    try: u,d=x.split("@",1); return u[:2]+"XXXX@"+d
    except: return "[REDACTED_EMAIL]"
def hide_name(x): return " ".join([p[0]+"X"*(len(p)-1) if len(p)>1 else "X" for p in x.split()])
def hide_ip(x):
    if IPV4_RE.fullmatch(x): return "***.***.***.***"
    if IPV6_RE.fullmatch(x): return "****:****:****:****"
    return "[REDACTED_IP]"
def hide_addr(x): return "[REDACTED_ADDRESS]"
def hide_device(x): return "[REDACTED_DEVICE]"

# --- detection ---
def scrub_row(rowdata):
    got_strict_hit=False; soft_hits=set(); cleaned={}
    for k,v in rowdata.items():
        if not isinstance(v,str): cleaned[k]=v; continue
        key=k.lower().strip(); val=v
        if key in PHONE_KEYS and PHONE_RE.search(v): val,got_strict_hit=hide_phone(v),True
        elif key in AADHAR_KEYS and AADHAR_RE.search(v): val,got_strict_hit=hide_aadhar(v),True
        elif key in PASSPORT_KEYS and PASSPORT_RE.search(v): val,got_strict_hit=hide_passport(v),True
        elif key in UPI_KEYS or UPI_RE.search(v): val,got_strict_hit=hide_upi(v),True
        elif key in NAME_KEYS and len(v.split())>=2: soft_hits.add("name")
        elif key in EMAIL_KEYS and EMAIL_RE.search(v): soft_hits.add("email")
        elif key in ADDR_KEYS: soft_hits.add("address")
        elif key in DEVICE_KEYS and (IPV4_RE.search(v) or IPV6_RE.search(v)): soft_hits.add("device")
        cleaned[k]=val
    addr_keys_present=sum(1 for k in rowdata if k.lower() in {"address","city","pin_code","pincode","zipcode"} and str(rowdata[k]).strip())
    if addr_keys_present>=3: soft_hits.add("address")
    is_pii=got_strict_hit or (len(soft_hits)>=2)
    if is_pii:
        for k,v in list(cleaned.items()):
            key=k.lower()
            if key in NAME_KEYS: cleaned[k]=hide_name(str(v))
            elif key in EMAIL_KEYS and EMAIL_RE.search(str(v)): cleaned[k]=hide_email(str(v))
            elif key in ADDR_KEYS: cleaned[k]=hide_addr(str(v))
            elif key in DEVICE_KEYS:
                if IPV4_RE.search(str(v)) or IPV6_RE.search(str(v)): cleaned[k]=hide_ip(str(v))
                else: cleaned[k]=hide_device(str(v))
    return cleaned,is_pii

# --- safe JSON loader ---
def safe_load(s):
    try: return json.loads(s)
    except:
        try: return ast.literal_eval(s)
        except: return {}

def run(infile,outfile):
    with open(infile,newline="",encoding="utf-8") as f, open(outfile,"w",newline="",encoding="utf-8") as out:
        reader=csv.DictReader(f); writer=csv.writer(out)
        writer.writerow(["record_id","redacted_data_json","is_pii"])
        for row in reader:
            data=safe_load(row.get("Data_json","") or row.get("data_json",""))
            cleaned,is_pii=scrub_row(data if isinstance(data,dict) else {})
            writer.writerow([row.get("record_id"),json.dumps(cleaned,ensure_ascii=False),str(is_pii)])

if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: python python_script.py input_file.csv [output_file.csv]"); sys.exit(1)
    inp=sys.argv[1]; outp=sys.argv[2] if len(sys.argv)>2 else "redacted_output.csv"
    run(inp,outp)
