import os
import re
import sys
import zipfile
import plistlib

input_ipa = r"C:\Users\sonhu\Downloads\vn.com.vng.zingalo_26.10.01_und3fined.ipa"
output_ipa = r"C:\Users\sonhu\Downloads\Zalo_Fixed_For_Sideloadly.ipa"

print(f"==> Dang mo file: {input_ipa}...")

def parse_strings_to_dict(text):
    res = {}
    lines = text.split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("/*") or line.startswith("*") or line.startswith("//"):
            continue
        m = re.match(r'^"?([^"=]+)"?\s*=\s*"(.*)";$', line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            res[key] = val
    return res

if not os.path.exists(input_ipa):
    print(f"Error: {input_ipa} not found!")
    sys.exit(1)

zin = zipfile.ZipFile(input_ipa, 'r')
zout = zipfile.ZipFile(output_ipa, 'w', compression=zipfile.ZIP_DEFLATED)

fixed_count = 0
total_files = len(zin.infolist())
print(f"==> Tong so file can xu ly: {total_files}")

for item in zin.infolist():
    data = zin.read(item.filename)
    if item.filename.endswith("InfoPlist.strings"):
        print(f"  [+] Phat hien va convert: {item.filename}")
        try:
            decoded = data.decode("utf-16")
        except Exception:
            try:
                decoded = data.decode("utf-8")
            except Exception:
                decoded = ""
        
        parsed_dict = parse_strings_to_dict(decoded)
        # Convert sang binary plist (bplist00) de Sideloadly libplist doc muot ma 100%
        binary_plist_data = plistlib.dumps(parsed_dict, fmt=plistlib.FMT_BINARY)
        zout.writestr(item, binary_plist_data)
        fixed_count += 1
    else:
        zout.writestr(item, data)

zin.close()
zout.close()

print(f"==> HOAN TAT! Da sua thanh cong {fixed_count} file InfoPlist.strings!")
print(f"==> File moi san sang: {output_ipa}")
print(f"==> Kich thuoc file: {os.path.getsize(output_ipa) / (1024*1024):.2f} MB")
