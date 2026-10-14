import json
import os
import sys

def analyze():
    out = []
    
    audit_path = r'c:\Users\sonhu\Downloads\ZaloAudit (2).log'
    traffic_path = r'c:\Users\sonhu\Downloads\ZaloTraffic (2).har'
    proxypin_path = r'c:\Users\sonhu\Downloads\ProxyPin10-12_20_22_45.har'
    
    out.append("==========================================")
    out.append("=== 1. ZaloAudit (2).log Analysis ===")
    out.append("==========================================")
    if os.path.exists(audit_path):
        with open(audit_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip()]
        out.append(f"Total log lines: {len(lines)}")
        
        # Categorize
        radar_hits = [l for l in lines if 'DETECTION-RADAR' in l]
        out.append(f"DETECTION-RADAR events: {len(radar_hits)}")
        for r in radar_hits:
            out.append(f"  {r}")
            
        sysctl_hits = [l for l in lines if 'sysctl' in l.lower()]
        out.append(f"sysctl events: {len(sysctl_hits)}")
        for s in sysctl_hits[:10]:
            out.append(f"  {s}")
            
        mg_hits = [l for l in lines if 'mgcopyanswer' in l.lower() or 'gestalt' in l.lower()]
        out.append(f"MobileGestalt events: {len(mg_hits)}")
        for m in mg_hits[:10]:
            out.append(f"  {m}")
            
        bundle_hits = [l for l in lines if 'bundle' in l.lower()]
        out.append(f"Bundle events: {len(bundle_hits)}")
        for b in bundle_hits[:10]:
            out.append(f"  {b}")
    else:
        out.append("File not found")
        
    out.append("\n==========================================")
    out.append("=== 2. ZaloTraffic (2).har Analysis ===")
    out.append("==========================================")
    if os.path.exists(traffic_path):
        with open(traffic_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        entries = data.get('log', {}).get('entries', [])
        out.append(f"Total entries: {len(entries)}")
        
        status_counts = {}
        error_list = []
        user_agents = set()
        model_params = set()
        device_ids = set()
        
        for e in entries:
            req = e.get('request', {})
            resp = e.get('response', {})
            url = req.get('url', '')
            status = resp.get('status', 0)
            status_counts[status] = status_counts.get(status, 0) + 1
            
            if status != 200:
                error_list.append((status, url, resp.get('statusText', '')))
                
            for h in req.get('headers', []):
                name = h.get('name', '').lower()
                val = h.get('value', '')
                if name == 'user-agent':
                    user_agents.add(val)
                elif name == 'deviceid':
                    device_ids.add(val)
                    
            # check post data
            post_data = req.get('postData') or {}
            text = post_data.get('text', '') or ''
            if 'model' in text:
                import re
                m = re.findall(r'name="model"[^;]*\r?\n\r?\n([^\r\n]+)', text)
                for item in m:
                    model_params.add(item)
                    
        out.append(f"Status codes: {status_counts}")
        out.append(f"User Agents seen: {user_agents}")
        out.append(f"Device IDs seen: {device_ids}")
        out.append(f"Model parameters in QoS: {model_params}")
        if error_list:
            out.append(f"Non-200 responses ({len(error_list)}):")
            for st, u, txt in error_list[:15]:
                out.append(f"  [{st}] {u[:80]} ({txt})")
    else:
        out.append("File not found")

    out.append("\n==========================================")
    out.append("=== 3. ProxyPin10-12_20_22_45.har Analysis ===")
    out.append("==========================================")
    if os.path.exists(proxypin_path):
        with open(proxypin_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        entries = data.get('log', {}).get('entries', [])
        out.append(f"Total entries: {len(entries)}")
        
        status_counts = {}
        error_list = []
        user_agents = set()
        model_params = set()
        device_ids = set()
        urls_visited = []
        
        for e in entries:
            req = e.get('request', {})
            resp = e.get('response', {})
            url = req.get('url', '')
            status = resp.get('status', 0)
            status_counts[status] = status_counts.get(status, 0) + 1
            urls_visited.append((status, url))
            
            if status != 200:
                error_list.append((status, url, resp.get('statusText', '')))
                
            for h in req.get('headers', []):
                name = h.get('name', '').lower()
                val = h.get('value', '')
                if name == 'user-agent':
                    user_agents.add(val)
                elif name == 'deviceid':
                    device_ids.add(val)
                    
            post_data = req.get('postData') or {}
            text = post_data.get('text', '') or ''
            if 'model' in text:
                import re
                m = re.findall(r'name="model"[^;]*\r?\n\r?\n([^\r\n]+)', text)
                for item in m:
                    model_params.add(item)
                    
        out.append(f"Status codes: {status_counts}")
        out.append(f"User Agents seen: {user_agents}")
        out.append(f"Device IDs seen: {device_ids}")
        out.append(f"Model parameters in QoS: {model_params}")
        out.append(f"Top 20 URLs visited:")
        for st, u in urls_visited[:20]:
            out.append(f"  [{st}] {u[:90]}")
        if error_list:
            out.append(f"Non-200 responses ({len(error_list)}):")
            for st, u, txt in error_list[:15]:
                out.append(f"  [{st}] {u[:80]} ({txt})")
    else:
        out.append("File not found")

    result = '\n'.join(out)
    with open('scratch/analysis_report.txt', 'w', encoding='utf-8') as f:
        f.write(result)
    print("Report written successfully.")

if __name__ == '__main__':
    analyze()
