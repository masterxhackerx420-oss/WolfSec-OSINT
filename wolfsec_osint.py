#!/usr/bin/env python3
"""
WolfSec OSINT Framework
DebianGang / WolfSec branded all-in-one OSINT toolkit.
Inspired by the OSINT Framework mindmap.
Covers domain, IP, username, email, and more using free public sources.
Includes CLI + Streamlit web UI + JSON/CSV export.
For authorized research & education only.
"""

import requests
import json
import socket
import dns.resolver
import whois
from urllib.parse import quote
import time
from datetime import datetime
import csv
import io
import streamlit as st
import sys

# ===================== Core OSINT Functions =====================

def get_ip_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query", timeout=10)
        data = r.json()
        return data if data.get("status") == "success" else {"error": data.get("message", "Failed")}
    except Exception as e:
        return {"error": str(e)}

def get_internetdb(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"note": "IP not found in InternetDB"}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=25)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain) and "*" not in n:
                        subdomains.add(n)
            return sorted(list(subdomains))
        return []
    except Exception as e:
        return [f"Error: {e}"]

def get_dns_records(domain):
    records = {}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if w.status else None,
            "emails": w.emails if w.emails else [],
            "org": str(w.org) if hasattr(w, 'org') and w.org else None
        }
    except Exception as e:
        return {"error": str(e)}

def check_username(username):
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://x.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
    }
    results = {}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; WolfSecOSINT/1.0)"}
    for name, url in platforms.items():
        try:
            r = requests.head(url, headers=headers, timeout=8, allow_redirects=True)
            exists = r.status_code in (200, 301, 302)
            results[name] = {"url": url, "status": r.status_code, "likely_exists": exists}
        except Exception:
            results[name] = {"url": url, "status": "error", "likely_exists": False}
        time.sleep(0.25)
    return results

def get_email_info(email):
    if "@" not in email:
        return {"error": "Invalid email"}
    domain = email.split("@")[1]
    info = {"email": email, "domain": domain}
    try:
        mx = dns.resolver.resolve(domain, "MX")
        info["mx"] = [str(r.exchange) for r in mx]
    except Exception as e:
        info["mx"] = str(e)
    info["gravatar"] = f"https://www.gravatar.com/avatar/{email}"
    return info

def export_results(data, filename_prefix="wolfsec_osint"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"/workspace/artifacts/{filename_prefix}_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return json_path

# ===================== Streamlit Web UI =====================

def run_streamlit():
    st.set_page_config(page_title="WolfSec OSINT", page_icon="🐺", layout="wide")
    st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    h1 { color: #00d4ff; }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🐺 WolfSec OSINT Framework")
    st.caption("DebianGang • Authorized research & education only")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Domain", "IP Address", "Username", "Email", "About"])
    
    with tab1:
        st.subheader("Domain Investigation")
        domain = st.text_input("Domain (e.g. example.com)", key="domain")
        if st.button("Investigate Domain", key="btn_domain") and domain:
            with st.spinner("Running domain recon..."):
                results = {}
                results["whois"] = get_whois(domain)
                results["dns"] = get_dns_records(domain)
                results["subdomains"] = get_subdomains(domain)[:40]
                st.session_state["last_results"] = {"type": "domain", "target": domain, "data": results}
                
                col1, col2 = st.columns(2)
                with col1:
                    st.json(results["whois"])
                    st.write("**DNS Records**")
                    st.json(results["dns"])
                with col2:
                    st.write(f"**Subdomains found: {len(results['subdomains'])}**")
                    st.write(results["subdomains"])
    
    with tab2:
        st.subheader("IP Investigation")
        ip = st.text_input("IP Address", key="ip")
        if st.button("Investigate IP", key="btn_ip") and ip:
            with st.spinner("Querying IP intelligence..."):
                results = {
                    "geolocation": get_ip_geo(ip),
                    "internetdb": get_internetdb(ip)
                }
                st.session_state["last_results"] = {"type": "ip", "target": ip, "data": results}
                st.json(results)
    
    with tab3:
        st.subheader("Username Search")
        username = st.text_input("Username", key="user")
        if st.button("Search Username", key="btn_user") and username:
            with st.spinner("Checking platforms..."):
                results = check_username(username)
                st.session_state["last_results"] = {"type": "username", "target": username, "data": results}
                for platform, info in results.items():
                    status = "✅ Likely exists" if info["likely_exists"] else "❌ Not found"
                    st.write(f"**{platform}**: {status} — [{info['url']}]({info['url']})")
    
    with tab4:
        st.subheader("Email Investigation")
        email = st.text_input("Email address", key="email")
        if st.button("Check Email", key="btn_email") and email:
            with st.spinner("Checking..."):
                results = get_email_info(email)
                st.session_state["last_results"] = {"type": "email", "target": email, "data": results}
                st.json(results)
                st.info("For breach data, check haveibeenpwned.com manually (API key required for automation).")
    
    with tab5:
        st.subheader("About WolfSec OSINT")
        st.markdown("""
        **WolfSec OSINT Framework** — DebianGang edition.
        
        Covers core categories from the classic OSINT Framework mindmap using free public sources:
        - Domain (WHOIS, DNS, Certificate Transparency subdomains)
        - IP (Geolocation + Shodan InternetDB)
        - Username footprinting
        - Email basics
        
        **Recommended full-power tools**:
        - SpiderFoot (200+ modules)
        - Sherlock / Maigret
        - theHarvester
        - Official directory: [osintframework.com](https://osintframework.com)
        
        Use only for authorized research, journalism, or defensive security.
        """)
    
    # Export section
    if "last_results" in st.session_state:
        st.divider()
        if st.button("Export last results as JSON"):
            path = export_results(st.session_state["last_results"])
            st.success(f"Exported to {path}")
            with open(path) as f:
                st.download_button("Download JSON", f, file_name=path.split("/")[-1])

# ===================== CLI Mode =====================

def run_cli():
    print("""
╔════════════════════════════════════════════════════════════╗
║              WOLFSEC OSINT FRAMEWORK                         ║
║                   DebianGang Edition                         ║
║           For authorized research & education only           ║
╚════════════════════════════════════════════════════════════╝
""")
    print("Run with --web for Streamlit UI, or use this CLI.\n")
    # Simple CLI fallback (expand as needed)
    print("CLI mode is basic. For full experience, run: streamlit run wolfsec_osint.py")

if __name__ == "__main__":
    if "--web" in sys.argv or len(sys.argv) == 1:
        run_streamlit()
    else:
        run_cli()
