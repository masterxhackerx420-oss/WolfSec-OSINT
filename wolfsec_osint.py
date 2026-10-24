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
            "org": str(w.org) if hasattr(w, "org") and w.org else None
        }
    except Exception as e:
        return {"error": str(e)}
