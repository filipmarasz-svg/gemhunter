#!/usr/bin/env python3
"""Uruchom raz: python cleanup.py - czyści spam z pattern_data.json"""
import json, os

pf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pattern_data.json")
if not os.path.exists(pf):
    print("Brak pattern_data.json")
    exit()

data = json.load(open(pf))
tokens = data.get("tokens", {})
before = len(tokens)

spam_names = ["solana","ethereum","bitcoin","shiba","dogecoin"]
removed = []
for addr, t in list(tokens.items()):
    name = (t.get("name","") + t.get("sym","")).lower()
    hits = sum(1 for c in spam_names if c in name)
    if hits >= 2:
        del tokens[addr]
        removed.append(t.get("name","?"))

# Też wyczyść blacklist z błędnych wpisów liq=$0
bl_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blacklist.json")
if os.path.exists(bl_file):
    bl = json.load(open(bl_file))
    reasons = bl.get("reasons", {})
    bad = [a for a,r in reasons.items() if "$0" in r or "Za niska liq: $0" in r]
    for addr in bad:
        if addr in bl["addresses"]:
            bl["addresses"].remove(addr)
        reasons.pop(addr, None)
    json.dump(bl, open(bl_file,"w"), indent=2)
    print(f"Blacklist: usunięto {len(bad)} błędnych wpisów liq=$0")

json.dump(data, open(pf,"w"), indent=2)
print(f"pattern_data: {before} -> {len(tokens)} tokenów")
print(f"Usunięto spam: {removed}")
