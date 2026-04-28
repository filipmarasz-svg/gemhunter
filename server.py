"""GemHunter v5 - smart filters, blacklist learning, auto-refresh cache"""
import json, logging, os, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.parse import urlparse, parse_qs, quote

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

HTML_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
BLACK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blacklist.json")
HEADERS    = {"User-Agent": "Mozilla/5.0 (compatible; GemHunter/1.0)", "Accept": "application/json"}

DS_SEARCH  = "https://api.dexscreener.com/latest/dex/search?q={q}"
DS_BOOSTS  = "https://api.dexscreener.com/token-boosts/latest/v1"
DS_NEW_PAIRS = "https://api.dexscreener.com/latest/dex/search?q=new+solana+token&order=createdAt"
DS_TOKEN   = "https://api.dexscreener.com/latest/dex/tokens/{addr}"
GOPLUS_ETH = "https://api.gopluslabs.io/api/v1/token_security/1?contract_addresses={addr}"
RUGCHECK   = "https://api.rugcheck.xyz/v1/tokens/{addr}/report/summary"
SOLSCAN_H  = "https://api-v2.solscan.io/v2/token/holders?address={addr}&page=1&page_size=10&sort_by=amount&sort_order=desc"

# Filtry per zakładka — kluczowe minimum
TAB_FILTERS = {
    "new":     {"min_h":0,    "max_h":6,     "min_liq":8000,   "min_mcap":10000,  "min_vol1h":500,   "min_ch1h":5,    "min_txns":20},
    "pump":    {"min_h":0.5,  "max_h":8,     "min_liq":10000,  "min_mcap":15000,  "min_vol1h":2000,  "min_ch1h":20,   "min_txns":50},
    "growing": {"min_h":6,    "max_h":30*24, "min_liq":8000,   "min_mcap":15000,  "min_vol1h":200,   "min_ch1h":-999, "min_txns":30},
    "viral":   {"min_h":2,    "max_h":14*24, "min_liq":20000,  "min_mcap":50000,  "min_vol1h":5000,  "min_ch1h":10,   "min_txns":100},
}

# Cache wyników — odświeżaj co 3 min w tle
CACHE      = {}
CACHE_TTL  = 180
cache_lock = threading.Lock()

try:
    import pattern_engine as PE
    PATTERN_ENGINE = True
    log.info("Pattern Engine OK")
except ImportError:
    PATTERN_ENGINE = False

# ── BLACKLIST ─────────────────────────────────────────────────────────────────

def load_blacklist() -> dict:
    try:
        if os.path.exists(BLACK_FILE):
            return json.load(open(BLACK_FILE))
    except Exception:
        pass
    return {"addresses": [], "reasons": {}, "learned_patterns": []}

def save_blacklist(bl: dict):
    json.dump(bl, open(BLACK_FILE, "w"), indent=2)

def auto_blacklist(token: dict, reason: str):
    bl   = load_blacklist()
    addr = token.get("address", "")
    name = token.get("name", "")
    if addr and addr not in bl["addresses"]:
        bl["addresses"].append(addr)
        bl["reasons"][addr] = f"{reason} | {name}"
        log.warning(f"🚫 Blacklist: [{token.get('chain')}] {name} — {reason}")
    # Naucz wzorzec jeśli nazwa to zlepek znanych coinów
    known = ["solana","ethereum","bitcoin","pepe","shiba","dogecoin","bnb","usdt","usdc","btc","eth","sol"]
    hits  = sum(1 for c in known if c in name.lower())
    pat   = "multi_coin_spam"
    if hits >= 3 and pat not in bl["learned_patterns"]:
        bl["learned_patterns"].append(pat)
        log.warning(f"🧠 Nauczono wzorzec: {pat} (z {name})")
    save_blacklist(bl)

def is_blacklisted(name: str, sym: str, address: str) -> tuple[bool, str]:
    bl = load_blacklist()
    if address in bl["addresses"]:
        reason = bl["reasons"].get(address, "")
        # Ignoruj stare błędne wpisy gdzie liq=$0 (brak danych, nie spam)
        if "$0" in reason:
            return False, ""
        return True, reason or "czarna lista"
    n = (name + sym).lower()
    # Blokuj konkretny wzorzec: nazwa zawiera 3+ pełne nazwy coinów (np. SolanaEthereumBitcoin)
    long_names = ["solana","ethereum","bitcoin","shiba","dogecoin"]
    long_hits = sum(1 for c in long_names if c in n)
    if long_hits >= 2:
        return True, f"Spam: łączy {long_hits} pełne nazwy coinów"
    # Krótkie nazwy - potrzeba więcej
    known = ["solana","ethereum","bitcoin","pepe","shiba","dogecoin","bnb","usdt","usdc","btc","eth","sol"]
    hits  = sum(1 for c in known if c in n)
    if hits >= 3:
        return True, f"Spam: nazwa łączy {hits} znane coiny"
    if len(name) > 22 and " " not in name and name.lower() == name:
        return True, "Spam: długa nazwa bez spacji"
    return False, ""

def fetch(url: str, timeout=12):
    req = Request(url, headers=HEADERS)
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

# ── ŹRÓDŁA ───────────────────────────────────────────────────────────────────

def get_search_pairs(chain_filter: str) -> list[dict]:
    q_map = {
        "SOL": ["solana meme","sol pepe","sol dog","bonk"],
        "ETH": ["ethereum meme","eth pepe","eth wojak","eth dog"],
        "ALL": ["solana meme","ethereum meme","sol pepe","eth pepe","sol dog","eth wojak"],
    }
    seen, results = set(), []
    import time as _time
    for q in q_map.get(chain_filter, q_map["ALL"]):
        try:
            _time.sleep(0.3)  # unikaj 429
            data = fetch(DS_SEARCH.format(q=quote(q)))
            for p in (data.get("pairs") or []):
                cid  = (p.get("chainId") or "").lower()
                if cid not in ("solana","ethereum"): continue
                addr = (p.get("baseToken") or {}).get("address","")
                if addr and addr not in seen:
                    seen.add(addr); results.append(p)
        except Exception as e:
            log.warning(f"Search ({q}): {e}")
    log.info(f"Search pairs: {len(results)}")
    return results

def get_boosted_pairs(chain_filter: str) -> list[dict]:
    results, seen = [], set()
    try:
        items = fetch(DS_BOOSTS)
        if not isinstance(items, list): return []
        for item in items[:60]:
            cid  = (item.get("chainId") or "").lower()
            addr = item.get("tokenAddress","")
            if not addr or cid not in ("solana","ethereum"): continue
            if chain_filter == "SOL" and cid != "solana": continue
            if chain_filter == "ETH" and cid != "ethereum": continue
            if addr in seen: continue
            seen.add(addr)
            try:
                data = fetch(DS_TOKEN.format(addr=addr), timeout=8)
                for p in (data.get("pairs") or []):
                    if (p.get("chainId") or "").lower() == cid:
                        results.append(p); break
            except Exception: pass
    except Exception as e:
        log.warning(f"Boosts: {e}")
    log.info(f"Boosted pairs: {len(results)}")
    return results

# ── SECURITY ──────────────────────────────────────────────────────────────────

def to_pct(val) -> float:
    v = float(val or 0)
    return min(v*100 if v <= 1.0 else v, 100.0)

def get_goplus_eth(addr: str) -> dict:
    try:
        data = fetch(GOPLUS_ETH.format(addr=addr), timeout=8)
        r    = data.get("result") or {}
        return r.get(addr.lower()) or r.get(addr) or {}
    except: return {}

def get_rugcheck_sol(addr: str) -> dict:
    try: return fetch(RUGCHECK.format(addr=addr), timeout=8)
    except: return {}

def analyze_eth(gp: dict):
    score, flags = 0, []
    top1, top10, dev, lp_lock, holders = 0.0,0.0,0.0,False,0
    if gp.get("is_honeypot")=="1":
        score+=50; flags.append({"label":"🚨 HONEYPOT","cls":"bad"})
    if gp.get("is_open_source")=="0":
        score+=15; flags.append({"label":"Zamknięty kod","cls":"bad"})
    lp = gp.get("lp_holders") or []
    lp_lock = any(h.get("is_locked")==1 for h in lp)
    if lp_lock: flags.append({"label":"LP Locked","cls":"ok"})
    else:        score+=20; flags.append({"label":"Brak LP lock","cls":"bad"})
    dev = to_pct(gp.get("creator_percent") or 0)
    if dev>10:   score+=20; flags.append({"label":f"Dev {dev:.0f}%","cls":"bad"})
    elif dev>3:  score+=8;  flags.append({"label":f"Dev {dev:.0f}%","cls":"warn"})
    else:                   flags.append({"label":"Dev 0%","cls":"ok"})
    hs    = gp.get("holders") or []
    top10 = min(sum(to_pct(h.get("percent",0)) for h in hs[:10]),100)
    top1  = min(to_pct(hs[0].get("percent",0)) if hs else 0, 100)
    if top10>70: score+=25; flags.append({"label":f"Top10: {top10:.0f}%","cls":"bad"})
    elif top10>50: score+=10; flags.append({"label":f"Top10: {top10:.0f}%","cls":"warn"})
    else:          flags.append({"label":f"Top10: {top10:.0f}%","cls":"ok"})
    if top1>15: score+=15; flags.append({"label":f"Bundle {top1:.0f}%","cls":"bad"})
    elif top1>8: score+=5; flags.append({"label":f"Bundle {top1:.0f}%","cls":"warn"})
    else:        flags.append({"label":f"Bundle {top1:.0f}%","cls":"ok"})
    holders = int(gp.get("holder_count") or 0)
    if 0<holders<100: score+=8; flags.append({"label":f"Tylko {holders} holderów","cls":"warn"})
    return min(score,100), flags, top1, top10, dev, lp_lock, holders

def safe_pct(v) -> float:
    """Konwertuje wartość na procenty — obsługuje 0-1 i 0-100 formaty."""
    try:
        f = float(v)
        # RugCheck zwraca np. 0.45 (=45%) lub 45.0
        return min(f * 100 if f <= 1.0 else f, 100.0)
    except Exception:
        return 0.0


def parse_rugcheck(rc: dict) -> tuple:
    """
    Parsuje odpowiedź RugCheck — obsługuje różne formaty API.
    Zwraca: (rc_score, top1, top10, dev_pct, lp_locked, h_count, risks)
    """
    if not rc:
        return 0, 0.0, 0.0, 0.0, False, 0, []

    rc_score = 0
    try:
        # score może być int lub float
        raw = rc.get("score") or rc.get("riskScore") or 0
        rc_score = int(float(raw))
    except Exception:
        pass

    # ── topHolders ──
    # Format 1: [{address, pct, ...}]   pct = 0.45 lub 45.0
    # Format 2: [{owner, amount, percentage}]  percentage = 45.0
    top1, top10 = 0.0, 0.0
    ths = rc.get("topHolders") or rc.get("holders") or []
    if ths:
        pcts = []
        for h in ths[:10]:
            v = h.get("pct") or h.get("percentage") or h.get("percent") or 0
            pcts.append(safe_pct(v))
        if pcts:
            top1  = pcts[0]
            top10 = min(sum(pcts), 100.0)

    # ── Dev / creator ──
    dev_pct = 0.0
    creator = rc.get("creator") or rc.get("creatorTokens") or {}
    if isinstance(creator, dict):
        v = creator.get("pct") or creator.get("percentage") or creator.get("percent") or 0
        dev_pct = safe_pct(v)

    # ── LP Lock ──
    lp_locked = False
    h_count   = 0
    markets   = rc.get("markets") or []
    for m in markets:
        lp = m.get("lp") or {}
        locked_pct = float(lp.get("lpLockedPct") or lp.get("lockedPct") or 0)
        if locked_pct > 50:
            lp_locked = True
        # Spróbuj wyciągnąć holder count
        if not h_count:
            h_count = int(m.get("holderCount") or m.get("holders") or 0)

    if not h_count:
        h_count = int(rc.get("holderCount") or rc.get("holders") or 0)

    # ── Risks ──
    risks = rc.get("risks") or []

    return rc_score, top1, top10, dev_pct, lp_locked, h_count, risks


def get_solscan_holders(addr: str) -> tuple:
    """Pobiera top holders z Solscan - fallback gdy RugCheck nie ma danych."""
    try:
        data = fetch(SOLSCAN_H.format(addr=addr), timeout=6)
        # Solscan może zwrócić różne formaty
        items = []
        if isinstance(data, dict):
            items = data.get("data", {}).get("items") or data.get("result") or data.get("items") or []
        if not items:
            return 0.0, 0.0, 0
        # Oblicz procenty z amount
        amounts = [float(h.get("amount") or h.get("uiAmount") or 0) for h in items[:10]]
        total = sum(float(h.get("amount") or 0) for h in items)
        if total <= 0:
            return 0.0, 0.0, 0
        pcts = [a / total * 100 for a in amounts if total > 0]
        top1 = min(pcts[0] if pcts else 0, 100)
        top10 = min(sum(pcts), 100)
        return round(top1, 1), round(top10, 1), len(items)
    except Exception as e:
        log.warning(f"Solscan ({addr[:10]}): {e}")
        return 0.0, 0.0, 0


def analyze_sol(pair: dict, age_h: float, rc: dict):
    score, flags = 0, []
    top1, top10, dev, lp_lock, holders = 0.0, 0.0, 0.0, False, 0

    liq  = float((pair.get("liquidity") or {}).get("usd") or 0)
    mcap = float(pair.get("marketCap") or 0)
    txns = pair.get("txns") or {}
    b1h  = int((txns.get("h1") or {}).get("buys") or 0)
    s1h  = int((txns.get("h1") or {}).get("sells") or 0)
    v24  = float((pair.get("volume") or {}).get("h24") or 0)

    if rc:
        rc_score, top1, top10, dev, lp_lock, holders, risks = parse_rugcheck(rc)

        # LP Lock
        if lp_lock:
            flags.append({"label": "LP Locked", "cls": "ok"})
        else:
            score += 20
            flags.append({"label": "Brak LP lock", "cls": "bad"})

        # Bundle (top1 holder)
        if top1 > 15:
            score += 15
            flags.append({"label": f"Bundle {top1:.0f}%", "cls": "bad"})
        elif top1 > 8:
            score += 5
            flags.append({"label": f"Bundle {top1:.0f}%", "cls": "warn"})
        elif top1 > 0:
            flags.append({"label": f"Bundle {top1:.0f}%", "cls": "ok"})

        # Top10
        if top10 > 70:
            score += 20
            flags.append({"label": f"Top10: {top10:.0f}%", "cls": "bad"})
        elif top10 > 50:
            score += 10
            flags.append({"label": f"Top10: {top10:.0f}%", "cls": "warn"})
        elif top10 > 0:
            flags.append({"label": f"Top10: {top10:.0f}%", "cls": "ok"})

        # Dev
        if dev > 10:
            score += 15
            flags.append({"label": f"Dev {dev:.0f}%", "cls": "bad"})
        elif dev > 3:
            score += 5
            flags.append({"label": f"Dev {dev:.0f}%", "cls": "warn"})

        # RugCheck score
        if rc_score > 500:
            score += 20
            flags.append({"label": f"RugCheck {rc_score} ⚠️", "cls": "bad"})
        elif rc_score > 200:
            score += 8
            flags.append({"label": f"RugCheck {rc_score}", "cls": "warn"})
        elif rc_score > 0:
            flags.append({"label": f"RugCheck ✓ ({rc_score})", "cls": "ok"})

        # Konkretne ryzyka z RugCheck
        for risk in risks[:4]:
            lvl = (risk.get("level") or "").lower()
            nm  = (risk.get("name") or risk.get("description") or "")[:32]
            if lvl in ("danger", "critical"):
                score += 8
                flags.append({"label": nm, "cls": "bad"})
            elif lvl in ("warn", "warning"):
                flags.append({"label": nm, "cls": "warn"})
    else:
        # RugCheck brak danych - spróbuj Solscan jako fallback
        addr_fb = (pair.get("baseToken") or {}).get("address", "")
        if addr_fb:
            s1, s10, sh = get_solscan_holders(addr_fb)
            if s1 > 0 or s10 > 0:
                top1, top10, holders = s1, s10, sh
                if top1 > 15:   score+=15; flags.append({"label":f"Bundle {top1:.0f}%","cls":"bad"})
                elif top1 > 8:  score+=5;  flags.append({"label":f"Bundle {top1:.0f}%","cls":"warn"})
                elif top1 > 0:             flags.append({"label":f"Bundle {top1:.0f}%","cls":"ok"})
                if top10 > 70:  score+=20; flags.append({"label":f"Top10: {top10:.0f}%","cls":"bad"})
                elif top10 > 50:score+=10; flags.append({"label":f"Top10: {top10:.0f}%","cls":"warn"})
                elif top10 > 0:            flags.append({"label":f"Top10: {top10:.0f}%","cls":"ok"})
            else:
                flags.append({"label":"Brak danych holders","cls":"warn"})
                score += 5
        else:
            flags.append({"label":"Brak danych holders","cls":"warn"})
            score += 5

    # ── Heurystyki DexScreener ──
    if mcap > 0:
        lr = liq / mcap
        if lr < 0.05:
            score += 15
            flags.append({"label": "Niska liq/mcap", "cls": "bad"})
        elif lr < 0.10:
            score += 5
            flags.append({"label": "Średnia liq/mcap", "cls": "warn"})
        else:
            flags.append({"label": "Dobra liquidity", "cls": "ok"})

    tot = b1h + s1h
    if tot > 0:
        sr = s1h / tot
        if sr > 0.65:
            score += 15
            flags.append({"label": f"Sell pressure {sr*100:.0f}%", "cls": "bad"})
        elif sr > 0.45:
            score += 5
            flags.append({"label": f"Sell ratio {sr*100:.0f}%", "cls": "warn"})
        else:
            flags.append({"label": f"Buy pressure {(1-sr)*100:.0f}%", "cls": "ok"})

    if mcap > 0 and v24 / mcap > 25:
        score += 10
        flags.append({"label": "Podejrzany vol/mcap", "cls": "warn"})

    return min(score, 100), flags, top1, top10, dev, lp_lock, holders

def fmt_age(h: float) -> str:
    if h<1: return f"{int(h*60)}m"
    if h<48: return f"{h:.0f}h"
    return f"{h/24:.0f}d"

# ── PROCESSING ────────────────────────────────────────────────────────────────

def process_pairs(pairs: list, tab: str, chain_filter: str) -> list:
    f      = TAB_FILTERS.get(tab, TAB_FILTERS["growing"])
    now_ms = time.time()*1000
    bl     = load_blacklist()
    results, seen = [], set()

    for pair in pairs:
        try:
            cid   = (pair.get("chainId") or "").lower()
            if cid not in ("solana","ethereum"): continue
            chain = "SOL" if cid=="solana" else "ETH"
            if chain_filter!="ALL" and chain!=chain_filter: continue

            base    = pair.get("baseToken") or {}
            address = base.get("address","")
            name    = base.get("name","Unknown")
            sym     = base.get("symbol","?")
            if not address or address in seen: continue
            seen.add(address)

            # ── Blacklist check ──
            is_bl, bl_reason = is_blacklisted(name, sym, address)
            if is_bl:
                log.info(f"Pominięto (blacklist): {name} — {bl_reason}")
                continue

            price     = float(pair.get("priceUsd") or 0)
            ch_24h    = float((pair.get("priceChange") or {}).get("h24") or 0)
            ch_1h     = float((pair.get("priceChange") or {}).get("h1") or 0)
            ch_6h     = float((pair.get("priceChange") or {}).get("h6") or 0)
            mcap      = float(pair.get("marketCap") or 0)
            vol_24h   = float((pair.get("volume") or {}).get("h24") or 0)
            vol_1h    = float((pair.get("volume") or {}).get("h1") or 0)
            vol_6h    = float((pair.get("volume") or {}).get("h6") or 0)
            liq       = float((pair.get("liquidity") or {}).get("usd") or 0)
            created   = pair.get("pairCreatedAt") or 0
            txns      = pair.get("txns") or {}
            b1h       = int((txns.get("h1") or {}).get("buys") or 0)
            s1h       = int((txns.get("h1") or {}).get("sells") or 0)
            b24h      = int((txns.get("h24") or {}).get("buys") or 0)
            s24h      = int((txns.get("h24") or {}).get("sells") or 0)
            age_h     = (now_ms-created)/3_600_000 if created else 9999

            # ── Twarde filtry ──
            if age_h < f["min_h"] or age_h > f["max_h"]: continue
            if liq < f["min_liq"]:
                if 0 < liq < 1000:
                    auto_blacklist({"address":address,"name":name,"sym":sym,"chain":chain},
                                   f"Za niska liq: ${liq:.0f}")
                continue

            # Min transakcji 24h - eliminuje martwe tokeny i śmieciowe pary
            total_txns = b24h + s24h
            min_txns = f.get("min_txns", 20)
            if total_txns < min_txns:
                continue
            if mcap  < f["min_mcap"]:  continue
            if vol_1h< f["min_vol1h"]: continue
            if ch_1h < f["min_ch1h"]:  continue

            # ── Viral: wymaga volume spike ──
            if tab=="viral":
                avg_6h = vol_6h/6 if vol_6h>0 else 1
                if vol_1h < avg_6h*2: continue

            # ── Security ──
            if chain=="ETH":
                gp = get_goplus_eth(address)
                if gp: risk,flags,top1,top10,dev,lp_lock,holders = analyze_eth(gp)
                else:  risk,flags,top1,top10,dev,lp_lock,holders = 35,[{"label":"Brak GoPlus","cls":"warn"}],0,0,0,False,0
            else:
                rc = get_rugcheck_sol(address)
                risk,flags,top1,top10,dev,lp_lock,holders = analyze_sol(pair, age_h, rc)

            results.append({
                "name":name,"sym":sym,"address":address,"chain":chain,
                "price":price,"change":round(ch_24h,1),"change1h":round(ch_1h,1),
                "change6h":round(ch_6h,1),"mcap":mcap,"vol":vol_24h,"vol1h":vol_1h,
                "vol6h":vol_6h,"liq":liq,"age":fmt_age(age_h),"age_h":round(age_h,2),
                "buys1h":b1h,"sells1h":s1h,"buys24h":b24h,"sells24h":s24h,
                "bundle":round(top1,1),"top10":round(top10,1),"devHold":round(dev,1),
                "lpLock":lp_lock,"holders":holders,"risk":risk,"flags":flags,
                "dexUrl":pair.get("url",f"https://dexscreener.com/{cid}/{address}"),
                "rcUrl":f"https://rugcheck.xyz/tokens/{address}" if chain=="SOL" else "",
            })
        except Exception as e:
            log.warning(f"process error: {e}")

    # Sortuj
    if tab in ("new","pump"):  results.sort(key=lambda x: x["change1h"], reverse=True)
    elif tab=="viral":         results.sort(key=lambda x: x["vol1h"], reverse=True)
    else:                      results.sort(key=lambda x: x["change"], reverse=True)
    return results[:25]


def get_all_pairs(tab: str, chain_filter: str) -> list:
    seen_addr, all_pairs = set(), []
    def add(pairs):
        for p in pairs:
            addr = (p.get("baseToken") or {}).get("address","")
            if addr and addr not in seen_addr:
                seen_addr.add(addr); all_pairs.append(p)

    if tab in ("new","pump"):
        add(get_search_pairs(chain_filter))
        add(get_boosted_pairs(chain_filter))
    elif tab=="viral":
        add(get_boosted_pairs(chain_filter))
        add(get_search_pairs(chain_filter))
    else:
        add(get_search_pairs(chain_filter))
        add(get_boosted_pairs(chain_filter))

    log.info(f"Łącznie par: {len(all_pairs)}")
    return all_pairs


# ── BACKGROUND REFRESH ────────────────────────────────────────────────────────

def background_refresh():
    """Odświeża cache co 3 minuty w tle dla wszystkich zakładek."""
    while True:
        for tab in ["new","pump","growing","viral"]:
            try:
                pairs  = get_all_pairs(tab, "ALL")
                tokens = process_pairs(pairs, tab, "ALL")
                key    = f"{tab}_ALL"
                with cache_lock:
                    CACHE[key] = {"tokens":tokens,"ts":time.time(),"count":len(tokens)}
                log.info(f"Cache refresh [{tab}]: {len(tokens)} tokenów")

                if PATTERN_ENGINE:
                    for t in tokens[:8]:
                        try:
                            PE.add_token_to_track(t["address"],t["chain"],t["name"],t["sym"],
                                                  t["price"],t["mcap"],t["vol1h"],t["liq"],
                                                  t["risk"],t["flags"])
                        except Exception: pass
            except Exception as e:
                log.error(f"BG refresh [{tab}]: {e}")
        time.sleep(CACHE_TTL)


def get_cached(tab: str, chain_filter: str) -> dict:
    key = f"{tab}_ALL"
    with cache_lock:
        entry = CACHE.get(key)

    if entry and time.time()-entry["ts"] < CACHE_TTL*2:
        tokens = entry["tokens"]
        if chain_filter != "ALL":
            tokens = [t for t in tokens if t["chain"]==chain_filter]
        return {"ok":True,"tokens":tokens,"count":len(tokens),"cached":True,
                "age_s":int(time.time()-entry["ts"])}
    return None

# ── HTTP HANDLER ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info(f"{self.address_string()} {fmt%args}")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self):
        try:
            body = open(HTML_FILE,"rb").read()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(404); self.end_headers()
            self.wfile.write(b"Brak index.html")

    def do_GET(self):
        parsed = urlparse(self.path)
        qs     = parse_qs(parsed.query)

        if parsed.path in ("/","/index.html"):
            self.send_html(); return

        if parsed.path=="/api/scan":
            tab   = qs.get("tab",  ["new"])[0]
            chain = qs.get("chain",["ALL"])[0].upper()
            force = qs.get("force",["0"])[0]=="1"
            log.info(f"Scan: tab={tab} chain={chain} force={force}")

            # Spróbuj z cache
            if not force:
                cached = get_cached(tab, chain)
                if cached:
                    log.info(f"Cache hit [{tab}] ({cached['age_s']}s)")
                    self.send_json(cached); return

            # Świeże dane
            try:
                pairs  = get_all_pairs(tab, chain)
                tokens = process_pairs(pairs, tab, chain)
                log.info(f"Świeże [{tab}]: {len(tokens)} tokenów")
                result = {"ok":True,"tokens":tokens,"count":len(tokens),"cached":False}
                # Zapisz do cache
                with cache_lock:
                    CACHE[f"{tab}_ALL"] = {"tokens":tokens,"ts":time.time(),"count":len(tokens)}
                self.send_json(result)
                if PATTERN_ENGINE:
                    for t in tokens[:8]:
                        try: PE.add_token_to_track(t["address"],t["chain"],t["name"],t["sym"],t["price"],t["mcap"],t["vol1h"],t["liq"],t["risk"],t["flags"])
                        except Exception: pass
            except Exception as e:
                log.error(f"Scan error: {e}", exc_info=True)
                self.send_json({"ok":False,"error":str(e)},500)
            return

        if parsed.path=="/api/patterns":
            if PATTERN_ENGINE:
                self.send_json(PE.get_pattern_data_for_api())
            else:
                self.send_json({"ok":False,"stats":{},"tracked_tokens":[],"lessons":[],"recent_rugs":[],"recent_gems":[]})
            return

        if parsed.path=="/api/results":
            if PATTERN_ENGINE:
                self.send_json(PE.get_results_data())
            else:
                self.send_json({"tokens":[],"total":0,"gems_count":0,"rugs_count":0})
            return

        if parsed.path=="/api/blacklist":
            self.send_json(load_blacklist()); return

        self.send_response(404); self.end_headers()


def clean_blacklisted_from_patterns():
    """Usuwa zblacklistowane tokeny z pattern_data.json przy starcie."""
    try:
        import os as _os
        pf = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "pattern_data.json")
        if not _os.path.exists(pf):
            return
        import json as _json
        data = _json.load(open(pf))
        tokens = data.get("tokens", {})
        removed = []
        for addr, t in list(tokens.items()):
            name = t.get("name","")
            sym  = t.get("sym","")
            is_bl, reason = is_blacklisted(name, sym, addr)
            if is_bl:
                del tokens[addr]
                removed.append(name)
        if removed:
            _json.dump(data, open(pf,"w"), indent=2)
            log.info(f"Usunięto z pattern_data: {removed}")
    except Exception as e:
        log.warning(f"clean_blacklisted: {e}")


def main():
    import os
    port   = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), Handler)
    log.info("╔══════════════════════════════════════╗")
    log.info("║  GemHunter v5 uruchomiony!           ║")
    log.info(f"║  Chrome: http://localhost:{port}        ║")
    log.info("╚══════════════════════════════════════╝")

    # Pattern Engine w tle
    # Wyczyść blacklistowane tokeny z pattern data
    clean_blacklisted_from_patterns()

    if PATTERN_ENGINE:
        threading.Thread(target=PE.run_tracking_loop, daemon=True).start()
        log.info("Pattern Engine uruchomiony")

    # Auto-refresh cache w tle
    threading.Thread(target=background_refresh, daemon=True).start()
    log.info(f"Auto-refresh uruchomiony (co {CACHE_TTL}s)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Zatrzymano.")

if __name__=="__main__":
    main()
