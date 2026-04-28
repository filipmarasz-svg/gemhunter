"""
GemHunter Pattern Engine — silnik uczenia się na wzorcach wykresów
Zapisuje historię tokenów, klasyfikuje wzorce, uczy się co jest gemem a co rugiem.

Uruchom osobno: python pattern_engine.py
Lub razem z serwerem: uruchom oba w dwóch terminalach.
"""
import json, os, time, logging, threading
from urllib.request import urlopen, Request
from urllib.parse import quote
from datetime import datetime, timezone
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PATTERN] %(message)s")
log = logging.getLogger(__name__)

DATA_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pattern_data.json")
REPORT_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pattern_report.json")
CHECK_INTERVAL = 300   # sprawdzaj co 5 minut
TRACK_HOURS    = 48    # śledź token przez 48h

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; GemHunter/1.0)", "Accept": "application/json"}

DS_TOKEN = "https://api.dexscreener.com/latest/dex/tokens/{addr}"

# ── WZORCE WYKRESÓW ──────────────────────────────────────────────────────────

PATTERNS = {
    "organic_pump": {
        "desc": "Zdrowy wzrost — stopniowy wzrost ceny z rosnącym wolumenem i holderami",
        "emoji": "🟢",
        "signals": ["steady_rise", "volume_growing", "no_sudden_dump", "buys_exceed_sells"],
    },
    "pump_and_dump": {
        "desc": "Pump & Dump — gwałtowny wzrost potem równie gwałtowny spadek",
        "emoji": "🔴",
        "signals": ["spike_then_crash", "vol_spike_single", "sell_pressure_after_peak"],
    },
    "rug_pull": {
        "desc": "Rug Pull — nagłe wycofanie liquidity, cena spada do 0",
        "emoji": "💀",
        "signals": ["liquidity_removed", "price_drop_90pct", "no_recovery"],
    },
    "slow_bleed": {
        "desc": "Slow Bleed — stopniowy spadek bez wyraźnego pumpu",
        "emoji": "🟠",
        "signals": ["gradual_decline", "low_volume", "sells_exceed_buys"],
    },
    "consolidation": {
        "desc": "Konsolidacja — stabilna cena, może być przed kolejnym ruchem",
        "emoji": "🟡",
        "signals": ["flat_price", "moderate_volume"],
    },
    "wojak_pattern": {
        "desc": "Wzorzec Wojak/ETH — klasyk meme ETH: akumulacja → viral pump → consolidacja",
        "emoji": "🐸",
        "signals": ["eth_chain", "cultural_meme_name", "mid_cap_range", "vol_mcap_healthy"],
    },
    "asteroid_pattern": {
        "desc": "Wzorzec Asteroid — nagły viral spike bez wcześniejszej historii",
        "emoji": "☄️",
        "signals": ["sudden_viral", "no_accumulation", "extreme_vol_spike"],
    },
}

# ── STORAGE ──────────────────────────────────────────────────────────────────

def load_data() -> dict:
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"tokens": {}, "patterns": defaultdict(int), "stats": {"total_tracked": 0, "rugs_detected": 0, "gems_found": 0}}

def save_data(data: dict):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_report() -> dict:
    if os.path.exists(REPORT_FILE):
        try:
            with open(REPORT_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_update": None, "top_patterns": [], "recent_rugs": [], "recent_gems": [], "lessons": []}

def save_report(report: dict):
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

# ── API ───────────────────────────────────────────────────────────────────────

def fetch_token_data(address: str, chain: str) -> dict | None:
    try:
        req = Request(DS_TOKEN.format(addr=address), headers=HEADERS)
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        pairs = data.get("pairs") or []
        # Znajdź parę dla właściwego łańcucha
        chain_id = "solana" if chain == "SOL" else "ethereum"
        for p in pairs:
            if (p.get("chainId") or "").lower() == chain_id:
                return p
        return pairs[0] if pairs else None
    except Exception as e:
        log.warning(f"Fetch error ({address[:10]}): {e}")
        return None

# ── KLASYFIKACJA WZORCÓW ─────────────────────────────────────────────────────

def classify_pattern(snapshots: list[dict], token_meta: dict) -> dict:
    """
    Analizuje historię snapshotów i klasyfikuje wzorzec wykresu.
    Każdy snapshot: {ts, price, mcap, vol1h, buys1h, sells1h, liq}
    """
    if len(snapshots) < 2:
        return {"pattern": "unknown", "confidence": 0, "reason": "Za mało danych"}

    prices   = [s["price"] for s in snapshots if s.get("price")]
    vols     = [s.get("vol1h", 0) for s in snapshots]
    liqs     = [s.get("liq", 0) for s in snapshots]
    buys     = [s.get("buys1h", 0) for s in snapshots]
    sells    = [s.get("sells1h", 0) for s in snapshots]

    if not prices or prices[0] == 0:
        return {"pattern": "unknown", "confidence": 0, "reason": "Brak danych cenowych"}

    p_first  = prices[0]
    p_last   = prices[-1]
    p_max    = max(prices)
    p_min    = min(prices)

    pct_change_total = (p_last - p_first) / p_first * 100 if p_first > 0 else 0
    pct_from_peak    = (p_last - p_max) / p_max * 100 if p_max > 0 else 0
    liq_change       = (liqs[-1] - liqs[0]) / liqs[0] * 100 if liqs[0] > 0 else 0
    vol_trend        = (vols[-1] - vols[0]) / vols[0] * 100 if vols[0] > 0 else 0
    avg_buy_ratio    = sum(b/(b+s) if b+s > 0 else 0.5 for b,s in zip(buys,sells)) / len(buys)

    chain  = token_meta.get("chain", "")
    name   = (token_meta.get("name", "") + token_meta.get("sym", "")).lower()
    mcap   = token_meta.get("mcap", 0)

    # ── RUG PULL: liquidity wycofana + cena -80% ──
    if liq_change < -60 and pct_change_total < -70:
        reason = f"Liq -{abs(liq_change):.0f}%, cena {pct_change_total:.0f}%"
        return {"pattern": "rug_pull", "confidence": 95, "reason": reason,
                "pct_change": pct_change_total, "liq_change": liq_change}

    # ── PUMP & DUMP: peak > 3x, potem spadek > 60% od szczytu ──
    if p_max > p_first * 3 and pct_from_peak < -60:
        reason = f"Peak +{(p_max/p_first-1)*100:.0f}%, potem {pct_from_peak:.0f}% od szczytu"
        return {"pattern": "pump_and_dump", "confidence": 88, "reason": reason,
                "pct_change": pct_change_total, "peak_multiple": p_max/p_first}

    # ── ASTEROID: nagły spike vol w 1 snapshocie, brak historii ──
    if len(vols) >= 3:
        max_vol_idx = vols.index(max(vols))
        if max_vol_idx == 1 and vols[1] > vols[0] * 10 and (len(vols) < 4 or vols[2] < vols[1] * 0.3):
            return {"pattern": "asteroid_pattern", "confidence": 80,
                    "reason": f"Vol spike x{vols[1]/max(vols[0],1):.0f} w snapshot 1, potem zanik",
                    "pct_change": pct_change_total}

    # ── WOJAK/ETH: ETH + kulturowa nazwa + MCap 1M-100M + zdrowy vol/mcap ──
    meme_words = ["wojak","pepe","frog","feels","chad","based","doge","cat","ape","moon","cope","rare"]
    is_cultural_meme = any(w in name for w in meme_words)
    if chain == "ETH" and is_cultural_meme and 1_000_000 < mcap < 100_000_000:
        vol_mcap_ratio = sum(vols) / mcap if mcap > 0 else 0
        if 0.1 < vol_mcap_ratio < 5 and avg_buy_ratio > 0.5:
            return {"pattern": "wojak_pattern", "confidence": 75,
                    "reason": f"ETH cultural meme, MCap ${mcap/1e6:.1f}M, vol/mcap={vol_mcap_ratio:.2f}",
                    "pct_change": pct_change_total}

    # ── ORGANIC PUMP: stopniowy wzrost > 50% z rosnącym vol ──
    if pct_change_total > 50 and vol_trend > 20 and avg_buy_ratio > 0.55 and pct_from_peak > -30:
        return {"pattern": "organic_pump", "confidence": 72,
                "reason": f"+{pct_change_total:.0f}% total, vol +{vol_trend:.0f}%, buy ratio {avg_buy_ratio:.0%}",
                "pct_change": pct_change_total}

    # ── SLOW BLEED: stopniowy spadek ──
    if pct_change_total < -40 and avg_buy_ratio < 0.45:
        return {"pattern": "slow_bleed", "confidence": 65,
                "reason": f"{pct_change_total:.0f}% total, sell dominuje {(1-avg_buy_ratio):.0%}",
                "pct_change": pct_change_total}

    # ── KONSOLIDACJA: cena +/-20% ──
    if abs(pct_change_total) < 20:
        return {"pattern": "consolidation", "confidence": 60,
                "reason": f"Stabilna cena {pct_change_total:+.0f}% total",
                "pct_change": pct_change_total}

    return {"pattern": "unknown", "confidence": 40,
            "reason": f"Nieznany wzorzec, zmiana {pct_change_total:+.0f}%",
            "pct_change": pct_change_total}


def generate_lesson(pattern: str, token: dict, result: dict) -> str:
    """Generuje lekcję czego bot się nauczył z tego tokenu."""
    name = token.get("name", "Unknown")
    chain = token.get("chain", "?")
    p = result.get("pattern", "unknown")
    reason = result.get("reason", "")
    pct = result.get("pct_change", 0)

    lessons_map = {
        "rug_pull": f"[{chain}] {name} → RUG PULL ({reason}). Sygnały: niska liq, koncentracja holderów",
        "pump_and_dump": f"[{chain}] {name} → P&D: pump x{result.get('peak_multiple',0):.1f}, potem {pct:.0f}%",
        "organic_pump": f"[{chain}] {name} → GEM: +{pct:.0f}% organic. Pattern: {reason}",
        "wojak_pattern": f"[ETH] {name} → Wojak pattern: {reason}",
        "asteroid_pattern": f"[{chain}] {name} → Asteroid spike: {reason}. Uwaga na exit timing",
        "slow_bleed": f"[{chain}] {name} → Slow bleed {pct:.0f}%. Unikaj przy niskim buy ratio",
        "consolidation": f"[{chain}] {name} → Konsolidacja. Czekaj na breakout z vol potwierdzeniem",
    }
    return lessons_map.get(p, f"[{chain}] {name} → {p}: {reason}")

# ── TRACKER ───────────────────────────────────────────────────────────────────

def add_token_to_track(address: str, chain: str, name: str, sym: str,
                       price: float, mcap: float, vol1h: float, liq: float,
                       risk: int, flags: list):
    """Dodaje token do śledzenia."""
    data = load_data()
    if address in data["tokens"]:
        return  # już śledzony

    now = time.time()
    data["tokens"][address] = {
        "address": address,
        "chain": chain,
        "name": name,
        "sym": sym,
        "mcap": mcap,
        "initial_risk": risk,
        "flags": flags,
        "added_at": now,
        "last_checked": now,
        "snapshots": [{
            "ts": now,
            "price": price,
            "mcap": mcap,
            "vol1h": vol1h,
            "liq": liq,
            "buys1h": 0,
            "sells1h": 0,
        }],
        "pattern": None,
        "pattern_confidence": 0,
        "status": "tracking",  # tracking | classified | archived
    }
    data["stats"]["total_tracked"] = data["stats"].get("total_tracked", 0) + 1
    save_data(data)
    log.info(f"Dodano do śledzenia: {name} ({chain}) addr={address[:12]}...")


def update_tracked_tokens():
    """Pobiera aktualne dane dla wszystkich śledzonych tokenów."""
    data = load_data()
    now = time.time()
    to_archive = []

    for addr, token in data["tokens"].items():
        if token.get("status") == "archived":
            continue

        # Sprawdź czy czas śledzenia minął
        added_at = token.get("added_at", now)
        if now - added_at > TRACK_HOURS * 3600:
            token["status"] = "archived"
            to_archive.append(addr)
            continue

        # Sprawdź czy minęło wystarczająco czasu od ostatniego sprawdzenia
        last = token.get("last_checked", 0)
        if now - last < CHECK_INTERVAL:
            continue

        # Pobierz aktualne dane
        pair = fetch_token_data(addr, token["chain"])
        if pair:
            price   = float(pair.get("priceUsd") or 0)
            vol1h   = float((pair.get("volume") or {}).get("h1") or 0)
            liq     = float((pair.get("liquidity") or {}).get("usd") or 0)
            mcap    = float(pair.get("marketCap") or 0)
            txns    = pair.get("txns") or {}
            buys1h  = int((txns.get("h1") or {}).get("buys") or 0)
            sells1h = int((txns.get("h1") or {}).get("sells") or 0)

            snapshot = {
                "ts": now, "price": price, "mcap": mcap,
                "vol1h": vol1h, "liq": liq,
                "buys1h": buys1h, "sells1h": sells1h,
            }
            token["snapshots"].append(snapshot)
            token["last_checked"] = now

            # Klasyfikuj wzorzec po 3+ snapshotach
            snaps = token["snapshots"]
            if len(snaps) >= 3:
                result = classify_pattern(snaps, token)
                token["pattern"] = result["pattern"]
                token["pattern_confidence"] = result["confidence"]
                token["pattern_reason"] = result.get("reason", "")
                token["pct_change"] = result.get("pct_change", 0)

                if result["pattern"] == "rug_pull":
                    data["stats"]["rugs_detected"] = data["stats"].get("rugs_detected", 0) + 1
                    log.warning(f"🚨 RUG PULL wykryty: {token['name']} ({token['chain']})")
                elif result["pattern"] in ("organic_pump", "wojak_pattern"):
                    data["stats"]["gems_found"] = data["stats"].get("gems_found", 0) + 1

            log.info(f"Update {token['name']}: price={price:.8f}, pattern={token.get('pattern','?')}")

    save_data(data)
    generate_report(data)


def generate_report(data: dict):
    """Generuje raport z lekcjami i statystykami."""
    report = load_report()

    tokens = list(data["tokens"].values())
    classified = [t for t in tokens if t.get("pattern") and t["pattern"] != "unknown"]

    # Zlicz wzorce
    pattern_counts = defaultdict(int)
    for t in classified:
        pattern_counts[t["pattern"]] += 1

    # Ostatnie rugi
    recent_rugs = [t for t in classified if t["pattern"] == "rug_pull"]
    recent_rugs.sort(key=lambda x: x.get("last_checked", 0), reverse=True)

    # Ostatnie gemy
    recent_gems = [t for t in classified if t["pattern"] in ("organic_pump", "wojak_pattern", "asteroid_pattern")]
    recent_gems.sort(key=lambda x: abs(x.get("pct_change", 0)), reverse=True)

    # Generuj lekcje dla nowo sklasyfikowanych
    lessons = report.get("lessons", [])
    for t in classified:
        lesson = generate_lesson(t["pattern"], t, {"pattern": t["pattern"], "reason": t.get("pattern_reason",""), "pct_change": t.get("pct_change",0), "peak_multiple": 1})
        if lesson not in lessons:
            lessons.append(lesson)
    lessons = lessons[-50:]  # max 50 ostatnich lekcji

    report = {
        "last_update": datetime.now(timezone.utc).isoformat(),
        "stats": data.get("stats", {}),
        "total_tracked": len(tokens),
        "classified": len(classified),
        "pattern_counts": dict(pattern_counts),
        "top_patterns": sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        "recent_rugs": [{"name":t["name"],"chain":t["chain"],"reason":t.get("pattern_reason",""),"pct":t.get("pct_change",0)} for t in recent_rugs[:5]],
        "recent_gems": [{"name":t["name"],"chain":t["chain"],"pattern":t["pattern"],"pct":t.get("pct_change",0),"confidence":t.get("pattern_confidence",0)} for t in recent_gems[:5]],
        "lessons": lessons,
        "risk_signals_learned": compute_risk_signals(classified),
    }
    save_report(report)
    log.info(f"Raport: {len(classified)} sklasyfikowanych, {len(recent_rugs)} rugów, {len(recent_gems)} gemów")


def compute_risk_signals(classified: list) -> dict:
    """
    Uczy się które sygnały ryzyka najczęściej poprzedzają rug pulle i dumpy.
    Zwraca scoring sygnałów oparty na historii.
    """
    rug_flags = defaultdict(int)
    gem_flags = defaultdict(int)
    total_rugs = 0
    total_gems = 0

    for t in classified:
        flags = [f.get("label","") for f in (t.get("flags") or [])]
        if t["pattern"] in ("rug_pull", "pump_and_dump"):
            total_rugs += 1
            for f in flags:
                rug_flags[f] += 1
        elif t["pattern"] in ("organic_pump", "wojak_pattern"):
            total_gems += 1
            for f in flags:
                gem_flags[f] += 1

    learned = {}
    all_flags = set(list(rug_flags.keys()) + list(gem_flags.keys()))
    for flag in all_flags:
        rug_rate  = rug_flags[flag] / max(total_rugs, 1)
        gem_rate  = gem_flags[flag] / max(total_gems, 1)
        learned[flag] = {
            "rug_correlation": round(rug_rate, 2),
            "gem_correlation": round(gem_rate, 2),
            "signal": "danger" if rug_rate > gem_rate * 1.5 else ("positive" if gem_rate > rug_rate * 1.5 else "neutral"),
        }
    return learned


# ── API ENDPOINT DLA SERWERA ──────────────────────────────────────────────────

def get_pattern_data_for_api() -> dict:
    """Zwraca dane wzorców dla frontendu."""
    report = load_report()
    data   = load_data()
    tokens = list(data.get("tokens", {}).values())

    active = [t for t in tokens if t.get("status") == "tracking"]
    classified = [t for t in tokens if t.get("pattern") and t["pattern"] not in ("unknown", None)]

    return {
        "stats": report.get("stats", {}),
        "total_tracked": len(tokens),
        "active_tracking": len(active),
        "classified": len(classified),
        "pattern_counts": report.get("pattern_counts", {}),
        "recent_rugs": report.get("recent_rugs", []),
        "recent_gems": report.get("recent_gems", []),
        "lessons": report.get("lessons", [])[-10:],
        "risk_signals": report.get("risk_signals_learned", {}),
        "tracked_tokens": [
            {
                "name": t["name"], "sym": t["sym"], "chain": t["chain"],
                "pattern": t.get("pattern"), "confidence": t.get("pattern_confidence", 0),
                "pct_change": t.get("pct_change", 0),
                "reason": t.get("pattern_reason", ""),
                "snapshots_count": len(t.get("snapshots", [])),
                "added_ago": f"{int((time.time()-t.get('added_at',time.time()))/3600)}h",
                "dexUrl": f"https://dexscreener.com/{'solana' if t['chain']=='SOL' else 'ethereum'}/{t['address']}",
            }
            for t in sorted(classified, key=lambda x: abs(x.get("pct_change",0)), reverse=True)[:20]
        ]
    }




def get_results_data() -> dict:
    """
    Zwraca dane wyników dla zakładki Wyniki.
    Dla każdego tokenu liczy x-krotność wzrostu od momentu dodania.
    """
    data   = load_data()
    tokens = list(data.get("tokens", {}).values())
    results = []

    for t in tokens:
        snaps = t.get("snapshots", [])
        if len(snaps) < 1:
            continue

        p0 = snaps[0].get("price", 0)
        if not p0:
            continue

        # Aktualna cena = ostatni snapshot
        p_now  = snaps[-1].get("price", 0)
        p_max  = max((s.get("price",0) for s in snaps), default=0)

        x_now  = round(p_now / p0, 2) if p0 > 0 else 0
        x_max  = round(p_max / p0, 2) if p0 > 0 else 0
        pct_now = round((p_now/p0 - 1)*100, 1) if p0 > 0 else 0
        pct_max = round((p_max/p0 - 1)*100, 1) if p0 > 0 else 0

        age_h   = round((time.time() - t.get("added_at", time.time())) / 3600, 1)
        snaps_n = len(snaps)

        # Status wyniku
        if x_now >= 3:      outcome = "gem"
        elif x_now >= 1.5:  outcome = "good"
        elif x_now >= 0.8:  outcome = "neutral"
        elif x_now >= 0.4:  outcome = "loss"
        else:               outcome = "rug"

        # Czy to był rug (cena blisko 0)
        is_rug = p_now < p0 * 0.1 and snaps_n > 3

        results.append({
            "name":       t.get("name","?"),
            "sym":        t.get("sym","?"),
            "chain":      t.get("chain","?"),
            "address":    t.get("address",""),
            "added_at":   t.get("added_at",0),
            "age_h":      age_h,
            "price_entry":p0,
            "price_now":  p_now,
            "price_peak": p_max,
            "x_now":      x_now,
            "x_max":      x_max,
            "pct_now":    pct_now,
            "pct_max":    pct_max,
            "pattern":    t.get("pattern","unknown"),
            "initial_risk": t.get("initial_risk",0),
            "snapshots":  snaps_n,
            "outcome":    outcome,
            "is_rug":     is_rug,
            "flags":      t.get("flags",[]),
            "dexUrl":     f"https://dexscreener.com/{'solana' if t.get('chain')=='SOL' else 'ethereum'}/{t.get('address','')}",
        })

    # Sortuj: najpierw gemy, potem reszta, na końcu rugi
    order = {"gem":0,"good":1,"neutral":2,"loss":3,"rug":4}
    results.sort(key=lambda x: (order.get(x["outcome"],5), -abs(x["pct_now"])))

    # Statystyki uczenia się
    total    = len(results)
    gems     = [r for r in results if r["outcome"] in ("gem","good")]
    rugs     = [r for r in results if r["outcome"]=="rug"]
    losses   = [r for r in results if r["outcome"]=="loss"]
    neutrals = [r for r in results if r["outcome"]=="neutral"]

    # Korelacja: jakie ryzyko miały gemy vs rugi
    gem_risks  = [r["initial_risk"] for r in gems if r["initial_risk"]>0]
    rug_risks  = [r["initial_risk"] for r in rugs if r["initial_risk"]>0]
    avg_gem_risk = round(sum(gem_risks)/len(gem_risks),1) if gem_risks else 0
    avg_rug_risk = round(sum(rug_risks)/len(rug_risks),1) if rug_risks else 0

    # Które flagi najczęściej były przy gemach
    gem_flag_counts = {}
    rug_flag_counts = {}
    for r in gems:
        for f in (r.get("flags") or []):
            lbl = f.get("label","")
            gem_flag_counts[lbl] = gem_flag_counts.get(lbl,0)+1
    for r in rugs:
        for f in (r.get("flags") or []):
            lbl = f.get("label","")
            rug_flag_counts[lbl] = rug_flag_counts.get(lbl,0)+1

    top_gem_flags = sorted(gem_flag_counts.items(), key=lambda x:-x[1])[:5]
    top_rug_flags = sorted(rug_flag_counts.items(), key=lambda x:-x[1])[:5]

    return {
        "tokens":         results,
        "total":          total,
        "gems_count":     len(gems),
        "rugs_count":     len(rugs),
        "losses_count":   len(losses),
        "neutral_count":  len(neutrals),
        "avg_gem_risk":   avg_gem_risk,
        "avg_rug_risk":   avg_rug_risk,
        "top_gem_flags":  top_gem_flags,
        "top_rug_flags":  top_rug_flags,
        "best_token":     max(results, key=lambda x: x["x_max"], default=None),
        "worst_token":    min(results, key=lambda x: x["x_now"], default=None),
    }
# ── MAIN LOOP ─────────────────────────────────────────────────────────────────

def run_tracking_loop():
    log.info("Pattern Engine uruchomiony. Sprawdzam co 5 minut...")
    while True:
        try:
            update_tracked_tokens()
        except Exception as e:
            log.error(f"Loop error: {e}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    log.info("╔══════════════════════════════════════╗")
    log.info("║  GemHunter Pattern Engine v1         ║")
    log.info("║  Śledzenie i klasyfikacja wzorców    ║")
    log.info("╚══════════════════════════════════════╝")
    run_tracking_loop()
