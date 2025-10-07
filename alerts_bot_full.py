# (BEGIN SCRIPT) - paste entire content below into alerts_bot_full.py

"""
alerts_bot_full.py
Single-file alerts worker — polls FiscalData (Treasury gold), Fed H.4.1,
Federal Register, CFTC Socrata publicreporting, gold futures via yfinance,
BTC price via CoinGecko, mempool large BTC txs via blockchain.info.
Sends alerts to Telegram, Slack (incoming webhook), and Email (SMTP).
Configure via repository Secrets (see README steps).
"""

import os
import logging
import requests
from datetime import datetime
from pycoingecko import CoinGeckoAPI
import yfinance as yf
from sodapy import Socrata
import smtplib
from email.message import EmailMessage

# -------------------------
# Logging
# -------------------------
LOG = logging.getLogger("alerts_bot_full")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# -------------------------
# Environment / Config
# -------------------------
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")  # optional

EMAIL_SMTP_SERVER = os.environ.get("EMAIL_SMTP_SERVER")            # e.g. smtp.gmail.com
EMAIL_SMTP_PORT = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
ALERT_EMAIL_USERNAME = os.environ.get("ALERT_EMAIL_USERNAME")      # sender email
ALERT_EMAIL_PASSWORD = os.environ.get("ALERT_EMAIL_PASSWORD")      # app password
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO")                  # comma-separated recipients

BLOCKCHAIR_API_KEY = os.environ.get("BLOCKCHAIR_API_KEY")  # optional
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY")    # optional

# Tuning
GOLD_7D_MOVE_PCT_ALERT = float(os.environ.get("GOLD_7D_MOVE_PCT_ALERT", "0.07"))
BTC_USD_WHALE_USD_THRESHOLD = float(os.environ.get("BTC_USD_WHALE_USD_THRESHOLD", "5000000"))

FED_TEXT_KEYWORDS = [k.strip().lower() for k in os.environ.get(
    "FED_TEXT_KEYWORDS", "gold,revalue,revaluation,gold certificate,monetiz,tokenize,reserve").split(",")]
FED_TEXT_SCORE_THRESHOLD = int(os.environ.get("FED_TEXT_SCORE_THRESHOLD", "1"))

# Endpoints
FISCALDATA_GOLD_ENDPOINT = "https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v2/accounting/od/gold_reserve"
FED_H41_URL = "https://www.federalreserve.gov/releases/h41/current/"
FEDERAL_REGISTER_API = "https://www.federalregister.gov/api/v1/documents.json"
COINGECKO = CoinGeckoAPI()
SOCRATA_DOMAIN = "publicreporting.cftc.gov"
CFTC_SOCRATA_TABLE = os.environ.get("CFTC_SOCRATA_TABLE", "6dca-aqww")  # default resource id; safe fallback

# -------------------------
# Notifiers
# -------------------------
def send_telegram(text: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        LOG.warning("Telegram not configured. Message would be: %s", text[:200])
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    try:
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        LOG.info("Telegram alert sent.")
        return True
    except Exception as e:
        LOG.exception("Failed to send Telegram message: %s", e)
        return False

def send_slack(text: str):
    if not SLACK_WEBHOOK_URL:
        LOG.warning("Slack webhook not configured.")
        return False
    try:
        r = requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)
        r.raise_for_status()
        LOG.info("Slack message sent.")
        return True
    except Exception as e:
        LOG.exception("Slack send failed: %s", e)
        return False

def send_email(subject: str, body: str):
    if not EMAIL_SMTP_SERVER or not ALERT_EMAIL_USERNAME or not ALERT_EMAIL_PASSWORD or not ALERT_EMAIL_TO:
        LOG.warning("Email not fully configured; skipping.")
        return False
    try:
        msg = EmailMessage()
        msg["From"] = ALERT_EMAIL_USERNAME
        msg["To"] = ALERT_EMAIL_TO
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(ALERT_EMAIL_USERNAME, ALERT_EMAIL_PASSWORD)
            server.send_message(msg)
        LOG.info("Email sent.")
        return True
    except Exception as e:
        LOG.exception("Email send failed: %s", e)
        return False

def broadcast(subject: str, body: str):
    msg = f"{subject}\n\n{body}"
    send_telegram(msg)
    send_slack(msg)
    send_email(subject, body)

# -------------------------
# Fetchers
# -------------------------
def fetch_treasury_gold():
    try:
        r = requests.get(FISCALDATA_GOLD_ENDPOINT, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        LOG.exception("fetch_treasury_gold error: %s", e)
        return None

def fetch_fed_h41_text():
    try:
        r = requests.get(FED_H41_URL, timeout=20)
        r.raise_for_status()
        return r.text
    except Exception as e:
        LOG.exception("fetch_fed_h41_text error: %s", e)
        return ""

def fetch_federal_register_hits(term, per_page=3):
    try:
        params = {"conditions[terms]": term, "per_page": per_page, "order": "relevance"}
        r = requests.get(FEDERAL_REGISTER_API, params=params, timeout=20)
        r.raise_for_status()
        js = r.json()
        results = []
        for d in js.get("results", []):
            results.append({"title": d.get("title"), "published_at": d.get("published_at")})
        return results
    except Exception as e:
        LOG.exception("fetch_federal_register_hits error: %s", e)
        return []

def fetch_market_data():
    out = {}
    try:
        gold = yf.Ticker("GC=F")
        hist_g = gold.history(period="10d", interval="1d")
        if not hist_g.empty:
            p = hist_g['Close'].dropna()
            if len(p) >= 2:
                out['gold_pct_7d'] = float((p.iloc[-1] / p.iloc[0]) - 1)
                out['gold_spot'] = float(p.iloc[-1])
        dxy = yf.Ticker("DX=F")
        hist_dxy = dxy.history(period="10d", interval="1d")
        if not hist_dxy.empty:
            p = hist_dxy['Close'].dropna()
            if len(p) >= 2:
                out['dxy_pct_7d'] = float((p.iloc[-1] / p.iloc[0]) - 1)
                out['dxy_spot'] = float(p.iloc[-1])
    except Exception as e:
        LOG.exception("fetch_market_data error: %s", e)
    return out

def fetch_btc_price_usd():
    try:
        p = COINGECKO.get_price(ids="bitcoin", vs_currencies="usd")
        return float(p.get("bitcoin", {}).get("usd", 0))
    except Exception as e:
        LOG.exception("fetch_btc_price_usd error: %s", e)
        return None

# CFTC Socrata (publicreporting)
def fetch_cftc_gold_rows(limit=6):
    try:
        url = f"https://{SOCRATA_DOMAIN}/resource/{CFTC_SOCRATA_TABLE}.json?$where=upper(contract_market_name)%20like%20'%25GOLD%25'&$order=report_date%20desc&$limit={limit}"
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        LOG.exception("fetch_cftc_gold_rows error: %s", e)
        return []

def summarize_cftc(rows):
    if not rows:
        return None
    rows_sorted = sorted(rows, key=lambda r: r.get("report_date", ""), reverse=True)
    latest = rows_sorted[0]
    prev = rows_sorted[1] if len(rows_sorted) > 1 else None
    def find_key(obj, tokens):
        for k in obj.keys():
            kl = k.lower()
            if all(t in kl for t in tokens):
                return k
        return None
    mm_long = find_key(latest, ["managed", "long"]) or find_key(latest, ["noncommercial", "long"])
    mm_short = find_key(latest, ["managed", "short"]) or find_key(latest, ["noncommercial", "short"])
    def safe_get(obj, k):
        if not k or k not in obj: return None
        try:
            return float(obj.get(k))
        except:
            try: return float(obj.get(k).replace(",", ""))
            except: return None
    latest_long = safe_get(latest, mm_long)
    prev_long = safe_get(prev, mm_long) if prev else None
    long_change = (latest_long - prev_long) if (latest_long is not None and prev_long is not None) else None
    return {"latest_date": latest.get("report_date"), "latest_long": latest_long, "previous_long": prev_long, "long_change": long_change}

# mempool BTC whale detection via blockchain.info
def fetch_unconfirmed_btc(limit=200):
    try:
        r = requests.get("https://blockchain.info/unconfirmed-transactions?format=json", timeout=15)
        r.raise_for_status()
        js = r.json()
        return js.get("txs", [])[:limit]
    except Exception as e:
        LOG.exception("fetch_unconfirmed_btc error: %s", e)
        return []

def detect_btc_whales(threshold_usd):
    btc_usd = fetch_btc_price_usd()
    if not btc_usd:
        return []
    txs = fetch_unconfirmed_btc(limit=500)
    whales = []
    for tx in txs:
        total_sats = sum(o.get("value", 0) for o in tx.get("out", []))
        total_btc = total_sats / 1e8
        total_usd = total_btc * btc_usd
        if total_usd >= threshold_usd:
            whales.append({"hash": tx.get("hash"), "total_btc": total_btc, "total_usd": total_usd})
    return whales

# -------------------------
# Run checks & alert
# -------------------------
def run_checks_and_alert():
    LOG.info("Starting check run: %s", datetime.utcnow().isoformat())
    alerts = []

    # Treasury dataset
    gd = fetch_treasury_gold()
    if gd:
        alerts.append("Treasury gold dataset fetched (check meta in repo logs).")

    # Fed H.4.1 text scan
    fed_text = fetch_fed_h41_text()
    hits = sum(1 for k in FED_TEXT_KEYWORDS if k in (fed_text or "").lower())
    if hits >= FED_TEXT_SCORE_THRESHOLD:
        alerts.append(f"Fed H.4.1 page contains {hits} keyword hits — investigate: {FED_H41_URL}")

    # Federal Register quick checks
    fr_matches = []
    for kw in FED_TEXT_KEYWORDS:
        m = fetch_federal_register_hits(kw, per_page=2)
        if m:
            fr_matches.append((kw, len(m)))
    if fr_matches:
        alerts.append(f"Federal Register keyword matches: {fr_matches}")

    # CFTC summary
    cftc_rows = fetch_cftc_gold_rows(limit=6)
    cftc_summary = summarize_cftc(cftc_rows)
    if cftc_summary:
        if cftc_summary.get("long_change") and abs(cftc_summary["long_change"]) > 5000:
            alerts.append(f"CFTC managed-money long changed by {cftc_summary['long_change']} contracts (report {cftc_summary['latest_date']})")
        else:
            alerts.append(f"CFTC managed-money latest_long={cftc_summary.get('latest_long')} (report {cftc_summary.get('latest_date')})")

    # Market signals
    md = fetch_market_data()
    if md.get("gold_pct_7d") is not None and abs(md["gold_pct_7d"]) >= GOLD_7D_MOVE_PCT_ALERT:
        alerts.append(f"Gold moved {md['gold_pct_7d']*100:.2f}% over ~7 days (spot {md.get('gold_spot')})")

    # BTC price
    btc_price = fetch_btc_price_usd()
    if btc_price:
        alerts.append(f"BTC spot ${btc_price:,.0f}")

    # unusual correlation
    if md.get('gold_pct_7d') and md.get('dxy_pct_7d'):
        if md['gold_pct_7d'] > 0.03 and md['dxy_pct_7d'] > 0.01:
            alerts.append(f"Unusual: gold and USD both up (gold +{md['gold_pct_7d']*100:.2f}%, DXY +{md['dxy_pct_7d']*100:.2f}%)")

    # BTC whales
    whales = detect_btc_whales(BTC_USD_WHALE_USD_THRESHOLD)
    if whales:
        alerts.append(f"Detected {len(whales)} large unconfirmed BTC tx(s) >= ${BTC_USD_WHALE_USD_THRESHOLD:,}")

    if alerts:
        subject = f"[EARLY-SIGNAL] {datetime.utcnow().isoformat()} UTC - {len(alerts)} items"
        body = "\n".join(f"- {a}" for a in alerts) + "\n\nSources: Treasury(FiscalData), Fed H.4.1, Federal Register, CFTC PRE (Socrata), Yahoo/Coingecko, blockchain.info."
        broadcast(subject, body)
    else:
        LOG.info("No alerts triggered this cycle.")

if __name__ == "__main__":
    run_checks_and_alert()

# (END SCRIPT)
