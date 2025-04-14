import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from shodan import Shodan
from datetime import datetime
import pytz

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/check", methods=["GET"])
def check_leak():
    query = request.args.get("query")
    # Заглушка для проверки
    return jsonify({"found": 0, "results": []})

@app.route("/check-password", methods=["POST"])
def check_password():
    # Заглушка для проверки
    return jsonify({"is_common": False, "message": "Пароль не найден в популярных"})

@app.route("/generate-passwords", methods=["POST"])
def generate_passwords():
    # Заглушка для проверки
    return jsonify({"passwords": ["test123", "test456"]})

@app.route("/ip-info", methods=["GET"])
def ip_info():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP не указан"}), 400

    try:
        geo = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,city,country,isp,timezone,org,as,reverse,proxy,query"
        ).json()
        if geo["status"] != "success":
            return jsonify({"error": geo.get("message", "Ошибка geo API")}), 400
    except:
        return jsonify({"error": "Ошибка при обращении к ip-api.com"}), 500

    # Получение портов из Shodan
    shodan_key = os.getenv("SHODAN_API_KEY")
    ports = []
    try:
        if shodan_key:
            api = Shodan(shodan_key)
            host = api.host(ip)
            ports = host.get("ports", [])
    except:
        pass

    # Privacy score
    score = 0
    if geo.get("proxy"):
        score += 2
    if geo.get("org", "").lower() in ["mullvad", "nordvpn", "expressvpn"]:
        score += 2
    if "vpn" in geo.get("org", "").lower():
        score += 1
    if geo.get("country", "").lower() not in ["russia", "россия"]:
        score += 1

    if score >= 3:
        score_text = "Высокий уровень анонимности"
    elif 1 <= score <= 2:
        score_text = "Есть признаки использования VPN/прокси"
    else:
        score_text = "Ваш IP легко отслеживается"

    # Локальное время
    local_time = None
    try:
        if geo.get("timezone"):
            tz = pytz.timezone(geo["timezone"])
            local_time = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass

    return jsonify({
        "city": geo.get("city"),
        "country": geo.get("country"),
        "isp": geo.get("isp"),
        "timezone": geo.get("timezone"),
        "local_time": local_time,
        "proxy": geo.get("proxy", False),
        "asn": geo.get("as"),
        "reverse_dns": geo.get("reverse"),
        "ports": ports if ports else None,
        "privacy_score": score,
        "privacy_score_text": score_text
    })
