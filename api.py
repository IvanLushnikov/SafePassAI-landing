from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
from dotenv import load_dotenv
from collections import deque
import requests
import shodan

from top10k import is_common_password

load_dotenv()
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
API_URL = "https://leakcheck.io/api/public"
request_timestamps = deque(maxlen=1)
LOCAL_DICTIONARIES = ["rockyou2021.txt", "seclists.txt", "probable.txt", "haklistgen.txt"]

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/check", methods=["GET"])
def check_data():
    query = request.args.get("query", "").strip()
    if not query or len(query) < 3:
        return jsonify({"error": "Слишком короткий запрос."}), 400
    try:
        local_matches = search_in_local_files(query)
        api_response = make_api_request(query)
        result = {"found": 0, "results": []}
        if local_matches:
            result["found"] += len(local_matches)
            result["results"] += [{"source": f[0], "lines": [f[2]]} for f in local_matches]
        if api_response and api_response.get("found", 0) > 0:
            result["found"] += api_response["found"]
            result["results"] += api_response["sources"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/check-password", methods=["POST"])
def check_password():
    data = request.get_json()
    password = data.get("password", "").strip()
    if not password or len(password) < 4:
        return jsonify({"error": "Пароль слишком короткий."}), 400
    try:
        is_common = is_common_password(password)
        return jsonify({
            "password": password,
            "is_common": is_common,
            "message": "Пароль слишком популярный!" if is_common else "Пароль не входит в топ-10к."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/generate-passwords", methods=["POST"])
def generate_passwords():
    data = request.get_json()
    name = data.get("name", "").strip().lower()
    city = data.get("city", "").strip().lower()
    year = data.get("year", "").strip()
    if not name or not city or not year:
        return jsonify({"error": "Все поля обязательны."}), 400
    variants = []
    base_parts = [name, city, year]
    for part1 in base_parts:
        for part2 in base_parts:
            if part1 != part2:
                variants.append(part1 + part2)
                variants.append(part1.capitalize() + part2)
                variants.append(part1 + part2 + "123")
                variants.append(part1 + part2 + "!")
    variants += [
        name + year,
        city + year,
        name + "123",
        name + "!",
        name + "_" + city,
        name + "@" + year,
    ]
    passwords = list(set(variants))[:10]
    return jsonify({"passwords": passwords})

@app.route("/shodan", methods=["GET"])
def shodan_info():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP не указан"}), 400
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        return jsonify({
            "ip_str": host.get("ip_str"),
            "org": host.get("org"),
            "ports": host.get("ports", [])
        })
    except shodan.APIError as e:
        return jsonify({"error": str(e)}), 500


def make_api_request(query: str) -> dict:
    current_time = time.time()
    if request_timestamps:
        elapsed = current_time - request_timestamps[0]
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
    request_timestamps.append(time.time())
    params = {
        "key": LEAKCHECK_API_KEY,
        "check": query,
        "type": "email" if "@" in query else "login"
    }
    try:
        response = requests.get(API_URL, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None


def search_in_local_files(query):
    results = []
    query_lower = query.lower()
    for filename in LOCAL_DICTIONARIES:
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if query_lower in line.lower():
                        results.append((filename, i + 1, line.strip()))
                        break
        except Exception:
            continue
    return results


if __name__ == "__main__":
    app.run(debug=True)


    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP не указан"}), 400

    # 1. Основная инфа из ip-api
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,city,country,isp,timezone,org,as,reverse,proxy,query").json()
        if geo["status"] != "success":
            return jsonify({"error": geo.get("message", "Ошибка geo API")}), 400
    except Exception as e:
        return jsonify({"error": "Ошибка при обращении к ip-api.com"}), 500

    # 2. Уязвимости / порты из Shodan
    from shodan import Shodan
    shodan_key = os.getenv("SHODAN_API_KEY")
    ports = []
    try:
        if shodan_key:
            api = Shodan(shodan_key)
            host = api.host(ip)
            ports = host.get("ports", [])
    except:
        pass

    # 3. Privacy score (условный скоринг)
    privacy_score = 0
    if geo.get("proxy"): privacy_score += 2
    if geo.get("org", "").lower() in ["mullvad", "nordvpn", "expressvpn"]: privacy_score += 2
    if "vpn" in geo.get("org", "").lower(): privacy_score += 1
    if geo.get("country", "").lower() != "russia": privacy_score += 1

    # 4. Ответ
    return jsonify({
        "city": geo.get("city"),
        "country": geo.get("country"),
        "isp": geo.get("isp"),
        "timezone": geo.get("timezone"),
        "local_time": None,  # опционально — можно рассчитать
        "proxy": geo.get("proxy", False),
        "asn": geo.get("as"),
        "reverse_dns": geo.get("reverse"),
        "ports": ports,
        "privacy_score": privacy_score
    })

@app.route("/ip-info", methods=["GET"])
def ip_info():
    import requests
    import os
    from flask import request, jsonify
    from shodan import Shodan
    from datetime import datetime
    import pytz

    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP не указан"}), 400

    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,city,country,isp,timezone,org,as,reverse,proxy,query").json()
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
    if geo.get("proxy"): score += 2
    if geo.get("org", "").lower() in ["mullvad", "nordvpn", "expressvpn"]: score += 2
    if "vpn" in geo.get("org", "").lower(): score += 1
    if geo.get("country", "").lower() not in ["russia", "россия"]: score += 1

    if score >= 3:
        score_text = "Высокий уровень анонимности"
    elif 1 <= score <= 2:
        score_text = "Есть признаки использования VPN/прокси"
    else:
        score_text = "Ваш IP легко отслеживается"

    # Расчёт локального времени
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
