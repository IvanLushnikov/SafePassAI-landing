import os
import csv
import openai
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from shodan import Shodan
from datetime import datetime
import pytz

# --- Настройки Flask и OpenAI ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
openai.api_key = os.environ.get("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")

# --- Загрузка базы знаний из CSV ---
from pathlib import Path

knowledge_base = []
try:
    base_path = Path(__file__).parent
    kb_path = Path("/opt/render/project/knowledge_base.csv")  # ← внутри try!
    with open(kb_path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            knowledge_base.append({"question": row["question"], "answer": row["answer"]})
except Exception as e:
    print(f"Ошибка при загрузке базы знаний: {e}")


# --- Поиск по базе ---
def simple_search(user_question):
    results = []
    for item in knowledge_base:
        if user_question.lower() in item["question"].lower():
            results.append(item)
    return results[:3]

# --- Маршрут для GPT-чата ---
@app.route("/ask", methods=["POST"])
def ask():
    data = request.get_json()
    user_question = data.get("question", "")
    context_items = simple_search(user_question)

    context = "\n\n".join([f"Вопрос: {i['question']}\nОтвет: {i['answer']}" for i in context_items])

    prompt = f"Ты эксперт по 44-ФЗ. Используй контекст ниже, чтобы ответить на вопрос:\n\n{context}\n\nВопрос: {user_question}"

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        answer = response.choices[0].message["content"]
        return jsonify({"answer": answer})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Остальные маршруты (без изменений) ---
@app.route("/check", methods=["GET"])
def check_leak():
    query = request.args.get("query")
    return jsonify({"found": 0, "results": []})

@app.route("/check-password", methods=["POST"])
def check_password():
    return jsonify({"is_common": False, "message": "Пароль не найден в популярных"})

@app.route("/generate-passwords", methods=["POST"])
def generate_passwords():
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

    shodan_key = os.getenv("SHODAN_API_KEY")
    ports = []
    try:
        if shodan_key:
            api = Shodan(shodan_key)
            host = api.host(ip)
            ports = host.get("ports", [])
    except:
        pass

    score = 0
    if geo.get("proxy"): score += 2
    if geo.get("org", "").lower() in ["mullvad", "nordvpn", "expressvpn"]: score += 2
    if "vpn" in geo.get("org", "").lower(): score += 1
    if geo.get("country", "").lower() not in ["russia", "россия"]: score += 1

    score_text = (
        "Высокий уровень анонимности" if score >= 3 else
        "Есть признаки использования VPN/прокси" if score >= 1 else
        "Ваш IP легко отслеживается"
    )

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

if __name__ == "__main__":
    app.run(debug=True)
