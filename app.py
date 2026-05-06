# app.py
import os
import joblib
import warnings
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, jsonify, g

# ---------------- CONFIG ----------------
DATABASE = "alerts.db"
MODEL_PATH = "model.pkl"

# ---------------- WARNINGS ----------------
warnings.filterwarnings("ignore", category=UserWarning)

# ---------------- FLASK APP ----------------
app = Flask(__name__, static_folder="static", template_folder="templates")

# ---------------- LOAD MODEL ----------------
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("Model file not found (model.pkl).")

model = joblib.load(MODEL_PATH)
print("Model loaded successfully.")

# ---------------- DATABASE ----------------
def get_db():
    if "_database" not in g:
        g._database = sqlite3.connect(DATABASE)
        g._database.row_factory = sqlite3.Row
    return g._database

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src TEXT,
            dst TEXT,
            proto TEXT,
            protocol_type INTEGER,
            duration REAL,
            src_bytes INTEGER,
            dst_bytes INTEGER,
            src_country TEXT,
            src_city TEXT,
            dst_country TEXT,
            dst_city TEXT,
            prediction TEXT,
            score REAL,
            created_at TEXT
        )
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop("_database", None)
    if db:
        db.close()

with app.app_context():
    init_db()
def clear_alerts():
    db = get_db()
    db.execute("DELETE FROM alerts")
    db.commit()
with app.app_context():  # ✅ called after definition
    init_db()
    clear_alerts()
# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("index.html")

# -------- MANUAL PREDICTION (Dashboard) --------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        duration = float(request.form["duration"])
        src_bytes = float(request.form["src_bytes"])
        dst_bytes = float(request.form["dst_bytes"])
        protocol_type = int(request.form["protocol_type"])

        import pandas as pd
        X = pd.DataFrame(
            [[duration, src_bytes, dst_bytes, protocol_type]],
            columns=["duration", "src_bytes", "dst_bytes", "protocol_type"]
        )

        pred = int(model.predict(X)[0])
        score = None
        if hasattr(model, "predict_proba"):
            score = float(model.predict_proba(X)[0].max())

        prediction_text = "Threat" if pred == 1 else "Normal"

        # Store manual test result
        db = get_db()
        db.execute("""
            INSERT INTO alerts
            (src, dst, proto, protocol_type, duration, src_bytes, dst_bytes, prediction, score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "manual", "manual",
            str(protocol_type), protocol_type,
            duration, src_bytes, dst_bytes,
            prediction_text, score,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        db.commit()

        # PASS INPUT VALUES TO TEMPLATE (IMPORTANT FIX)
        return render_template(
            "result.html",
            prediction=prediction_text,
            score=score,
            duration=duration,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            protocol_type=protocol_type
        )

    except Exception as e:
        return f"Prediction error: {e}", 400

# -------- LIVE SNIFFER ALERT INGEST --------
@app.route("/alert", methods=["POST"])
def receive_alert():
    try:
        data = request.get_json(force=True)

        db = get_db()
        db.execute("""
            INSERT INTO alerts
            (src, dst, proto, protocol_type, duration, src_bytes, dst_bytes,
             src_country, src_city, dst_country, dst_city,
             prediction, score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("src"),
            data.get("dst"),
            data.get("proto"),
            int(data.get("protocol_type", 0)),
            float(data.get("duration", 0)),
            int(data.get("src_bytes", 0)),
            int(data.get("dst_bytes", 0)),
            data.get("src_country"),
            data.get("src_city"),
            data.get("dst_country"),
            data.get("dst_city"),
            data.get("prediction", "Unknown"),
            data.get("score"),
            datetime.utcnow().isoformat()
        ))
        db.commit()

        print("Alert received:", data.get("src"), "→", data.get("dst"))
        return jsonify({"status": "ok"}), 200

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

# -------- ALERT DASHBOARD --------
@app.route("/alerts")
def show_alerts():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return render_template("alerts.html", alerts=rows)

# -------- STATUS --------
@app.route("/status")
def status():
    return jsonify({"status": "running"})

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
