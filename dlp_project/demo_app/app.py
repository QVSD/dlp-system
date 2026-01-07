from flask import Flask, request, jsonify
import logging
from flask import abort
from .dlp_hook import check_dlp
from dlp_engine.metrics import get_metrics

app = Flask(__name__)

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    # BAD PRACTICE (intentional)
    logging.info(f"endpoint=/login payload={data}")
    return jsonify({"status": "ok"})

@app.route("/profile", methods=["GET"])
def profile():
    user = {
        "email": "test.user@example.com",
        "cnp": "1960101223344",
        "iban": "RO49AAAA1B31007593840000"
    }

    allowed, finding, new_payload = check_dlp(user, "/profile")

    if not allowed:
        abort(403, description=f"DLP BLOCKED: {finding.dtype}")

    if new_payload:
        return jsonify(new_payload)

    return jsonify(user)


@app.route("/metrics", methods=["GET"])
def metrics():
    return jsonify(get_metrics())

if __name__ == "__main__":
    app.run(debug=True)
