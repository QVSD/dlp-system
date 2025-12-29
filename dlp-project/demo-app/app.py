from flask import Flask, request, jsonify
import logging

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
    logging.info(f"Login attempt: {data}")
    return jsonify({"status": "ok"})

@app.route("/profile", methods=["GET"])
def profile():
    user = {
        "email": "test.user@example.com",
        "cnp": "1960101223344",
        "iban": "RO49AAAA1B31007593840000"
    }
    logging.info(f"Profile data returned: {user}")
    return jsonify(user)

if __name__ == "__main__":
    app.run(debug=True)
