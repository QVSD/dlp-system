from flask import Flask, request, jsonify
import logging
from flask import abort
from .dlp_hook import check_dlp
from dlp_engine.metrics import get_metrics
import os
from dlp_engine.rbac import get_role_policy
from dlp_engine.audit_reader import tail_audit
from dlp_engine.policy import set_mode, MODE


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

@app.route("/audit", methods=["GET"])
def audit():
    role = os.getenv("DLP_ROLE", "DEFAULT")
    rp = get_role_policy(role)

    if not rp.can_read_audit:
        abort(403, description="RBAC: not allowed to read audit logs")

    # Auditor does not see the masked_value (already in rbac.py), but audit log has masked_value.
    # filter output:
    events = tail_audit(50)
    if not rp.see_masked_value:
        for e in events:
            e.pop("masked_value", None)

    return jsonify({"role": role, "events": events})

@app.route("/admin/mode", methods=["POST"])
def set_dlp_mode():
    role = os.getenv("DLP_ROLE", "DEFAULT")
    rp = get_role_policy(role)

    if not rp.can_change_mode:
        abort(403, description="RBAC: not allowed to change mode")

    data = request.get_json(force=True)
    new_mode = data.get("mode", "").upper()

    if new_mode not in ("MONITOR", "ENFORCE"):
        abort(400, description="mode must be MONITOR or ENFORCE")

    set_mode(new_mode)
    return jsonify({"status": "ok", "mode": MODE})


if __name__ == "__main__":
    app.run(debug=True)
