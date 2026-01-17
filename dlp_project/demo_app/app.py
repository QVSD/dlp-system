from flask import Flask, render_template, request, redirect, abort, jsonify
import logging
from flask import abort
from .dlp_hook import check_dlp
from dlp_engine.metrics import get_metrics
import os
from dlp_engine.rbac import get_role_policy
from dlp_engine.audit_reader import tail_audit
from dlp_engine.policy import set_mode, MODE


app = Flask(__name__)

ROLE = os.getenv("DLP_ROLE", "DEFAULT")

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

@app.route("/", methods=["GET"])
def index():
    role = os.getenv("DLP_ROLE", "DEFAULT")

    if role == "DEFAULT":
        return render_template("user_home.html")

    if role == "SOC_ANALYST":
        return redirect("/soc")

    if role == "SECURITY_ADMIN":
        return redirect("/admin")

    return abort(403)


@app.route("/profile/update", methods=["POST"])
def update_profile():
    payload = {
        "email": request.form.get("email"),
        "cnp": request.form.get("cnp"),
        "iban": request.form.get("iban"),
    }
    payload = {k: v for k, v in payload.items() if v}

    allowed, finding, new_payload = check_dlp(payload, "/profile")

    if not allowed:
        return render_template(
            "user_home.html",
            error=" Update blocked by security policy",
            role="DEFAULT"
        )

    return render_template(
        "user_home.html",
        result=new_payload,
        role="DEFAULT"
    )


def render_with_rbac(template, **kwargs):
    rp = get_role_policy(ROLE)

    return render_template(
        template,
        role=ROLE,
        mode=MODE,
        rbac=rp,
        **kwargs
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
        "phone": "+40722123456",
        "cnp": "1960101223344",
        "iban": "RO49AAAA1B31007593840000",
       # "card": "4111111111111111",
       # "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"
    }

    allowed, finding, new_payload = check_dlp(user, "/profile")

    if not allowed:
        abort(403, description=f"DLP BLOCKED: {finding.dtype}")

    if new_payload:
        return jsonify(new_payload)

    return jsonify(user)

@app.route("/auth", methods=["POST"])
def auth():
    data = request.json

    allowed, finding, new_payload = check_dlp(data, "/auth")

    if not allowed:
        abort(403, description=f"DLP BLOCKED: {finding.dtype}")

    return jsonify({"status": "authenticated"})

@app.route("/metrics", methods=["GET"])
def metrics():
    metrics = get_metrics()
    return render_with_rbac("metrics.html", metrics=metrics)

@app.route("/audit", methods=["GET"])
def audit():
    rp = get_role_policy(ROLE)

    if not rp.can_read_audit:
        abort(403, description="RBAC: not allowed to read audit logs")

    # Auditor does not see the masked_value (already in rbac.py), but audit log has masked_value.
    # filter output:
    events = tail_audit(50)
    if not rp.see_masked_value:
        for e in events:
            e.pop("masked_value", None)

    
    return render_with_rbac("audit.html", events=events)

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

@app.route("/admin", methods=["GET", "POST"])
def admin():
    rp = get_role_policy(ROLE)
    if not rp.can_change_mode:
        abort(403)

    if request.method == "POST":
        set_mode(request.form["mode"])
        return redirect("/")

    events = tail_audit(20)
    return render_with_rbac("admin.html", events=events)


@app.route("/app")
def user_app():
    return render_with_rbac("app.html", role=ROLE, mode=MODE)


@app.route("/soc")
def soc():
    rp = get_role_policy(ROLE)
    if not rp.can_read_audit:
        abort(403)

    events = tail_audit(20)
    return render_with_rbac("soc.html", events=events)


if __name__ == "__main__":
    app.run(debug=True)
