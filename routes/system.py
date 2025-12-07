from flask import Blueprint, render_template, redirect, url_for, request, session
from app.database import get_db

system_bp = Blueprint("system", __name__, url_prefix="/system")

# ----------------------------
# SYSTEM MAIN PAGES
# ----------------------------

@system_bp.route("/")
def system_home():
    return redirect(url_for("system.general_setup"))

@system_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@system_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


# ----------------------------
# HELP PAGES
# ----------------------------

@system_bp.route("/docs")
def docs():
    return render_template("docs.html")

@system_bp.route("/about")
def about():
    return render_template("about.html")

@system_bp.route("/bug")
def bug():
    return render_template("bug.html")

@system_bp.route("/forum")
def forum():
    return render_template("forum.html")

@system_bp.route("/freebsd")
def freebsd():
    return render_template("freebsd.html")

@system_bp.route("/pfsense-book")
def pfsense_book():
    return render_template("pfsense_book.html")

@system_bp.route("/paid-support")
def paid_support():
    return render_template("paid_support.html")

@system_bp.route("/survey")
def survey():
    return render_template("survey.html")

@system_bp.route("/upgrade")
def upgrade():
    return render_template("upgrade.html")

@system_bp.route("/help")
def help_page():
    return render_template("help.html")


# ----------------------------
# GENERAL SETUP
# ----------------------------

@system_bp.route("/general-setup", methods=["GET", "POST"])
def general_setup():
    from app.database import get_db
    conn = get_db()
    cursor = conn.cursor()

    # Load config (temporary until SQLite integration)
    import json, os
    CONFIG_FILE = "config.json"

    def load_config():
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        return {
            "hostname": "pfSense",
            "domain": "home.arpa",
            "dns_servers": [],
            "dns_override": True,
            "dns_behavior": "Use local DNS (127.0.0.1), fall back to remote DNS Servers (Default)",
            "timezone": "Etc/UTC",
            "timeservers": "2.pfsense.pool.ntp.org",
            "language": "English",
            "theme": "pfSense",
            "login_color": "Dark Blue",
            "show_hostname": True,
            "login_message": ""
        }

    def save_config(cfg):
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=4)

    config = load_config()

    if request.method == "POST":
        config["hostname"] = request.form.get("hostname")
        config["domain"] = request.form.get("domain")
        config["dns_servers"] = request.form.getlist("dns_server")
        config["dns_override"] = bool(request.form.get("dns_override"))
        config["dns_behavior"] = request.form.get("dns_behavior")
        config["timezone"] = request.form.get("timezone")
        config["timeservers"] = request.form.get("timeservers")
        config["language"] = request.form.get("language")
        config["theme"] = request.form.get("theme")
        config["login_color"] = request.form.get("login_color")
        config["show_hostname"] = bool(request.form.get("show_hostname"))
        config["login_message"] = request.form.get("login_message")

        save_config(config)
        return redirect(url_for("system.general_setup"))

    return render_template("general_setup.html", config=config)


# ----------------------------
# ADVANCED SYSTEM (submenus)
# ----------------------------

@system_bp.route("/advanced")
def advanced():
    return redirect(url_for("system.admin_access"))

@system_bp.route("/register")
def register():
    return render_template("register.html")

@system_bp.route("/admin-access")
def admin_access():
    return render_template("admin_access.html")

@system_bp.route("/advanced/firewall-nat")
def advanced_firewall_nat():
    return render_template("advanced_firewall_nat.html")

@system_bp.route("/advanced/network")
def advanced_network():
    return render_template("advanced_network.html")

@system_bp.route("/advanced/miscellaneous")
def advanced_miscellaneous():
    return render_template("advanced_miscellaneous.html")


# ----------------------------
# SYSTEM TUNABLES
# ----------------------------

@system_bp.route("/advanced/system-tunables")
def advanced_system_tunables():
    tunables = session.get("tunables", [
        {"name": "net.inet.ip.portrange.first", "value": "1024", "description": ""}
    ])
    return render_template("advanced_system_tunables.html", tunables=tunables)


@system_bp.route("/advanced/system-tunables/edit", methods=["GET", "POST"])
@system_bp.route("/advanced/system-tunables/edit/<int:index>", methods=["GET", "POST"])
def advanced_system_tunables_edit(index=None):
    tunables = session.get("tunables", [
        {"name": "net.inet.ip.portrange.first", "value": "1024", "description": ""}
    ])

    tunable = tunables[index] if index is not None and index < len(tunables) else None
    return render_template("advanced_system_tunables_edit.html", tunable=tunable, index=index)


@system_bp.route("/advanced/system-tunables/save", methods=["POST"])
def advanced_system_tunables_save():
    tunables = session.get("tunables", [
        {"name": "net.inet.ip.portrange.first", "value": "1024", "description": ""}
    ])

    tunable_name = request.form.get("tunable_name")
    tunable_value = request.form.get("tunable_value")
    tunable_description = request.form.get("tunable_description", "")
    index = request.form.get("index")

    new_tunable = {
        "name": tunable_name,
        "value": tunable_value,
        "description": tunable_description
    }

    if index and index.isdigit():
        tunables[int(index)] = new_tunable
    else:
        tunables.append(new_tunable)

    session["tunables"] = tunables
    return redirect(url_for("system.advanced_system_tunables"))


@system_bp.route("/advanced/system-tunables/delete/<int:index>", methods=["POST"])
def advanced_system_tunables_delete(index):
    tunables = session.get("tunables", [
        {"name": "net.inet.ip.portrange.first", "value": "1024", "description": ""}
    ])

    if index < len(tunables):
        tunables.pop(index)
        session["tunables"] = tunables

    return redirect(url_for("system.advanced_system_tunables"))


# ----------------------------
# CERTIFICATES
# ----------------------------

@system_bp.route("/certificates")
def certificates():
    return render_template("certificates.html")

@system_bp.route("/add_ca")
def add_ca():
    return render_template("add_ca.html")

@system_bp.route("/add_certificate")
def add_certificate():
    return render_template("add_certificate.html")


# ----------------------------
# HIGH AVAILABILITY
# ----------------------------

@system_bp.route("/high-availability")
def high_availability():
    return render_template("high_availability.html")


# ----------------------------
# PACKAGE MANAGER
# ----------------------------

@system_bp.route("/package-manager")
def package_manager():
    return render_template("package_manager.html")


# ----------------------------
# SETUP WIZARD
# ----------------------------

@system_bp.route("/setup-wizard")
def setup_wizard():
    return render_template("setup_wizard.html")


@system_bp.route("/setup-wizard/step/<int:step>")
def setup_wizard_step(step):
    if step in range(2, 11):
        return render_template(f"setup_wizard_step{step}.html")
    return "Invalid wizard step", 404


# ----------------------------
# COPYRIGHT PAGE
# ----------------------------

@system_bp.route("/copyright", methods=["GET", "POST"])
def copyright_page():
    if request.method == "POST":
        return redirect(url_for("system.dashboard"))
    return render_template("copyright.html")


# ----------------------------
# SYSTEM UPDATE PAGE
# ----------------------------

@system_bp.route("/update", methods=["GET", "POST"])
def update_page():
    active_tab = "system"
    message = None

    if request.method == "POST":
        if "check_updates" in request.form:
            message = "Checking for updates..."
            active_tab = "system"

        elif "update_system" in request.form:
            message = "System update initiated..."
            active_tab = "system"

        elif "save_settings" in request.form:
            message = "Settings saved successfully"
            active_tab = "settings"

    return render_template("update.html", message=message, active_tab=active_tab)


# ----------------------------
# NOTIFICATIONS
# ----------------------------

@system_bp.route("/notifications", methods=["GET", "POST"])
def notifications():
    if request.method == "POST":
        return redirect(url_for("system.notifications"))
    return render_template("notifications.html")
