import hmac
import os
import secrets
from datetime import datetime
from ipaddress import ip_address, ip_network
from time import time

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import check_password_hash


load_dotenv()

db = SQLAlchemy()

ASSET_CATEGORIES = {
    "servers": "Servers",
    "firewalls": "Firewalls",
    "switchs": "Switchs",
    "other-parts": "Other Parts",
}

RACK_SIZES = (1, 2, 3, 4, 6, 8)
LOGIN_ATTEMPTS = {}
LOGIN_RATE_LIMIT = 5
LOGIN_RATE_WINDOW_SECONDS = 300


class Datacenter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(120), nullable=False)
    building = db.Column(db.String(160), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    codename = db.Column(db.String(80), nullable=False, unique=True)
    fqdn = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    racks = db.relationship(
        "Rack", back_populates="datacenter", cascade="all, delete-orphan"
    )
    ip_ranges = db.relationship(
        "IpRange", back_populates="datacenter", cascade="all, delete-orphan"
    )
    assets = db.relationship("Asset", back_populates="datacenter")

    @property
    def display_name(self):
        return f"{self.codename} - {self.name}"


class Rack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    datacenter_id = db.Column(
        db.Integer, db.ForeignKey("datacenter.id"), nullable=False, index=True
    )
    name = db.Column(db.String(80), nullable=False)
    total_units = db.Column(db.Integer, default=48, nullable=False)

    datacenter = db.relationship("Datacenter", back_populates="racks")
    assets = db.relationship("Asset", back_populates="rack")

    __table_args__ = (
        db.UniqueConstraint("datacenter_id", "name", name="uq_rack_datacenter_name"),
    )

    @property
    def used_units(self):
        return sum(asset.rack_size for asset in self.assets)

    @property
    def occupancy_percent(self):
        if not self.total_units:
            return 0
        return round((self.used_units / self.total_units) * 100, 1)


class IpRange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    datacenter_id = db.Column(
        db.Integer, db.ForeignKey("datacenter.id"), nullable=False, index=True
    )
    cidr = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(160), default="", nullable=False)

    datacenter = db.relationship("Datacenter", back_populates="ip_ranges")


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(40), nullable=False, index=True)
    datacenter_id = db.Column(
        db.Integer, db.ForeignKey("datacenter.id"), nullable=False, index=True
    )
    rack_id = db.Column(db.Integer, db.ForeignKey("rack.id"), nullable=False, index=True)
    brand = db.Column(db.String(120), nullable=False)
    model = db.Column(db.String(160), nullable=False)
    rack_unit = db.Column(db.Integer, nullable=False)
    rack_size = db.Column(db.Integer, nullable=False)
    serial_no = db.Column(db.String(160), nullable=False)
    host_ip = db.Column(db.String(64), nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    datacenter = db.relationship("Datacenter", back_populates="assets")
    rack = db.relationship("Rack", back_populates="assets")

    @property
    def title(self):
        return f"{self.brand} {self.model}"

    @property
    def rack_label(self):
        category = ASSET_CATEGORIES.get(self.category, self.category)
        return f"{category} - {self.title} - {self.host_ip}"

    @property
    def unit_label(self):
        end_unit = self.rack_unit + self.rack_size - 1
        if self.rack_size == 1:
            return f"U{self.rack_unit}"
        return f"U{self.rack_unit}-U{end_unit}"


def create_app():
    app = Flask(__name__)
    secret_key = os.getenv("SECRET_KEY", "").strip()
    if not secret_key:
        raise RuntimeError("SECRET_KEY environment variable is required.")
    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///inventory.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = env_bool("SESSION_COOKIE_SECURE", False)
    app.config["SESSION_COOKIE_PATH"] = "/"
    app.config["SESSION_COOKIE_NAME"] = os.getenv(
        "SESSION_COOKIE_NAME",
        "__Host-inventory-session"
        if app.config["SESSION_COOKIE_SECURE"]
        else "inventory-session",
    )
    validate_session_cookie_config(app)
    app.config["ENABLE_HSTS"] = env_bool("ENABLE_HSTS", False)
    db.init_app(app)

    register_security(app)
    register_routes(app)
    register_cli(app)
    return app


def register_security(app):
    @app.before_request
    def require_login_and_csrf():
        g.current_user = session.get("username")

        if request.endpoint == "static":
            return None

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            validate_csrf_token()

        if request.endpoint == "login":
            return None

        if not g.current_user:
            return redirect(url_for("login", next=safe_next_path()))

        return None

    @app.context_processor
    def inject_security_helpers():
        return {"csrf_token": csrf_token}

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if app.config["ENABLE_HSTS"]:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        return response


def register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables."""
        db.create_all()
        print("Database tables created.")


def register_routes(app):
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("username"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            if login_rate_limited():
                flash("Too many login attempts. Please wait and try again.", "danger")
                return render_template(
                    "login.html",
                    next=valid_redirect_target(request.form.get("next")),
                ), 429

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if authenticate_user(username, password):
                clear_login_failures()
                session.clear()
                session["username"] = username
                csrf_token()
                flash("Logged in.", "success")
                return redirect(valid_redirect_target(request.form.get("next")))
            record_login_failure()
            flash("Invalid username or password.", "danger")

        return render_template(
            "login.html", next=valid_redirect_target(request.args.get("next"))
        )

    @app.post("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/")
    def dashboard():
        totals = {
            "datacenters": Datacenter.query.count(),
            "racks": Rack.query.count(),
            "assets": Asset.query.count(),
        }
        by_category = dict(
            db.session.query(Asset.category, func.count(Asset.id))
            .group_by(Asset.category)
            .all()
        )
        rack_rows = (
            db.session.query(
                Datacenter.codename,
                Rack.id,
                Rack.name,
                Rack.total_units,
                func.coalesce(func.sum(Asset.rack_size), 0).label("used_units"),
            )
            .join(Datacenter, Datacenter.id == Rack.datacenter_id)
            .outerjoin(Asset, Asset.rack_id == Rack.id)
            .group_by(Datacenter.codename, Rack.id, Rack.name, Rack.total_units)
            .order_by(Datacenter.codename, Rack.name)
            .all()
        )
        return render_template(
            "dashboard.html",
            totals=totals,
            by_category=by_category,
            rack_rows=rack_rows,
            categories=ASSET_CATEGORIES,
        )

    @app.route("/datacenters")
    def datacenters():
        rows = Datacenter.query.order_by(Datacenter.codename).all()
        return render_template("datacenters/list.html", datacenters=rows)

    @app.route("/datacenters/new", methods=["GET", "POST"])
    def datacenter_new():
        if request.method == "POST":
            dc = Datacenter()
            errors = fill_datacenter_from_form(dc)
            if not errors:
                db.session.add(dc)
                db.session.commit()
                flash("Datacenter created.", "success")
                return redirect(url_for("datacenter_detail", datacenter_id=dc.id))
            for error in errors:
                flash(error, "danger")
        return render_template("datacenters/form.html", datacenter=None)

    @app.route("/datacenters/<int:datacenter_id>")
    def datacenter_detail(datacenter_id):
        dc = get_datacenter(datacenter_id)
        return render_template("datacenters/detail.html", datacenter=dc)

    @app.route("/datacenters/<int:datacenter_id>/edit", methods=["GET", "POST"])
    def datacenter_edit(datacenter_id):
        dc = get_datacenter(datacenter_id)
        if request.method == "POST":
            errors = fill_datacenter_from_form(dc)
            if not errors:
                db.session.commit()
                flash("Datacenter updated.", "success")
                return redirect(url_for("datacenter_detail", datacenter_id=dc.id))
            for error in errors:
                flash(error, "danger")
        return render_template("datacenters/form.html", datacenter=dc)

    @app.route("/datacenters/<int:datacenter_id>/racks/<int:rack_id>")
    def rack_detail(datacenter_id, rack_id):
        dc = get_datacenter(datacenter_id)
        rack = Rack.query.filter_by(id=rack_id, datacenter_id=dc.id).first_or_404()
        assets = Asset.query.filter_by(rack_id=rack.id).order_by(Asset.rack_unit).all()
        unit_map = build_unit_map(rack, assets)
        return render_template(
            "datacenters/rack.html",
            datacenter=dc,
            rack=rack,
            assets=assets,
            unit_map=unit_map,
            categories=ASSET_CATEGORIES,
        )

    @app.route("/assets/<category>")
    def asset_list(category):
        label = category_label(category)
        assets = (
            Asset.query.filter_by(category=category)
            .join(Asset.datacenter)
            .join(Asset.rack)
            .order_by(Datacenter.codename, Rack.name, Asset.rack_unit)
            .all()
        )
        return render_template(
            "assets/list.html", assets=assets, category=category, label=label
        )

    @app.route("/assets/<category>/new", methods=["GET", "POST"])
    def asset_new(category):
        label = category_label(category)
        asset = Asset(category=category)
        if request.method == "POST":
            errors = fill_asset_from_form(asset)
            if not errors:
                db.session.add(asset)
                db.session.commit()
                flash(f"{label} item created.", "success")
                return redirect(url_for("asset_list", category=category))
            for error in errors:
                flash(error, "danger")
        return render_template(
            "assets/form.html",
            category=category,
            label=label,
            **asset_form_context(asset),
        )

    @app.route("/assets/<category>/<int:asset_id>/edit", methods=["GET", "POST"])
    def asset_edit(category, asset_id):
        label = category_label(category)
        asset = Asset.query.filter_by(id=asset_id, category=category).first_or_404()
        if request.method == "POST":
            errors = fill_asset_from_form(asset)
            if not errors:
                db.session.commit()
                flash(f"{label} item updated.", "success")
                return redirect(url_for("asset_list", category=category))
            for error in errors:
                flash(error, "danger")
        return render_template(
            "assets/form.html",
            category=category,
            label=label,
            **asset_form_context(asset),
        )

    @app.post("/assets/<category>/<int:asset_id>/delete")
    def asset_delete(category, asset_id):
        category_label(category)
        asset = Asset.query.filter_by(id=asset_id, category=category).first_or_404()
        db.session.delete(asset)
        db.session.commit()
        flash("Asset deleted.", "success")
        return redirect(url_for("asset_list", category=category))

    @app.route("/api/datacenters/<int:datacenter_id>/racks")
    def api_racks(datacenter_id):
        dc = get_datacenter(datacenter_id)
        return {
            "racks": [
                {"id": rack.id, "name": rack.name, "total_units": rack.total_units}
                for rack in sorted(dc.racks, key=lambda item: item.name)
            ]
        }


def category_label(category):
    if category not in ASSET_CATEGORIES:
        abort(404)
    return ASSET_CATEGORIES[category]


def configured_users():
    users = {}
    for item in os.getenv("INVENTORY_USERS", "").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        username, password = item.split(":", 1)
        username = username.strip()
        if username:
            users[username] = password.strip()
    return users


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def validate_session_cookie_config(app):
    cookie_name = app.config["SESSION_COOKIE_NAME"]
    if cookie_name.startswith("__Host-"):
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise RuntimeError("__Host- session cookies require SESSION_COOKIE_SECURE=1.")
        if app.config.get("SESSION_COOKIE_DOMAIN"):
            raise RuntimeError("__Host- session cookies must not set SESSION_COOKIE_DOMAIN.")
        if app.config.get("SESSION_COOKIE_PATH") != "/":
            raise RuntimeError("__Host- session cookies require SESSION_COOKIE_PATH=/")


def authenticate_user(username, password):
    stored_password = configured_users().get(username)
    if not stored_password:
        return False

    if stored_password.startswith(("scrypt:", "pbkdf2:", "argon2:")):
        try:
            return check_password_hash(stored_password, password)
        except ValueError:
            return False

    return hmac.compare_digest(stored_password, password)


def login_attempt_key():
    return request.remote_addr or "unknown"


def current_login_failures():
    now = time()
    attempts = [
        attempted_at
        for attempted_at in LOGIN_ATTEMPTS.get(login_attempt_key(), [])
        if now - attempted_at < LOGIN_RATE_WINDOW_SECONDS
    ]
    LOGIN_ATTEMPTS[login_attempt_key()] = attempts
    return attempts


def login_rate_limited():
    return len(current_login_failures()) >= LOGIN_RATE_LIMIT


def record_login_failure():
    attempts = current_login_failures()
    attempts.append(time())
    LOGIN_ATTEMPTS[login_attempt_key()] = attempts


def clear_login_failures():
    LOGIN_ATTEMPTS.pop(login_attempt_key(), None)


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token():
    expected = session.get("_csrf_token")
    provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        abort(400, description="Invalid CSRF token.")


def safe_next_path():
    return request.full_path if request.query_string else request.path


def valid_redirect_target(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


def get_datacenter(datacenter_id):
    return Datacenter.query.get_or_404(datacenter_id)


def split_lines(value):
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def asset_form_context(asset):
    selected_datacenter = None
    if asset.datacenter_id:
        selected_datacenter = Datacenter.query.get(asset.datacenter_id)
    return {
        "asset": asset,
        "datacenters": Datacenter.query.order_by(Datacenter.codename).all(),
        "selected_datacenter": selected_datacenter,
        "rack_sizes": RACK_SIZES,
    }


def fill_datacenter_from_form(dc):
    errors = []
    dc.country = request.form.get("country", "").strip()
    dc.building = request.form.get("building", "").strip()
    dc.name = request.form.get("name", "").strip()
    dc.codename = request.form.get("codename", "").strip().upper()
    dc.fqdn = request.form.get("fqdn", "").strip().lower()

    for field, label in (
        ("country", "Country"),
        ("building", "Building"),
        ("name", "Datacenter name"),
        ("codename", "Datacenter codename"),
        ("fqdn", "Datacenter FQDN"),
    ):
        if not getattr(dc, field):
            errors.append(f"{label} is required.")

    rack_names = split_lines(request.form.get("racks"))
    if not rack_names:
        errors.append("At least one rack is required.")

    ip_ranges = split_lines(request.form.get("ip_ranges"))
    for cidr in ip_ranges:
        try:
            ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"Invalid IP range: {cidr}")

    duplicate = (
        Datacenter.query.filter(Datacenter.codename == dc.codename)
        .filter(Datacenter.id != (dc.id or 0))
        .first()
    )
    if duplicate:
        errors.append("Datacenter codename must be unique.")

    if errors:
        return errors

    existing_racks = {rack.name: rack for rack in dc.racks}
    requested_names = set()
    for name in rack_names:
        requested_names.add(name)
        if name not in existing_racks:
            dc.racks.append(Rack(name=name, total_units=48))
    for rack in list(dc.racks):
        if rack.name not in requested_names and not rack.assets:
            db.session.delete(rack)
        elif rack.name not in requested_names:
            errors.append(f"Rack {rack.name} has assets and cannot be removed.")

    if errors:
        return errors

    dc.ip_ranges.clear()
    for cidr in ip_ranges:
        dc.ip_ranges.append(IpRange(cidr=cidr))

    return []


def fill_asset_from_form(asset):
    errors = []
    asset.datacenter_id = int_or_none(request.form.get("datacenter_id"))
    asset.rack_id = int_or_none(request.form.get("rack_id"))
    asset.brand = request.form.get("brand", "").strip()
    asset.model = request.form.get("model", "").strip()
    asset.rack_unit = int_or_none(request.form.get("rack_unit"))
    asset.rack_size = int_or_none(request.form.get("rack_size"))
    asset.serial_no = request.form.get("serial_no", "").strip()
    asset.host_ip = request.form.get("host_ip", "").strip()
    asset.notes = request.form.get("notes", "").strip()

    required = (
        ("datacenter_id", "Datacenter"),
        ("rack_id", "Rack"),
        ("brand", "Brand"),
        ("model", "Model"),
        ("rack_unit", "Rack unit"),
        ("rack_size", "Rack size"),
        ("serial_no", "Serial number"),
        ("host_ip", "Host IP"),
    )
    for field, label in required:
        if not getattr(asset, field):
            errors.append(f"{label} is required.")

    rack = None
    if asset.rack_id:
        rack = Rack.query.get(asset.rack_id)
        if not rack:
            errors.append("Selected rack was not found.")
        elif asset.datacenter_id != rack.datacenter_id:
            errors.append("Selected rack does not belong to selected datacenter.")

    if asset.rack_size and asset.rack_size not in RACK_SIZES:
        errors.append("Rack size is not valid.")

    if rack and asset.rack_unit and asset.rack_size:
        last_unit = asset.rack_unit + asset.rack_size - 1
        if asset.rack_unit < 1 or last_unit > rack.total_units:
            errors.append(f"Rack position must fit inside U1-U{rack.total_units}.")

    if asset.host_ip:
        try:
            ip_address(asset.host_ip)
        except ValueError:
            errors.append("Host IP is not valid.")

    if not errors and rack and rack_position_overlaps(asset, rack):
        errors.append("Rack position overlaps another asset.")

    return errors


def int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def rack_position_overlaps(asset, rack):
    start = asset.rack_unit
    end = asset.rack_unit + asset.rack_size - 1
    existing_assets = Asset.query.filter(Asset.rack_id == rack.id).filter(
        Asset.id != (asset.id or 0)
    )
    for existing in existing_assets:
        existing_start = existing.rack_unit
        existing_end = existing.rack_unit + existing.rack_size - 1
        if start <= existing_end and end >= existing_start:
            return True
    return False


def build_unit_map(rack, assets):
    unit_map = {unit: None for unit in range(1, rack.total_units + 1)}
    for asset in assets:
        for unit in range(asset.rack_unit, asset.rack_unit + asset.rack_size):
            unit_map[unit] = asset
    return unit_map


app = create_app()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=env_bool("FLASK_DEBUG", False))
