import os
from datetime import datetime
from ipaddress import ip_address, ip_network

from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func


load_dotenv()

db = SQLAlchemy()

ASSET_CATEGORIES = {
    "servers": "Servers",
    "firewalls": "Firewalls",
    "switchs": "Switchs",
    "other-parts": "Other Parts",
}

RACK_SIZES = (1, 2, 3, 4, 6, 8)


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
    def unit_label(self):
        end_unit = self.rack_unit + self.rack_size - 1
        if self.rack_size == 1:
            return f"U{self.rack_unit}"
        return f"U{self.rack_unit}-U{end_unit}"


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///inventory.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    register_routes(app)
    register_cli(app)
    return app


def register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables."""
        db.create_all()
        print("Database tables created.")


def register_routes(app):
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
    app.run(debug=True)
