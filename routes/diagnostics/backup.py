from routes.diagnostics import diagnostics_bp
from routes.diagnostics._common import *  # noqa: F401,F403
from routes.diagnostics._common import _env_int, _env_bool, _max_backup_upload_bytes, _pbkdf2_iterations, _default_backup_dir, _backup_dir, _usb_backup_dir, _ensure_yaml_support, _ensure_crypto_support, _general_config_path, _database_path, _audit_log_path, _load_general_config_file, _safe_slug, _normalize_abs, _is_same_or_ancestor, _is_overly_broad_directory, _b64_encode, _b64_decode, _payload_to_bytes, _normalize_yaml_value, _is_text_like_path, _mask_secrets_in_text, _maybe_mask_bytes, _derive_key, _collect_log_roots, _collect_config_roots, _master_key_path, _snapshot_component_definitions, _safe_relative_path, _is_dangerous_target, _path_within_root, _snapshot_file_component, _snapshot_directory_component, _build_full_snapshot_payload, _serialize_snapshot_envelope, _decode_snapshot_envelope, _build_backup_filename, _save_safety_backup, _write_usb_backup, _atomic_write, _apply_fs_metadata, _decode_file_blob, _restore_file_component, _force_rmtree, _restore_directory_component, _restore_full_snapshot, _restart_services_after_restore, _backup_page_context  # noqa: F401


@diagnostics_bp.route("/")
@login_required
def diagnostics_home():
    # The diagnostics landing page is a stub; send operators to a real,
    # completed diagnostics page instead of a placeholder.
    return redirect(url_for("diagnostics.arp_table"))


# --------------------------------------------------
# ARP TABLE
# --------------------------------------------------

@diagnostics_bp.route("/arp-table")
@login_required
def arp_table():
    return render_template("arp_table.html")


# --------------------------------------------------
# AUTHENTICATION TEST PAGE
# --------------------------------------------------

@diagnostics_bp.route("/authentication")
@login_required
def authentication():
    from flask import abort, current_app
    if not current_app.config.get("ENABLE_UNFINISHED_PAGES"):
        abort(404)
    return render_template("authentication.html")


# --------------------------------------------------
# BACKUP & RESTORE
# --------------------------------------------------

@diagnostics_bp.route("/backup-restore")
@login_required
def backup_restore():
    requested_tab = (request.args.get("tab", "backup") or "backup").strip().lower()
    active_tab = "restore" if requested_tab == "restore" else "backup"
    return render_template(
        "backup_restore.html",
        backup_context=_backup_page_context(),
        active_tab=active_tab,
    )


@diagnostics_bp.route("/backup-restore/download", methods=["POST"])
@login_required
@superuser_required
@reauth_required_form("diagnostics.backup_restore", tab="backup")
def backup_restore_download():
    try:
        _ensure_yaml_support()
    except BackupDependencyError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="backup"))

    backup_target = (request.form.get("backup_target", "local_pc") or "local_pc").strip().lower()
    file_format = (request.form.get("file_format", "yaml") or "yaml").strip().lower()
    mask_passwords = bool(request.form.get("mask_passwords"))

    if backup_target not in {"local_pc", "usb_disk"}:
        flash("Unsupported backup target selected.", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="backup"))

    if file_format != "yaml":
        flash("Only YAML snapshot format is supported.", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="backup"))

    encryption_password = (request.form.get("encryption_password") or "").strip()
    encryption_password_confirm = (request.form.get("encryption_password_confirm") or "").strip()
    if encryption_password or encryption_password_confirm:
        if encryption_password != encryption_password_confirm:
            flash("Backup password and confirmation do not match.", "danger")
            return redirect(url_for("diagnostics.backup_restore", tab="backup"))
        if len(encryption_password) < 8:
            flash("Encryption password must be at least 8 characters.", "danger")
            return redirect(url_for("diagnostics.backup_restore", tab="backup"))

    try:
        payload = _build_full_snapshot_payload(mask_passwords=mask_passwords)
        backup_bytes, encrypted, payload_size = _serialize_snapshot_envelope(payload, encryption_password)
        backup_filename = _build_backup_filename(payload, encrypted)
    except (BackupDependencyError, BackupFormatError, OSError, ValueError) as exc:
        flash(f"Failed to create snapshot backup: {exc}", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="backup"))

    if backup_target == "usb_disk":
        try:
            target_path = _write_usb_backup(backup_filename, backup_bytes)
        except (BackupFormatError, OSError) as exc:
            flash(f"Unable to write snapshot to USB backup path: {exc}", "danger")
            return redirect(url_for("diagnostics.backup_restore", tab="backup"))

        log_event(
            category="system",
            action="config_snapshot_saved_usb",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={
                "filename": backup_filename,
                "target_path": target_path,
                "encrypted": encrypted,
                "password_masked": bool(payload.get("password_masked")),
                "payload_size_bytes": payload_size,
            },
        )
        flash(f"Snapshot backup saved to USB path: {target_path}", "success")
        return redirect(url_for("diagnostics.backup_restore", tab="backup"))

    log_event(
        category="system",
        action="config_snapshot_downloaded",
        username=session.get("username", "anonymous"),
        remote_addr=request.remote_addr,
        details={
            "filename": backup_filename,
            "encrypted": encrypted,
            "password_masked": bool(payload.get("password_masked")),
            "payload_size_bytes": payload_size,
            "target": "local_pc",
        },
    )

    return send_file(
        io.BytesIO(backup_bytes),
        as_attachment=True,
        download_name=backup_filename,
        mimetype="application/x-yaml",
    )


@diagnostics_bp.route("/backup-restore/restore", methods=["POST"])
@login_required
@superuser_required
@reauth_required_form("diagnostics.backup_restore", tab="restore")
def backup_restore_restore():
    try:
        _ensure_yaml_support()
    except BackupDependencyError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    backup_file = request.files.get("backup_file")
    if backup_file is None or not backup_file.filename:
        flash("Choose a backup file before starting restore.", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    max_upload_bytes = _max_backup_upload_bytes()
    max_upload_mb = round(max_upload_bytes / (1024 * 1024), 1)
    raw_bytes = backup_file.read(max_upload_bytes + 1)
    if len(raw_bytes) > max_upload_bytes:
        flash(f"Backup file is too large. Maximum size is {max_upload_mb} MB.", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    restore_password = (request.form.get("restore_password") or "").strip()
    create_safety_backup = bool(request.form.get("create_safety_backup"))
    logout_after_restore = bool(request.form.get("logout_after_restore"))
    confirm_restore = bool(request.form.get("confirm_restore"))

    if not confirm_restore:
        flash("Confirm restore acknowledgement before continuing.", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    try:
        restore_payload, was_encrypted = _decode_snapshot_envelope(raw_bytes, restore_password)
    except (BackupFormatError, BackupDependencyError) as exc:
        flash(str(exc), "danger")
        log_event(
            category="system",
            action="config_snapshot_restore_rejected",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={"reason": str(exc), "filename": backup_file.filename},
        )
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    if restore_payload.get("password_masked"):
        flash(
            "This backup was created with password masking and cannot be restored as a full snapshot.",
            "danger",
        )
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    try:
        rollback_payload = _build_full_snapshot_payload(mask_passwords=False)
    except Exception as exc:
        flash(f"Could not create a rollback snapshot before restore: {exc}", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    safety_backup_name = None
    if create_safety_backup:
        try:
            safety_backup_name, _ = _save_safety_backup(rollback_payload)
        except Exception:
            flash("Could not write a pre-restore safety file, but restore will continue.", "warning")

    restore_stats = {"components_applied": 0, "files_restored": 0, "bytes_restored": 0, "dirs_restored": 0}
    try:
        restore_stats = _restore_full_snapshot(restore_payload)
    except Exception as exc:
        rollback_error = None
        try:
            _restore_full_snapshot(rollback_payload)
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)

        log_event(
            category="system",
            action="config_snapshot_restore_failed",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={
                "filename": backup_file.filename,
                "encrypted_backup": was_encrypted,
                "error": str(exc),
                "rollback_error": rollback_error or "",
            },
        )

        if rollback_error:
            flash("Restore failed and automatic rollback also failed. Check system logs immediately.", "danger")
        else:
            flash("Restore failed. Previous configuration was restored automatically.", "danger")
        return redirect(url_for("diagnostics.backup_restore", tab="restore"))

    success_parts = [
        "Snapshot restore completed successfully.",
        f"{restore_stats.get('components_applied', 0)} component(s) applied.",
        f"{restore_stats.get('files_restored', 0)} file(s) restored.",
    ]
    if restore_stats.get("dirs_restored", 0):
        success_parts.append(f"{restore_stats.get('dirs_restored', 0)} directories recreated.")
    if safety_backup_name:
        success_parts.append(f"Safety file saved: {safety_backup_name}.")

    log_event(
        category="system",
        action="config_snapshot_restored",
        username=session.get("username", "anonymous"),
        remote_addr=request.remote_addr,
        details={
            "filename": backup_file.filename,
            "encrypted_backup": was_encrypted,
            "create_safety_backup": create_safety_backup,
            "safety_backup_name": safety_backup_name or "",
            "components_applied": restore_stats.get("components_applied", 0),
            "files_restored": restore_stats.get("files_restored", 0),
            "dirs_restored": restore_stats.get("dirs_restored", 0),
            "bytes_restored": restore_stats.get("bytes_restored", 0),
        },
    )

    flash(" ".join(success_parts), "success")

    # Restart affected services so restored config files take effect on FreeBSD.
    restart_after = bool(request.form.get("restart_services_after_restore"))
    if restart_after:
        _restart_services_after_restore()

    if logout_after_restore:
        session.clear()
        return redirect(url_for("auth.login"))

    return redirect(url_for("diagnostics.backup_restore", tab="restore"))


# --------------------------------------------------
# COMMAND PROMPT
# --------------------------------------------------
