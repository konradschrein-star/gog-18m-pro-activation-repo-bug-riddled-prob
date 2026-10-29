#!/usr/bin/env python3
"""
Avatarity Fleet Exporter
========================
Packages verified Google AI Pro accounts from ./avatarity_profiles/ into an
Avatarity-ready production bundle:
  1. accounts_import.json & accounts.json (for AccountFleetManager & AccountRegistry)
  2. profiles/<profileName>/flow-session-state.json (for FlowBrowserSession)
  3. profiles/<profileName>/fingerprint.json (deterministic device fingerprint)
  4. avatarity_profiles_bundle.tar.gz archive for 1-command deployment to production nodes
"""

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_PROFILES_DIR = Path(os.environ.get("PROFILES_DIR", str(BASE_DIR / "avatarity_profiles")))
DEFAULT_BUNDLE_DIR = Path(os.environ.get("BUNDLE_DIR", str(BASE_DIR / "avatarity_bundle")))
DEFAULT_SHEET_FILE = Path(os.environ.get("ACCOUNTS_CSV", str(DATA_DIR / "emails_sheet.csv")))
DEFAULT_META_FILE = Path(os.environ.get("PROXIES_META_FILE", str(DATA_DIR / "clean_proxies_metadata.json")))


def load_credentials_sheet(sheet_path: Path) -> Dict[str, Dict[str, str]]:
    """
    Parses accounts CSV into a normalized dictionary keyed by lowercase email.
    Format per line: Email: ... | Password: ... | 2FA: ... | Number: ... | Link: ... | Backup: ...
    """
    credentials: Dict[str, Dict[str, str]] = {}
    if not sheet_path.exists():
        print(f"[Warn] Credentials sheet {sheet_path} does not exist; skipping credential enrichment.")
        return credentials

    text = sheet_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        entry: Dict[str, str] = {}
        for part in parts:
            if ":" in part:
                k, v = part.split(":", 1)
                entry[k.strip().lower()] = v.strip()
        email = entry.get("email", "").strip().lower()
        if email:
            credentials[email] = {
                "email": email,
                "password": entry.get("password", ""),
                "totp_secret": entry.get("2fa", "").replace(" ", "").upper(),
                "backup_email": entry.get("backup", ""),
                "activation_link": entry.get("link", ""),
            }

    print(f"[Exporter] Loaded {len(credentials)} credential records from {sheet_path.name}")
    return credentials


def load_proxy_metadata(meta_path: Path) -> Dict[int, Dict[str, Any]]:
    """
    Parses clean_proxies_metadata.json into a dict keyed by proxy port.
    """
    proxies_by_port: Dict[int, Dict[str, Any]] = {}
    if not meta_path.exists():
        print(f"[Warn] Proxy metadata {meta_path} does not exist; skipping proxy enrichment.")
        return proxies_by_port

    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "port" in item:
                    proxies_by_port[int(item["port"])] = item
    except Exception as e:
        print(f"[Warn] Failed to parse proxy metadata: {e}")

    print(f"[Exporter] Loaded {len(proxies_by_port)} proxy metadata records from {meta_path.name}")
    return proxies_by_port


def parse_port_from_proxy_url(proxy_url: Optional[str]) -> Optional[int]:
    if not proxy_url:
        return None
    m = re.search(r":(\d{4,5})(?:/|$)", proxy_url)
    return int(m.group(1)) if m else None


def is_session_authenticated(session_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Inspects cookies for Google authentication tokens: SID, __Secure-1PSID, SSID, HSID.
    """
    cookies = session_data.get("cookies", [])
    if not isinstance(cookies, list):
        return False, []

    found = []
    for c in cookies:
        if isinstance(c, dict) and c.get("name") in ("SID", "__Secure-1PSID", "SSID", "HSID"):
            found.append(c["name"])

    has_auth = "SID" in found or "__Secure-1PSID" in found
    return has_auth, list(set(found))


def build_avatarity_account_record(
    profile_name: str,
    session_data: Dict[str, Any],
    cred: Optional[Dict[str, str]],
    proxy_meta: Optional[Dict[str, Any]],
    now_iso: str,
) -> Dict[str, Any]:
    """
    Generates a schema-compliant account record recognized by:
      - node-agent/lib/account-registry.js (normalizeAccount)
      - gateway/src/squad2-queue/account-fleet-manager.ts (hydrateFromDisk / saveToDisk)
      - gateway/scripts/manage-accounts.js (normalizeAccountObject)
    """
    email = session_data.get("email") or (cred.get("email") if cred else "") or profile_name
    email = email.strip().lower()

    is_auth, _ = is_session_authenticated(session_data)
    status = "ready" if is_auth else "auth_required"

    project_id = session_data.get("projectId") or None

    egress_proxy = (
        session_data.get("egressProxy")
        or (proxy_meta.get("proxy_url") if proxy_meta else None)
        or "direct"
    )

    totp_secret = cred.get("totp_secret") if cred else None
    password = cred.get("password") if cred else None

    tier = "ultra" if "ultra" in profile_name.lower() else "pro"

    notes_parts = ["Google One AI Pro Activated"]
    if proxy_meta:
        port = proxy_meta.get("port")
        isp = proxy_meta.get("isp")
        city = proxy_meta.get("city")
        region = proxy_meta.get("region")
        loc = f"{city}, {region}" if city and region else (region or "US")
        notes_parts.append(f"Proxy :{port} ({isp} // {loc})")
    if cred and cred.get("backup_email"):
        notes_parts.append(f"Recovery: {cred['backup_email']}")

    note_str = " | ".join(notes_parts)[:240]

    return {
        "profile": profile_name,
        "email": email,
        "label": email,
        "tier": tier,
        "status": status,
        "enabled": True,
        "signedIn": is_auth,
        "lastSignedIn": session_data.get("savedAt") or now_iso,
        "projectId": project_id,
        "activeProjectId": project_id,
        "egress": egress_proxy,
        "egressProxy": egress_proxy,
        "proxy": egress_proxy,
        "totpSecret": totp_secret if totp_secret else None,
        "password": password if password else None,
        "encryptedPassword": password if password else None,
        "dailyVideos": 0,
        "dailyImages": 0,
        "dailyVideoCount": 0,
        "dailyImageCount": 0,
        "totalVideoCount": 0,
        "totalImageCount": 0,
        "consecutiveErrors": 0,
        "cooldownUntil": None,
        "lastUsed": None,
        "lastUsedAt": None,
        "lastCheckedAt": now_iso,
        "notes": note_str,
        "note": note_str,
    }


def export_profiles(
    profiles_dir: Path,
    bundle_dir: Path,
    sheet_file: Path,
    meta_file: Path,
    create_tar: bool = True,
    apply_to_repo: bool = False,
    repo_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    print("\n=======================================================")
    print("  Avatarity Sovereign Account Fleet Exporter")
    print("=======================================================")
    print(f"Source Profiles Dir : {profiles_dir}")
    print(f"Target Bundle Dir   : {bundle_dir}")

    if not profiles_dir.exists():
        print(f"[Error] Profiles source directory {profiles_dir} does not exist.")
        return {"success": False, "count": 0}

    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_profiles_dir = bundle_dir / "profiles"
    bundle_profiles_dir.mkdir(parents=True, exist_ok=True)

    credentials = load_credentials_sheet(sheet_file)
    proxies_by_port = load_proxy_metadata(meta_file)

    now_iso = datetime.now(timezone.utc).isoformat()
    exported_accounts: List[Dict[str, Any]] = []

    profile_folders = sorted([d for d in profiles_dir.iterdir() if d.is_dir()], key=lambda d: d.name)
    print(f"[Exporter] Discovered {len(profile_folders)} candidate profile directory entries.")

    for p_dir in profile_folders:
        profile_name = p_dir.name
        session_file = p_dir / "flow-session-state.json"
        fp_file = p_dir / "fingerprint.json"
        live_fp_file = p_dir / "fingerprint_verified_live.json"
        act_status_file = p_dir / "activated_status.json"

        if not session_file.exists():
            print(f"  [Skip] {profile_name}: Missing flow-session-state.json")
            continue

        try:
            session_data = json.loads(session_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  [Error] {profile_name}: Malformed flow-session-state.json ({e})")
            continue

        email = session_data.get("email", "").strip().lower()
        cred = credentials.get(email) if email else None
        if not cred:
            for c_email, c_val in credentials.items():
                if profile_name in c_email:
                    cred = c_val
                    break

        proxy_url = session_data.get("egressProxy")
        port = parse_port_from_proxy_url(proxy_url)
        proxy_meta = proxies_by_port.get(port) if port else None

        acct_record = build_avatarity_account_record(
            profile_name, session_data, cred, proxy_meta, now_iso
        )
        exported_accounts.append(acct_record)

        dest_profile_dir = bundle_profiles_dir / profile_name
        dest_profile_dir.mkdir(parents=True, exist_ok=True)

        (dest_profile_dir / "flow-session-state.json").write_text(
            json.dumps(session_data, indent=2) + "\n", encoding="utf-8"
        )

        fp_data = session_data.get("fingerprint")
        if not fp_data and fp_file.exists():
            try:
                fp_data = json.loads(fp_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        if fp_data:
            (dest_profile_dir / "fingerprint.json").write_text(
                json.dumps(fp_data, indent=2) + "\n", encoding="utf-8"
            )

        if live_fp_file.exists():
            shutil.copy2(live_fp_file, dest_profile_dir / "fingerprint_verified_live.json")
        if act_status_file.exists():
            shutil.copy2(act_status_file, dest_profile_dir / "activated_status.json")

        for item in ["Local State", "Default"]:
            src_item = p_dir / item
            dst_item = dest_profile_dir / item
            if src_item.exists() and not dst_item.exists():
                try:
                    if src_item.is_dir():
                        shutil.copytree(
                            src_item,
                            dst_item,
                            dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(
                                "*.tmp", "*lock*", "*journal*", "Session_*", "Tabs_*"
                            ),
                        )
                    else:
                        shutil.copy2(src_item, dst_item)
                except Exception as copy_err:
                    print(f"    [Notice] Optional copy note for {item}: {copy_err}")

        is_auth, tokens = is_session_authenticated(session_data)
        auth_badge = "[AUTHENTICATED]" if is_auth else "[AUTH REQUIRED]"
        cookie_count = len(session_data.get("cookies", []))
        print(
            f"  -> Exported: {profile_name:<18} | {email:<26} | "
            f"{auth_badge:<16} | cookies={cookie_count:<3} | tokens={','.join(tokens)}"
        )

    exported_accounts.sort(key=lambda a: a["profile"])

    payload_wrapper = {
        "version": 1,
        "updatedAt": now_iso,
        "fleetSize": len(exported_accounts),
        "accounts": exported_accounts,
    }

    accounts_import_file = bundle_dir / "accounts_import.json"
    accounts_import_file.write_text(json.dumps(payload_wrapper, indent=2) + "\n", encoding="utf-8")
    print(f"\n[OK] Written {accounts_import_file} ({len(exported_accounts)} accounts)")

    accounts_file = bundle_dir / "accounts.json"
    accounts_file.write_text(json.dumps(payload_wrapper, indent=2) + "\n", encoding="utf-8")

    archive_path = None
    if create_tar:
        archive_path = bundle_dir.parent / "avatarity_profiles_bundle.tar.gz"
        print(f"[Packaging] Compressing bundle into {archive_path.name} ...")
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(bundle_dir, arcname="veoforge-bundle")
        print(
            f"[OK] VPS Archive ready: {archive_path} "
            f"({archive_path.stat().st_size / (1024 * 1024):.2f} MB)"
        )

    if apply_to_repo and repo_dir:
        if repo_dir.exists():
            gw_data_dir = repo_dir / "gateway" / "data"
            gw_data_dir.mkdir(parents=True, exist_ok=True)
            repo_accounts_file = gw_data_dir / "accounts.json"
            repo_accounts_file.write_text(
                json.dumps(payload_wrapper, indent=2) + "\n", encoding="utf-8"
            )
            print(f"[Applied to Repo] Updated {repo_accounts_file}")

            repo_profiles_dir = gw_data_dir / "profiles"
            repo_profiles_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(bundle_profiles_dir, repo_profiles_dir, dirs_exist_ok=True)
            print(f"[Applied to Repo] Synced profiles to {repo_profiles_dir}")
        else:
            print(f"[Warn] Repo dir {repo_dir} not found; skipping repo sync.")

    auth_count = sum(1 for a in exported_accounts if a["signedIn"])
    print("\n=======================================================")
    print("  EXPORT SUMMARY")
    print("=======================================================")
    print(f"  Total Accounts Exported : {len(exported_accounts)}")
    print(f"  Ready & Authenticated   : {auth_count}")
    print(f"  Bundle Directory        : {bundle_dir}")
    if archive_path and archive_path.exists():
        print(f"  VPS Deploy Archive      : {archive_path}")
        print("\nTo deploy onto your production node (/var/lib/veoforge-node):")
        print(f'  scp "{archive_path}" root@<VPS_HOST>:/tmp/veoforge-bundle.tar.gz')
        print(
            '  ssh root@<VPS_HOST> "tar -xzf /tmp/veoforge-bundle.tar.gz '
            '-C /var/lib/veoforge-node/ --strip-components=1 && systemctl reload veoforge-node"'
        )
    print("=======================================================\n")

    return {
        "success": True,
        "count": len(exported_accounts),
        "auth_count": auth_count,
        "bundle_dir": str(bundle_dir),
        "accounts_import_file": str(accounts_import_file),
        "archive_path": str(archive_path) if archive_path else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export authenticated Google AI Pro accounts to Avatarity bundle."
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=DEFAULT_PROFILES_DIR,
        help="Path to avatarity_profiles source directory",
    )
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=DEFAULT_BUNDLE_DIR,
        help="Output directory for Avatarity bundle",
    )
    parser.add_argument(
        "--sheet-file",
        type=Path,
        default=DEFAULT_SHEET_FILE,
        help="Path to accounts CSV file",
    )
    parser.add_argument(
        "--meta-file",
        type=Path,
        default=DEFAULT_META_FILE,
        help="Path to clean_proxies_metadata.json",
    )
    parser.add_argument(
        "--no-tar",
        action="store_true",
        help="Skip creating .tar.gz archive",
    )
    parser.add_argument(
        "--apply-to-repo",
        action="store_true",
        help="Write accounts.json and profiles directly into local repository gateway/data",
    )
    parser.add_argument(
        "--repo-dir",
        type=Path,
        default=None,
        help="Path to local Avatarity repository root when using --apply-to-repo",
    )

    args = parser.parse_args()

    export_profiles(
        profiles_dir=args.profiles_dir,
        bundle_dir=args.bundle_dir,
        sheet_file=args.sheet_file,
        meta_file=args.meta_file,
        create_tar=not args.no_tar,
        apply_to_repo=args.apply_to_repo,
        repo_dir=args.repo_dir,
    )


if __name__ == "__main__":
    main()
