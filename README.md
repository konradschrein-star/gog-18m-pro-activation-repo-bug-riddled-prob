# Google AI Pro 18-Month Fleet Activator & Avatarity Exporter

High-throughput, queue-driven browser automation toolkit for activating Google One AI Pro (18-Month) memberships across a multi-account fleet with 1:1 sticky residential proxy isolation, deterministic per-profile hardware fingerprinting, automatic entitlement token rescue, and 1-command export into an Avatarity production bundle.

---

## Core Architecture

1. **Zero-Interception Native `ServiceLogin`**
   - Launches persistent native Chrome contexts via `patchright` with zero CDP `Fetch`, `Emulation`, or `addInitScript` hooks active during `accounts.google.com/ServiceLogin`, preserving clean BotGuard and reCAPTCHA Enterprise telemetry.
   - Automatically completes email, password, `pyotp` 2FA TOTP (with 30-second window rollover guard), and post-login recovery email / speedbump prompts.
   - Fast-fails without touching any activation link if an account encounters a login challenge.

2. **Per-Profile Hardware Fingerprint & Timezone Isolation**
   - Immediately after `ServiceLogin` completes, installs a deterministic SHA-256 email-seeded device profile (`fingerprint.json`) with native `Function.prototype.toString` masking:
     - **WebGL Vendor & Renderer** (`ANGLE` NVIDIA RTX 3060/3070/4060/4070, Intel Iris Xe/UHD, AMD Radeon RX)
     - **Canvas 2D & WebGL `readPixels`** deterministic sub-pixel noise
     - **AudioBuffer** channel sample noise
     - **Screen Geometry & DPR** (`1920x1080`, `1536x864`, `1600x900`, `2560x1440`, etc.)
     - **Navigator Hardware** (`hardwareConcurrency`, `deviceMemory`, `mediaDevices.enumerateDevices`, `webdriver=false`, `gpu=undefined`)
     - **Geo-Aligned Timezone** matched to the exit IP's residential timezone (`America/New_York`, `America/Chicago`, `America/Los_Angeles`, etc.)
   - Verifies the live fingerprint on `https://myaccount.google.com` and records `fingerprint_verified_live.json` in each profile folder.

3. **Queue-Driven Link Redemption & Entitlement Token Rescue**
   - Activation links are popped from `link_queue` **only after** `SID` / `__Secure-1PSID` authentication cookies and live fingerprint isolation are verified.
   - **Dead / Already-Used Link Recovery:** If a link returns HTTP 404 or `Subscription already in use`, the worker logs it in `activation_ledger.json` and immediately pops the next link in the same authenticated browser session.
   - **Entitlement Token Rescue:** If an account is already an active Google AI Pro member (`You're already a member`), the resolved `one.google.com/activate-plan/subscription/new/...` entitlement URL is pushed back onto `link_queue` for the next worker so zero activation links are wasted.

4. **Strict Consumer Eyeball ISP `/24` Proxy Scanner (`scan_residential_proxies.py`)**
   - Scans sticky residential proxy ports concurrently, enriches exit IPs via batch ASN/ISP intelligence, strips datacenter/VPN/leased subnets (`M247`, `Datacamp`, `Choopa`, `IPXO`, `Netrouting`, `PacketHub`, etc.), prioritizes Tier-1 US consumer eyeball ISPs (`Comcast`, `AT&T`, `Verizon`, `Spectrum/Charter`, `Cox`, `T-Mobile`, `CenturyLink/Lumen`), and deduplicates strictly by `/24` subnet.

---

## Multi-Machine Quickstart Guide

### 1. Clone & Install Dependencies

```bash
git clone <REPO_URL>
cd gog-18m-pro-activation-repo-bug-riddled-prob

python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# macOS / Linux:
# source .venv/bin/activate

pip install -r requirements.txt
patchright install chrome
```

### 2. Configure Environment (`.env`)

Copy `.env.example` to `.env` and fill in your sticky residential proxy credentials:

```bash
cp .env.example .env
```

```dotenv
PROXY_HOST=gw.dataimpulse.com
PROXY_USER=your_proxy_user
PROXY_PASS=your_proxy_pass
PROXY_START_PORT=10000
PROXY_END_PORT=10998

ACCOUNTS_CSV=./data/emails_sheet.csv
LINKS_FILE=./data/activation_links.txt
PROXIES_META_FILE=./data/clean_proxies_metadata.json
LEDGER_FILE=./data/activation_ledger.json
```

### 3. Populate `./data/` Inputs

Create the `./data/` folder (gitignored) and drop in your input files:

1. **`./data/emails_sheet.csv`** — One account per line in pipe-delimited `Key: Value` format:
   ```text
   Email: user001@example.com | Password: your_password | 2FA: JBSWY3DPEHPK3PXP | Backup: recovery001@example.com
   ```
2. **`./data/activation_links.txt`** — One activation link per line:
   ```text
   https://activationservice.services/?id=<LINK_ID>
   ```
3. **`./data/clean_proxies_metadata.json`** — Either copy your existing `clean_333_strict_metadata.json` to `./data/clean_proxies_metadata.json` (both filenames are auto-detected), or scan a fresh pool:
   ```bash
   python scan_residential_proxies.py --start-port 10000 --end-port 10998 --target-count 333
   ```

---

## Running the Fleet Queue Across Multiple Machines

To split work cleanly across two or more machines (e.g., Desktop + Laptop) without colliding on links, accounts, or sticky proxy ports, assign disjoint `--link-start` / `--link-end` and `--acc-start` / `--acc-end` slices to each machine:

### Machine A (e.g., Links `4..60`, Accounts `15..160`)
```bash
python run_fleet_queue.py --link-start 4 --link-end 60 --acc-start 15 --acc-end 160 --concurrency 3
```

### Machine B / Laptop (e.g., Links `60..121`, Accounts `160..333`)
```bash
python run_fleet_queue.py --link-start 60 --link-end 121 --acc-start 160 --acc-end 333 --concurrency 3
```

### CLI Options (`run_fleet_queue.py`)
| Flag | Default | Description |
| :--- | :--- | :--- |
| `--link-start` | `0` | 0-based start index (inclusive) in `LINKS_FILE` |
| `--link-end` | `all` | 0-based end index (exclusive) in `LINKS_FILE` |
| `--acc-start` | `0` | 0-based start account index (inclusive) in `ACCOUNTS_CSV` |
| `--acc-end` | `333` | 0-based end account index (exclusive) in `ACCOUNTS_CSV` |
| `--concurrency` | `3` | Number of parallel Chrome browser workers |
| `--accounts-csv` | `./data/emails_sheet.csv` | Path to accounts sheet |
| `--links-file` | `./data/activation_links.txt` | Path to activation links file |
| `--proxies-meta` | `./data/clean_proxies_metadata.json` | Path to proxy metadata JSON |
| `--ledger-file` | `./data/activation_ledger.json` | Shared JSON ledger tracking consumed links and account states |
| `--profiles-dir` | `./avatarity_profiles` | Output directory for persistent Chrome profiles & `flow-session-state.json` |
| `--proofs-dir` | `./proofs` | Output directory for offer & celebration verification screenshots |
| `--headless` | `False` | Run Chrome in headless mode (headed mode is recommended) |

---

## Exporting Activated Profiles to Avatarity

Once a batch finishes, package all authenticated profiles (`flow-session-state.json` + `fingerprint.json` + `accounts_import.json`) into a deployable `.tar.gz` archive:

```bash
python export_to_avatarity.py
```

This produces:
- `./avatarity_bundle/accounts_import.json` (ready for `AccountFleetManager` / `AccountRegistry`)
- `./avatarity_bundle/profiles/<profile_slug>/flow-session-state.json`
- `./avatarity_bundle/profiles/<profile_slug>/fingerprint.json`
- `./avatarity_profiles_bundle.tar.gz`
