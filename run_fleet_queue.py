#!/usr/bin/env python3
"""
High-Throughput Queue-Driven Google AI Pro 18-Month Fleet Activator
===================================================================
- Only pops an activation link from link_queue AFTER an account is logged in
  (SID / __Secure-1PSID verified) and live fingerprint isolation is verified.
- If a popped link is dead/404 or already used, keeps the authenticated browser
  open and immediately pops the next link from link_queue.
- If an account is already an active Google AI Pro member, automatically rescues
  the resolved entitlement URL back into link_queue for the next worker.
- Zero CDP Fetch/Emulation/InitScript interception during ServiceLogin.
- Full per-profile WebGL/Canvas/Audio/Screen/HardwareConcurrency/WebGPU
  fingerprint isolation installed immediately after ServiceLogin.
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pyotp
from patchright.async_api import BrowserContext, Page, Request, Route, async_playwright

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

GPU_PROFILES: List[Tuple[str, str]] = [
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
]

SCREEN_PROFILES: List[Dict[str, Any]] = [
    {"width": 1920, "height": 1080, "availHeight": 1032, "dpr": 1},
    {"width": 1920, "height": 1080, "availHeight": 1040, "dpr": 1.25},
    {"width": 1536, "height": 864, "availHeight": 816, "dpr": 1.25},
    {"width": 1600, "height": 900, "availHeight": 852, "dpr": 1},
    {"width": 1440, "height": 900, "availHeight": 852, "dpr": 1},
    {"width": 1680, "height": 1050, "availHeight": 1002, "dpr": 1},
    {"width": 1366, "height": 768, "availHeight": 720, "dpr": 1},
    {"width": 2560, "height": 1440, "availHeight": 1392, "dpr": 1.25},
]

CPU_MEM_PROFILES: List[Tuple[int, int]] = [
    (8, 8),
    (12, 16),
    (16, 16),
    (16, 32),
    (6, 8),
    (8, 16),
    (4, 8),
    (20, 32),
]

CHROME_VERSIONS: List[Tuple[str, str]] = [
    ("132", "132.0.6834.160"),
    ("133", "133.0.6943.99"),
    ("133", "133.0.6943.127"),
    ("134", "134.0.6998.89"),
]

FILE_LOCK = asyncio.Lock()


def resolve_input_file(primary: Path, fallbacks: List[Path]) -> Path:
    if primary.exists():
        return primary
    for candidate in fallbacks:
        if candidate.exists():
            return candidate
    return primary


def build_device_fingerprint(email: str, proxy_meta: Dict[str, Any]) -> Dict[str, Any]:
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).digest()
    seed = int.from_bytes(digest[:8], "big")
    gpu_vendor, gpu_renderer = GPU_PROFILES[seed % len(GPU_PROFILES)]
    screen = SCREEN_PROFILES[(seed >> 8) % len(SCREEN_PROFILES)]
    cores, memory = CPU_MEM_PROFILES[(seed >> 16) % len(CPU_MEM_PROFILES)]
    major_ver, full_ver = CHROME_VERSIONS[(seed >> 24) % len(CHROME_VERSIONS)]
    platform_ver = "15.0.0" if ((seed >> 32) % 2 == 0) else "10.0.0"

    canvas_shift_r = ((seed >> 36) % 5) - 2
    canvas_shift_g = ((seed >> 40) % 5) - 2
    canvas_shift_b = ((seed >> 44) % 5) - 2
    if canvas_shift_r == 0 and canvas_shift_g == 0 and canvas_shift_b == 0:
        canvas_shift_b = 1
    audio_noise = (((seed >> 48) % 900) + 100) * 1e-8
    rect_jitter = (((seed >> 52) % 80) + 11) * 1e-6

    media_ids = [
        hashlib.sha256(f"{email}:audioinput".encode()).hexdigest()[:64],
        hashlib.sha256(f"{email}:audiooutput".encode()).hexdigest()[:64],
        hashlib.sha256(f"{email}:videoinput".encode()).hexdigest()[:64],
        hashlib.sha256(f"{email}:group".encode()).hexdigest()[:64],
    ]

    tz = proxy_meta.get("timezone") or "America/New_York"
    return {
        "email": email,
        "seed": seed,
        "userAgent": (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
        ),
        "chromeMajor": major_ver,
        "chromeFull": full_ver,
        "platformVersion": platform_ver,
        "gpuVendor": gpu_vendor,
        "gpuRenderer": gpu_renderer,
        "screen": screen,
        "hardwareConcurrency": cores,
        "deviceMemory": memory,
        "canvasShift": [canvas_shift_r, canvas_shift_g, canvas_shift_b],
        "audioNoise": audio_noise,
        "rectJitter": rect_jitter,
        "mediaDeviceIds": media_ids,
        "timezoneId": tz,
        "locale": "en-US",
        "proxyPort": proxy_meta.get("port"),
        "proxyIp": proxy_meta.get("ip"),
        "proxyIsp": proxy_meta.get("isp"),
        "proxySubnet": proxy_meta.get("subnet_24"),
    }


def build_fingerprint_init_script(fp: Dict[str, Any]) -> str:
    cfg_json = json.dumps(fp)
    return f"""
(() => {{
  const cfg = {cfg_json};
  if (window._avatarityFpApplied) return;
  try {{
    Object.defineProperty(window, '_avatarityFpApplied', {{ value: true, enumerable: false }});
  }} catch (_) {{}}

  const nativeStrings = new WeakMap();
  const origFnToString = Function.prototype.toString;
  const patchedToString = function toString() {{
    if (nativeStrings.has(this)) {{
      return nativeStrings.get(this);
    }}
    return origFnToString.apply(this, arguments);
  }};
  nativeStrings.set(patchedToString, 'function toString() {{ [native code] }}');
  try {{
    Object.defineProperty(Function.prototype, 'toString', {{
      value: patchedToString,
      writable: true,
      configurable: true
    }});
  }} catch (_) {{}}

  const markNative = (fn, name) => {{
    nativeStrings.set(fn, `function ${{name}}() {{ [native code] }}`);
    return fn;
  }};

  const defineProp = (obj, prop, value) => {{
    if (!obj) return;
    try {{
      const getter = markNative(function() {{ return value; }}, `get ${{prop}}`);
      Object.defineProperty(obj, prop, {{
        get: getter,
        configurable: true,
        enumerable: true
      }});
    }} catch (_) {{}}
  }};

  if (window.Navigator && window.Navigator.prototype) {{
    defineProp(window.Navigator.prototype, 'hardwareConcurrency', cfg.hardwareConcurrency);
    defineProp(window.Navigator.prototype, 'deviceMemory', cfg.deviceMemory);
    defineProp(window.Navigator.prototype, 'language', 'en-US');
    defineProp(window.Navigator.prototype, 'languages', Object.freeze(['en-US', 'en']));
    defineProp(window.Navigator.prototype, 'webdriver', false);
    if ('gpu' in window.Navigator.prototype) {{
      defineProp(window.Navigator.prototype, 'gpu', undefined);
    }}
  }}

  if (window.Screen && window.Screen.prototype) {{
    defineProp(window.Screen.prototype, 'width', cfg.screen.width);
    defineProp(window.Screen.prototype, 'height', cfg.screen.height);
    defineProp(window.Screen.prototype, 'availWidth', cfg.screen.width);
    defineProp(window.Screen.prototype, 'availHeight', cfg.screen.availHeight);
    defineProp(window.Screen.prototype, 'colorDepth', 24);
    defineProp(window.Screen.prototype, 'pixelDepth', 24);
  }}
  defineProp(window, 'devicePixelRatio', cfg.screen.dpr || 1);

  if (window.MediaDevices && window.MediaDevices.prototype && window.MediaDevices.prototype.enumerateDevices) {{
    window.MediaDevices.prototype.enumerateDevices = markNative(async function enumerateDevices() {{
      return [
        {{ deviceId: 'default', kind: 'audioinput', label: '', groupId: cfg.mediaDeviceIds[3], toJSON() {{ return this; }} }},
        {{ deviceId: cfg.mediaDeviceIds[0], kind: 'audioinput', label: '', groupId: cfg.mediaDeviceIds[3], toJSON() {{ return this; }} }},
        {{ deviceId: 'default', kind: 'audiooutput', label: '', groupId: cfg.mediaDeviceIds[3], toJSON() {{ return this; }} }},
        {{ deviceId: cfg.mediaDeviceIds[1], kind: 'audiooutput', label: '', groupId: cfg.mediaDeviceIds[3], toJSON() {{ return this; }} }},
        {{ deviceId: cfg.mediaDeviceIds[2], kind: 'videoinput', label: '', groupId: cfg.mediaDeviceIds[2], toJSON() {{ return this; }} }}
      ];
    }}, 'enumerateDevices');
  }}

  const patchWebGL = (proto) => {{
    if (!proto || !proto.getParameter) return;
    const origGetParameter = proto.getParameter;
    proto.getParameter = markNative(function getParameter(param) {{
      if (param === 37445) return cfg.gpuVendor;
      if (param === 37446) return cfg.gpuRenderer;
      return origGetParameter.apply(this, arguments);
    }}, 'getParameter');

    if (proto.readPixels) {{
      const origReadPixels = proto.readPixels;
      proto.readPixels = markNative(function readPixels() {{
        const res = origReadPixels.apply(this, arguments);
        try {{
          const pixels = arguments[6];
          if (pixels && pixels.length >= 16) {{
            const idx = (cfg.seed % 7) * 4;
            pixels[idx] = (pixels[idx] + cfg.canvasShift[0]) & 0xff;
          }}
        }} catch (_) {{}}
        return res;
      }}, 'readPixels');
    }}
  }};
  if (window.WebGLRenderingContext) patchWebGL(window.WebGLRenderingContext.prototype);
  if (window.WebGL2RenderingContext) patchWebGL(window.WebGL2RenderingContext.prototype);

  const mutateCanvasData = (data) => {{
    if (!data || data.length < 64) return;
    const idx = ((cfg.seed % 11) * 4) % (data.length - 4);
    data[idx] = Math.max(0, Math.min(255, data[idx] + cfg.canvasShift[0]));
    data[idx + 1] = Math.max(0, Math.min(255, data[idx + 1] + cfg.canvasShift[1]));
    data[idx + 2] = Math.max(0, Math.min(255, data[idx + 2] + cfg.canvasShift[2]));
  }};

  if (window.CanvasRenderingContext2D && window.CanvasRenderingContext2D.prototype) {{
    const origGetImageData = window.CanvasRenderingContext2D.prototype.getImageData;
    window.CanvasRenderingContext2D.prototype.getImageData = markNative(function getImageData(sx, sy, sw, sh) {{
      const img = origGetImageData.apply(this, arguments);
      try {{ mutateCanvasData(img.data); }} catch (_) {{}}
      return img;
    }}, 'getImageData');
  }}

  if (window.HTMLCanvasElement && window.HTMLCanvasElement.prototype) {{
    const origToDataURL = window.HTMLCanvasElement.prototype.toDataURL;
    window.HTMLCanvasElement.prototype.toDataURL = markNative(function toDataURL() {{
      try {{
        const ctx = this.getContext('2d');
        if (ctx && this.width > 2 && this.height > 2) {{
          const px = CanvasRenderingContext2D.prototype.getImageData.call(ctx, 0, 0, 2, 2);
          if (px) ctx.putImageData(px, 0, 0);
        }}
      }} catch (_) {{}}
      return origToDataURL.apply(this, arguments);
    }}, 'toDataURL');
  }}

  if (window.AudioBuffer && window.AudioBuffer.prototype && window.AudioBuffer.prototype.getChannelData) {{
    const origGetChannelData = window.AudioBuffer.prototype.getChannelData;
    window.AudioBuffer.prototype.getChannelData = markNative(function getChannelData() {{
      const data = origGetChannelData.apply(this, arguments);
      try {{
        if (data && data.length > 32 && !data._fpPatched) {{
          for (let i = 0; i < Math.min(data.length, 128); i += 13) {{
            data[i] = data[i] + cfg.audioNoise;
          }}
          Object.defineProperty(data, '_fpPatched', {{ value: true, enumerable: false }});
        }}
      }} catch (_) {{}}
      return data;
    }}, 'getChannelData');
  }}
}})();
"""


async def setup_bandwidth_saver(context: BrowserContext) -> None:
    async def handle_route(route: Route, request: Request) -> None:
        url = request.url
        rtype = request.resource_type

        if "accounts.google.com" in url or "accounts.youtube.com" in url:
            await route.continue_()
            return

        if (
            rtype in ("media",)
            or "play.google.com/log" in url
            or "google-analytics.com" in url
            or "doubleclick.net" in url
            or "googlevideo.com" in url
            or "www.youtube.com" in url
            or "ytimg.com" in url
            or "optimizationguide-pa.googleapis.com" in url
            or "content-autofill.googleapis.com" in url
            or "safebrowsing.googleapis.com" in url
        ):
            await route.fulfill(status=204, body=b"")
            return

        await route.fallback()

    await context.route("**/*", handle_route)


async def verify_fingerprint_isolation(page: Page) -> Dict[str, Any]:
    return await page.evaluate(
        """() => {
        const c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        const ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('Avatarity-FP-Check', 2, 15);
        const dataUrl = c.toDataURL();

        const glCanvas = document.createElement('canvas');
        const gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
        let vendor = null, renderer = null;
        if (gl) {
            const dbg = gl.getExtension('WEBGL_debug_renderer_info');
            vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
            renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
        }

        return {
            userAgent: navigator.userAgent,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
            languages: navigator.languages,
            webdriver: navigator.webdriver,
            webgpuAvailable: typeof navigator.gpu !== 'undefined',
            screen: {
                width: screen.width,
                height: screen.height,
                availHeight: screen.availHeight,
                dpr: window.devicePixelRatio
            },
            webglVendor: vendor,
            webglRenderer: renderer,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            canvasSampleTail: dataUrl.slice(-48)
        };
    }""",
        isolated_context=False,
    )


def load_all_accounts(emails_file: Path) -> List[Dict[str, Any]]:
    if not emails_file.exists():
        raise FileNotFoundError(
            f"Accounts file not found at {emails_file}. Place your accounts sheet at {emails_file} or set ACCOUNTS_CSV."
        )
    lines = emails_file.read_text(encoding="utf-8", errors="replace").splitlines()
    accounts: List[Dict[str, Any]] = []
    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        kv: Dict[str, str] = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                kv[k.strip().lower()] = v.strip()
        if "email" not in kv:
            continue
        email = kv["email"]
        profile_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", email.split("@")[0])
        accounts.append(
            {
                "index": idx,
                "account_number": idx + 1,
                "email": email,
                "profile_slug": profile_slug,
                "password": kv.get("password", ""),
                "totp_secret": kv.get("2fa", "").replace(" ", ""),
                "backup_email": kv.get("backup", ""),
            }
        )
    return accounts


async def update_shared_ledger(
    ledger_file: Path,
    idx: int,
    result: Dict[str, Any],
    activation_url: Optional[str] = None,
    link_entry: Optional[Dict[str, Any]] = None,
) -> None:
    async with FILE_LOCK:
        try:
            ledger_file.parent.mkdir(parents=True, exist_ok=True)
            if ledger_file.exists():
                ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
            else:
                ledger = {"updated_at": "", "consumed_links": {}, "accounts": {}}
            ledger["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            ledger.setdefault("accounts", {})[str(idx)] = result
            if activation_url and link_entry:
                ledger.setdefault("consumed_links", {})[activation_url] = link_entry
            ledger_file.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[LedgerSync] Note: {e}")


async def dismiss_google_speedbumps(page: Page, backup_email: str, tag: str) -> None:
    for _ in range(3):
        url = page.url
        if "myaccount.google.com" in url or "google.com/?" in url:
            break
        try:
            body_txt = (await page.locator("body").inner_text(timeout=3000)).lower()
        except Exception:
            body_txt = ""

        if "confirm your recovery email" in body_txt and backup_email:
            print(f"[{tag}] Handling 'Confirm your recovery email' prompt...")
            rec_item = page.locator(
                'div[role="link"]:has-text("Confirm your recovery email"), '
                'li:has-text("Confirm your recovery email")'
            )
            if await rec_item.count() > 0 and await rec_item.first.is_visible():
                await rec_item.first.click()
                await asyncio.sleep(3)
            rec_input = page.locator(
                'input[type="email"], input[name="knowledgePreregisteredEmailResponse"], '
                "input#knowledge-preregistered-email-response"
            )
            if await rec_input.count() > 0 and await rec_input.first.is_visible():
                await rec_input.first.fill(backup_email)
                await asyncio.sleep(0.5)
                await page.locator('button:has-text("Next"), button:has-text("Confirm")').first.click()
                await asyncio.sleep(4)
                continue

        skip_btn = page.locator(
            'button:has-text("Skip"), button:has-text("Not now"), button:has-text("I agree"), '
            'button:has-text("Accept all"), button:has-text("Continue"), button:has-text("Cancel"), '
            'button:has-text("I understand")'
        )
        if await skip_btn.count() > 0 and await skip_btn.first.is_visible():
            btn_label = (await skip_btn.first.inner_text()).strip()
            print(f"[{tag}] Clicking post-login speedbump button: '{btn_label}'")
            await skip_btn.first.click()
            await asyncio.sleep(3)
        else:
            break


async def activate_single_account(
    acc: Dict[str, Any],
    proxy_meta: Dict[str, Any],
    proxy_host: str,
    proxy_user: str,
    proxy_pass: str,
    profiles_root: Path,
    proofs_dir: Path,
    ledger_file: Path,
    link_queue: asyncio.Queue,
    sem: asyncio.Semaphore,
    headless: bool = False,
) -> Optional[Dict[str, Any]]:
    async with sem:
        if link_queue.empty():
            return None

        idx = acc["index"]
        acc_num = acc["account_number"]
        email = acc["email"]
        profile_slug = acc["profile_slug"]
        tag = f"Acc#{acc_num:03d}:{profile_slug}"

        profile_dir = profiles_root / profile_slug
        act_status_file = profile_dir / "activated_status.json"
        if act_status_file.exists():
            try:
                st = json.loads(act_status_file.read_text(encoding="utf-8"))
                if st.get("status") == "VERIFIED_ACTIVE":
                    print(f"[{tag}] Already VERIFIED_ACTIVE on disk; skipping.")
                    return st
            except Exception:
                pass

        # If profile exists but does not have flow-session-state.json, wipe for clean login
        if profile_dir.exists() and not (profile_dir / "flow-session-state.json").exists():
            shutil.rmtree(profile_dir, ignore_errors=True)
        profile_dir.mkdir(parents=True, exist_ok=True)

        fp = build_device_fingerprint(email, proxy_meta)
        (profile_dir / "fingerprint.json").write_text(json.dumps(fp, indent=2), encoding="utf-8")

        print(
            f"\n[{tag}] Starting | Proxy :{proxy_meta['port']} "
            f"({proxy_meta.get('ip')} - {proxy_meta.get('isp')}) | GPU: {fp['gpuRenderer']}"
        )

        result: Dict[str, Any] = {
            "index": idx,
            "account_number": acc_num,
            "email": email,
            "profile_slug": profile_slug,
            "proxy_port": proxy_meta["port"],
            "proxy_ip": proxy_meta.get("ip"),
            "proxy_isp": proxy_meta.get("isp"),
            "status": "INIT",
            "activation_link": None,
            "final_url": None,
            "celebration_screenshot": None,
            "error": None,
        }

        win_w = min(fp["screen"]["width"], 1440)
        win_h = min(fp["screen"]["availHeight"], 900)

        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                channel="chrome",
                headless=headless,
                no_viewport=True,
                proxy={
                    "server": f"http://{proxy_host}:{proxy_meta['port']}",
                    "username": proxy_user,
                    "password": proxy_pass,
                    "bypass": "<-loopback>,activationservice.services,*.activationservice.services",
                },
                locale="en-US",
                timezone_id=fp["timezoneId"],
                ignore_default_args=["--enable-automation"],
                args=[
                    f"--window-size={win_w},{win_h}",
                    "--window-position=50,50",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-infobars",
                    "--disable-session-crashed-bubble",
                    "--hide-crash-restore-bubble",
                    "--no-default-browser-check",
                    "--disable-extensions",
                    "--disable-sync",
                    "--disable-component-extensions-with-background-pages",
                    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--force-webrtc-ip-handling-policy",
                    "--no-first-run",
                ],
            )

            try:
                page = context.pages[0] if context.pages else await context.new_page()

                cookies = await context.cookies("https://accounts.google.com")
                has_sid = any(c["name"] in ("SID", "__Secure-1PSID") for c in cookies)

                if not has_sid:
                    print(f"[{tag}] Navigating to Google ServiceLogin...")
                    await page.goto(
                        "https://accounts.google.com/ServiceLogin?hl=en",
                        wait_until="domcontentloaded",
                        timeout=45000,
                    )
                    await asyncio.sleep(2.2)

                    await page.mouse.move(180, 220, steps=14)
                    await asyncio.sleep(0.25)
                    await page.mouse.move(460, 330, steps=18)

                    email_input = page.locator('input[type="email"], input#identifierId')
                    await email_input.first.wait_for(state="visible", timeout=25000)
                    print(f"[{tag}] Entering email: {email}")
                    await email_input.first.click()
                    await asyncio.sleep(0.35)
                    await email_input.first.fill(email)
                    await asyncio.sleep(0.9)
                    await page.locator('#identifierNext button, button:has-text("Next")').first.click()
                    await asyncio.sleep(4.5)

                    if "challenge/recaptcha" in page.url:
                        print(f"[{tag}] Detected challenge/recaptcha; clicking checkbox...")
                        try:
                            anchor_iframe = page.locator(
                                'iframe[src*="recaptcha/api2/anchor"], iframe[src*="recaptcha/enterprise/anchor"]'
                            ).first
                            await anchor_iframe.wait_for(state="visible", timeout=10000)
                            await asyncio.sleep(1.0)
                            box = await anchor_iframe.bounding_box()
                            if box:
                                await page.mouse.move(box["x"] + 28, box["y"] + 35, steps=16)
                                await asyncio.sleep(0.25)
                                await page.mouse.click(box["x"] + 28, box["y"] + 35)
                                await asyncio.sleep(3.5)
                            rc_frame = page.frame_locator(
                                'iframe[src*="recaptcha/api2/anchor"], iframe[src*="recaptcha/enterprise/anchor"]'
                            ).first
                            checked = await rc_frame.locator('#recaptcha-anchor[aria-checked="true"]').count()
                            if checked > 0:
                                print(f"[{tag}] Checkbox passed! Clicking Next...")
                                await page.locator('button:has-text("Next"), #identifierNext button').first.click()
                                await asyncio.sleep(4.0)
                            else:
                                print(f"[{tag}] Challenge requires image selection; fast-failing without consuming link.")
                                result["status"] = "CHALLENGE_SKIPPED"
                                result["error"] = "Challenge on ServiceLogin"
                                await update_shared_ledger(ledger_file, idx, result)
                                await context.close()
                                return result
                        except Exception as rc_err:
                            result["status"] = "CHALLENGE_SKIPPED"
                            result["error"] = str(rc_err)
                            await update_shared_ledger(ledger_file, idx, result)
                            await context.close()
                            return result

                    if "rejected" in page.url or "challenge/dp" in page.url or "challenge/iap" in page.url:
                        print(f"[{tag}] Challenge/rejected after email ({page.url}); fast-failing without consuming link.")
                        result["status"] = "CHALLENGE_SKIPPED"
                        result["error"] = f"Challenge after email: {page.url}"
                        await update_shared_ledger(ledger_file, idx, result)
                        await context.close()
                        return result

                    pwd_input = page.locator(
                        'input[name="Passwd"]:not([aria-hidden="true"]), '
                        'input[type="password"]:not([name="hiddenPassword"]):not([aria-hidden="true"])'
                    )
                    await pwd_input.first.wait_for(state="visible", timeout=15000)
                    print(f"[{tag}] Entering password...")
                    await pwd_input.first.click()
                    await asyncio.sleep(0.3)
                    await pwd_input.first.fill(acc["password"])
                    await asyncio.sleep(0.7)
                    await page.locator('#passwordNext button, button:has-text("Next")').first.click()
                    await asyncio.sleep(4.5)

                    totp_input = page.locator('input[type="tel"], input#totpPin, input[name="totpPin"]')
                    try:
                        await totp_input.first.wait_for(state="visible", timeout=14000)
                        rem = 30 - (int(time.time()) % 30)
                        if rem <= 3:
                            await asyncio.sleep(rem + 1)
                        code = pyotp.TOTP(acc["totp_secret"]).now()
                        print(f"[{tag}] Entering 2FA TOTP code: {code}")
                        await totp_input.first.fill(code)
                        await asyncio.sleep(0.5)
                        await page.locator('#totpNext button, button:has-text("Next")').first.click()
                        await asyncio.sleep(5)
                    except Exception as e:
                        print(f"[{tag}] TOTP step note: {e}")

                    await dismiss_google_speedbumps(page, acc["backup_email"], tag)

                # ServiceLogin finished; install per-profile fingerprint isolation + bandwidth saver
                await context.add_init_script(build_fingerprint_init_script(fp))
                await setup_bandwidth_saver(context)

                await page.goto(
                    "https://myaccount.google.com/?hl=en",
                    wait_until="domcontentloaded",
                    timeout=45000,
                )
                await asyncio.sleep(2.5)
                fp_live = await verify_fingerprint_isolation(page)
                (profile_dir / "fingerprint_verified_live.json").write_text(
                    json.dumps(fp_live, indent=2), encoding="utf-8"
                )
                print(
                    f"[{tag}] Live Fingerprint Verified: WebGL={fp_live.get('webglRenderer')} | "
                    f"TZ={fp_live.get('timezone')} | WebGPU={fp_live.get('webgpuAvailable')}"
                )

                cookies = await context.cookies()
                has_sid = any(c["name"] in ("SID", "__Secure-1PSID") for c in cookies)
                if not has_sid:
                    err_shot = proofs_dir / f"acc{acc_num:03d}_{profile_slug}_login_failed.png"
                    await page.screenshot(path=str(err_shot))
                    result["status"] = "LOGIN_FAILED"
                    result["error"] = f"No SID cookie at {page.url}"
                    await update_shared_ledger(ledger_file, idx, result)
                    await context.close()
                    return result

                state = await context.storage_state()
                avatarity_state = {
                    "version": 1,
                    "savedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "projectId": None,
                    "email": email,
                    "egressProxy": f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_meta['port']}",
                    "fingerprint": fp,
                    **state,
                }
                (profile_dir / "flow-session-state.json").write_text(
                    json.dumps(avatarity_state, indent=2), encoding="utf-8"
                )
                result["status"] = "LOGGED_IN"
                await update_shared_ledger(ledger_file, idx, result)

                # Pop links until one redirects cleanly (in case of any dead/404 or already-used link)
                while not link_queue.empty():
                    try:
                        activation_url = link_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

                    result["activation_link"] = activation_url
                    print(f"[{tag}] Opening activation link: {activation_url}")
                    resp = await page.goto(activation_url, wait_until="domcontentloaded", timeout=45000)
                    status_code = resp.status if resp else 0

                    for _ in range(25):
                        await asyncio.sleep(1)
                        if "activationservice.services" not in page.url:
                            break
                        body_check = (await page.locator("body").inner_text()).strip()
                        if status_code == 404 or "404" in body_check or "not found" in body_check.lower():
                            break

                    if "activationservice.services" in page.url:
                        print(
                            f"[{tag}] [WARN] Link dead/404 ({activation_url}); "
                            "trying next link for this logged-in session..."
                        )
                        await update_shared_ledger(
                            ledger_file,
                            idx,
                            result,
                            activation_url,
                            {"status": "LINK_DEAD", "account_index": idx, "email": email},
                        )
                        continue

                    await asyncio.sleep(4)
                    offer_shot = proofs_dir / f"acc{acc_num:03d}_{profile_slug}_6_offer_page.png"
                    await page.screenshot(path=str(offer_shot))
                    print(f"[{tag}] Reached Offer URL: {page.url}")

                    offer_text = await page.locator("body").inner_text()
                    offer_lower = offer_text.lower()

                    if "subscription already in use" in offer_lower or "link has already been used" in offer_lower:
                        print(
                            f"[{tag}] [WARN] Link already used ({activation_url}); "
                            "trying next link in same browser session..."
                        )
                        await update_shared_ledger(
                            ledger_file,
                            idx,
                            result,
                            activation_url,
                            {"status": "LINK_ALREADY_USED", "account_index": idx, "email": email},
                        )
                        continue

                    # Automatic Entitlement Token Rescue if account is already an active member
                    if "you're already a member" in offer_lower or "already a member" in offer_lower:
                        print(
                            f"[{tag}] Account is ALREADY a Google AI Pro member! "
                            f"Rescuing offer URL {page.url} back into link_queue for next account..."
                        )
                        if "one.google.com/activate-plan/subscription/new/" in page.url:
                            link_queue.put_nowait(page.url)
                        result["status"] = "VERIFIED_ACTIVE"
                        result["final_url"] = page.url
                        result["celebration_screenshot"] = str(offer_shot)
                        result["verified_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        result["note"] = "Already a Google AI Pro member prior to redemption; entitlement token rescued"
                        (profile_dir / "activated_status.json").write_text(
                            json.dumps(result, indent=2), encoding="utf-8"
                        )
                        await update_shared_ledger(ledger_file, idx, result)
                        break

                    activate_btn = page.locator(
                        'button:has-text("Activate plan"), [role="button"]:has-text("Activate plan"), '
                        'button:has-text("Accept"), button:has-text("Confirm"), button:has-text("Redeem")'
                    )
                    try:
                        await activate_btn.first.wait_for(state="visible", timeout=20000)
                    except Exception:
                        pass

                    if await activate_btn.count() > 0 and await activate_btn.first.is_visible():
                        btn_text = (await activate_btn.first.inner_text()).strip()
                        print(f"[{tag}] Clicking '{btn_text}' CTA...")
                        await activate_btn.first.click()

                        for _ in range(25):
                            await asyncio.sleep(1)
                            if "one.google.com/celebration" in page.url:
                                break
                            try:
                                t = await page.locator("body").inner_text()
                                if "Google AI Pro member" in t:
                                    break
                            except Exception:
                                pass
                        await asyncio.sleep(3)

                    final_shot = proofs_dir / f"acc{acc_num:03d}_{profile_slug}_7_final_activated.png"
                    await page.screenshot(path=str(final_shot))
                    final_text = await page.locator("body").inner_text()
                    final_url = page.url

                    is_celebration = (
                        "one.google.com/celebration" in final_url
                        or "Google AI Pro member" in final_text
                        or "You're a Google AI Pro member" in final_text
                    )

                    state2 = await context.storage_state()
                    avatarity_state.update(state2)
                    avatarity_state["savedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    (profile_dir / "flow-session-state.json").write_text(
                        json.dumps(avatarity_state, indent=2), encoding="utf-8"
                    )

                    if is_celebration:
                        result["status"] = "VERIFIED_ACTIVE"
                        result["final_url"] = final_url
                        result["celebration_screenshot"] = str(final_shot)
                        result["verified_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        (profile_dir / "activated_status.json").write_text(
                            json.dumps(result, indent=2), encoding="utf-8"
                        )
                        link_entry = {
                            "status": "VERIFIED_ACTIVE",
                            "account_index": idx,
                            "email": email,
                        }
                        print(f"[{tag}] [SUCCESS] VERIFIED_ACTIVE on {final_url} -> Proof: {final_shot.name}")
                    else:
                        result["status"] = "NEEDS_REVIEW"
                        result["final_url"] = final_url
                        result["celebration_screenshot"] = str(final_shot)
                        result["error"] = f"Did not see celebration text; snippet: {final_text[:240]}"
                        link_entry = {
                            "status": "NEEDS_REVIEW",
                            "account_index": idx,
                            "email": email,
                        }
                        print(f"[{tag}] [WARN] Needs review at {final_url} -> Screenshot: {final_shot.name}")

                    await update_shared_ledger(ledger_file, idx, result, activation_url, link_entry)
                    break

            except Exception as e:
                try:
                    err_shot = proofs_dir / f"acc{acc_num:03d}_{profile_slug}_exception.png"
                    await page.screenshot(path=str(err_shot))
                except Exception:
                    pass
                result["status"] = "ERROR"
                result["error"] = str(e)
                await update_shared_ledger(ledger_file, idx, result)
                print(f"[{tag}] [EXCEPTION] {e}")
            finally:
                await context.close()

        return result


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="High-Throughput Queue-Driven Google AI Pro Fleet Activator"
    )
    parser.add_argument(
        "--link-start",
        type=int,
        default=0,
        help="0-based start index in activation links file",
    )
    parser.add_argument(
        "--link-end",
        type=int,
        default=None,
        help="0-based end index (exclusive) in activation links file",
    )
    parser.add_argument(
        "--acc-start",
        type=int,
        default=0,
        help="0-based start account index in accounts CSV",
    )
    parser.add_argument(
        "--acc-end",
        type=int,
        default=333,
        help="0-based end account index (exclusive)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Number of concurrent Chrome workers",
    )
    parser.add_argument(
        "--accounts-csv",
        type=Path,
        default=Path(os.environ.get("ACCOUNTS_CSV", str(DATA_DIR / "emails_sheet.csv"))),
        help="Path to accounts CSV file (env: ACCOUNTS_CSV)",
    )
    parser.add_argument(
        "--links-file",
        type=Path,
        default=Path(os.environ.get("LINKS_FILE", str(DATA_DIR / "activation_links.txt"))),
        help="Path to activation links file (env: LINKS_FILE)",
    )
    parser.add_argument(
        "--proxies-meta",
        type=Path,
        default=Path(os.environ.get("PROXIES_META_FILE", str(DATA_DIR / "clean_proxies_metadata.json"))),
        help="Path to clean proxy metadata JSON (env: PROXIES_META_FILE)",
    )
    parser.add_argument(
        "--ledger-file",
        type=Path,
        default=Path(os.environ.get("LEDGER_FILE", str(DATA_DIR / "activation_ledger.json"))),
        help="Path to activation ledger JSON (env: LEDGER_FILE)",
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=Path(os.environ.get("PROFILES_DIR", str(BASE_DIR / "avatarity_profiles"))),
        help="Directory for persistent browser profiles (env: PROFILES_DIR)",
    )
    parser.add_argument(
        "--proofs-dir",
        type=Path,
        default=Path(os.environ.get("PROOFS_DIR", str(BASE_DIR / "proofs"))),
        help="Directory for celebration/debug screenshots (env: PROOFS_DIR)",
    )
    parser.add_argument(
        "--proxy-host",
        type=str,
        default=os.environ.get("PROXY_HOST", "gw.dataimpulse.com"),
        help="Proxy gateway hostname (env: PROXY_HOST)",
    )
    parser.add_argument(
        "--proxy-user",
        type=str,
        default=os.environ.get("PROXY_USER", ""),
        help="Proxy username (env: PROXY_USER)",
    )
    parser.add_argument(
        "--proxy-pass",
        type=str,
        default=os.environ.get("PROXY_PASS", ""),
        help="Proxy password (env: PROXY_PASS)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run Chrome in headless mode (default: False / headed)",
    )
    args = parser.parse_args()

    if not args.proxy_user or not args.proxy_pass or args.proxy_user == "your_proxy_user":
        raise SystemExit(
            "[Error] Missing proxy credentials. Configure PROXY_USER and PROXY_PASS in .env or via CLI flags."
        )

    accounts_csv = resolve_input_file(
        args.accounts_csv,
        [DATA_DIR / "emails_sheet.csv", BASE_DIR / "emails_sheet.csv"],
    )
    links_file = resolve_input_file(
        args.links_file,
        [
            DATA_DIR / "activation_links.txt",
            DATA_DIR / "activation_links_batch1.txt",
            BASE_DIR / "activation_links.txt",
            BASE_DIR / "activation_links_batch1.txt",
        ],
    )
    proxies_meta_file = resolve_input_file(
        args.proxies_meta,
        [
            DATA_DIR / "clean_proxies_metadata.json",
            DATA_DIR / "clean_333_strict_metadata.json",
            BASE_DIR / "clean_proxies_metadata.json",
            BASE_DIR / "clean_333_strict_metadata.json",
        ],
    )

    if not links_file.exists():
        raise FileNotFoundError(
            f"Activation links file not found at {links_file}. Place links in ./data/activation_links.txt or set LINKS_FILE."
        )
    if not proxies_meta_file.exists():
        raise FileNotFoundError(
            f"Proxy metadata file not found at {proxies_meta_file}. Run scan_residential_proxies.py first or place metadata in ./data/."
        )

    args.profiles_dir.mkdir(parents=True, exist_ok=True)
    args.proofs_dir.mkdir(parents=True, exist_ok=True)
    args.ledger_file.parent.mkdir(parents=True, exist_ok=True)

    accounts = load_all_accounts(accounts_csv)
    proxies_meta = json.loads(proxies_meta_file.read_text(encoding="utf-8"))
    all_links = [
        line.strip()
        for line in links_file.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("http")
    ]
    link_end = args.link_end if args.link_end is not None else len(all_links)
    selected_links = all_links[args.link_start : link_end]

    # Skip links already marked consumed in ledger
    consumed: Dict[str, Any] = {}
    if args.ledger_file.exists():
        try:
            consumed = json.loads(args.ledger_file.read_text(encoding="utf-8")).get("consumed_links", {})
        except Exception:
            consumed = {}

    link_queue: asyncio.Queue = asyncio.Queue()
    for link in selected_links:
        if link not in consumed:
            link_queue.put_nowait(link)

    cand_queue: asyncio.Queue = asyncio.Queue()
    for idx in range(args.acc_start, min(args.acc_end, len(accounts))):
        cand_queue.put_nowait(idx)

    print(
        f"=== Fleet Queue Runner: {link_queue.qsize()} links (slice {args.link_start}:{link_end}) "
        f"| Candidate Accounts {args.acc_start}..{min(args.acc_end, len(accounts)) - 1} "
        f"| Concurrency={args.concurrency} ==="
    )

    sem = asyncio.Semaphore(args.concurrency)
    results: List[Dict[str, Any]] = []

    async def worker_loop() -> None:
        while not link_queue.empty() and not cand_queue.empty():
            try:
                idx = cand_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            acc = accounts[idx]
            p_meta = proxies_meta[idx % len(proxies_meta)]
            res = await activate_single_account(
                acc=acc,
                proxy_meta=p_meta,
                proxy_host=args.proxy_host,
                proxy_user=args.proxy_user,
                proxy_pass=args.proxy_pass,
                profiles_root=args.profiles_dir,
                proofs_dir=args.proofs_dir,
                ledger_file=args.ledger_file,
                link_queue=link_queue,
                sem=sem,
                headless=args.headless,
            )
            if res:
                results.append(res)

    workers = [worker_loop() for _ in range(args.concurrency)]
    await asyncio.gather(*workers)

    verified = [r for r in results if r.get("status") == "VERIFIED_ACTIVE"]
    print(f"\n=== Fleet Queue Complete: {len(verified)} VERIFIED_ACTIVE / {len(results)} attempted ===")


if __name__ == "__main__":
    asyncio.run(main())
