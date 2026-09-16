"""iOS .ipa reading helpers — offline, dependency-free.

An `.ipa` is a zip: `Payload/<App>.app/` holds `Info.plist` (binary or XML plist), the Mach-O
executable, `embedded.mobileprovision` (a CMS blob wrapping an entitlements plist), and frameworks.
These helpers locate those parts and decode them with the standard library only:

  * `plistlib` reads BOTH binary (`bplist00`) and XML plists, so — unlike Android's binary XML —
    no hand-written decoder is needed.
  * the provisioning profile is a signed CMS blob, but the entitlements plist is embedded in the
    clear inside it; we extract the `<plist>…</plist>` span and parse that. We never verify the
    signature (we are reading posture, not trusting the profile), so no crypto is required.
  * a light Mach-O load-command scan reports FairPlay encryption (`cryptid`) — which tells a
    reviewer why string analysis of a store binary finds little.

Everything is bounded and defensive: a malformed part costs coverage of that part, never a crash.
"""

from __future__ import annotations

import plistlib
import struct
import zipfile
from dataclasses import dataclass, field

from guardian_scanner.mobile.safezip import (
    ArchiveMemberTooLarge,
    read_bounded,
    read_whole_capped,
)


class IpaError(RuntimeError):
    """The uploaded file is not a readable iOS .ipa."""


@dataclass
class IpaBundle:
    app_dir: str                      # "Payload/Example.app"
    info_plist: dict = field(default_factory=dict)
    entitlements: dict = field(default_factory=dict)
    executable_name: str = ""
    encrypted: bool = False           # Mach-O FairPlay encryption (cryptid != 0)


def load_plist(data: bytes) -> dict:
    """Parse a plist (binary or XML). Returns {} on anything unparseable or non-dict."""
    try:
        obj = plistlib.loads(data)
    except Exception:  # noqa: BLE001 - defensive: a malformed plist costs coverage, never a crash
        return {}
    return obj if isinstance(obj, dict) else {}


def entitlements_from_mobileprovision(data: bytes) -> dict:
    """Extract the entitlements plist embedded in a provisioning profile (CMS blob).

    The profile is DER-wrapped and signed, but the plist payload sits in the clear inside it. We
    slice the `<?xml … </plist>` span and parse it — no signature check (we read posture only).
    The `Entitlements` sub-dict is what carries `get-task-allow`, `aps-environment`, app id, etc.
    """
    start = data.find(b"<?xml")
    end = data.rfind(b"</plist>")
    if start == -1 or end == -1:
        return {}
    profile = load_plist(data[start:end + len(b"</plist>")])
    ent = profile.get("Entitlements")
    return ent if isinstance(ent, dict) else {}


# Mach-O magic numbers (thin + fat/universal) and the encryption load commands.
_MACHO_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}
_FAT_MAGICS = {0xCAFEBABE, 0xBEBAFECA}
_LC_ENCRYPTION_INFO = 0x21
_LC_ENCRYPTION_INFO_64 = 0x2C


def macho_is_encrypted(data: bytes) -> bool:
    """Best-effort: does a (thin) Mach-O carry a FairPlay encryption command with cryptid != 0?

    A store-downloaded binary is encrypted (cryptid=1) and yields almost no readable strings; a
    dev/enterprise build usually is not. We parse only the header + load commands, bounded, and
    return False on anything we cannot cleanly read — this is an indicator, not a guarantee.
    """
    if len(data) < 28:
        return False
    magic = struct.unpack(">I", data[:4])[0]
    if magic in _FAT_MAGICS:
        # A fat binary: check the first slice only (enough to flag store encryption).
        try:
            nfat = struct.unpack(">I", data[4:8])[0]
            if nfat == 0:
                return False
            offset = struct.unpack(">I", data[16:20])[0]  # first arch's file offset
            return macho_is_encrypted(data[offset:offset + 4_000_000])
        except (struct.error, IndexError):
            return False
    if magic not in _MACHO_MAGICS:
        return False
    little = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    end = "<" if little else ">"
    try:
        ncmds = struct.unpack(f"{end}I", data[16:20])[0]
        pos = 32 if is64 else 28
        for _ in range(min(ncmds, 4_000)):
            if pos + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack(f"{end}II", data[pos:pos + 8])
            if cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
                # cryptid is the 3rd uint32 after (cmd, cmdsize, cryptoff, cryptsize).
                cryptid = struct.unpack(f"{end}I", data[pos + 16:pos + 20])[0]
                return cryptid != 0
            if cmdsize == 0:
                break
            pos += cmdsize
    except (struct.error, IndexError):
        return False
    return False


def read_bundle(zf: zipfile.ZipFile) -> IpaBundle:
    """Locate the .app bundle; read Info.plist, entitlements, and the executable's crypto state."""
    names = zf.namelist()
    # The bundle is Payload/<Something>.app/… — find the Info.plist directly under a .app.
    info_names = [n for n in names
                  if n.endswith("/Info.plist") and ".app/" in n
                  and n.split(".app/")[1] == "Info.plist"]
    if not info_names:
        raise IpaError("no Payload/*.app/Info.plist — not an iOS .ipa")
    info_name = sorted(info_names, key=len)[0]
    app_dir = info_name[: -len("/Info.plist")]
    try:
        info = load_plist(read_whole_capped(zf, info_name))
    except (KeyError, zipfile.BadZipFile, OSError, ArchiveMemberTooLarge) as exc:
        raise IpaError(f"could not read Info.plist: {exc}") from exc

    bundle = IpaBundle(app_dir=app_dir, info_plist=info,
                       executable_name=str(info.get("CFBundleExecutable") or ""))

    prov = f"{app_dir}/embedded.mobileprovision"
    if prov in names:
        try:
            bundle.entitlements = entitlements_from_mobileprovision(
                read_whole_capped(zf, prov))
        except (KeyError, zipfile.BadZipFile, OSError, ArchiveMemberTooLarge):
            bundle.entitlements = {}

    if bundle.executable_name:
        exe = f"{app_dir}/{bundle.executable_name}"
        if exe in names:
            try:
                # Bounded read of the Mach-O head only — never inflate the whole (possibly bomb)
                # executable before slicing (AUD-P1-5).
                bundle.encrypted = macho_is_encrypted(read_bounded(zf, exe, 8_000_000))
            except (KeyError, zipfile.BadZipFile, OSError):
                bundle.encrypted = False
    return bundle
