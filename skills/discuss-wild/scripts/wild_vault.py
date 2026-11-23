#!/usr/bin/env python3
"""wild-series shared vault (format v2: multi-password key slots).

Encrypts a skill's channel config (QnA email, Google Form URL, ...) so it is
not readable in a public repo, lets the teacher hand out SEVERAL passwords
(per class, per student) that all open it, and caches the decrypted payload
so a student enters a password only once.

Standard library only, so it runs in any Python 3.8+ sandbox.

Design (envelope encryption, like LUKS key slots):
  DEK      = 64 random bytes (enc 32 + mac 32)       one per vault
  data     = Enc(DEK, payload)                        encrypt-then-MAC
  KEK      = PBKDF2-HMAC-SHA256(password, salt, iter) one salt per vault
  slot[i]  = Enc(KEK_i, DEK)                          one per password
  Enc(k, m): keystream = HMAC-SHA256(k.enc, nonce||ctr); tag = HMAC(k.mac, hdr||nonce||ct)

Consequences:
  * add/remove a password never re-encrypts the data
  * changing the address (set-payload) keeps every password and access token valid
  * remove-password revokes that slot; `rekey` also replaces the DEK so a
    student who extracted it cannot read future versions
  * one salt per vault keeps unlock time constant for any number of slots
    (trade-off: one brute-force guess is tested against all slots at once)

Series-wide key derivation:
  Every vault in a series shares the same salt + iterations (`init --join`).
  The same class password therefore yields the same KEK in every skill, so
  a KEK cached by one skill (or one saved access token) opens all the others.
  series id = sha256(salt:iter)[:8], visible in `list-passwords`.

Student access token (for ephemeral sandboxes such as claude.ai web), one per series:
  WILD-TOKEN v3 <series-id> <kek-b64>
  Holds the KEK, never the password. Survives address changes and rekey;
  stops working in a skill as soon as the teacher removes that slot there.

Exit codes: 0 ok · 2 wrong password · 3 locked / revoked · 4 bad input
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
from pathlib import Path

FORMAT_VERSION = 2
KDF = "pbkdf2-sha256"
KDF_ITER = 600_000
KEY_PREFIX = "WILD-TOKEN"
TOKEN_VERSION = 3
OPEN_STATES = ("ok", "refreshed", "series")
HOME = Path(os.environ.get("WILD_SKILLS_HOME", str(Path.home() / ".wild-skills")))
CACHE = HOME / "vault.json"


class WrongKey(Exception):
    pass


# ---------------------------------------------------------------- crypto ---
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _kdf(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)


def _stream(key32: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += hmac.new(key32, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:n])


def _seal(key64: bytes, header: bytes, plaintext: bytes) -> dict:
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _stream(key64[:32], nonce, len(plaintext))))
    tag = hmac.new(key64[32:], header + nonce + ct, hashlib.sha256).digest()
    return {"nonce": _b64e(nonce), "ct": _b64e(ct), "tag": _b64e(tag)}


def _open(key64: bytes, header: bytes, box: dict) -> bytes:
    nonce, ct, tag = _b64d(box["nonce"]), _b64d(box["ct"]), _b64d(box["tag"])
    expect = hmac.new(key64[32:], header + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise WrongKey()
    return bytes(a ^ b for a, b in zip(ct, _stream(key64[:32], nonce, len(ct))))


def _hdr(kind: str, slot_id: str = "") -> bytes:
    return f"wild-vault:v{FORMAT_VERSION}:{kind}:{slot_id}".encode("ascii")


# ----------------------------------------------------------------- vault ---
def kek_for(env: dict, password: str) -> bytes:
    return _kdf(password, _b64d(env["salt"]), int(env["iter"]))


def unwrap(env: dict, kek: bytes, slot_id: str = None):
    """Return (slot_id, DEK) for the first slot this KEK opens."""
    for s in env["slots"]:
        if slot_id and s["id"] != slot_id:
            continue
        try:
            return s["id"], _open(kek, _hdr("slot", s["id"]), s)
        except WrongKey:
            continue
    raise WrongKey()


def read_payload(env: dict, dek: bytes) -> dict:
    return json.loads(_open(dek, _hdr("data"), env["data"]).decode("utf-8"))


def write_payload(env: dict, dek: bytes, payload: dict) -> None:
    env["data"] = _seal(dek, _hdr("data"), json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def add_slot(env: dict, dek: bytes, kek: bytes, label: str) -> str:
    sid = os.urandom(3).hex()
    env["slots"].append({"id": sid, "label": label, **_seal(kek, _hdr("slot", sid), dek)})
    return sid


def new_vault(payload: dict, password: str, label: str, join: dict = None):
    env = {"v": FORMAT_VERSION, "kdf": KDF,
           "iter": join["iter"] if join else KDF_ITER,
           "salt": join["salt"] if join else _b64e(os.urandom(16)), "slots": []}
    dek = os.urandom(64)
    add_slot(env, dek, kek_for(env, password), label)
    write_payload(env, dek, payload)
    return env


def fingerprint(env: dict) -> str:
    """Changes whenever the data is re-encrypted (new address or rekey)."""
    return hashlib.sha256((env["data"]["nonce"] + env["data"]["tag"]).encode()).hexdigest()[:16]


def series_id(env: dict) -> str:
    """Same for every vault that shares key derivation (salt + iterations)."""
    return hashlib.sha256(f"{env['salt']}:{env['iter']}".encode()).hexdigest()[:8]


# ----------------------------------------------------------------- cache ---
def _load_cache() -> dict:
    try:
        return json.loads(CACHE.read_text("utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cache(data: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HOME, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=str(HOME), prefix=".vault-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, CACHE)


def _store(skill: str, env: dict, slot_id: str, kek: bytes, payload: dict) -> None:
    cache = _load_cache()
    kek_b64, sid = _b64e(kek), series_id(env)
    cache.setdefault("skills", {})[skill] = {
        "fingerprint": fingerprint(env), "series": sid, "slot": slot_id, "kek": kek_b64,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "payload": payload,
    }
    known = cache.setdefault("series", {}).setdefault(sid, [])
    if kek_b64 not in known:
        known.append(kek_b64)
    _save_cache(cache)


def _try_keks(env: dict, skill: str, kek_b64s) -> bool:
    """Open this vault with the first KEK that fits; cache the result."""
    for kb in kek_b64s:
        try:
            kek = _b64d(kb)
            slot, dek = unwrap(env, kek)
            payload = read_payload(env, dek)
        except (WrongKey, ValueError, KeyError):
            continue
        _store(skill, env, slot, kek, payload)
        return True
    return False


def _resolve(env: dict, skill: str):
    """Return (state, entry).

    ok        cached copy is current
    refreshed teacher changed the address; re-read silently with the cached KEK
    series    opened with a KEK cached by another skill of the same series
    no-cache  nothing usable: ask for an access token or a password
    revoked   cached KEK no longer opens any slot here: ask for a new password
    """
    cache = _load_cache()
    entry = cache.get("skills", {}).get(skill)
    series_keks = cache.get("series", {}).get(series_id(env), [])
    if entry and "kek" in entry:
        if entry["fingerprint"] == fingerprint(env):
            return "ok", entry
        others = [k for k in series_keks if k != entry["kek"]]
        if _try_keks(env, skill, [entry["kek"]] + others):
            return "refreshed", _load_cache()["skills"][skill]
        return "revoked", None
    if _try_keks(env, skill, series_keks):
        return "series", _load_cache()["skills"][skill]
    return "no-cache", None


# ------------------------------------------------------------------- io ---
def _read_secrets(count: int, prompts):
    """Read secrets from stdin (one per line) when piped, else prompt."""
    if not sys.stdin.isatty():
        lines = sys.stdin.read().splitlines()
        if len(lines) < count:
            _die(4, f"expected {count} line(s) on stdin")
        return [l.rstrip("\r") for l in lines[:count]]
    return [getpass.getpass(p) for p in prompts]


def _load_env(path: str) -> dict:
    try:
        env = json.loads(Path(path).read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _die(4, f"cannot read vault config {path}: {e}")
    if env.get("v") != FORMAT_VERSION and not getattr(_load_env, "allow_v1", False):
        _die(4, f"vault format v{env.get('v')} is not v{FORMAT_VERSION}; teacher must run `migrate`")
    return env


def _write_env(path: str, env: dict) -> None:
    Path(path).write_text(json.dumps(env, indent=2) + "\n", "utf-8")


def _out(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _die(code: int, msg: str):
    _out({"ok": False, "error": msg})
    sys.exit(code)


def _dek_from_password(env: dict, password: str):
    try:
        return unwrap(env, kek_for(env, password))
    except WrongKey:
        _die(2, "wrong password")


# ---------------------------------------------------- student commands ---
def cmd_status(a):
    env = _load_env(a.config)
    state, entry = _resolve(env, a.skill)
    _out({"ok": True, "unlocked": state in OPEN_STATES, "state": state,
          "saved_at": entry and entry.get("saved_at")})


def cmd_unlock(a):
    env = _load_env(a.config)
    (pw,) = _read_secrets(1, ["password: "])
    kek = kek_for(env, pw)
    try:
        sid, dek = unwrap(env, kek)
    except WrongKey:
        _die(2, "wrong password")
    payload = read_payload(env, dek)
    _store(a.skill, env, sid, kek, payload)
    _out({"ok": True, "unlocked": True, "placeholder": bool(payload.get("placeholder")),
          "suggest_token": os.environ.get("CLAUDECODE") != "1"})


def cmd_get(a):
    env = _load_env(a.config)
    state, entry = _resolve(env, a.skill)
    if state not in OPEN_STATES:
        _die(3, f"locked ({state}): unlock with an access token or a password")
    label = next((x["label"] for x in env["slots"] if x["id"] == entry.get("slot")), None)
    _out({"ok": True, "payload": entry["payload"], "slot": {"id": entry.get("slot"), "label": label}})


def cmd_token(a):
    env = _load_env(a.config)
    sid = series_id(env)
    if a.action == "export":
        state, entry = _resolve(env, a.skill)
        if state not in OPEN_STATES:
            _die(3, "locked: run unlock first")
        _out({"ok": True, "series": sid,
              "token": f"{KEY_PREFIX} v{TOKEN_VERSION} {sid} {entry['kek']}"})
        return
    parts = [l.split() for l in sys.stdin.read().splitlines() if l.strip().startswith(KEY_PREFIX)]
    keks = [p[3] for p in parts if len(p) == 4 and p[1] == f"v{TOKEN_VERSION}" and p[2] == sid]
    if not keks:
        _die(4, f"no {KEY_PREFIX} v{TOKEN_VERSION} line for series {sid} on stdin")
    if not _try_keks(env, a.skill, keks):
        _die(3, "access token revoked or invalid; unlock with a password")
    payload = _load_cache()["skills"][a.skill]["payload"]
    _out({"ok": True, "unlocked": True, "placeholder": bool(payload.get("placeholder"))})


def cmd_forget(a):
    cache = _load_cache()
    if a.all:
        cache.pop("skills", None)
    else:
        cache.get("skills", {}).pop(a.skill, None)
    _save_cache(cache)
    _out({"ok": True})


def cmd_profile(a):
    cache = _load_cache()
    prof = cache.setdefault("profile", {})
    if prof.pop("group", None) is not None:
        # legacy field: it held the class, which now always comes from the password slot label
        _save_cache(cache)
    if a.action == "set":
        for k in ("name", "team"):
            v = getattr(a, k)
            if v is not None:
                prof[k] = v
        _save_cache(cache)
    _out({"ok": True, "profile": prof})


# ---------------------------------------------------- teacher commands ---
def cmd_init(a):
    try:
        payload = json.loads(Path(a.inp).read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _die(4, f"cannot read plaintext {a.inp}: {e}")
    payload.pop("_comment", None)
    p1, p2 = _read_secrets(2, ["password: ", "repeat: "])
    if p1 != p2:
        _die(4, "passwords do not match")
    join = _load_env(a.join) if a.join else None
    env = new_vault(payload, p1, a.label, join)
    _write_env(a.out, env)
    _out({"ok": True, "written": a.out, "series": series_id(env), "slots": _slot_list(env)})


def cmd_migrate(a):
    """v1 single-password file -> v2, keeping that password as the first slot."""
    _load_env.allow_v1 = True
    env1 = _load_env(a.config)
    if env1.get("v") == FORMAT_VERSION:
        _die(4, "already v2")
    (pw,) = _read_secrets(1, ["current password: "])
    salt, nonce = _b64d(env1["salt"]), _b64d(env1["nonce"])
    ct, tag = _b64d(env1["ct"]), _b64d(env1["tag"])
    k = _kdf(pw, salt, int(env1["iter"]))
    hdr = f"wild-vault:v{env1['v']}:{env1['kdf']}:{env1['iter']}".encode("ascii")
    if not hmac.compare_digest(hmac.new(k[32:], hdr + salt + nonce + ct, hashlib.sha256).digest(), tag):
        _die(2, "wrong password")
    payload = json.loads(bytes(x ^ y for x, y in zip(ct, _stream(k[:32], nonce, len(ct)))).decode("utf-8"))
    env = new_vault(payload, pw, a.label)
    _write_env(a.config, env)
    _out({"ok": True, "written": a.config, "slots": _slot_list(env)})


def _slot_list(env):
    return [{"id": s["id"], "label": s["label"]} for s in env["slots"]]


def cmd_list(a):
    env = _load_env(a.config)
    _out({"ok": True, "series": series_id(env), "fingerprint": fingerprint(env), "slots": _slot_list(env)})


def cmd_add(a):
    env = _load_env(a.config)
    if any(s["label"] == a.label for s in env["slots"]):
        _die(4, f"label '{a.label}' already exists")
    cur, n1, n2 = _read_secrets(3, ["any existing password: ", "new password: ", "repeat: "])
    if n1 != n2:
        _die(4, "new passwords do not match")
    _, dek = _dek_from_password(env, cur)
    try:
        unwrap(env, kek_for(env, n1))
        _die(4, "that password already opens a slot")
    except WrongKey:
        pass
    sid = add_slot(env, dek, kek_for(env, n1), a.label)
    _write_env(a.config, env)
    _out({"ok": True, "added": sid, "slots": _slot_list(env)})


def cmd_remove(a):
    env = _load_env(a.config)
    keep = [s for s in env["slots"] if a.slot not in (s["id"], s["label"])]
    if len(keep) == len(env["slots"]):
        _die(4, f"no slot with id/label '{a.slot}'")
    if not keep:
        _die(4, "refusing to remove the last slot")
    env["slots"] = keep
    _write_env(a.config, env)
    _out({"ok": True, "slots": _slot_list(env),
          "note": "access tokens of the removed slot stop working; run `rekey` to also replace the data key"})


def cmd_set_payload(a):
    env = _load_env(a.config)
    try:
        payload = json.loads(Path(a.inp).read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _die(4, f"cannot read plaintext {a.inp}: {e}")
    payload.pop("_comment", None)
    (pw,) = _read_secrets(1, ["any existing password: "])
    _, dek = _dek_from_password(env, pw)
    write_payload(env, dek, payload)
    _write_env(a.config, env)
    _out({"ok": True, "fingerprint": fingerprint(env), "note": "all passwords and access tokens stay valid"})


def cmd_set_form(a):
    """Replace only the `form` block (shared Google Form); keeps qna_email and everything else."""
    env = _load_env(a.config)
    try:
        data = json.loads(Path(a.inp).read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _die(4, f"cannot read form json {a.inp}: {e}")
    form = data.get("form", data)
    fields = form.get("fields") if isinstance(form, dict) else None
    if not (isinstance(form.get("prefill_url"), str) and form["prefill_url"].startswith("https://")
            and isinstance(fields, dict) and fields
            and all(isinstance(v, str) and v.startswith("entry.") for v in fields.values())):
        _die(4, "form json needs prefill_url (https://...) and fields {key: 'entry.N'}")
    (pw,) = _read_secrets(1, ["any existing password: "])
    _, dek = _dek_from_password(env, pw)
    payload = read_payload(env, dek)
    payload["form"] = {"prefill_url": form["prefill_url"], "fields": fields}
    payload.pop("placeholder", None)
    write_payload(env, dek, payload)
    _write_env(a.config, env)
    _out({"ok": True, "fingerprint": fingerprint(env), "form_fields": sorted(fields),
          "note": "only the form block changed; passwords and access tokens stay valid"})


def cmd_rekey(a):
    """New data key; every remaining slot's password must be supplied (one per line, slot order)."""
    env = _load_env(a.config)
    labels = [s["label"] for s in env["slots"]]
    pws = _read_secrets(len(labels), [f"password for '{l}': " for l in labels])
    old_dek, keks = None, []
    for s, pw in zip(env["slots"], pws):
        kek = kek_for(env, pw)
        try:
            _, dek = unwrap(env, kek, s["id"])
        except WrongKey:
            _die(2, f"wrong password for slot '{s['label']}'")
        old_dek, keks = dek, keks + [(s, kek)]
    payload = read_payload(env, old_dek)
    new_dek = os.urandom(64)
    env["slots"] = []
    for s, kek in keks:
        env["slots"].append({"id": s["id"], "label": s["label"], **_seal(kek, _hdr("slot", s["id"]), new_dek)})
    write_payload(env, new_dek, payload)
    _write_env(a.config, env)
    _out({"ok": True, "slots": _slot_list(env), "note": "slot ids kept: existing access tokens stay valid"})


# ------------------------------------------------------------------ cli ---
def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def cfg(name, fn, skill=True):
        sp = sub.add_parser(name)
        sp.add_argument("--config", required=True, help="path to channels.enc.json")
        if skill:
            sp.add_argument("--skill", required=True, help="skill name, e.g. ask-wild")
        sp.set_defaults(fn=fn)
        return sp

    # student
    cfg("status", cmd_status)
    cfg("unlock", cmd_unlock)
    cfg("get", cmd_get)
    cfg("token", cmd_token).add_argument("action", choices=["export", "import"])
    f = sub.add_parser("forget")
    f.add_argument("--skill")
    f.add_argument("--all", action="store_true")
    f.set_defaults(fn=cmd_forget)
    pr = sub.add_parser("profile")
    pr.add_argument("action", choices=["get", "set"])
    pr.add_argument("--name")
    pr.add_argument("--team", help="optional sub-unit inside the class, e.g. a team or '2조' "
                    "(the class itself comes from the password slot label)")
    pr.set_defaults(fn=cmd_profile)

    # teacher
    i = sub.add_parser("init")
    i.add_argument("--in", dest="inp", required=True)
    i.add_argument("--out", required=True)
    i.add_argument("--label", default="initial")
    i.add_argument("--join", help="existing vault of the series: share its key derivation")
    i.set_defaults(fn=cmd_init)
    cfg("migrate", cmd_migrate, skill=False).add_argument("--label", default="initial")
    cfg("list-passwords", cmd_list, skill=False)
    cfg("add-password", cmd_add, skill=False).add_argument("--label", required=True)
    cfg("remove-password", cmd_remove, skill=False).add_argument("--slot", required=True, help="slot id or label")
    cfg("set-payload", cmd_set_payload, skill=False).add_argument("--in", dest="inp", required=True)
    cfg("set-form", cmd_set_form, skill=False).add_argument("--in", dest="inp", required=True)
    cfg("rekey", cmd_rekey, skill=False)

    a = p.parse_args()
    if a.cmd == "forget" and not (a.all or a.skill):
        _die(4, "forget needs --skill or --all")
    a.fn(a)


if __name__ == "__main__":
    main()
