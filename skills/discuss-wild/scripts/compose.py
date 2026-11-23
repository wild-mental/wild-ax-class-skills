#!/usr/bin/env python3
"""wild-series: build the three delivery channels from an approved request packet.

stdin  : packet JSON  {"subject", "body", "fields": {...}}  (keys must match form.fields in the vault;
         "skill" and "group" are filled in automatically; "team" is the student's optional
         team / 조, "개인" when absent — the class itself comes from the password slot label)
args   : --config / --skill  (reads the decrypted payload from the wild vault cache)
stdout : {"email": {...} | null, "form_url": str | null, "mailto": str | null, "notes": [...]}

Never sends anything itself. Claude uses the output to (1) call the mail
connector, (2) show the Google Form link, or (3) show the mailto link.
"""
import argparse
import re
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

MAILTO_MAX = 1800  # conservative: many mail clients choke beyond ~2000 chars
HERE = Path(__file__).resolve().parent


def _configured(value) -> bool:
    return isinstance(value, str) and value.strip() != "" and "REPLACE_ME" not in value


def _vault(config: str, skill: str) -> dict:
    r = subprocess.run(
        [sys.executable, str(HERE / "wild_vault.py"), "get", "--config", config, "--skill", skill],
        capture_output=True, text=True,
    )
    data = json.loads(r.stdout or "{}")
    if r.returncode != 0 or not data.get("ok"):
        print(json.dumps({"ok": False, "error": data.get("error", "locked")}))
        sys.exit(r.returncode or 3)
    return data


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--skill", default="ask-wild")
    a = p.parse_args()

    packet = json.loads(sys.stdin.read())
    subject, body = packet["subject"], packet["body"]
    fields = dict(packet.get("fields", {}))
    fields.setdefault("skill", a.skill)  # lets one series-wide Google Form tell requests apart
    vault = _vault(a.config, a.skill)
    payload = vault["payload"]
    label = (vault.get("slot") or {}).get("label")
    # the class is the slot label; the student only supplies an optional finer unit (team, 조 …).
    # "group" is accepted from older packets and treated the same way.
    team = (fields.pop("team", None) or fields.pop("group", None) or "").strip()
    if not team or team == label:
        team = "개인"  # no team / 조: the student works alone
    name = (fields.get("name") or "").strip()
    # subject: [<skill>]<topic>-[<label>][<team>][<name>]  (no team → [개인]; empty label/name left out)
    tags = re.match(r"^((?:\[[^\]]*\]\s*)*)(.*)$", subject.strip(), re.S)
    lead = re.findall(r"\[([^\]]*)\]", tags.group(1))
    topic = tags.group(2).strip()
    skill_tag = lead[0] if lead else a.skill
    suffix = "".join(f"[{x}]" for x in (label, team, name) if x)
    if suffix and topic.endswith("-" + suffix):
        topic = topic[: -len(suffix) - 1]
    if team and topic.endswith(f" · {team}"):  # older packets appended " · <team>"
        topic = topic[: -len(team) - 3]
    subject = f"[{skill_tag}]{topic}" + (f"-{suffix}" if suffix else "")
    footer = " · ".join(x for x in (label and f"반: {label}", team and f"소속: {team}") if x)
    if footer and footer not in body:
        body = body.rstrip() + f"\n({footer})"
    group = " · ".join(x for x in (label, team) if x)
    if group:
        fields["group"] = group  # the form's single "Class" column: <label> · <team>
    notes = []

    if payload.get("placeholder"):
        notes.append("vault holds placeholder values: teacher has not configured real channels yet")

    to = payload.get("qna_email")
    email = {"to": to, "subject": subject, "body": body} if _configured(to) and not payload.get("placeholder") else None

    form_url = None
    form = payload.get("form") or {}
    base, entry_ids = form.get("prefill_url"), form.get("fields") or {}
    if _configured(base) and entry_ids and not payload.get("placeholder"):
        params = {"usp": "pp_url"}
        for key, entry in entry_ids.items():
            if fields.get(key):
                params[entry] = fields[key]
        form_url = base + ("&" if "?" in base else "?") + urlencode(params, quote_via=quote)

    mailto = None
    if email:
        mb = body
        build = lambda b: "mailto:" + quote(to, safe="@") + "?" + urlencode(
            {"subject": subject, "body": b}, quote_via=quote)
        mailto = build(mb)
        if len(mailto) > MAILTO_MAX:
            while len(build(mb + "\n…")) > MAILTO_MAX and len(mb) > 50:
                mb = mb[: int(len(mb) * 0.9)]
            mailto = build(mb + "\n…")
            notes.append("mailto body truncated; give the student the full text to paste")

    print(json.dumps({"ok": True, "slot_label": label, "email": email, "form_url": form_url,
                      "mailto": mailto, "notes": notes}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
