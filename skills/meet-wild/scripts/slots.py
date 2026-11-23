#!/usr/bin/env python3
"""meet-wild: list and check meeting slots.

Rule (Wild): a meeting is on a class day, at one of the fixed times
(12:00, 12:30, 18:00 by default), in Wild's time zone, and requested at
least 6 hours ahead. Wild confirms by reply; nothing is booked automatically.

Class days, in order of preference:
  1. --events-stdin: events read from Wild's public "class days" Google Calendar
     (the student's Calendar connector output). Every non-cancelled event = a class day.
  2. --schedule JSON from the vault payload (`class_schedule`):
     {"weekdays": ["Tue", "Thu"], "dates": ["2026-12-05"], "exclude": ["2026-12-25"]}
  3. neither: every day is allowed and the student is asked to pick a day
     they have class (Wild double-checks when replying).

Usage:
  slots.py list  [--events-stdin | --schedule JSON] [--times 12:00,12:30,18:00] [--tz Asia/Seoul] [--count 8] [--student-tz TZ]
  slots.py check "YYYY-MM-DD HH:MM" [same options]

Output JSON. Exit: 0 ok/valid · 1 invalid slot · 4 bad input
"""
import argparse
import json
import sys
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TIMES = ["12:00", "12:30", "18:00"]
MIN_NOTICE = timedelta(hours=6)
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
KO_DAYS = ["월", "화", "수", "목", "금", "토", "일"]


def _die(msg):
    print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
    sys.exit(4)


def parse_schedule(raw):
    if not raw:
        return None
    try:
        s = json.loads(raw)
    except json.JSONDecodeError as e:
        _die(f"bad schedule json: {e}")
    wd = {d[:3].title() for d in s.get("weekdays", [])}
    if wd - set(DAYS):
        _die(f"unknown weekday in {sorted(wd - set(DAYS))}")
    try:
        dates = {date.fromisoformat(d) for d in s.get("dates", [])}
        excl = {date.fromisoformat(d) for d in s.get("exclude", [])}
    except ValueError as e:
        _die(f"bad date in schedule: {e}")
    return {"weekdays": wd, "dates": dates, "exclude": excl}


def dates_from_events(raw, tz):
    """Accept a Calendar connector response in any common shape and return class dates."""
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError as e:
        _die(f"bad events json: {e}")
    if isinstance(data, dict):
        data = data.get("events") or data.get("items") or data.get("data") or []
    out = set()
    for ev in data if isinstance(data, list) else []:
        if not isinstance(ev, dict) or str(ev.get("status", "")).lower() == "cancelled":
            continue
        st = ev.get("start") or ev.get("startTime") or ev.get("start_time")
        if isinstance(st, dict):
            st = st.get("date") or st.get("dateTime")
        if not isinstance(st, str) or len(st) < 10:
            continue
        try:
            if len(st) == 10:
                out.add(date.fromisoformat(st))
            else:
                dt = datetime.fromisoformat(st.replace("Z", "+00:00"))
                out.add((dt.astimezone(tz) if dt.tzinfo else dt).date())
        except ValueError:
            continue
    return out


def is_class_day(d, sched):
    if sched is None:
        return True
    if d in sched["exclude"]:
        return False
    return d in sched["dates"] or DAYS[d.weekday()] in sched["weekdays"]


def fmt(dt, student_tz=None):
    out = {"slot": dt.strftime("%Y-%m-%d %H:%M"),
           "label": f"{dt.strftime('%Y-%m-%d')} ({KO_DAYS[dt.weekday()]}) {dt.strftime('%H:%M')}–"
                    f"{(dt + timedelta(minutes=20)).strftime('%H:%M')} {dt.tzinfo.key}"}
    if student_tz and student_tz.key != dt.tzinfo.key:
        s = dt.astimezone(student_tz)
        out["student_local"] = f"{s.strftime('%Y-%m-%d')} ({KO_DAYS[s.weekday()]}) {s.strftime('%H:%M')} {student_tz.key}"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["list", "check"])
    ap.add_argument("slot", nargs="?")
    ap.add_argument("--schedule")
    ap.add_argument("--events-stdin", action="store_true")
    ap.add_argument("--times", default=",".join(DEFAULT_TIMES))
    ap.add_argument("--tz", default="Asia/Seoul")
    ap.add_argument("--student-tz")
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--now", help="override current time (testing), 'YYYY-MM-DD HH:MM' in --tz")
    a = ap.parse_args()

    try:
        tz = ZoneInfo(a.tz)
        stz = ZoneInfo(a.student_tz) if a.student_tz else None
    except ZoneInfoNotFoundError as e:
        _die(f"unknown time zone: {e}")
    times = [t.strip() for t in a.times.split(",") if t.strip()]
    if a.events_stdin:
        sched = {"weekdays": set(), "dates": dates_from_events(sys.stdin.read(), tz), "exclude": set()}
        source = "calendar"
    else:
        sched = parse_schedule(a.schedule)
        source = "vault" if sched else "none"
    now = datetime.strptime(a.now, "%Y-%m-%d %H:%M").replace(tzinfo=tz) if a.now else datetime.now(tz)
    earliest = now + MIN_NOTICE
    base = {"ok": True, "now": now.strftime("%Y-%m-%d %H:%M %Z"), "earliest": earliest.strftime("%Y-%m-%d %H:%M %Z"),
            "times": times, "schedule_configured": sched is not None, "schedule_source": source}
    if source == "calendar" and not sched["dates"]:
        base["warning"] = "수업일 캘린더에서 앞으로의 수업일을 찾지 못했습니다."

    if a.action == "list":
        found, d = [], now.date()
        for _ in range(120):
            if is_class_day(d, sched):
                for t in times:
                    dt = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
                    if dt >= earliest:
                        found.append(fmt(dt, stz))
            if len(found) >= a.count:
                break
            d += timedelta(days=1)
        print(json.dumps({**base, "slots": found[: a.count]}, ensure_ascii=False, indent=2))
        return

    if not a.slot:
        _die("check needs a slot 'YYYY-MM-DD HH:MM'")
    try:
        dt = datetime.strptime(a.slot.strip(), "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    except ValueError:
        _die("slot must be 'YYYY-MM-DD HH:MM' in Wild's time zone")
    problems = []
    if dt.strftime("%H:%M") not in times:
        problems.append(f"시간은 {', '.join(times)} 중 하나여야 합니다.")
    if not is_class_day(dt.date(), sched):
        problems.append("수업이 있는 날이 아닙니다.")
    if dt < earliest:
        problems.append(f"최소 6시간 전에 요청해야 합니다. 가장 빠른 면담 가능 시각: {base['earliest']}")
    print(json.dumps({**base, "valid": not problems, "problems": problems, **fmt(dt, stz)}, ensure_ascii=False, indent=2))
    sys.exit(0 if not problems else 1)


if __name__ == "__main__":
    main()
