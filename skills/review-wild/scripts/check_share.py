#!/usr/bin/env python3
"""wild-series: decide whether a shared link is set up properly before it is sent to Wild.

Policy (Wild): the link must open without sign-in. Edit access is allowed.

Deterministic policy so every student gets the same verdict for the same state.
The script never touches the network; Claude supplies the sharing state from
one of two sources:

  --permissions-stdin   JSON permissions list from the student's Google Drive
                        connector (get_file_permissions output, or its "permissions" array)
  --reported STATE      what the student sees in the share dialog (see REPORTED)

Usage:
  check_share.py URL [--purpose submit|review] [--permissions-stdin] [--reported STATE]
                     [--accept-user EMAIL ...]

Output: JSON {service, file_id, verdict: pass|fail|unverified, reasons, fix_steps, verify_steps,
              auto_share?: {file_id, email, role}}   # Google + Drive connector: invite Wild as viewer
Notion is judged from the URL alone: pages published to the web live on
*.notion.site, while notion.so links are workspace links that need sign-in.
(A Notion custom domain is treated as "other": incognito-window check.)

Exit code: 0 pass · 1 fail · 2 unverified · 4 bad input
"""
import argparse
import json
import re
import sys
from urllib.parse import urlparse, parse_qs

# what the student may report from the share dialog
REPORTED = {
    # Google
    "restricted":            "Google: 일반 액세스 = 제한됨 (초대한 사람만)",
    "anyone_reader":         "Google: 링크가 있는 모든 사용자 · 뷰어",
    "anyone_commenter":      "Google: 링크가 있는 모든 사용자 · 댓글 작성자",
    "anyone_writer":         "Google: 링크가 있는 모든 사용자 · 편집자",
    "domain_only":           "Google: 특정 조직(학교 등) 사용자만",
    # Notion
    "notion_invited":        "Notion: Wild 선생님을 보기/댓글 권한으로 초대함",
    "notion_published_edit": "Notion: 웹에 게시했고 편집 허용이 켜져 있음",
    # GitHub
    "github_public":         "GitHub: 공개 저장소",
    "github_private":        "GitHub: 비공개 저장소, Wild 선생님 미초대",
    "github_invited":        "GitHub: 비공개 저장소, Wild 선생님 GitHub 계정을 공동 작업자로 초대함",
    # any service
    "private_window_opens":  "로그인하지 않은 창(시크릿 창)에서 링크가 열림",
    "private_window_blocked":"로그인하지 않은 창에서 로그인 요구 또는 접근 거부",
}

GOOGLE_HOSTS = ("docs.google.com", "drive.google.com")
NOTION_HOSTS = ("notion.so", "www.notion.so", "notion.site")
GITHUB_HOSTS = ("github.com", "www.github.com", "raw.githubusercontent.com")


def identify(url: str):
    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.netloc:
        return None, None, None
    host = u.netloc.lower()
    if host in GOOGLE_HOSTS:
        kind = {"document": "google-docs", "spreadsheets": "google-sheets",
                "presentation": "google-slides", "forms": "google-forms",
                "file": "google-drive-file", "drive": "google-drive-folder"}
        seg = [s for s in u.path.split("/") if s]
        service = kind.get(seg[0], "google-drive") if seg else "google-drive"
        if "/d/e/" in u.path and (u.path.endswith("/pub") or "/pub" in u.path):
            return service, None, "published"
        m = re.search(r"/d/([A-Za-z0-9_-]{10,})", u.path) or re.search(r"/folders/([A-Za-z0-9_-]{10,})", u.path)
        fid = m.group(1) if m else (parse_qs(u.query).get("id") or [None])[0]
        return service, fid, None
    if host == "gist.github.com":
        return "github-gist", None, "published"   # public and secret gists both open by link
    if host in GITHUB_HOSTS:
        seg = [x for x in u.path.split("/") if x]
        repo = f"{seg[0]}/{seg[1]}" if len(seg) >= 2 else None
        return "github", repo, None
    if host in NOTION_HOSTS or host.endswith(".notion.site"):
        return "notion", None, ("published" if host.endswith("notion.site") else None)
    return "other", None, None


ROLE_RANK = {"reader": 1, "commenter": 2, "writer": 3, "fileOrganizer": 4, "organizer": 4, "owner": 5}


def norm_email(e):
    """Gmail delivers name+tag@ and n.a.m.e@ to the same account: compare on that basis."""
    e = (e or "").strip().lower()
    if "@" not in e:
        return e
    local, domain = e.split("@", 1)
    local = local.split("+", 1)[0]
    if domain in ("gmail.com", "googlemail.com"):
        local, domain = local.replace(".", ""), "gmail.com"
    return f"{local}@{domain}"


def share_target(e):
    """Address to invite: the inbox account itself (drop the +tag, keep the rest)."""
    e = (e or "").strip()
    if "@" not in e:
        return None
    local, domain = e.split("@", 1)
    return f"{local.split('+', 1)[0]}@{domain}"


def google_from_permissions(perms, accept_users, purpose):
    reasons, anyone = [], [p for p in perms if p.get("type") == "anyone"]
    users = {norm_email(p.get("emailAddress")) for p in perms if p.get("type") == "user"}
    domains = [p for p in perms if p.get("type") == "domain"]
    if anyone:
        role = max((p.get("role", "reader") for p in anyone), key=lambda r: ROLE_RANK.get(r, 0))
        if ROLE_RANK.get(role, 0) >= ROLE_RANK["writer"]:
            return "pass", ["링크가 있는 모든 사용자가 편집할 수 있습니다. (Wild 선생님 기준: 편집 허용도 제출 가능)"]
        if purpose == "review" and role == "reader":
            return "pass", ["링크가 있는 모든 사용자가 볼 수 있습니다. 댓글 작성자로 바꾸면 선생님이 문서에 바로 의견을 남길 수 있습니다(권장)."]
        return "pass", [f"링크가 있는 모든 사용자가 {'볼' if role == 'reader' else '보고 댓글을 달'} 수 있습니다."]
    if accept_users and users & {norm_email(e) for e in accept_users}:
        extra = []
        if purpose == "review":
            invited = [p for p in perms if p.get("type") == "user" and norm_email(p.get("emailAddress")) in {norm_email(e) for e in accept_users}]
            if invited and all(p.get("role") == "reader" for p in invited):
                extra = ["댓글 작성자로 바꾸면 선생님이 문서에 바로 의견을 남길 수 있습니다(권장)."]
        return "pass", ["Wild 선생님 계정에 직접 공유되어 있습니다."] + extra
    if domains:
        reasons.append("특정 조직(" + ", ".join(p.get("domain", "?") for p in domains) + ") 사용자만 열 수 있습니다. Wild 선생님 계정은 그 조직에 속하지 않을 수 있습니다.")
    reasons.append("일반 액세스가 '제한됨'이라 초대된 사람만 열 수 있습니다.")
    return "fail", reasons


def from_reported(state, purpose):
    if state == "github_invited":
        return "pass", [REPORTED[state], "Wild 선생님이 초대를 **수락하셔야** 열립니다. 마감이 가까우면 공개 전환이 더 확실합니다."]
    if state in ("anyone_reader", "anyone_commenter", "anyone_writer", "github_public",
                 "notion_invited", "notion_published_edit", "private_window_opens"):
        extra = []
        if purpose == "review" and state == "anyone_reader":
            extra = ["댓글 작성자로 바꾸면 선생님이 문서에 바로 의견을 남길 수 있습니다(권장)."]
        return "pass", [REPORTED[state]] + extra
    return "fail", [REPORTED[state] + " → Wild 선생님이 열 수 없습니다."]


def github_options(repo, user):
    owner, name = (repo.split("/", 1) + [""])[:2] if repo else ("<owner>", "<repo>")
    user = user or "<Wild 선생님 GitHub 사용자명>"
    return {
        "ask": "비공개 저장소라 Wild 선생님이 열 수 없어요. 어떻게 할까요? ① 저장소를 공개로 바꾸기 ② Wild 선생님 계정(" + user + ")을 공동 작업자로 초대하기",
        "option_public": [
            "저장소 페이지 → **Settings** → **General** 맨 아래 **Danger Zone**.",
            "**Change repository visibility** → **Public**으로 바꾸고 확인합니다.",
            "공개하면 누구나 볼 수 있으니, 비밀번호·개인정보가 들어 있지 않은지 먼저 확인합니다.",
        ],
        "option_invite": [
            "저장소 페이지 → **Settings** → **Collaborators**(또는 Collaborators and teams).",
            f"**Add people** → `{user}` 입력 → 초대를 보냅니다.",
            "Wild 선생님이 초대를 **수락하셔야** 열립니다. 마감이 가까우면 ① 공개 전환이 더 확실합니다.",
        ],
        "gh_invite_command": f"gh api -X PUT repos/{owner}/{name}/collaborators/{user} -f permission=pull",
    }


def fix_steps(service, purpose):
    role = "댓글 작성자" if purpose == "review" else "뷰어"
    if service.startswith("google"):
        return [
            "문서 오른쪽 위 **공유** 버튼을 누릅니다.",
            "**일반 액세스**에서 '제한됨'을 **링크가 있는 모든 사용자**로 바꿉니다.",
            f"오른쪽 역할은 **{role}**를 권합니다. (편집자여도 제출할 수 있습니다.)",
            "**링크 복사** 후 완료. 복사한 링크로 제출합니다.",
        ]
    if service == "notion":
        return [
            "페이지 오른쪽 위 **공유(Share)** → **게시(Publish)** 탭을 엽니다.",
            "**웹에 게시**를 켭니다.",
            "게시된 링크(…notion.site/…)를 복사해 제출합니다. (notion.so 링크는 로그인이 필요합니다.)",
            "또는 공유 탭에서 Wild 선생님을 '보기' 또는 '댓글' 권한으로 초대해도 됩니다.",
        ]
    return [
        "그 서비스의 공유 설정에서 '링크가 있는 사람은 누구나 보기'(또는 그와 같은 뜻의 옵션)를 켭니다.",
    ]


VERIFY = [
    "브라우저의 **시크릿 창(로그인하지 않은 창)**에서 제출할 링크를 붙여 넣어 봅니다.",
    "로그인 요구 없이 내용이 보이면 통과입니다. 로그인하라고 나오거나 '액세스 권한 필요'가 뜨면 공유 설정을 다시 확인합니다.",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--purpose", choices=["submit", "review"], default="submit")
    ap.add_argument("--permissions-stdin", action="store_true")
    ap.add_argument("--reported", choices=sorted(REPORTED))
    ap.add_argument("--repo-visibility", choices=["public", "private", "internal"],
                    help="GitHub repo visibility from the student's GitHub connector")
    ap.add_argument("--github-user", help="Wild's GitHub username (vault payload github_username)")
    ap.add_argument("--accept-user", action="append", default=[],
                    help="Wild's address(es); pass the vault's qna_email (its +tag is ignored)")
    a = ap.parse_args()

    service, fid, hint = identify(a.url)
    if not service:
        print(json.dumps({"ok": False, "error": "not an http(s) link"}, ensure_ascii=False))
        sys.exit(4)

    if a.permissions_stdin:
        if not service.startswith("google"):
            print(json.dumps({"ok": False, "error": "permissions JSON applies to Google links only"}, ensure_ascii=False))
            sys.exit(4)
        data = json.loads(sys.stdin.read() or "[]")
        perms = data.get("permissions", data) if isinstance(data, dict) else data
        verdict, reasons = google_from_permissions(perms, a.accept_user, a.purpose)
        source = "drive-connector"
    elif a.repo_visibility and service == "github":
        source = "github-connector"
        if a.repo_visibility == "public":
            verdict, reasons = "pass", ["공개 저장소입니다."]
        else:
            verdict, reasons = "fail", [f"{'조직 내부' if a.repo_visibility == 'internal' else '비공개'} 저장소라 Wild 선생님이 열 수 없습니다."]
    elif a.reported:
        verdict, reasons = from_reported(a.reported, a.purpose)
        source = "student-report"
    elif service == "github":
        verdict, reasons, source = "unverified", ["주소만으로는 공개 저장소인지 알 수 없습니다."], "none"
    elif hint == "published":
        verdict, reasons, source = "pass", ["웹에 게시된 공개 링크입니다."], "url"
        if service == "github-gist":
            reasons = ["GitHub Gist는 공개·비밀(secret) 모두 링크로 열립니다."]
        if service == "notion":
            reasons = ["웹에 게시된 Notion 링크(…notion.site/…)입니다."]
    elif service == "notion":
        # notion.so links are workspace links: published pages live on *.notion.site
        verdict, source = "fail", "url"
        reasons = ["Notion 워크스페이스 링크(notion.so)라 웹에 게시되지 않은 상태입니다. Wild 선생님이 로그인 없이 열 수 없습니다.",
                   "Wild 선생님을 페이지에 직접 초대했다면 그 사실을 알려 주세요."]
    else:
        verdict, reasons, source = "unverified", ["공유 상태를 아직 확인하지 않았습니다."], "none"

    out = {"ok": True, "service": service, "file_id": fid, "purpose": a.purpose,
           "source": source, "verdict": verdict, "reasons": reasons}
    if verdict == "fail" and service.startswith("google") and fid and a.accept_user and source == "drive-connector":
        # the student's Drive connector can fix this itself: invite Wild's inbox account as viewer
        out["auto_share"] = {"file_id": fid, "email": share_target(a.accept_user[0]), "role": "reader"}
    if service == "github" and verdict == "fail":
        out["github_options"] = github_options(fid, a.github_user)
    if verdict != "pass" and service != "github":
        out["fix_steps"] = fix_steps(service, a.purpose)
    if verdict != "pass":
        out["verify_steps"] = VERIFY
        out["report_options"] = {k: v for k, v in REPORTED.items()
                                 if (service.startswith("google") and not k.startswith("notion"))
                                 or (service == "notion" and (k.startswith("notion") or k.startswith("private_window")))
                                 or (service == "github" and (k.startswith("github") or k.startswith("private_window")))
                                 or (service == "other" and k.startswith("private_window"))}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    sys.exit({"pass": 0, "fail": 1, "unverified": 2}[verdict])


if __name__ == "__main__":
    main()
