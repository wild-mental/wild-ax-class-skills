# wild-ax-class-skills

Wild 선생님 수업(AX-WAVE)에서 쓰는 **Claude 스킬 5종**입니다.
Claude에게 하고 싶은 말만 하면, 스킬이 정해진 형식으로 정리하고 확인한 뒤 Wild 선생님께 보내 줍니다.

| 스킬 | 언제 쓰나 | 이렇게 말해 보세요 |
|---|---|---|
| [ask-wild](skills/ask-wild/) | 공부하다 막혔을 때 질문 | "Wild 선생님께 질문 보내줘" |
| [meet-wild](skills/meet-wild/) | 20분 면담 요청 (수업일 12:00 · 12:30 · 18:00) | "Wild 선생님이랑 면담 잡아줘" |
| [review-wild](skills/review-wild/) | 작업 중인 결과물에 피드백 요청 | "이 초안 피드백 받고 싶어" |
| [discuss-wild](skills/discuss-wild/) | 수업·멘토링에서 다룰 주제 제안 | "이 주제 수업에서 토론하고 싶어" |
| [submit-wild](skills/submit-wild/) | 과제 최종본 제출 | "과제 제출해줘" |

## 빠른 설치 (claude.ai)

1. [`dist/`](dist/)에서 ZIP 5개를 내려받습니다.
2. Claude **사용자 지정 → 스킬 → + → 스킬 만들기 → 스킬 업로드**에서 ZIP을 하나씩 올립니다(압축 풀지 않고 그대로).
3. Claude 설정에서 **코드 실행**이 켜져 있는지 확인합니다.
4. 처음 실행할 때 수업에서 받은 **반 암호**를 한 번 입력합니다.

Claude Code, 커넥터 설정, 링크 공유 기준, 스킬별 예제는 **[학생 가이드](docs/GUIDE.md)** 를 보세요.

## 구성

```
wild-ax-class-skills/
├── README.md          이 문서
├── docs/
│   └── GUIDE.md       학생 가이드 (설치 · 커넥터 · 링크 제출 명세 · 예제 · 문제 해결)
├── skills/            스킬 원본 (Claude Code는 이 폴더를 ~/.claude/skills/에 복사)
│   ├── ask-wild/
│   ├── meet-wild/
│   ├── review-wild/
│   ├── discuss-wild/
│   └── submit-wild/
└── dist/              claude.ai 업로드용 ZIP (스킬 폴더째 압축)
```

## 알아 두기

- **보내기 전에 항상 미리보기를 보여주고 승인을 받습니다.** 승인 없이는 아무것도 보내지 않습니다.
- 선생님 연락처 등 설정은 **암호화**되어 있어 이 리포에서는 보이지 않습니다. 반 암호는 수업에서만 안내합니다.
- 스킬이 업데이트되면 선생님이 공지합니다. 설치된 스킬은 저절로 바뀌지 않으니 다시 설치해 주세요.
