# Cortex XSIAM — DNS Tunneling C2 Detection Lab

> **교육·탐지 연구용 랩 자료입니다.** 이 저장소는 DNS 터널링 기반 C2(Command & Control) 공격이
> **어떻게 동작하고, Palo Alto Networks Cortex XSIAM / XDR로 어떻게 탐지·차단**되는지를
> 설명하는 **문서·구성도·탐지 룰**만 담고 있습니다.
> 실제 동작하는 C2 서버/클라이언트 소스코드와 빌드 산출물은 **의도적으로 포함하지 않습니다.**

<p align="center">
  <img alt="purpose" src="https://img.shields.io/badge/purpose-education%20%2F%20detection-00a077">
  <img alt="platform" src="https://img.shields.io/badge/SIEM-Cortex%20XSIAM%20%2F%20XDR-0ea5e9">
  <img alt="mitre" src="https://img.shields.io/badge/MITRE-T1071.004-8250df">
  <img alt="license" src="https://img.shields.io/badge/license-MIT%20(restricted%20use)-64748b">
</p>

---

## 🎯 이 랩이 다루는 것 (What this lab covers)

| 관점 | 내용 |
|------|------|
| **공격 (Red)** | DNS 프로토콜(UDP 53)만으로 세션 수립 · 명령 전달 · 데이터 유출을 수행하는 C2 채널의 원리 |
| **방어 (Blue)** | Cortex XSIAM/XDR 및 방화벽(NGFW) 관점의 탐지 시그니처, XQL 쿼리, Sigma 룰 |
| **시연 (Purple)** | C레벨/실무자 대상 핸즈온 교육용 구성도와 공격→탐지 스토리라인 |

DNS 터널링은 MITRE ATT&CK **[T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)**에
해당하며, 대부분의 네트워크에서 DNS(53)가 허용되기 때문에 방화벽을 우회하는 은신 채널로 악용됩니다.

---

## 📦 저장소 구조

```
Cortex-XSIAM-Demo_DNS_Tunneling/
├── README.md
├── LICENSE
├── docs/
│   ├── protocol.md              # DNS 터널링 프로토콜 개념 명세
│   ├── detection-guide.md       # XSIAM 탐지 접근법 요약
│   └── diagrams/                # 구성도 (브라우저에서 열기)
│       └── dns-tunneling-detail.html        # DNS 터널링 C2 상세 다이어그램
└── detection/
    ├── xsiam_xql.md             # Cortex XSIAM XQL 탐지 쿼리
    └── sigma/
        └── dns_tunneling_c2.yml # 벤더 중립 Sigma 룰
```

> 📖 **구성도 보는 법**: `docs/diagrams/*.html` 파일을 브라우저로 직접 열면 됩니다 (별도 서버 불필요).

---

## 🧬 DNS 터널링 개념 요약

일반적인 DNS 터널 C2는 하나의 UDP 53 채널을 **역할별 레코드 타입**으로 나눠 씁니다:

| 방향 | 레코드 | 역할 |
|------|--------|------|
| 세션 수립 | `NULL` (qtype 10) | 핸드셰이크 / keepalive |
| 명령 수신 (C2 → PC) | `CNAME` / `TXT` | Base32 인코딩된 명령 하달 |
| 결과 유출 (PC → C2) | `A` | 서브도메인 레이블에 청크 데이터 삽입 |

자세한 프로토콜 설명은 **[docs/protocol.md](docs/protocol.md)** 참고.

---

## 🛡️ 탐지 관점 (Detection)

이 채널은 정상 DNS와 다음 지점에서 통계적으로 구분됩니다 — 탐지 룰은 이 특징을 노립니다:

- **비정상 레코드 타입 비율** — 일반 클라이언트가 `NULL`/`TXT`를 대량 조회하지 않음
- **높은 쿼리 빈도** — 짧은 폴링 주기(수 초)로 동일 도메인 반복 질의
- **긴/고엔트로피 서브도메인** — Base32 인코딩된 데이터가 레이블에 실림
- **단일 도메인 집중** — 한 2LD로 트래픽이 몰림
- **응답 대비 송신 데이터 불균형** — 업링크(유출) 편향

→ Cortex XSIAM XQL 쿼리: **[detection/xsiam_xql.md](detection/xsiam_xql.md)**
→ Sigma 룰: **[detection/sigma/dns_tunneling_c2.yml](detection/sigma/dns_tunneling_c2.yml)**

---

## 🧪 랩 환경 예시 (참고)

| 구성요소 | 역할 |
|----------|------|
| 피해자 PC (Windows 11) | Cortex XDR 에이전트 설치, DNS 질의 발생원 |
| DNS/C2 서버 | 권한 있는 격리 랩 내부에만 존재 |
| PA NGFW | DNS 이상 트래픽 1차 탐지 |
| Cortex XSIAM | 인시던트 자동 생성 · 상관분석 · 대응 |

> 실제 C2 서버/클라이언트 코드는 이 저장소에 포함되지 않습니다. 재현이 필요한 연구자는
> 공개된 오픈소스 터널링 도구(dnscat2, iodine 등)를 **본인이 소유·관리하는 격리 환경**에서만 사용하십시오.

---

## ⚠️ 법적 고지 및 사용 조건 (Legal / Authorized Use Only)

- 본 자료는 **방어 역량 강화와 보안 교육**을 목적으로 합니다.
- 여기 담긴 어떤 기법도 **본인이 명시적 서면 허가를 받은 시스템**에서만 사용해야 합니다.
- 무단 침입, 데이터 유출, 서비스 방해 등 **불법 행위에 사용하는 것을 금지**하며,
  그로 인한 결과에 대해 저자는 어떠한 책임도 지지 않습니다.
- 사용자는 자신의 관할 지역 법률(예: 정보통신망법 등)을 준수할 책임이 있습니다.

By using this repository you agree to use its contents **only** against systems you own or are
explicitly authorized to test. The authors accept **no liability** for misuse.

---

## 📄 License

[MIT License](LICENSE) — 사용 제한 조항 포함. 교육·연구·방어 목적에 한합니다.
