# Cortex XSIAM — DNS Tunneling XQL Detection

> 아래 XQL 쿼리는 **탐지 아이디어를 보여주는 참고용**입니다.
> 실제 환경의 데이터셋(`dns` 필드 스키마), 정상 도메인, 임계값에 맞게 **튜닝 후** 사용하세요.
> 데이터 소스는 방화벽 DNS 로그 / XDR 네트워크 스토리 등 테넌트 구성에 따라 다릅니다.

MITRE: **T1071.004 (Application Layer Protocol: DNS)**, **T1048 (Exfiltration Over Alternative Protocol)**

---

## 1. 비정상 DNS 레코드 타입 (NULL / TXT 대량 조회)

정상 클라이언트는 NULL/TXT 레코드를 대량으로 조회하지 않습니다.

```sql
dataset = xdr_data
| filter action_dns_query_name != null
| filter dns_query_type in ("NULL", "TXT", "CNAME")
| comp count() as q_cnt by agent_hostname, action_dns_query_name, dns_query_type
| filter q_cnt > 50
| sort desc q_cnt
```

---

## 2. 고엔트로피 · 긴 서브도메인 (Base32 인코딩 흔적)

서브도메인 라벨이 비정상적으로 길면 인코딩된 데이터일 가능성이 큽니다.

```sql
dataset = xdr_data
| filter action_dns_query_name != null
| alter qname   = action_dns_query_name
| alter sub     = arrayindex(regextract(qname, "^([^\.]+)\."), 0)
| alter sub_len = len(sub)
| filter sub_len > 40
| comp count() as hits, count_distinct(sub) as uniq_labels by agent_hostname, qname
| filter uniq_labels > 100
| sort desc uniq_labels
```

---

## 3. 한 도메인에 몰리는 다수의 유니크 서브도메인

터널은 하나의 2LD 아래 수천 개의 서로 다른 라벨을 만듭니다.

```sql
dataset = xdr_data
| filter action_dns_query_name != null
| alter parent = arrayindex(regextract(action_dns_query_name, "([^\.]+\.[^\.]+)$"), 0)
| comp count_distinct(action_dns_query_name) as uniq_subs,
       count() as total_q
       by agent_hostname, parent
| filter uniq_subs > 200
| sort desc uniq_subs
```

---

## 4. 규칙적 폴링 (짧은 주기 반복 질의) — beacon 유사

```sql
dataset = xdr_data
| filter action_dns_query_name != null
| alter parent = arrayindex(regextract(action_dns_query_name, "([^\.]+\.[^\.]+)$"), 0)
| comp count() as q_cnt,
       earliest(_time) as first_seen,
       latest(_time)   as last_seen
       by agent_hostname, parent
| alter window_sec = timestamp_diff(last_seen, first_seen, "SECOND")
| filter window_sec > 300 and q_cnt > 200
| alter avg_interval_sec = divide(window_sec, q_cnt)
| filter avg_interval_sec < 10
| sort asc avg_interval_sec
```

---

## 5. 상관(Correlation) 룰로 승격하는 팁

- 위 신호 중 **2개 이상 동시 충족** 시 인시던트로 승격(예: 고엔트로피 + 규칙적 폴링).
- **알려진 정상 도메인**(CDN, 텔레메트리, OS 업데이트)은 allowlist 처리해 오탐 축소.
- 엔드포인트 상관: 같은 호스트에서 **의심 프로세스 → DNS 폭주**가 이어지면 신뢰도 상승.
- 대응 자동화: 플레이북으로 **호스트 격리(Isolate)** + 방화벽 도메인 차단 연계.

> 필드명(`action_dns_query_name`, `dns_query_type` 등)은 테넌트 스키마에 따라 다를 수 있으니
> `dataset = xdr_data | fields *` 로 실제 필드를 확인 후 매핑하세요.
