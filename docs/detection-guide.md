# Detection Guide — DNS Tunneling with Cortex XSIAM

DNS 터널 C2를 탐지·대응하는 단계별 접근법 요약입니다.

## 1. 가시성 확보 (Collect)
- 방화벽/리졸버의 **DNS 질의 로그**를 XSIAM으로 수집 (QNAME, 레코드 타입, 클라이언트IP, 시간).
- 엔드포인트에서는 **Cortex XDR 네트워크 스토리**로 프로세스 ↔ DNS 연계 확보.

## 2. 베이스라인 (Baseline)
- 조직의 정상 도메인/텔레메트리/CDN을 **allowlist**로 정리.
- 호스트별 평상시 DNS 질의량·레코드 타입 분포를 파악해 임계값 설정.

## 3. 탐지 (Detect)
- **[detection/xsiam_xql.md](../detection/xsiam_xql.md)** 의 XQL 4종을 스케줄 쿼리/상관 룰로 등록.
- 단일 신호는 오탐이 많으므로 **2개 이상 동시 충족 시 승격**.

## 4. 대응 (Respond)
- 플레이북 자동화: 의심 호스트 **Isolate**, 해당 2LD 방화벽 **차단**, 분석가 티켓 생성.
- Cortex MCP 등으로 조사 자동화 시 조사 시간을 크게 단축할 수 있음.

## 5. 검증 (Validate)
- 허가된 격리 랩에서 공개 터널링 도구로 재현 트래픽을 만들어 룰이 실제로 뜨는지 확인.
- 임계값을 조정해 오탐/미탐 균형을 맞춘다.

> 구성도(`docs/diagrams/`)를 함께 보면 공격 흐름과 탐지 지점을 한눈에 이해할 수 있습니다.
