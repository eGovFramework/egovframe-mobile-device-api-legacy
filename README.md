# egovframe-mobile-device-api-legacy

**eGovFramework 4.3.x 이하 Legacy 통합 저장소** — Android / iOS 하이브리드 앱 및 `web-guide` 서버 예제입니다.

> **중요:** 본 저장소는 **로컬 개발·학습용 템플릿**입니다. **운영(Production) 환경에 그대로 배포하지 마세요.**

eGovFramework **5.0.0 이상**을 사용하신다면 [egovframe-mobile-device-api](https://github.com/eGovFramework/egovframe-mobile-device-api) 저장소를 참고하세요.

---

## 개요

| 구성 | 설명 |
|------|------|
| `web-guide/` | Spring MVC WAR 서버 (Device API 백엔드) |
| `android-studio/` | Android Studio Cordova 샘플 앱 |
| `android-eclipse/` | Android Eclipse Cordova 샘플 앱 |
| `ios/` | iOS Cordova 샘플 앱 |

| eGovFramework 버전 | 저장소 |
|---|---|
| 4.3.x 이하 | 이 저장소 (Legacy) |
| 5.0.0 이상 | [egovframe-mobile-device-api](https://github.com/eGovFramework/egovframe-mobile-device-api) |

버전별 브랜치(예: `3.9.x`, `3.10.x`)가 별도로 관리되는 경우, 해당 브랜치의 `README`와 설정을 함께 확인하세요.

---

## 로컬 개발 환경

### 권장 사용 방식

- 서버·DB·앱을 **개발 PC 또는 사설망**에서만 기동합니다.
- 서버는 가능하면 `127.0.0.1`(localhost)에 바인딩하고, 외부망에 포트를 열지 않습니다.
- 샘플 DB 계정·URL은 `web-guide/src/main/resources/egovframework/egovProps/globals.properties`를 로컬에 맞게 수정해 사용합니다.

### 서버 (`web-guide`)

- Java 8, Maven, DB(MySQL 등) 필요
- WAR 빌드 후 Tomcat 등에 배포
- API 문서: `http://localhost:<port>/<context>/swagger-ui.html` (로컬 확인용)

### 모바일 앱

- Android: `res/values/serverinfo.xml`, iOS: `EgovPlugins/EGovComModule.h`의 **서버 URL**을 로컬 PC IP·포트에 맞게 변경
- 기본값은 **HTTP**이며, 로컬 개발 편의를 위한 설정입니다.
- Android HTTPS 정책은 **앱당 `network_policy.xml` 파일 하나**로 관리합니다.
  - Eclipse: `res/xml/network_policy.xml`
  - Studio: `app/src/main/res/xml/network_policy.xml`
- 로컬 개발 기본값: `require-https="false"` (HTTP 허용)
- release/운영 빌드 전: 동일 파일에서 `require-https="true"`로 변경 후 빌드
- iOS 운영 빌드: `kREQUIRE_HTTPS YES`

---

## 보안 안내 (필독)

본 프로젝트는 **참고 구현**이며, 일부 설정은 로컬 데모를 위해 의도적으로 완화되어 있습니다.

### 운영 배포 금지 사유 (요약)

| 구분 | 로컬 템플릿 기본 상태 | 운영 시 필수 조치 |
|------|----------------------|------------------|
| 전송 | HTTP 허용 | HTTPS 전용, 인증서·핀닝 검토 |
| 인증 | `device.uuid`·세션 기반 샘플 인증 | Spring Security / JWT 등 강한 인증·인가 |
| API 문서 | Swagger UI 노출 | 운영 환경에서 비활성화 또는 접근 제한 |
| WebSocket | Origin `*` 등 완화 설정 | Origin·인증 제한 |
| Cordova | `config.xml` 광범위 allowlist | 필요 도메인만 허용 |
| 비밀정보 | Firebase Admin SDK JSON 등 포함 가능 | **반드시 교체·폐기**, Secret 관리 |
| 의존성 | Spring 4.3 / 구형 Cordova 스택 | 보안 패치·지원 종료 여부 점검 |

### 저장소에 포함될 수 있는 민감 파일

- `web-guide/.../egovdeviceapi-firebase-adminsdk-*.json` — **실제 키가 아닌지 확인**하고, 로컬 테스트용 더미 키로 교체하세요. 유출 시 즉시 **키 폐기·재발급**이 필요합니다.
- `globals.properties`의 DB 비밀번호 — 로컬 전용 값으로 유지하고, 실제 운영 비밀번호를 커밋하지 마세요.

### 운영 전환 시 최소 체크리스트

1. 모든 `SERVER_URL` / `kSERVER_URL`을 **HTTPS**로 변경
2. Android `res/xml/network_policy.xml`(Eclipse) 또는 `app/src/main/res/xml/network_policy.xml`(Studio)에서 `require-https="true"` 설정, iOS `kREQUIRE_HTTPS YES`
3. Swagger, WebSocket 데모(`chat-sockjs.jsp`), TCP 채팅 샘플(`SocketChatServer`) **비활성화 또는 격리**
4. Firebase·FCM·APNs 등 **서비스 계정 키를 환경 변수/Secret으로 이전**
5. 파일 업로드·다운로드·푸시 API에 **인증·소유권 검증** 재검토
6. `commons-fileupload`, `jackson-databind` 등 **의존성 CVE 점검** 및 상향

취약점 점검·조치 내역은 별도 점검 보고서를 참고하고, 운영 적용 전 **독립적인 보안 점검**을 수행하세요.

---

## 지원 버전

| 항목 | 버전 |
|------|------|
| eGovFramework RTE | **3.10.0** (Legacy 통합 기준) |
| Spring Framework | 4.3.25.RELEASE |
| spring-security-crypto | 4.2.20.RELEASE |
| commons-fileupload | 1.3.3 |
| jackson-databind | 2.9.10.5 |
| swagger | 2.9.2 |
| Java | 8 |

---

## 참고 링크

- [eGovFramework 공식 사이트](https://www.egovframe.go.kr)
- [표준프레임워크 모바일 가이드](https://www.egovframe.go.kr/wiki/doku.php?id=egovframework:hyb3.10)
- [egovframe-mobile-device-api (5.0.x+)](https://github.com/eGovFramework/egovframe-mobile-device-api)
