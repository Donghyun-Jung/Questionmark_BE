## 동국대학교 개발자 학습환경 플랫폼
# DUEL (Dongguk University E-Learning Laboratory)

## BE 리포지토리

백엔드 코드는 다음 GitHub 레포지토리에서 관리됩니다:
[BE 리포지토리 바로가기](https://github.com/CSID-DGU/2024-1-OSSProj-Questionmark-07-BE.git)

## 팀 구성원

| 역할 | 성명   | 학번       | 소속학과      | 연계전공        | 이메일                         |
|------|--------|------------|--------------|----------------|--------------------------------|
| 팀장 | 정동현 | 2019112473 | 산업시스템공학과 | 융합SW연계전공 | [wsdv4444@dgu.edu](mailto:wsdv4444@dgu.edu) |
| 팀원 | 이희주 | 2018111039 | 사회학과       | 융합SW연계전공 | [lhj2778@naver.com](mailto:lhj2778@naver.com) |
| 팀원 | 이하연 | 2019110914 | 경제학과       | 융합SW연계전공 | [hlee09300@naver.com](mailto:hlee09300@naver.com) |

## 프로젝트 개요

### 문제 상황 인식

1. **융합 SW 연계전공 학습 중 문제점**
   - 매주 제출하는 코딩 과제 및 GitHub 연동의 복잡성.
   - 정보가 정리되어 있지 않고 학습 참고가 어려움.
   - 학생과 운영진 모두에게 불편함이 존재함.

2. **자기주도적 개발 학습의 어려움**
   - 개발, 스택 공부의 시작이 어려움.
   - 공부 순서 및 진행 확인의 어려움.

### 문제 해결 방안

1. **그룹 로드맵 서비스**
   - 로드맵 생성 및 구성원 가입 가능.
   - 각 단계별 학습 및 TIL 제출 기능.
   - 제출된 TIL 한눈에 확인 가능.

2. **로드맵 제공 및 TIL 공유**
   - 과목별, 과제별 로드맵 제공.
   - 학습 및 제출 지원.
   - 다른 사람의 TIL을 통한 자가 학습 평가 지원.

## 주요 기능 및 개발 내용

### 백엔드 (BE)

- **로그인/회원가입**: Gmail(SMTP)와 Redis를 사용한 이메일 인증 및 JWT 관리.
- **검색 기능**: 다양한 항목으로의 검색 지원.
- **이미지 업로드**: AWS S3를 사용한 이미지 업로드 및 관리.
- **알림 및 댓글 기능**: 사용자 상호작용 지원.
- **성능 개선**: N+1 문제 해결 및 쿼리 최적화.
- **권한 처리**: 사용자 역할에 따른 접근 제어.

### 프론트엔드 (FE)

- **서버 사이드 렌더링 (SSR)**: Next.js를 사용하여 SSR 구현.
- **접근 권한 분기 처리**: 서버 사이드에서 접근 권한 관리.
- **React-Query의 prefetch와 Hydration**: 데이터 관리 및 최적화.

## 기대효과

- **마크다운 에디터를 통한 TIL 작성 지원**.
- **개발 학습 로드맵 제공 및 커뮤니티 조성**.
- **통합 개발 학습 환경 제공을 통한 효율적인 학습 경험**.


## 이용 방법 (유저 플로우)

프로젝트의 유저 플로우는 아래 이미지를 통해 확인할 수 있습니다:
![DUEL 학습 방법](https://github.com/CSID-DGU/2024-1-OSSProj-Questionmark-07/assets/144092849/0d0f86e2-11d7-4a1d-8b6e-09691c534ba2)

## 개발 환경

- **Backend**: MySQL, MariaDB, NGINX, Redis, Junit 5, Spring Boot, Docker, Kubernetes, Gradle.
- **Frontend**: TypeScript, React, Next.js, React Query, Storybook.


# 추가 자료

## API 명세서

API에 대한 상세한 명세는 다음 링크에서 확인할 수 있습니다:
[API 명세서 바로가기](https://www.notion.so/API-53fd633284584fe9aa59e7d7e1658625?pvs=21)


## 프로젝트 관리

- **범위 일정 관리**: 
  [범위 일정 관리 바로가기](https://foregoing-education-610.notion.site/8e367ee8cd234c0a98314418e41001aa?pvs=4)

- **이슈 관리**: 
  [이슈 관리 바로가기](https://foregoing-education-610.notion.site/408c4b08259647abb722e4183eac5b4c?pvs=4)

- **회의록**: 
  [회의록 바로가기](https://foregoing-education-610.notion.site/52e53cda8ea042e6a223c7d14a239f84?v=8b8435fa506c427ba3a5bbd11d085d86&pvs=4)

## 보고서 및 발표 자료

- **중간보고서**: 
  [중간보고서 바로보기](https://github.com/CSID-DGU/2024-1-OSSProj-Questionmark-07/blob/main/Docs/2_1_OSSProj_7_Questionmark_%EC%A4%91%EA%B0%84%EB%B3%B4%EA%B3%A0%EC%84%9C_.md)

- **중간발표자료**: 
  [중간발표자료 바로보기](https://github.com/CSID-DGU/2024-1-OSSProj-Questionmark-07/blob/main/Docs/2_2_OSSProj_7_Questionmark_%EC%A4%91%EA%B0%84%EB%B0%9C%ED%91%9C%EC%9E%90%EB%A3%8C_.md)

