## CLI-Based Secure Messaging with Session Key Encryption

## 프로젝트 개요
- 세션키를 이용한 대칭키 기반 암호화 메시징 구현
- 메시지가 전송되는 과정에서 암 복호화 흐름을 CLI 환경에서 단계별로 시각적으로 확인할 수 있도록 설계
- 단순 라이브러리를 사용에 그치지 않고, 암호화 전/후 데이터의 변화를 직접 확인할 수 있도록 구현

## 프로젝트 목적
- 세션 키 기반 암호화 통신에서의 Handshake 절차와 데이터 흐름을 구현을 통해 검증
- CLI 환경에서 보안 통신의 핵심 요소를 직접 구현

## 시스템 구성
- 키 교환 단계
  - RSA 공개키/개인키 로드
  - AES 세션 키 및 IV 생성 후 RSA로 암호화하여 전달
- 전달된 세션 키를 기반으로 AES-256-CBC 암호화 메시지 송수신
- SHA-256 해시를 이용한 메시지 무결성 확인

## 주요 기능
- 멀티스레드 구조 적용  
   -수신 스레드 : 암호문 수신 및 복호화 요청 플래그 설정  
   -IO 스레드 : 사용자 입력, 암 복호화 및 메시지 전송 처리
- mutex 기반 입력 제어로 동시 입력 충돌 방지
- 키 입력 시 ECHO OFF 처리로 민감 정보 노출 방지
- CLI 환경에서 암호화 흐름 직관적으로 확인 가능

## 문제 해결
1) 키 입력이 상대방 입력으로 전달되는 문제  
-원인: 입력/수신 스레드가 동일한 stdin을 공유  
-해결: 입력을 IO 스레드로 단일화  
  decrypt_pending 플래그 + thread mutex로 제어  
  recv_thread는 직접 입력을 받지 않고 플래그만 설정

2) Enter(개행)이 암호문으로 처리되는 문제  
-원인: stdin 버퍼에 개행이 남아 다음 메시지로 처리됨  
-해결: strlen == 0일 경우 즉시 continue 처리 및 개행 제거 로직 일원화

3) 무결성 검증 기능이 작동하지 않던 문제  
-원인: hash_hex 파싱 오류 및 데이터 분리 문제  
-해결: 패킷을 cipher|hash 형태로 통합
  strchr()로 안정적인 분리 및 hex_to_bytes() 적용

4) 스레드 충돌 및 버퍼 파손 문제  
-원인: 여러 스레드가 동시에 공용 버퍼에 접근  
-해결: 입력·수신·복호화 과정을 명확히 분리하고 Mutex로 공용 버퍼 보호

## 데이터 흐름
<img width="70%" height="70%" alt="1  데이터 흐름" src="https://github.com/user-attachments/assets/24dc9c7b-699c-4f28-8a44-3f956eb3cff9" />  

## 시연
<img width="100%" height="100%" alt="1  시연 (1)" src="https://github.com/user-attachments/assets/50308729-449d-49c6-bee9-0096dbbbc6c2" />  

<img width="100%" height="100%" alt="1  시연 (2)" src="https://github.com/user-attachments/assets/6145e0a5-d868-4ade-b278-8e72455c72d9" />

## 사용 기술
- Launuage: C
- Environment: CLI
- Cryptography: 대칭키 암호화 방식(Session Key 기반)

## 최종 결과물
<img width="70%" height="70%" alt="1  최종결과물" src="https://github.com/user-attachments/assets/166299a5-53f2-4631-b3be-f59cbf0edde7" />


