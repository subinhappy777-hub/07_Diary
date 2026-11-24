# Vercel + Supabase 배포 연결

Vercel은 GitHub 저장소에서 화면과 `/api` 서버 기능을 배포합니다. Supabase Free는 계정, 로그인 세션, 다이어리 자료를 저장합니다. 이 구성은 기존 아이디/비밀번호 로그인을 유지하며 Supabase Auth 이메일 가입 화면으로 바꾸지 않습니다.

## 1. Supabase 데이터베이스 준비

1. Supabase에서 Free 플랜 프로젝트를 만듭니다.
2. 프로젝트의 **SQL Editor**에서 `supabase/schema.sql` 전체를 실행합니다.
3. **Project Settings → API Keys**에서 Project URL과 서버용 Secret key(`sb_secret_...`)를 확인합니다. Secret key는 브라우저 코드나 GitHub 저장소에 넣지 마세요.

## 2. Vercel과 GitHub 연결

1. Vercel에 로그인하고 **Add New → Project**를 선택합니다.
2. GitHub 계정을 연결한 뒤 `subinhappy777-hub/07_Diary` 저장소를 가져옵니다.
3. 프로젝트의 **Settings → Environment Variables**에 아래 값을 Production 환경으로 등록합니다.
   - `SUPABASE_URL`: Supabase Project URL
   - `SUPABASE_SECRET_KEY`: 서버용 Secret key
4. 저장소의 `main` 브랜치에 변경이 올라오면 Vercel이 배포합니다. 필요한 경우 Vercel의 **Deployments**에서 새 배포를 실행합니다.
5. 배포가 끝나면 Vercel 프로젝트의 **Domains**에 표시된 `https://...vercel.app` 주소로 접속합니다. 이 주소에서 가입/로그인 후 계정별 저장이 동작합니다.

## 보안 구성

- Vercel API는 계정마다 다른 무작위 salt를 사용하는 scrypt 해시를 저장합니다.
- 256비트 무작위 세션 토큰은 HttpOnly·Secure·SameSite=Lax 쿠키로 전달하며 DB에는 SHA-256 지문만 저장합니다. 세션은 7일 후 만료되고 로그아웃하면 삭제됩니다. 별도의 서명 비밀키는 사용하지 않습니다.
- 사용자는 세션에서 확인한 본인 ID의 자료만 읽고 갱신할 수 있습니다. Supabase 테이블은 RLS를 켜고 `anon`/`authenticated` 직접 접근을 회수합니다. Supabase Secret key는 Vercel 서버 환경 변수에만 둡니다.
- 이 컴퓨터의 `diary.sqlite` 자료는 Supabase에 자동 복사되지 않습니다. 기존 자료는 로컬 화면에서 JSON으로 내보낸 뒤 배포된 Vercel 로그인 화면에서 백업 파일로 가져옵니다.
