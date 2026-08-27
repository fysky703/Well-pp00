# Khmer Google Login + Google Authenticator 2FA (Vercel)

Project starter សម្រាប់ Website ដែលមាន៖

- React + Vite + TypeScript
- Node.js + Express API
- Google OAuth Login
- Google Authenticator (TOTP) 2FA
- QR Code setup
- Backup codes
- PostgreSQL sessions និង users
- Ready សម្រាប់ Vercel
- UI ជាភាសាខ្មែរ

## 1. តម្រូវការ

- Node.js 20+
- PostgreSQL database (Neon ឬ Supabase ងាយស្រួល)
- Google Cloud OAuth Client (Web application)
- Vercel account

Vercel គាំទ្រ Express apps និង Vite/React deployments។

## 2. បង្កើត Google OAuth

នៅ Google Cloud Console → APIs & Services → Credentials → Create Credentials → OAuth client ID → Web application.

Local redirect URI:

`http://localhost:3001/api/auth/google/callback`

Production redirect URI:

`https://YOUR-DOMAIN.vercel.app/api/auth/google/callback`

URI ត្រូវតែ match ជាក់លាក់ជាមួយ `GOOGLE_REDIRECT_URI`។

## 3. Database

បង្កើត PostgreSQL database ហើយ run `db/schema.sql`។

Schema ប្រើ `gen_random_uuid()` ដូច្នេះនៅ database ដែលត្រូវការ extension អាច run៖

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

បន្ទាប់មក run `db/schema.sql`។

## 4. Environment variables

Copy `.env.example` → `.env` ហើយបំពេញ values.

Generate encryption key៖

```bash
npm install
npm run generate:key
```

យក output ទៅ `MASTER_KEY_HEX`។

## 5. Local run

```bash
npm install
npm run dev
```

បើក៖ `http://localhost:5173`

API local៖ `http://localhost:3001`

## 6. Deploy ទៅ Vercel

1. Push project ទៅ GitHub.
2. Import repository ចូល Vercel.
3. Vercel នឹងប្រើ `vercel.json` សម្រាប់ build React និង Express API.
4. នៅ Vercel → Settings → Environment Variables បញ្ចូល៖
   - `DATABASE_URL`
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REDIRECT_URI`
   - `APP_URL`
   - `MASTER_KEY_HEX`
   - `NODE_ENV=production`
5. Redeploy.
6. ប្តូរ Google OAuth redirect URI ទៅ URL production របស់អ្នក។

## 7. Production checklist

- ប្រើ HTTPS (Vercel ផ្តល់ HTTPS)
- កុំដាក់ `.env` ឬ Google client secret ទៅ GitHub
- ប្រើ hosted PostgreSQL ដែលមាន SSL
- កំណត់ domain របស់ app និង Google OAuth redirect URI ឱ្យត្រឹមត្រូវ
- បើប្រើ custom domain ត្រូវកែ `APP_URL` និង `GOOGLE_REDIRECT_URI`

## Security note

TOTP secret ត្រូវបាន encrypt នៅ database ដោយ AES-256-GCM និង `MASTER_KEY_HEX`។ Backup codes ត្រូវបានរក្សាទុកជា bcrypt hashes។ Session tokens ត្រូវបាន hash មុនរក្សាទុក database។

## Important

នេះជាគម្រោង starter ដែលមាន authentication flow សម្រាប់ deployment។ មុនដាក់ប្រើក្នុង production ធ្ងន់ៗ គួរបន្ថែម rate limiting, audit logs, account recovery policy និង monitoring តាមតម្រូវការរបស់ website របស់អ្នក។
