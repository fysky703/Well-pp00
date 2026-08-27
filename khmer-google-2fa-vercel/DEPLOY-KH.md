# Deploy ទៅ Vercel — សេចក្តីណែនាំខ្លីជាភាសាខ្មែរ

## A. Google OAuth

1. បើក Google Cloud Console.
2. បង្កើត Project ថ្មី ឬប្រើ Project ដែលមានស្រាប់។
3. បង្កើត OAuth Client ID ប្រភេទ **Web application**.
4. បន្ថែម Authorized redirect URI:
   - Local: `http://localhost:3001/api/auth/google/callback`
   - Vercel: `https://YOUR-PROJECT.vercel.app/api/auth/google/callback`
5. កុំដាក់ Client Secret ក្នុង GitHub.

Google តម្រូវឱ្យ redirect URI ត្រូវ match ជាក់លាក់ជាមួយ URI ដែលបានកំណត់។

## B. PostgreSQL

ប្រើ Neon ឬ Supabase PostgreSQL។

Run `db/schema.sql` នៅក្នុង database query editor។

បើ database មិនទាន់មាន `pgcrypto`៖

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

បន្ទាប់មក run schema.

## C. Vercel Environment Variables

នៅ Vercel → Project → Settings → Environment Variables បញ្ចូល៖

```text
DATABASE_URL=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://YOUR-PROJECT.vercel.app/api/auth/google/callback
APP_URL=https://YOUR-PROJECT.vercel.app
MASTER_KEY_HEX=64-hex-characters
NODE_ENV=production
```

Generate `MASTER_KEY_HEX` ដោយ៖

```bash
npm install
npm run generate:key
```

## D. Deploy

Push folder នេះទៅ GitHub → Vercel → Add New Project → Import repository → Deploy.

Vercel នឹង build React ពី `frontend/` ហើយ serve Express API តាម `/api/*`។

## E. បន្ទាប់ពី Deploy

1. Copy Vercel URL.
2. Update Google OAuth redirect URI ជា URL production ពិតប្រាកដ។
3. Update `APP_URL` និង `GOOGLE_REDIRECT_URI` នៅ Vercel.
4. Redeploy.
5. Test Google Login.
6. Login → រៀបចំ Google Authenticator → Scan QR → បញ្ចូល 6 digits.

## F. សុវត្ថិភាព

- `.env` មិនត្រូវ upload ទៅ GitHub.
- `GOOGLE_CLIENT_SECRET` រក្សាទុកតែនៅ Vercel Environment Variables.
- Backup codes ត្រូវរក្សាទុក offline ឬ password manager.
- មុន production ធ្ងន់ៗ គួរបន្ថែម rate limiting, audit logs និង monitoring.
