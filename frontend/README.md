# CuraNet Frontend

Production-grade Next.js + Tailwind app aligned with trust-first healthcare UX. Highlights:

- Next.js App Router, TypeScript, Tailwind with CSS variables
- shadcn/ui primitives + theme toggle (next-themes)
- TanStack Query data layer, refresh-token auth pattern (access in memory)
- React Hook Form + Zod for forms
- Framer Motion for microinteractions, respecting reduced-motion
- i18n scaffolding (en, hi)
- Sentry and PostHog stubs (opt-in)

## Scripts

- dev: Start local dev server
- build: Production build (Turbopack)
- start: Start production server

## Environment

- NEXT_PUBLIC_API_URL: Backend base URL (default http://localhost:3001)
- NEXT_PUBLIC_SENTRY_DSN: Optional
- NEXT_PUBLIC_POSTHOG_KEY: Optional
- NEXT_PUBLIC_POSTHOG_HOST: Optional

## Auth model

- Refresh token: HttpOnly cookie set by backend.
- Access token: stored in memory only. On 401, refresh flow is attempted automatically and original request retried once.

## Folder Highlights

- src/lib/api.ts — API client, React Query client, auth retry logic
- src/components/session-provider.tsx — bootstraps session via refresh + /me
- src/app/auth/login — basic login form
- src/app/auth/register — Suspense-wrapped client RegisterForm

## Next steps

- Add role dashboards (/patient, /doctor, /pharmacy, /admin)
- Implement consent UI components and audit views
- Add offline engine with IndexedDB (idb) for drafts & queued ops
- Set up Storybook and MSW for component/dev ergonomicsThis is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
