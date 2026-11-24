// Mock switch. Public variable injected at build time (only the NEXT_PUBLIC_ prefix is readable in the browser).
// Set NEXT_PUBLIC_MOCK=1 on Vercel and the whole site runs on mock, no backend needed.
export const MOCK = process.env.NEXT_PUBLIC_MOCK === "1";
