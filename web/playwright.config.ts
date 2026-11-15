import { defineConfig } from '@playwright/test';

// 화면 테스트: docker compose up 으로 띄운 전체 스택(web:8080 → server)에 붙는다.
//   E2E_BASE_URL : 관리 화면 주소 (기본 http://localhost:8080)
//   PW_CHANNEL   : 설치된 브라우저 사용 (chrome, msedge). 비우면 Playwright 의 chromium (npx playwright install chromium)
export default defineConfig({
  testDir: './e2e',
  timeout: 240_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8080',
    channel: process.env.PW_CHANNEL || undefined,
    viewport: { width: 1600, height: 1000 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    locale: 'ko-KR',
    timezoneId: 'Asia/Seoul',
  },
});
