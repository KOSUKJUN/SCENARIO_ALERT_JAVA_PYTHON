// 설정 > 로그 수집원: 원본에 기관 컬럼이 없어 수집원(_asset_id) → 기관 매핑으로 기관을 정한다.
// 전제: 매핑 없는 수집원 E2E_NEW_LOGSRC 의 이벤트가 최근 24시간에 있다 (테스트 전에 ClickHouse 에 한 건 넣는다).
import { expect, test, type Page } from '@playwright/test';

const SHOTS = process.env.E2E_SHOTS ?? 'test-results/log-sources';
const ASSET = 'E2E_NEW_LOGSRC';

async function login(page: Page, user = 'admin', pw = 'admin123') {
  await page.goto('/login');
  await page.getByTestId('login-username').fill(user);
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('userbox')).toContainText(user);
}

test('매핑 없는 수집원을 기관에 지정하고 지운다', async ({ page }) => {
  await login(page);
  await page.goto('/settings/log-sources');
  await expect(page.getByTestId('log-sources')).toContainText('ORG001_WAF_LOGSRC');
  const unmapped = page.getByTestId('log-sources-unmapped');
  await expect(unmapped).toContainText(ASSET);
  await page.screenshot({ path: `${SHOTS}/1-unmapped.png`, fullPage: true });

  await page.getByTestId(`log-source-pick-${ASSET}`).selectOption('ORG003');
  await page.getByTestId(`log-source-assign-${ASSET}`).click();
  await expect(page.getByTestId('log-sources')).toContainText(ASSET);
  await expect(page.getByTestId('log-sources-unmapped')).toHaveCount(0);
  await page.screenshot({ path: `${SHOTS}/2-assigned.png`, fullPage: true });

  // 정리: 매핑 삭제 → 다시 미매핑으로
  page.once('dialog', (d) => void d.accept());
  await page.getByTestId('log-sources').locator('tr', { hasText: ASSET }).getByRole('button', { name: '삭제' }).click();
  await expect(page.getByTestId('log-sources-unmapped')).toContainText(ASSET);
});
