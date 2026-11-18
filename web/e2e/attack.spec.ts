// MITRE ATT&CK 화면: 커버리지 매트릭스, 기법 상세, 기법 찾기, 버전 비교·활성화, 룰·순서도 기법 고르기, 경보의 기법 표시.
// 전제: data/attack 에 enterprise-attack 19.2, 20.1 번들을 넣고 init 을 돌린 스택 (20.1 활성).
// 화면 캡처는 E2E_SHOTS 디렉터리(기본 test-results/attack)에 남긴다.
import { expect, test, type Page } from '@playwright/test';

const SHOTS = process.env.E2E_SHOTS ?? 'test-results/attack';

async function login(page: Page, user = 'admin', pw = 'admin123') {
  await page.goto('/login');
  await page.getByTestId('login-username').fill(user);
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('userbox')).toContainText(user);
}

test('ATT&CK 매트릭스·기법 상세·찾기', async ({ page }) => {
  await login(page);
  await page.getByTestId('nav-attack').click();
  await expect(page.getByTestId('attack-coverage-summary')).toContainText('enterprise-attack 20.1');
  await expect(page.getByTestId('attack-coverage-summary')).toContainText('탐지');
  const cell = page.getByTestId('attack-cell-TA0001-T1190');
  await expect(cell).toHaveClass(/covered/);
  await page.screenshot({ path: `${SHOTS}/1-matrix.png`, fullPage: false });

  await cell.click();
  const d = page.getByTestId('attack-detail');
  await expect(d).toContainText('Exploit Public-Facing Application');
  await expect(d).toContainText('SR_PHP2SHELL_EXPLOIT');
  await expect(d).toContainText('SC_PHP2SHELL');
  await expect(d).toContainText('M1016');
  await page.screenshot({ path: `${SHOTS}/2-technique.png` });
  await page.keyboard.press('Escape');

  // 탐지하지 않는 기법: 커버리지 없음 안내
  await page.getByTestId('attack-matrix-filter').fill('T1566');
  await page.getByTestId('attack-cell-TA0001-T1566').click();
  await expect(page.getByTestId('attack-uncovered')).toBeVisible();
  await page.keyboard.press('Escape');

  await page.getByTestId('tab-search').click();
  await page.getByTestId('attack-search-input').fill('web shell');
  await expect(page.getByTestId('attack-search-results')).toContainText('T1505.003');
});

test('ATT&CK 버전 비교·활성화 (19.2 ↔ 20.1)', async ({ page }) => {
  await login(page);
  await page.goto('/attack/versions');
  await expect(page.getByTestId('attack-version-20.1')).toContainText('활성');
  await expect(page.getByTestId('attack-version-19.2')).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/3-versions.png` });

  await page.getByTestId('attack-diff-19.2').click();
  const diff = page.getByTestId('attack-diff');
  await expect(diff).toContainText('20.1');
  await expect(diff).toContainText('영향 없음');
  await page.screenshot({ path: `${SHOTS}/4-diff.png` });
  await page.getByTestId('attack-activate').click();
  await expect(page.getByTestId('attack-version-19.2')).toContainText('활성');
  // 되돌리기
  await page.getByTestId('attack-diff-20.1').click();
  await expect(page.getByTestId('attack-diff')).toContainText('추가 9');
  await page.getByTestId('attack-activate').click();
  await expect(page.getByTestId('attack-version-20.1')).toContainText('활성');
});

test('룰·순서도에서 기법 고르기, 경보의 기법 표시', async ({ page }) => {
  await login(page, 'author', 'author123');
  // 단일룰 편집기: 저장된 기법이 이름과 함께 보이고, 찾아서 더할 수 있다 (저장하지 않는다)
  await page.goto('/single-rules/SR_WEB_SERVER_DOWNLOAD');
  const picker = page.getByTestId('rule-attack');
  await expect(picker.getByTestId('attack-chip-T1105')).toContainText('Ingress Tool Transfer');
  await page.getByTestId('rule-attack-input').fill('lateral tool');
  await page.getByTestId('attack-result-T1570').click();
  await expect(picker.getByTestId('attack-chip-T1570')).toContainText('Lateral Tool Transfer');
  await picker.scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${SHOTS}/5-rule-picker.png` });

  // 순서도 편집기: 경보 노드의 기법
  await page.goto('/scenarios/SC_WEB_ATTACK_SUCCESS');
  await page.getByTestId('node-a1').click();
  await expect(page.getByTestId('prop-attack').getByTestId('attack-chip-T1505.003')).toContainText('Web Shell');
  await page.screenshot({ path: `${SHOTS}/6-scenario-node.png` });

  // 경보: 기법 필터 → 상세의 기법 칩 (경보는 analyst 이상)
  await page.getByTestId('logout').click();
  await login(page, 'analyst', 'analyst123');
  await page.goto('/alerts?technique=T1059');
  const first = page.locator('[data-testid^="alert-link-"]').first();
  await expect(first).toContainText('PHP2Shell');
  await page.screenshot({ path: `${SHOTS}/7-alert-list.png` });
  await first.click();
  const atk = page.getByTestId('alert-attack');
  await expect(atk.getByTestId('alert-attack-T1059.004')).toContainText('Unix Shell');
  await expect(atk).toContainText('enterprise-attack 20.1 기준');
  await page.screenshot({ path: `${SHOTS}/8-alert-detail.png` });
  await atk.getByTestId('alert-attack-T1190').click();
  await expect(page.getByTestId('attack-detail')).toContainText('Exploit Public-Facing Application');
});
