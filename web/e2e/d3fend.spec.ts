// MITRE D3FEND 화면: 버전 비교, 대응 기법 매트릭스·상세, 대응방책 연계 현황, 룰·경보 노드의 지정 대응방책, 경보의 대응방책.
// 전제: data/d3fend/1.5.0, 1.6.0 을 넣고 init 을 돌린 스택 (1.6.0 활성), 기본 룰·순서도에 지정 대응방책이 있고
//       샘플 데이터로 SC_PHP2SHELL 경보가 만들어져 있다. 화면 캡처는 E2E_SHOTS(기본 test-results/d3fend)에 남긴다.
import { expect, test, type Page } from '@playwright/test';

const SHOTS = process.env.E2E_SHOTS ?? 'test-results/d3fend';

async function login(page: Page, user = 'admin', pw = 'admin123') {
  await page.goto('/login');
  await page.getByTestId('login-username').fill(user);
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('userbox')).toContainText(user);
}

test('D3FEND 버전 비교 (1.5.0 → 1.6.0) 와 대응 기법 매트릭스·상세', async ({ page }) => {
  await login(page);
  await page.getByTestId('nav-d3fend').click();
  await expect(page.getByTestId('d3fend-summary')).toContainText('D3FEND 1.6.0');
  // 지정된 기법은 칠해진다: D3-PT 는 SR_WEB_CMD_OUTPUT 등이 지정
  const pt = page.getByTestId('d3fend-cell-D3-PT');
  await expect(pt).toHaveClass(/designated/);
  await page.screenshot({ path: `${SHOTS}/1-matrix.png` });
  await pt.click();
  const d = page.getByTestId('d3fend-detail');
  await expect(d).toContainText('Process Termination');
  await expect(d).toContainText('퇴출 (Evict)');
  await expect(d).toContainText('SR_WEB_CMD_OUTPUT');
  await expect(page.getByTestId('d3fend-detail-attack')).toContainText('T1505.003');
  await page.screenshot({ path: `${SHOTS}/2-technique.png` });
  await page.keyboard.press('Escape');

  await page.getByTestId('tab-versions').click();
  await expect(page.getByTestId('d3fend-version-1.6.0')).toContainText('활성');
  await page.getByTestId('d3fend-diff-1.5.0').click();
  const diff = page.getByTestId('d3fend-diff');
  await expect(diff).toContainText('1.6.0');
  await expect(diff).toContainText('영향 없음');
  await page.screenshot({ path: `${SHOTS}/3-diff.png` });
  await page.getByRole('button', { name: '닫기', exact: true }).getByText('닫기').click();
  await expect(diff).toHaveCount(0);
});

test('D3FEND 버전 내보내기 → 삭제 → 패키지로 다시 가져오기', async ({ page }) => {
  test.setTimeout(180_000);
  await login(page);
  await page.goto('/d3fend/versions');
  const row = page.getByTestId('d3fend-version-1.5.0');
  const sha = await row.locator('td[title]').getAttribute('title');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByTestId('d3fend-export-1.5.0').click()]);
  expect(dl.suggestedFilename()).toBe('d3fend_1.5.0.zip');
  const zip = `${SHOTS}/${dl.suggestedFilename()}`;
  await dl.saveAs(zip);

  page.once('dialog', (d) => void d.accept());
  await page.getByTestId('d3fend-delete-1.5.0').click();
  await expect(row).toHaveCount(0);

  await page.getByTestId('d3fend-package-file').setInputFiles(zip);
  await page.getByTestId('d3fend-package-upload').click();
  await expect(page.getByText('D3FEND 1.5.0: 가져왔습니다')).toBeVisible({ timeout: 120_000 });
  await expect(row.locator('td[title]')).toHaveAttribute('title', sha ?? '');
  await expect(page.getByTestId('d3fend-version-1.6.0')).toContainText('활성');
  await page.screenshot({ path: `${SHOTS}/package.png` });
});

test('대응방책 연계 현황과 룰·경보 노드의 지정 대응방책', async ({ page }) => {
  await login(page);
  await page.goto('/d3fend/links');
  await expect(page.getByTestId('d3fend-links-summary')).toContainText('사고 대응');
  await expect(page.getByTestId('d3fend-link-SC_PHP2SHELL-a1')).toContainText('D3-NI');
  await page.getByTestId('d3fend-link-open-SC_PHP2SHELL-a1').click();
  await expect(page.getByTestId('cm-tactic-Isolate')).toContainText('D3-NI');
  await page.screenshot({ path: `${SHOTS}/4-links.png` });
  await page.keyboard.press('Escape');

  // 이벤트 탐지모듈 편집기: 지정 대응방책 칩과 ATT&CK 기준 추천
  await page.goto('/scenarios/detections/SR_TI_HIT');
  const picker = page.getByTestId('rule-d3fend');
  await expect(picker.getByTestId('d3fend-chip-D3-OTF')).toContainText('Outbound Traffic Filtering');
  await expect(picker.getByTestId('d3fend-chip-D3-DNSDL')).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/5-rule-editor.png`, fullPage: true });
});

test('경보 상세의 대응방책: 지정(스냅샷) + D3FEND 권고 (사고 대응 전술 먼저)', async ({ page, request }) => {
  await login(page);
  const tok = await page.evaluate(() => localStorage.getItem('scenario_token'));
  const headers = { Authorization: `Bearer ${tok}` };
  // PHP2Shell 공격 + 응답에 명령 실행 결과 (긴급, 경보 노드 a1: 격리·종료·차단·패치·프로세스 분석 지정)
  const inj = await request.post('/api/v1/dev/sample-data/inject', { headers, data: { scenario: 'php2shell_rce', org_id: 'ORG001' } });
  expect(inj.ok()).toBeTruthy();
  let alert: { alert_id: string } | undefined;
  await expect(async () => {
    const r = await (await request.get('/api/v1/alerts?source_id=SC_PHP2SHELL&severity=critical&limit=50', { headers })).json();
    alert = (r.items as { alert_id: string; d3fend?: unknown[] }[]).find((a) => (a.d3fend ?? []).length > 0) ?? undefined;
    if (!alert) {
      const det = await Promise.all((r.items as { alert_id: string }[]).map(async (a) =>
        (await request.get(`/api/v1/alerts/${a.alert_id}`, { headers })).json()));
      alert = det.find((a) => (a.d3fend ?? []).length > 0);
    }
    expect(alert).toBeTruthy();
  }).toPass({ timeout: 120_000 });
  await page.goto(`/alerts/${alert!.alert_id}`);
  const card = page.getByTestId('alert-countermeasures');
  await expect(card.getByTestId('cm-designated')).toContainText('D3-NI');
  await expect(card).toContainText('D3FEND 1.6.0 기준');
  const groups = card.locator('[data-testid^="cm-tactic-"]');
  await expect(groups.first()).toHaveAttribute('data-testid', 'cm-tactic-Isolate');
  await expect(card.getByTestId('cm-tactic-Isolate')).toContainText('지정');
  await expect(card.getByTestId('cm-tactic-Evict')).toContainText('D3-PT');
  await card.getByTestId('cm-tactic-Isolate').getByRole('link', { name: 'D3-NI' }).click();
  await expect(page.getByTestId('d3fend-detail')).toContainText('Network Isolation');
  await page.keyboard.press('Escape');
  await card.scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${SHOTS}/6-alert.png`, fullPage: true });
});
