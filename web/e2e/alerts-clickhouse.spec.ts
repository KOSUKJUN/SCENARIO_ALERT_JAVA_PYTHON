// 경보 본문은 ClickHouse codlog.alert_integrated_all, 상태(경로·판정·ATT&CK)는 MariaDB alert_state.
// 시나리오 그룹 코드(경보 rull_grp_cd)를 만든 그룹에 SC_PHP2SHELL 을 넣고, 다른 기관(ORG002)으로 공격을 주입해 새 경보가
// 그 그룹 코드·출발지/목적지·장비 값을 달고 화면에 보이는지 확인한다.
// 같은 대상의 경보가 억제 시간(6시간) 안에 이미 있으면 새 경보가 아니라 갱신이라, 그때는 그룹 코드 확인을 건너뛴다.
import { expect, test, type Page } from '@playwright/test';

const SHOTS = process.env.E2E_SHOTS ?? 'test-results/alerts-clickhouse';
const SUFFIX = Date.now().toString(36).toUpperCase();
const CODE = `E2E_${SUFFIX}`.slice(0, 32);
const ORG = 'ORG002';

async function login(page: Page, user = 'author', pw = 'author123') {
  await page.goto('/login');
  await page.getByTestId('login-username').fill(user);
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('userbox')).toContainText(user);
}

type Item = { alert_id: string; title: string; rull_grp_cd?: string; group_cd?: string; group_nm?: string; hit_count: number; first_seen: string; created_at: string; data_type?: string };

test('경보 본문은 ClickHouse 에서, 룰 그룹 코드는 rull_grp_cd, 기관은 group_cd·group_nm 으로', async ({ page, request }) => {
  const started = new Date();
  await login(page);
  const tok = await page.evaluate(() => localStorage.getItem('scenario_token'));
  const headers = { Authorization: `Bearer ${tok}` };

  // 그룹 (코드 직접 지정) → SC_PHP2SHELL 을 넣는다
  const g = await (await request.post('/api/v1/scenario-groups', { headers, data: { name: `E2E 경보 그룹 ${SUFFIX}`, grp_cd: CODE } })).json();
  expect(g.grp_cd).toBe(CODE);
  const before = await (await request.get('/api/v1/scenarios/SC_PHP2SHELL', { headers })).json();
  const prevGroup: number | null = before.scenario.group_id ?? null;
  expect((await request.put('/api/v1/scenario-groups/assign', { headers, data: { group_id: g.group_id, scenario_ids: ['SC_PHP2SHELL'] } })).ok()).toBeTruthy();

  try {
    // 화면: 그룹 패널에 코드가 보인다
    await page.getByTestId('nav-scenarios').click();
    await expect(page.getByTestId(`group-code-${g.group_id}`)).toHaveText(CODE);

    // 공격 주입 → 1~2분 안에 경보
    const inj = await request.post('/api/v1/dev/sample-data/inject', { headers, data: { scenario: 'php2shell_rce', org_id: ORG } });
    expect(inj.ok()).toBeTruthy();
    let alert: Item | undefined;
    await expect(async () => {
      const r = await (await request.get(`/api/v1/alerts?source_id=SC_PHP2SHELL&org_id=${ORG}&limit=50`, { headers })).json();
      alert = (r.items as Item[]).find((a) => a.title && !a.title.startsWith('(경보 본문 없음)'));
      expect(alert).toBeTruthy();
    }).toPass({ timeout: 180_000, intervals: [5_000] });
    const a = alert as Item;
    // 제목·최초 시각·횟수는 ClickHouse 본문에서 온다
    expect(a.data_type).toBe('SCENARIO');
    expect(a.hit_count).toBeGreaterThanOrEqual(1);
    expect(a.first_seen).toMatch(/^\d{4}-\d\d-\d\dT/);
    const fresh = new Date(a.created_at.replace(' ', 'T')) >= new Date(started.getTime() - 5_000);
    if (fresh) expect(a.rull_grp_cd).toBe(CODE);
    else test.info().annotations.push({ type: 'note', description: '같은 대상 경보가 이미 있어(억제) 그룹 코드 확인을 건너뜀' });
    expect(a.group_cd).toBe(ORG); // CODPRO 그룹 = 대상 기관
    expect(a.group_nm).not.toBe('');

    // 상세 화면: 경로(MariaDB) + 본문(ClickHouse)
    await page.goto(`/alerts/${a.alert_id}`);
    await expect(page.getByText(a.title).first()).toBeVisible();
    if (fresh) await expect(page.getByTestId('alert-grp-cd')).toContainText(CODE);
    await expect(page.getByTestId('alert-net')).toBeVisible();
    await expect(page.getByTestId('alert-codpro-group')).toContainText(ORG);
    await expect(page.getByTestId('alert-graph')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/1-alert-detail.png`, fullPage: true });

    // 목록 화면
    await page.goto(`/alerts?org_id=${ORG}`);
    await expect(page.getByTestId(`alert-link-${a.alert_id}`)).toBeVisible();
  } finally {
    await request.put('/api/v1/scenario-groups/assign', { headers, data: { group_id: prevGroup, scenario_ids: ['SC_PHP2SHELL'] } });
    await request.delete(`/api/v1/scenario-groups/${g.group_id}`, { headers });
  }
});
