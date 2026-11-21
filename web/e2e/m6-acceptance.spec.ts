// M6 수용 기준: 화면에서 이벤트 탐지모듈(단일룰) 2개를 만들고 순서도로 이어 silent 반영까지 코드 수정 없이 완료한다.
//
// 1) 단일룰 A(시그니처)와 B(카운트)를 양식으로 만들고 저장 → 백테스트 → silent
// 2) 새 순서도: A 를 캔버스로 끌어다 놓고, B 와 경보 노드를 추가해 시작 → A → B → 경보로 잇는다
// 3) 검증 → 저장 → 백테스트 → silent
// 4) 서버 API 로 결과(상태, 그래프 JSON)를 확인한다
import { expect, test, type Locator, type Page } from '@playwright/test';

const SUFFIX = Date.now().toString(36).toUpperCase();
const RULE_A = `SR_E2E_A_${SUFFIX}`;
const RULE_B = `SR_E2E_B_${SUFFIX}`;
const SCENARIO = `SC_E2E_${SUFFIX}`;

async function login(page: Page, user = 'author', pw = 'author123') {
  await page.goto('/login');
  await page.getByTestId('login-username').fill(user);
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('userbox')).toContainText(user);
}

/** 저장 → 변경 메모 → 확인. */
async function save(page: Page, button: string, note: string) {
  await page.getByTestId(button).click();
  await page.getByTestId('change-note').fill(note);
  await page.getByTestId('confirm-save').click();
}

/** 백테스트 패널에서 실행하고 완료까지 기다린다 (서버 백테스트 루프가 대기열을 처리). */
async function backtest(page: Page) {
  const panel = page.getByTestId('backtest-panel');
  await panel.getByTestId('backtest-start').click();
  await expect(panel.getByTestId('backtest-done')).toBeVisible({ timeout: 120_000 });
  await expect(panel.getByTestId('backtest-result')).toBeVisible();
}

async function toSilent(page: Page) {
  await page.getByTestId('status-silent').click();
  await expect(page.getByTestId('status-current')).toHaveText('테스트운영');
}

/** 시나리오 분석 → [이벤트 탐지모듈 관리] 새 창. 모듈 만들기·상세는 그 창의 오른쪽 사이드 패널에서 한다 */
async function openModules(page: Page): Promise<Page> {
  await page.getByTestId('nav-scenarios').click();
  const [pop] = await Promise.all([page.waitForEvent('popup'), page.getByTestId('modules-popup').click()]);
  await expect(pop.getByTestId('rule-list')).toBeVisible();
  return pop;
}

/** 노드 핸들 끼리 마우스로 끌어 화살표를 잇는다. */
async function connect(page: Page, from: Locator, to: Locator) {
  const a = await from.boundingBox();
  const b = await to.boundingBox();
  if (!a || !b) throw new Error('핸들을 찾을 수 없습니다');
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
  await page.mouse.down();
  await page.mouse.move((a.x + b.x) / 2, (a.y + b.y) / 2, { steps: 8 });
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 8 });
  await page.mouse.up();
}

test('이벤트 탐지모듈 2개 → 순서도 → silent (화면만으로)', async ({ page, request }) => {
  await login(page);

  // ---------- 이벤트 탐지모듈 A: 시그니처 (IPS 에서 특정 시그니처) ----------
  const pop = await openModules(page);
  await pop.getByTestId('rule-new').click();
  await expect(pop.getByTestId('module-side-panel')).toBeVisible();
  await pop.getByTestId('rule-id').fill(RULE_A);
  await pop.getByTestId('rule-name').fill('E2E 시그니처 룰');
  await pop.getByTestId('rule-type-signature').check();
  await pop.getByTestId('rule-dtp-IPS').check();
  await pop.getByTestId('filter-add-cond-filter').click();
  await pop.getByTestId('filter-field-filter.all[0]').selectOption('signature_name');
  await pop.getByTestId('filter-op-filter.all[0]').selectOption('eq');
  await pop.getByTestId('filter-value-filter.all[0]').fill('E2E Probe Alpha');
  await expect(pop.getByTestId('rule-compile-state')).toHaveText(/검증 통과/);
  await expect(pop.getByTestId('rule-sql')).toContainText('INSERT INTO');
  await pop.getByTestId('rule-preview').click();
  await expect(pop.getByTestId('preview-result')).toBeVisible();
  await save(pop, 'rule-save', 'E2E 생성');
  await expect(pop.getByTestId('module-side-panel')).toContainText(RULE_A); // 이 창 안에서 그대로 이어서 본다
  await expect(pop).toHaveURL(/\/popup\/modules$/);
  await expect(page).toHaveURL(/\/scenarios$/); // 원래 창은 그대로
  await expect(pop.getByTestId('status-current')).toHaveText('초안');
  await backtest(pop);
  await toSilent(pop);

  // ---------- 이벤트 탐지모듈 B: 카운트 (10분 안에 서로 다른 목적지 20개 이상, 445 포트) ----------
  await pop.getByTestId('rule-new').click();
  await expect(pop.getByTestId('module-side-panel')).toBeVisible();
  await pop.getByTestId('rule-id').fill(RULE_B);
  await pop.getByTestId('rule-name').fill('E2E 카운트 룰');
  await pop.getByTestId('rule-type-count').check();
  await pop.getByTestId('rule-dtp-IPS').check();
  await pop.getByTestId('rule-dtp-FIREWALL').check();
  await pop.getByTestId('filter-add-cond-filter').click();
  await pop.getByTestId('filter-field-filter.all[0]').selectOption('dst_port');
  await pop.getByTestId('filter-op-filter.all[0]').selectOption('eq');
  await pop.getByTestId('filter-value-filter.all[0]').fill('445');
  await pop.getByTestId('rule-agg-func').selectOption('distinct_count');
  await pop.getByTestId('rule-agg-field').selectOption('dst_ip');
  await pop.getByTestId('rule-threshold').fill('20');
  await expect(pop.getByTestId('rule-compile-state')).toHaveText(/검증 통과/);
  await save(pop, 'rule-save', 'E2E 생성');
  await expect(pop.getByTestId('module-side-panel')).toContainText(RULE_B);
  await expect(pop.getByTestId(`rule-link-${RULE_B}`)).toBeVisible(); // 목록도 새로 읽었다
  await backtest(pop);
  await toSilent(pop);
  await pop.close();

  // ---------- 순서도: 시작 → A → (30분 내) B → 경보 ----------
  await page.getByTestId('nav-scenarios').click();
  await page.getByTestId('scenario-new').click();
  await page.getByTestId('scenario-id').fill(SCENARIO);
  await page.getByTestId('scenario-name').fill('E2E 순서도');
  const canvas = page.getByTestId('scenario-canvas');
  await page.getByTestId('palette-search').fill('SR_E2E_');
  // A 는 끌어다 놓기, B 는 더블클릭, 경보는 + 버튼
  await page.getByTestId(`palette-rule-${RULE_A}`).dragTo(canvas, { targetPosition: { x: 330, y: 200 } });
  await expect(page.getByTestId('node-n1')).toContainText(RULE_A);
  await page.getByTestId(`palette-rule-${RULE_B}`).dblclick();
  await expect(page.getByTestId('node-n2')).toContainText(RULE_B);
  await page.getByTestId('palette-add-alert').click();
  await expect(page.getByTestId('node-a1')).toBeVisible();
  await page.getByTestId('prop-severity').selectOption('high');
  await page.getByTestId('prop-title').fill('E2E 경보: {{entity}}');
  // 노드가 겹치지 않게 자동 정렬 후 잇는다
  await page.getByRole('button', { name: '자동 정렬' }).click();
  await page.waitForTimeout(400);
  await connect(page, page.getByTestId('handle-n0-out'), page.getByTestId('handle-n1-in'));
  await connect(page, page.getByTestId('handle-n1-out'), page.getByTestId('handle-n2-in'));
  await expect(page.getByTestId('props-edge')).toBeVisible();
  await expect(page.getByTestId('prop-edge-within')).toHaveValue('30m'); // 룰 노드로 들어가는 화살표는 허용 시간
  await connect(page, page.getByTestId('handle-n2-out'), page.getByTestId('handle-a1-in'));

  await page.getByTestId('scenario-validate').click();
  await expect(page.getByTestId('notice').first()).toContainText('검증 통과');
  await save(page, 'scenario-save', 'E2E 생성');
  await expect(page).toHaveURL(new RegExp(`/scenarios/${SCENARIO}$`));
  await expect(page.getByTestId('status-current')).toHaveText('초안');
  await page.getByTestId('scenario-backtest').click();
  await backtest(page);
  await toSilent(page);

  // ---------- 서버 상태 확인 ----------
  const tok = await page.evaluate(() => localStorage.getItem('scenario_token'));
  const headers = { Authorization: `Bearer ${tok}` };
  const sc = await (await request.get(`/api/v1/scenarios/${SCENARIO}`, { headers })).json();
  expect(sc.scenario.status).toBe('silent');
  expect(sc.scenario.rule_ids.sort()).toEqual([RULE_A, RULE_B].sort());
  const g = sc.graph;
  expect(g.nodes.map((n: { type: string }) => n.type).sort()).toEqual(['alert', 'rule', 'rule', 'start']);
  expect(g.edges).toHaveLength(3);
  const ab = g.edges.find((e: { from: string; to: string }) => e.from === 'n1' && e.to === 'n2');
  expect(ab.within).toBe('30m');
  expect(g.nodes.every((n: { pos?: number[] }) => Array.isArray(n.pos) && n.pos.length === 2)).toBe(true);
  for (const r of [RULE_A, RULE_B]) {
    const rule = await (await request.get(`/api/v1/single-rules/${r}`, { headers })).json();
    expect(rule.rule.status).toBe('silent');
  }
});
