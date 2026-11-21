// 시나리오 분석: 왼쪽 시나리오 그룹(추가·이름·이동·삭제), 검색 조건, [이벤트 탐지모듈 관리] 새 창, 순서도 안에서 이벤트 탐지모듈 만들기·편집(옆 패널),
// 노드 도구 막대(편집·복제·삭제), 화살표 삭제, 자동 정렬(왼쪽 → 오른쪽), 예전 /single-rules 주소 이동.
// 화면 캡처는 E2E_SHOTS 디렉터리(기본 test-results/scenario-hub)에 남긴다.
import { expect, test, type Locator, type Page } from '@playwright/test';

const SHOTS = process.env.E2E_SHOTS ?? 'test-results/scenario-hub';
const SUFFIX = Date.now().toString(36).toUpperCase();
const RULE = `SR_E2E_HUB_${SUFFIX}`;
const SCENARIO = `SC_E2E_HUB_${SUFFIX}`;
const GROUP = `E2E 그룹 ${SUFFIX}`;

async function login(page: Page, user = 'author', pw = 'author123') {
  await page.goto('/login');
  await page.getByTestId('login-username').fill(user);
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('userbox')).toContainText(user);
}

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

async function save(page: Page, button: string, note: string) {
  await page.getByTestId(button).click();
  await page.getByTestId('change-note').fill(note);
  await page.getByTestId('confirm-save').click();
}

async function centerX(l: Locator): Promise<number> {
  const b = await l.boundingBox();
  if (!b) throw new Error('노드를 찾을 수 없습니다');
  return b.x + b.width / 2;
}

test('시나리오 분석: 그룹·검색·새 창 모듈 목록, 순서도 안에서 이벤트 탐지모듈 만들기·편집, 도구 막대, 자동 정렬', async ({ page, request }) => {
  await login(page);
  // ---------- 왼쪽 시나리오 그룹 | 오른쪽 검색 조건·시나리오 리스트 ----------
  await page.getByTestId('nav-scenarios').click();
  await expect(page.getByTestId('nav-scenarios')).toHaveClass(/active/);
  await expect(page.getByTestId('nav-detections')).toHaveCount(0);
  await expect(page.getByTestId('group-item-all')).toHaveClass(/on/);
  await expect(page.getByTestId('scenario-list')).toContainText('사용 이벤트 탐지모듈');
  await expect(page.locator('.mod-chip').first()).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/1-scenarios-tab.png` });
  // 검색은 [검색] 으로 적용
  await page.getByTestId('scenario-search').fill('SC_SMB_WORM');
  await page.getByTestId('scenario-search-btn').click();
  await expect(page.getByTestId('scenario-link-SC_SMB_WORM')).toBeVisible();
  await expect(page.locator('[data-testid^="scenario-link-"]')).toHaveCount(1);

  // 그룹 추가 → 그 그룹이 선택되고 아직 비어 있다
  await page.getByTestId('group-add').click();
  await page.getByTestId('group-add-input').fill(GROUP);
  await page.getByTestId('group-add-input').press('Enter');
  await expect(page).toHaveURL(/\/scenarios\?group=\d+$/);
  const gid = Number(new URL(page.url()).searchParams.get('group'));
  await expect(page.getByTestId(`group-item-${gid}`)).toHaveClass(/on/);
  await expect(page.locator('[data-testid^="scenario-link-"]')).toHaveCount(0);
  await expect(page.getByText('조건에 맞는 시나리오가 없습니다')).toBeVisible();

  // 전체에서 SC_SMB_WORM 을 골라 그룹으로 옮긴다 (검색 조건은 그대로)
  await page.getByTestId('group-item-all').click();
  await page.getByTestId('scenario-check-SC_SMB_WORM').check();
  await page.getByTestId('group-move-select').selectOption(String(gid));
  await page.getByTestId('group-move').click();
  await expect(page.getByTestId('scenario-group-SC_SMB_WORM')).toHaveText(GROUP);
  await page.getByTestId('scenario-reset').click();
  await page.getByTestId(`group-item-${gid}`).click();
  await expect(page.locator('[data-testid^="scenario-link-"]')).toHaveCount(1);
  await expect(page.getByTestId(`group-item-${gid}`)).toContainText('1');
  // 이름 바꾸기
  await page.getByTestId(`group-item-${gid}`).hover();
  await page.getByTestId(`group-rename-${gid}`).click();
  await page.getByTestId(`group-rename-input-${gid}`).fill(`${GROUP} 수정`);
  await page.getByTestId(`group-rename-input-${gid}`).press('Enter');
  await expect(page.getByTestId(`group-item-${gid}`)).toContainText(`${GROUP} 수정`);
  await page.screenshot({ path: `${SHOTS}/2-group.png` });

  // [이벤트 탐지모듈 관리] → 새 창에 모듈 목록만. 모듈을 누르면 같은 창 오른쪽 사이드 패널에 상세가 열린다
  const mainUrl = page.url();
  const [pop] = await Promise.all([page.waitForEvent('popup'), page.getByTestId('modules-popup').click()]);
  await expect(pop.getByTestId('modules-popup-page').getByTestId('rule-list')).toBeVisible();
  await expect(pop.getByTestId('nav-scenarios')).toHaveCount(0); // 메뉴 없이 목록만
  await expect(pop.getByTestId('module-side-panel')).toHaveCount(0);
  await pop.screenshot({ path: `${SHOTS}/2b-popup.png` });
  await pop.getByTestId('rule-link-SR_TI_HIT').click();
  const side = pop.getByTestId('module-side-panel');
  await expect(side).toBeVisible();
  await expect(side.getByTestId('rule-name')).not.toHaveValue('');
  await expect(side.getByTestId('rule-sql')).toContainText('INSERT INTO');
  await expect(side.getByTestId('tab-versions')).toBeVisible(); // 백테스트·버전·실행·히트 탭도 이 창에서
  await expect(pop.getByTestId('rule-link-SR_TI_HIT').locator('xpath=ancestor::tr')).toHaveClass(/row-open/);
  await expect(pop).toHaveURL(/\/popup\/modules$/);
  expect(page.url()).toBe(mainUrl); // 원래 창은 그대로
  await pop.screenshot({ path: `${SHOTS}/2c-popup-side.png` });
  // 다른 모듈을 누르면 패널 내용이 바뀌고, 새 모듈 만들기도 같은 패널, Esc·✕ 로 닫는다
  await pop.getByTestId('rule-link-SR_SMB_OUT_FANOUT').click();
  await expect(side.getByTestId('rule-id')).toHaveValue('SR_SMB_OUT_FANOUT');
  await pop.getByTestId('rule-new').click();
  await expect(side.getByTestId('rule-id')).toHaveValue('');
  await pop.keyboard.press('Escape');
  await expect(side).toHaveCount(0);
  await pop.getByTestId('rule-link-SR_TI_HIT').click();
  await side.getByTestId('rule-drawer-close').click();
  await expect(side).toHaveCount(0);
  await pop.close();

  // 예전 주소는 새 주소로 간다
  await page.goto('/single-rules/SR_TI_HIT');
  await expect(page).toHaveURL(/\/scenarios\/detections\/SR_TI_HIT$/);
  await expect(page.getByTestId('rule-name')).not.toHaveValue('');
  await page.getByTestId('rule-back').click();
  await expect(page).toHaveURL(/\/scenarios$/);

  // ---------- 새 시나리오 (그룹을 고른 채 등록하면 그 그룹으로): 순서도 안에서 이벤트 탐지모듈을 새로 만든다 ----------
  await page.getByTestId(`group-item-${gid}`).click();
  await page.getByTestId('scenario-new').click();
  await expect(page.getByTestId('scenario-group')).toHaveValue(String(gid));
  await page.getByTestId('scenario-id').fill(SCENARIO);
  await page.getByTestId('scenario-name').fill('E2E 통합 화면');
  await page.getByTestId('palette-new-rule').click();
  const drawer = page.getByTestId('rule-drawer');
  await expect(drawer).toBeVisible();
  await drawer.getByTestId('rule-id').fill(RULE);
  await drawer.getByTestId('rule-name').fill('E2E 옆 패널 탐지');
  await drawer.getByTestId('rule-type-signature').check();
  await drawer.getByTestId('rule-dtp-IPS').check();
  await drawer.getByTestId('filter-add-cond-filter').click();
  await drawer.getByTestId('filter-field-filter.all[0]').selectOption('signature_name');
  await drawer.getByTestId('filter-op-filter.all[0]').selectOption('eq');
  await drawer.getByTestId('filter-value-filter.all[0]').fill('E2E Hub Probe');
  await expect(drawer.getByTestId('rule-compile-state')).toHaveText(/검증 통과/);
  await page.screenshot({ path: `${SHOTS}/3-drawer-new.png` });
  await save(page, 'rule-save', 'E2E 옆 패널에서 생성');
  // 저장하면 순서도에 노드로 들어가고, 주소는 그대로다
  await expect(page.getByTestId('node-n1')).toContainText(RULE);
  await expect(page.getByTestId('node-n1')).toContainText('E2E 옆 패널 탐지');
  await expect(page.getByTestId('node-n1').locator('.mod-ico')).toBeVisible(); // 순서도의 모듈 아이콘
  await expect(page.getByTestId('node-start').locator('.scn-ico')).toBeVisible(); // 시작 노드의 시나리오 아이콘
  await expect(page).toHaveURL(/\/scenarios\/new\?group=\d+$/);
  await drawer.getByTestId('rule-drawer-close').click();
  await expect(drawer).toHaveCount(0);

  // ---------- 경보 노드, 연결, 자동 정렬 ----------
  await page.getByTestId('palette-add-alert').click();
  await expect(page.getByTestId('node-a1')).toBeVisible();
  await page.getByTestId('prop-severity').selectOption('high');
  await page.getByTestId('prop-title').fill('E2E 통합: {{entity}}');
  await page.getByRole('button', { name: '자동 정렬' }).click();
  await page.waitForTimeout(400);
  await connect(page, page.getByTestId('handle-n0-out'), page.getByTestId('handle-n1-in'));
  await connect(page, page.getByTestId('handle-n1-out'), page.getByTestId('handle-a1-in'));
  await page.getByRole('button', { name: '자동 정렬' }).click();
  await page.waitForTimeout(500);
  await expect(page.locator('.vue-flow__edge')).toHaveCount(2); // 자동 정렬은 화살표를 지우지 않는다
  const xs = [await centerX(page.getByTestId('node-start')), await centerX(page.getByTestId('node-n1')), await centerX(page.getByTestId('node-a1'))];
  expect(xs[0]).toBeLessThan(xs[1]);
  expect(xs[1]).toBeLessThan(xs[2]);

  // ---------- 노드 도구 막대: 편집(옆 패널에 기존 탐지) ----------
  await page.getByTestId('node-n1').click();
  await expect(page.getByTestId('node-toolbar')).toBeVisible();
  await page.getByTestId('node-edit').click();
  await expect(drawer).toBeVisible();
  await expect(drawer.getByTestId('rule-name')).toHaveValue('E2E 옆 패널 탐지');
  await drawer.getByTestId('rule-name').fill('E2E 옆 패널 탐지 (수정)');
  await save(page, 'rule-save', 'E2E 이름 수정');
  await expect(page.getByTestId('notice').first()).toContainText(`${RULE} 를 저장했습니다`);
  await page.screenshot({ path: `${SHOTS}/4-drawer-edit.png` });
  await drawer.getByTestId('rule-drawer-close').click();
  await expect(page.getByTestId('node-n1')).toContainText('E2E 옆 패널 탐지 (수정)');
  await expect(page.getByTestId(`palette-rule-${RULE}`)).toContainText('(수정)');

  // 두 번 누르면 바로 편집, Esc 로 닫는다
  await page.getByTestId('node-n1').dblclick();
  await expect(drawer).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toHaveCount(0);

  // ---------- 복제·삭제 ----------
  await page.getByTestId('node-n1').click();
  await page.getByTestId('node-duplicate').click();
  await expect(page.getByTestId('node-n2')).toContainText(RULE);
  await page.getByTestId('node-delete').click(); // 복제된 노드가 선택돼 있다
  await expect(page.getByTestId('node-n2')).toHaveCount(0);

  // ---------- 화살표 선택 → 가운데 ✕ 로 삭제 → 다시 잇기 ----------
  await page.locator('.vue-flow__edge[data-id="n1->a1"]').click({ force: true });
  await page.getByTestId('edge-delete-n1->a1').click();
  await expect(page.locator('.vue-flow__edge[data-id="n1->a1"]')).toHaveCount(0);
  await connect(page, page.getByTestId('handle-n1-out'), page.getByTestId('handle-a1-in'));
  await expect(page.locator('.vue-flow__edge[data-id="n1->a1"]')).toHaveCount(1);

  // ---------- 검증 → 저장 ----------
  await page.locator('.vue-flow__pane').click({ position: { x: 20, y: 20 } });
  await page.getByTestId('scenario-validate').click();
  await expect(page.getByTestId('notice').first()).toContainText('검증 통과');
  await save(page, 'scenario-save', 'E2E 통합 화면');
  await expect(page).toHaveURL(new RegExp(`/scenarios/${SCENARIO}$`));
  await page.screenshot({ path: `${SHOTS}/5-editor.png` });

  // 서버에 그래프와 이벤트 탐지모듈이 들어갔다
  const tok = await page.evaluate(() => localStorage.getItem('scenario_token'));
  const headers = { Authorization: `Bearer ${tok}` };
  const sc = await (await request.get(`/api/v1/scenarios/${SCENARIO}`, { headers })).json();
  expect(sc.scenario.rule_ids).toEqual([RULE]);
  expect(sc.scenario.group_id).toBe(gid); // 목록에서 고른 그룹으로 저장됐다
  expect(sc.graph.edges).toHaveLength(2);
  const rule = await (await request.get(`/api/v1/single-rules/${RULE}`, { headers })).json();
  expect(rule.rule.name).toBe('E2E 옆 패널 탐지 (수정)');

  // 목록: 시나리오 탭에 이름, 쓰는 이벤트 탐지모듈 칩은 이름으로
  await page.getByTestId('scenario-back').click();
  await page.getByTestId('scenario-search').fill(SCENARIO);
  await page.getByTestId('scenario-search-btn').click();
  await expect(page.getByTestId(`scenario-link-${SCENARIO}`)).toHaveText('E2E 통합 화면');
  await expect(page.getByTestId('scenario-list')).toContainText('E2E 옆 패널 탐지 (수정)');
  await expect(page.getByTestId(`scenario-group-${SCENARIO}`)).toHaveText(`${GROUP} 수정`);

  // 그룹 삭제 → 그 그룹의 시나리오는 미분류가 된다
  page.once('dialog', (d) => void d.accept());
  await page.getByTestId(`group-item-${gid}`).hover();
  await page.getByTestId(`group-delete-${gid}`).click();
  await expect(page.getByTestId(`group-item-${gid}`)).toHaveCount(0);
  await expect(page.getByTestId('group-item-all')).toHaveClass(/on/);
  await expect(page.getByTestId(`scenario-group-${SCENARIO}`)).toHaveText('미분류');
});

test('읽기 전용(analyst): 새 노드 모양, 도구 막대·만들기 버튼 없음', async ({ page }) => {
  await login(page, 'analyst', 'analyst123');
  await page.goto('/scenarios/SC_SMB_WORM');
  await expect(page.getByTestId('node-n2')).toContainText('탐지 확인');
  await expect(page.getByTestId('handle-n2-yes')).toBeVisible();
  await page.getByTestId('node-n2').click();
  await expect(page.getByTestId('node-toolbar')).toHaveCount(0); // analyst 는 편집 권한이 없다
  await expect(page.getByTestId('palette-new-rule')).toHaveCount(0);
  await page.screenshot({ path: `${SHOTS}/6-readonly.png` });
});
