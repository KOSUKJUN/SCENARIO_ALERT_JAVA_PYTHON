<script setup lang="ts">
// Snort 룰 가져오기: 룰 텍스트(붙여넣기·파일) → 이벤트 탐지모듈 정의로 변환·검증 → 고른 것만 draft 로 만든다.
// 바로 운영하지 않는다. 만든 뒤 편집기에서 미리보기·백테스트를 거쳐 silent/active 로 올린다.
import { computed, ref, shallowRef } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../../api';
import { useMeta } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { RuleSummary, SnortImportItem, SnortImportResponse } from '../../types';

const DRAFT_KEY = 'scenario-alert:rule-draft';
const SAMPLE = `# 예시 (문서용 IP 대역)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB IPC$ 공유 접근"; flow:to_server,established; content:"IPC$"; nocase; classtype:attempted-recon; sid:9000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH 무차별 대입"; flags:S; threshold: type both, track by_dst, count 30, seconds 60; priority:1; sid:9000002; rev:1;)
alert tcp $HOME_NET any -> any [6881,6969] (msg:"P2P 토렌트 통신"; classtype:policy-violation; sid:9000003; rev:1;)
alert tcp any any -> any 80 (msg:"웹 관리자 페이지 접근"; content:"/admin/"; http_uri; nocase; pcre:"/\\/admin\\/[a-z]+\\.php/i"; sid:9000004; rev:1;)`;

const router = useRouter();
const meta = useMeta();
const text = ref('');
const match = ref<'content' | 'msg'>('content');
const dataTp = ref<string[]>(['IDS', 'IPS', 'TMS']);
const idPrefix = ref('SR_SNORT_');
const busy = ref(false);
const error = ref<unknown>(null);
// 정의 타입(FilterNode)이 재귀라 깊은 ref 대신 shallowRef (통째로 바꿔 넣는다)
const result = shallowRef<SnortImportResponse | null>(null);
const selected = ref<Set<number>>(new Set());
const created = ref<Record<number, { ok: boolean; msg: string }>>({});
const creating = ref(false);

const selectable = (it: SnortImportItem) => !!it.definition && !!it.ok && !it.exists && !created.value[it.line]?.ok;
const selectableItems = computed(() => (result.value?.items ?? []).filter(selectable));
const allSelected = computed(() => selectableItems.value.length > 0 && selectableItems.value.every((i) => selected.value.has(i.line)));
const counts = computed(() => {
  const items = result.value?.items ?? [];
  return {
    ok: items.filter((i) => i.definition && i.ok && !i.exists).length,
    exists: items.filter((i) => i.exists).length,
    invalid: items.filter((i) => i.definition && !i.ok).length,
    skipped: items.filter((i) => !i.definition).length,
  };
});

async function onFile(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0];
  if (!f) return;
  text.value = await f.text();
  (e.target as HTMLInputElement).value = '';
}

function toggleDtp(d: string, on: boolean) {
  dataTp.value = on ? [...dataTp.value, d] : dataTp.value.filter((x) => x !== d);
}

async function convert() {
  busy.value = true;
  error.value = null;
  created.value = {};
  try {
    result.value = await api.post<SnortImportResponse>('/single-rules/import/snort', {
      text: text.value,
      match: match.value,
      data_tp: dataTp.value,
      id_prefix: idPrefix.value.trim() || undefined,
    });
    selected.value = new Set(result.value.items.filter(selectable).map((i) => i.line));
  } catch (e) {
    error.value = e;
    result.value = null;
  } finally {
    busy.value = false;
  }
}

function toggle(line: number, on: boolean) {
  const s = new Set(selected.value);
  if (on) s.add(line);
  else s.delete(line);
  selected.value = s;
}

function toggleAll(on: boolean) {
  selected.value = on ? new Set(selectableItems.value.map((i) => i.line)) : new Set();
}

/** 고른 룰을 하나씩 draft 로 만든다 (실패해도 나머지는 계속) */
async function createSelected() {
  const items = (result.value?.items ?? []).filter((i) => selected.value.has(i.line) && selectable(i));
  creating.value = true;
  for (const it of items) {
    try {
      const r = await api.post<{ rule: RuleSummary }>('/single-rules', {
        definition: it.definition,
        change_note: `Snort 룰 가져오기${it.sid ? ` (sid ${it.sid})` : ''}`,
      });
      created.value = { ...created.value, [it.line]: { ok: true, msg: `${r.rule.rule_id} 생성 (draft)` } };
    } catch (e) {
      created.value = { ...created.value, [it.line]: { ok: false, msg: e instanceof Error ? e.message : String(e) } };
    }
  }
  selected.value = new Set();
  creating.value = false;
}

/** 편집기에서 다듬어 저장: 정의를 넘기고 새 룰 화면을 연다 */
function openInEditor(it: SnortImportItem) {
  if (!it.definition) return;
  try {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(it.definition));
  } catch {
    /* 저장소를 못 쓰면 새 룰 화면이 빈 정의로 열린다 */
  }
  void router.push('/scenarios/detections/new');
}

function statusOf(it: SnortImportItem): { kind: string; label: string } {
  const c = created.value[it.line];
  if (c) return c.ok ? { kind: 'ok', label: '생성됨' } : { kind: 'bad', label: '생성 실패' };
  if (!it.definition) return { kind: 'warn', label: '건너뜀' };
  if (it.exists) return { kind: 'info', label: '같은 ID 있음' };
  if (!it.ok) return { kind: 'bad', label: '검증 오류' };
  return { kind: 'ok', label: '변환됨' };
}
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>Snort 룰 가져오기</h2>
      <div class="actions"><RouterLink to="/scenarios" class="button">시나리오 분석</RouterLink></div>
    </div>

    <CardBox title="1. 룰 입력">
      <p class="hint">
        Snort 2.x / 3.x 룰을 붙여넣거나 .rules 파일을 고르세요. 한 줄에 룰 하나, 줄 끝 \ 로 이어 쓸 수 있고 # 주석 줄은 건너뜁니다.
        만들어진 룰은 draft 상태라 바로 탐지에 쓰이지 않습니다.
      </p>
      <textarea v-model="text" rows="10" class="code" spellcheck="false" placeholder="alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:&quot;...&quot;; content:&quot;...&quot;; sid:1000001; rev:1;)" data-testid="snort-text" />
      <div class="form-row wrap">
        <label class="button small">파일 열기<input type="file" accept=".rules,.txt,text/plain" hidden data-testid="snort-file" @change="onFile" /></label>
        <button type="button" class="small" @click="text = SAMPLE">예시 넣기</button>
        <span class="muted small">{{ text ? `${text.split('\n').length}줄` : '' }}</span>
      </div>
      <div class="form-grid">
        <div class="field">
          <span class="field-label">매칭 방식</span>
          <label class="check"><input v-model="match" type="radio" value="content" data-testid="snort-match-content" /> 페이로드 조건 (content·pcre·헤더)</label>
          <label class="check"><input v-model="match" type="radio" value="msg" data-testid="snort-match-msg" /> 시그니처명 = msg (장비가 이 룰로 이미 탐지한 로그)</label>
        </div>
        <div class="field">
          <span class="field-label">데이터 유형</span>
          <div class="checks">
            <label v-for="d in meta.data.value?.data_types ?? ['IDS', 'IPS', 'TMS']" :key="d" class="check">
              <input type="checkbox" :checked="dataTp.includes(d)" @change="toggleDtp(d, ($event.target as HTMLInputElement).checked)" />{{ d }}
            </label>
          </div>
          <span class="hint">URI·HTTP 메서드 조건이 있는 룰은 WAF, WEB 으로 바뀝니다</span>
        </div>
        <label class="field">
          <span class="field-label">룰 ID 접두어</span>
          <input v-model="idPrefix" placeholder="SR_SNORT_" data-testid="snort-prefix" />
          <span class="hint">ID = 접두어 + sid (sid 가 없으면 L + 줄 번호)</span>
        </label>
      </div>
      <ErrorBox :error="error" />
      <div class="form-row">
        <button class="primary" :disabled="busy || !text.trim() || !dataTp.length" data-testid="snort-convert" @click="convert">
          {{ busy ? '변환 중…' : '변환·검증' }}
        </button>
      </div>
    </CardBox>

    <CardBox v-if="result" title="2. 변환 결과 확인">
      <template #actions>
        <span class="muted small">
          전체 {{ result.total }} · 만들 수 있음 {{ counts.ok }} · 같은 ID 있음 {{ counts.exists }} · 검증 오류 {{ counts.invalid }} · 건너뜀 {{ counts.skipped }}
        </span>
        <button class="primary" :disabled="creating || !selected.size" data-testid="snort-create" @click="createSelected">
          {{ creating ? '만드는 중…' : `선택한 ${selected.size}개 룰 만들기 (draft)` }}
        </button>
      </template>
      <div class="table-wrap">
        <table class="table compact" data-testid="snort-result">
          <thead>
            <tr>
              <th><input type="checkbox" :checked="allSelected" :disabled="!selectableItems.length" @change="toggleAll(($event.target as HTMLInputElement).checked)" /></th>
              <th>줄</th><th>상태</th><th>ID / 이름</th><th>유형</th><th>등급</th><th>변환 내용</th><th />
            </tr>
          </thead>
          <tbody>
            <tr v-for="it in result.items" :key="it.line" :class="{ 'row-bad': it.definition && !it.ok, 'row-warn': !it.definition }" :data-testid="`snort-row-${it.line}`">
              <td><input type="checkbox" :checked="selected.has(it.line)" :disabled="!selectable(it)" @change="toggle(it.line, ($event.target as HTMLInputElement).checked)" /></td>
              <td class="num">{{ it.line }}</td>
              <td>
                <UiBadge :kind="statusOf(it).kind">{{ statusOf(it).label }}</UiBadge>
                <div v-if="created[it.line]" class="small" :class="created[it.line].ok ? 'muted' : 'err-text'">
                  <RouterLink v-if="created[it.line].ok && it.definition" :to="`/scenarios/detections/${it.definition.id}`">{{ created[it.line].msg }}</RouterLink>
                  <template v-else>{{ created[it.line].msg }}</template>
                </div>
              </td>
              <td>
                <template v-if="it.definition">
                  <code>{{ it.definition.id }}</code>
                  <div class="small">{{ it.definition.name }}</div>
                </template>
                <span v-else class="muted small">sid {{ it.sid ?? '-' }}</span>
              </td>
              <td class="small">
                <template v-if="it.definition">
                  {{ it.definition.type === 'count' ? `count ≥ ${it.definition.threshold} / ${it.definition.window}` : `signature / ${it.definition.window}` }}
                  <div class="muted">{{ (it.definition.data_tp ?? []).join(', ') }}</div>
                </template>
              </td>
              <td><SeverityBadge v-if="it.definition" :severity="it.definition.severity ?? 'medium'" /></td>
              <td class="small">
                <div v-if="it.skipped" class="warn-text">{{ it.skipped }}</div>
                <ul v-if="it.errors?.length" class="issue-lines">
                  <li v-for="(e, i) in it.errors" :key="`e${i}`">{{ e.path }}: {{ e.message }}</li>
                </ul>
                <ul v-if="it.notes.length || it.warnings?.length" class="issue-lines">
                  <li v-for="(n, i) in it.notes" :key="`n${i}`" class="warn">{{ n }}</li>
                  <li v-for="(w, i) in it.warnings ?? []" :key="`w${i}`" class="warn">{{ w.path }}: {{ w.message }}</li>
                </ul>
                <details>
                  <summary>원문·정의·SQL</summary>
                  <pre class="code small">{{ it.source }}</pre>
                  <pre v-if="it.definition" class="code small">{{ JSON.stringify(it.definition.filter, null, 2) }}</pre>
                  <pre v-if="it.sql" class="sql">{{ it.sql }}</pre>
                </details>
              </td>
              <td>
                <button v-if="it.definition && !it.exists && !created[it.line]?.ok" class="small" :data-testid="`snort-edit-${it.line}`" @click="openInEditor(it)">편집기로 열기</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </CardBox>
  </div>
</template>
