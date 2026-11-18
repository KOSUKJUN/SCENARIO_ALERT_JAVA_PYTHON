<script setup lang="ts">
// 단일룰 편집기: 왼쪽 양식(또는 JSON), 오른쪽 변환된 SQL 과 미리보기. 검증은 서버(/single-rules/compile)가 한다.
import { computed, nextTick, ref, watch, type Ref } from 'vue';
import { useRouter } from 'vue-router';
import { ApiError, api, enc } from '../../api';
import { has } from '../../auth';
import { useMeta, watchDebounced } from '../../composables';
import AttackPicker from '../../components/AttackPicker.vue';
import D3fendPicker from '../../components/D3fendPicker.vue';
import BacktestPanel from '../../components/BacktestPanel.vue';
import CardBox from '../../components/CardBox.vue';
import ChangeNoteModal from '../../components/ChangeNoteModal.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import StatusControl from '../../components/StatusControl.vue';
import TabBar from '../../components/TabBar.vue';
import type { CompileResponse, MetaFields, PreviewResponse, RuleDefinition, RuleDetail, RuleSaveResponse, RuleSummary, Status } from '../../types';
import { SEVERITY_LABEL, fmtTime } from '../../util';
import FilterEditor from './FilterEditor.vue';
import PreviewView from './PreviewView.vue';
import RuleHitsTab from './RuleHitsTab.vue';
import RuleRunsTab from './RuleRunsTab.vue';
import RuleVersionsTab from './RuleVersionsTab.vue';
import { fieldAvailability, issuesFor, type FormIssue } from './filter';

const props = defineProps<{ ruleId?: string }>();
const router = useRouter();
const isNew = computed(() => !props.ruleId);
const canEdit = computed(() => has('author'));
const meta = useMeta();

const DUR_WINDOW = ['1m', '5m', '10m', '15m', '30m', '1h', '2h', '6h', '12h', '1d'];
const DUR_SCHEDULE = ['1m', '2m', '5m', '10m', '15m', '30m', '1h'];
const DUR_SUPPRESS = ['10m', '30m', '1h', '6h', '12h', '1d', '7d'];
const AGG_LABEL: Record<string, string> = {
  count: 'count (이벤트 수 합계)',
  distinct_count: 'distinct_count (서로 다른 값 수)',
  sum: 'sum (합계)',
};

// 정의 타입(FilterNode·Json)이 재귀라 ref<T> 의 UnwrapRef 펼치기를 피한다
const def = ref(null) as Ref<RuleDefinition | null>;
const summary = ref<RuleSummary | null>(null);
const loadError = ref<unknown>(null);
const jsonMode = ref(false);
const jsonText = ref('');
const jsonError = ref<string | null>(null);
const compile = ref<CompileResponse | null>(null);
const compileError = ref<unknown>(null);
const compiling = ref(false);
const preview = ref<PreviewResponse | null>(null);
const previewError = ref<unknown>(null);
const previewBusy = ref(false);
const previewHours = ref(24);
const saveOpen = ref(false);
const saving = ref(false);
const saveError = ref<unknown>(null);
const saveMsg = ref<string | null>(null);
const tab = ref('backtest');
const dirty = ref(false);
let loading = false;

function newDefinition(m: MetaFields): RuleDefinition {
  const et = m.entity_types[0];
  return {
    id: '',
    name: '',
    description: '',
    type: 'count',
    entity: { type: et?.type ?? 'host', field: et?.fields[0] ?? '' },
    data_tp: [],
    filter: { all: [] },
    aggregate: { func: m.aggregate_funcs[0]?.func ?? 'count' },
    window: '10m',
    threshold: 10,
    exclude_lists: [],
    schedule: '1m',
    alert_on_hit: false,
    severity: 'medium',
    suppress_for: '1h',
  };
}

/** Snort 가져오기 화면에서 "편집기로 열기" 로 넘긴 정의 (한 번 쓰고 지운다) */
function takeImportedDraft(): RuleDefinition | null {
  try {
    const raw = sessionStorage.getItem('scenario-alert:rule-draft');
    sessionStorage.removeItem('scenario-alert:rule-draft');
    return raw ? (JSON.parse(raw) as RuleDefinition) : null;
  } catch {
    return null;
  }
}

function stripStatus(d: RuleDefinition): RuleDefinition {
  const c = { ...d };
  delete c.status;
  return c;
}

/** 프로그램이 정의를 바꿀 때 (불러오기·저장 결과): 저장 안 됨 표시를 켜지 않는다. */
function setDef(d: RuleDefinition, markDirty = false) {
  loading = true;
  def.value = d;
  void nextTick(() => {
    loading = false;
    dirty.value = markDirty;
  });
}

watch(
  () => meta.data.value,
  (m) => {
    if (!m) return;
    if (isNew.value) {
      const draft = takeImportedDraft();
      if (draft) setDef(draft, true);
      else setDef(newDefinition(m));
      return;
    }
    api
      .get<RuleDetail>(`/single-rules/${enc(props.ruleId ?? '')}`)
      .then((r) => {
        setDef(stripStatus(r.definition));
        summary.value = r.rule;
      })
      .catch((e: unknown) => (loadError.value = e));
  },
  { immediate: true },
);

watch(
  def,
  () => {
    if (!loading) dirty.value = true;
  },
  { deep: true },
);

// 변환 SQL (입력이 600ms 멈추면)
let compileSeq = 0;
watchDebounced(
  () => (def.value ? JSON.stringify(def.value) : ''),
  (key) => {
    if (!key || !canEdit.value) return;
    const seq = ++compileSeq;
    compiling.value = true;
    api
      .post<CompileResponse>('/single-rules/compile', { definition: JSON.parse(key) })
      .then((r) => {
        if (seq === compileSeq) {
          compile.value = r;
          compileError.value = null;
        }
      })
      .catch((e: unknown) => {
        if (seq === compileSeq) compileError.value = e;
      })
      .finally(() => {
        if (seq === compileSeq) compiling.value = false;
      });
  },
  600,
);

const issues = computed<FormIssue[]>(() => {
  const se = saveError.value instanceof ApiError ? saveError.value : null;
  const errs = se?.errors.length ? se.errors : compile.value?.errors ?? [];
  const warns = se?.warnings.length ? se.warnings : compile.value?.warnings ?? [];
  return [...errs.map((e) => ({ ...e, level: 'error' as const })), ...warns.map((w) => ({ ...w, level: 'warn' as const }))];
});
const errorCount = computed(() => issues.value.filter((i) => i.level === 'error').length);
const warnCount = computed(() => issues.value.length - errorCount.value);
const errOf = (...paths: string[]) => paths.flatMap((p) => issuesFor(issues.value, p).map((i) => i.message));

const m = computed(() => meta.data.value);
const dataTp = computed(() => def.value?.data_tp ?? []);
const entityFields = computed(() => m.value?.entity_types.find((e) => e.type === def.value?.entity.type)?.fields ?? []);
const aggFields = computed(() => m.value?.aggregate_funcs.find((a) => a.func === def.value?.aggregate?.func)?.fields ?? []);
const fieldMeta = (n?: string) => m.value?.fields.find((f) => f.name === n);
function availNote(name?: string): string {
  const a = fieldAvailability(fieldMeta(name), dataTp.value);
  if (!a.missing.length) return '';
  return a.none ? '고른 데이터 유형 모두에서 비어 있음' : `${a.missing.join(', ')} 에서 비어 있음`;
}
function optLabel(name: string): string {
  const f = fieldMeta(name);
  const a = fieldAvailability(f, dataTp.value);
  return `${f?.label ?? name} (${name})${a.none ? ' — 선택 유형에 없음' : a.missing.length ? ' ⚠' : ''}`;
}
const ctx = computed(() => ({ meta: m.value as MetaFields, dataTp: dataTp.value, issues: issues.value, readOnly: !canEdit.value }));

function setType(t: 'signature' | 'count') {
  const d = def.value;
  if (!d || !m.value) return;
  const rest = { ...d };
  delete rest.aggregate;
  delete rest.threshold;
  delete rest.min_count;
  def.value =
    t === 'count'
      ? { ...rest, type: t, aggregate: d.aggregate ?? { func: m.value.aggregate_funcs[0]?.func ?? 'count' }, threshold: d.threshold ?? 10 }
      : { ...rest, type: t, min_count: d.min_count ?? 1 };
}
function setEntityType(t: string) {
  if (!def.value) return;
  const fs = m.value?.entity_types.find((x) => x.type === t)?.fields ?? [];
  def.value.entity = { type: t, field: fs[0] ?? '' };
}
function toggleDtp(d: string, on: boolean) {
  if (!def.value || !m.value) return;
  const cur = def.value.data_tp ?? [];
  def.value.data_tp = on ? m.value.data_types.filter((x) => x === d || cur.includes(x)) : cur.filter((x) => x !== d);
}
function setAggFunc(func: string) {
  if (!def.value) return;
  const fs = m.value?.aggregate_funcs.find((a) => a.func === func)?.fields ?? [];
  const cur = def.value.aggregate?.field ?? '';
  def.value.aggregate = fs.length ? { func, field: fs.includes(cur) ? cur : fs[0] } : { func };
}
function toggleExclude(id: string, on: boolean) {
  if (!def.value) return;
  const cur = def.value.exclude_lists ?? [];
  def.value.exclude_lists = on ? [...cur, id] : cur.filter((x) => x !== id);
}
/** ATT&CK 기법: 비우면 정의에서 뺀다 (기존 정의와 같은 모양 유지) */
function setAttack(v: string[]) {
  if (!def.value) return;
  def.value.attack = v.length ? v : undefined;
}
/** 지정 대응방책(D3FEND): 비우면 정의에서 뺀다 */
function setD3fend(v: string[]) {
  if (!def.value) return;
  def.value.d3fend = v.length ? v : undefined;
}
function numOrUndef(v: string): number | undefined {
  return v === '' ? undefined : Number(v);
}

function toggleJson() {
  if (!jsonMode.value) {
    jsonText.value = JSON.stringify(def.value, null, 2);
    jsonError.value = null;
  }
  jsonMode.value = !jsonMode.value;
}
function onJson(t: string) {
  jsonText.value = t;
  try {
    const v: unknown = JSON.parse(t);
    if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error('정의는 JSON 객체여야 합니다');
    def.value = v as RuleDefinition;
    jsonError.value = null;
  } catch (e) {
    jsonError.value = e instanceof Error ? e.message : String(e);
  }
}

async function runPreview() {
  previewBusy.value = true;
  previewError.value = null;
  try {
    preview.value = await api.post<PreviewResponse>('/single-rules/preview', { definition: def.value, hours: previewHours.value });
  } catch (e) {
    previewError.value = e;
    preview.value = null;
  } finally {
    previewBusy.value = false;
  }
}

async function save(note: string) {
  saving.value = true;
  saveError.value = null;
  saveMsg.value = null;
  try {
    const body = { definition: def.value, change_note: note || null };
    const r = isNew.value
      ? await api.post<RuleSaveResponse>('/single-rules', body)
      : await api.put<RuleSaveResponse>(`/single-rules/${enc(props.ruleId ?? '')}`, body);
    saveOpen.value = false;
    summary.value = r.rule;
    setDef(stripStatus(r.definition));
    saveMsg.value = `저장했습니다 (v${r.rule.version})${r.warnings.length ? ` · 경고 ${r.warnings.length}건` : ''}`;
    if (isNew.value) await router.replace(`/single-rules/${r.rule.rule_id}`);
  } catch (e) {
    saveError.value = e;
    saveOpen.value = false;
  } finally {
    saving.value = false;
  }
}

async function changeStatus(s: Status) {
  const r = await api.post<{ rule: RuleSummary }>(`/single-rules/${enc(props.ruleId ?? '')}/status`, { status: s });
  summary.value = r.rule;
}

function loadVersion(d: RuleDefinition) {
  setDef(stripStatus(d), true);
  if (jsonMode.value) jsonText.value = JSON.stringify(stripStatus(d), null, 2);
}

const tabs = computed(() => [
  { key: 'backtest', label: '백테스트', hidden: !canEdit.value },
  { key: 'versions', label: '버전 이력', hidden: isNew.value },
  { key: 'runs', label: '실행 이력', hidden: isNew.value },
  { key: 'hits', label: '최근 히트', hidden: isNew.value || !has('analyst') },
]);
</script>

<template>
  <ErrorBox v-if="meta.error.value || loadError" :error="meta.error.value || loadError" />
  <LoadingBox v-else-if="!def || !m" />
  <div v-else class="page rule-editor">
    <div class="page-head">
      <h2>
        {{ isNew ? '새 단일룰' : `단일룰 ${ruleId}` }}
        <span v-if="dirty" class="dirty" data-testid="dirty">● 저장 안 됨</span>
      </h2>
      <div class="actions">
        <RouterLink to="/single-rules" class="button">목록</RouterLink>
        <button data-testid="rule-json-toggle" @click="toggleJson">{{ jsonMode ? '양식으로 편집' : 'JSON 보기/편집' }}</button>
        <button v-if="canEdit" class="primary" data-testid="rule-save" @click="saveOpen = true">저장</button>
      </div>
    </div>
    <div v-if="summary" class="subhead">
      <StatusControl :current="summary.status" :change="changeStatus" :disabled="isNew" />
      <span class="muted small">
        v{{ summary.version }} · 수정 {{ fmtTime(summary.updated_at) }} · 마지막 평가 {{ fmtTime(summary.last_evaluated_to) }}
        <template v-if="summary.consecutive_failures > 0"> · 연속 실패 {{ summary.consecutive_failures }}회</template>
      </span>
    </div>
    <NoticeBox v-if="saveMsg" kind="ok">{{ saveMsg }}</NoticeBox>
    <ErrorBox :error="saveError" closable @close="saveError = null" />

    <div class="editor-split">
      <div class="editor-left">
        <CardBox v-if="jsonMode" title="정의 JSON">
          <textarea class="code json-edit" :value="jsonText" spellcheck="false" data-testid="rule-json" @input="onJson(($event.target as HTMLTextAreaElement).value)" />
          <div v-if="jsonError" class="field-error">JSON 오류: {{ jsonError }}</div>
        </CardBox>

        <fieldset v-else class="rule-form" :disabled="!canEdit">
          <CardBox title="기본 정보">
            <div class="form-grid">
              <FormField label="ID" :error="errOf('id')" hint="대문자로 시작, 대문자·숫자·_ (예: SR_SMB_OUT_FANOUT)">
                <input :value="def.id" :disabled="!isNew" data-testid="rule-id" @input="def.id = ($event.target as HTMLInputElement).value.toUpperCase()" />
              </FormField>
              <FormField label="이름" :error="errOf('name')">
                <input v-model="def.name" data-testid="rule-name" />
              </FormField>
            </div>
            <FormField label="설명" :error="errOf('description')">
              <textarea v-model="def.description" rows="2" data-testid="rule-description" />
            </FormField>
            <div class="form-grid">
              <FormField label="유형" :error="errOf('type')">
                <div class="radio-row" data-testid="rule-type">
                  <label class="check"><input type="radio" :checked="def.type === 'signature'" data-testid="rule-type-signature" @change="setType('signature')" />시그니처 (조건에 맞는 이벤트 발생)</label>
                  <label class="check"><input type="radio" :checked="def.type === 'count'" data-testid="rule-type-count" @change="setType('count')" />카운트 (창 안의 집계가 임계치 이상)</label>
                </div>
              </FormField>
              <FormField label="대상" :error="errOf('entity')">
                <div class="inline-pair">
                  <select :value="def.entity.type" data-testid="rule-entity-type" @change="setEntityType(($event.target as HTMLSelectElement).value)">
                    <option v-for="t in m.entity_types" :key="t.type" :value="t.type">{{ t.type }}</option>
                  </select>
                  <select v-model="def.entity.field" data-testid="rule-entity-field">
                    <option v-for="f in entityFields" :key="f" :value="f">{{ optLabel(f) }}</option>
                  </select>
                </div>
                <span v-if="availNote(def.entity.field)" class="warn-text">{{ availNote(def.entity.field) }}</span>
              </FormField>
            </div>
            <FormField label="데이터 유형 (data_tp)" :error="errOf('data_tp')">
              <div class="checks" data-testid="rule-data-tp">
                <label v-for="d in m.data_types" :key="d" class="check">
                  <input type="checkbox" :checked="dataTp.includes(d)" :data-testid="`rule-dtp-${d}`" @change="toggleDtp(d, ($event.target as HTMLInputElement).checked)" />
                  {{ d }}
                </label>
              </div>
            </FormField>
          </CardBox>

          <CardBox title="조건 (filter)">
            <div data-testid="rule-filter">
              <FilterEditor :node="def.filter ?? { all: [] }" path="filter" :depth="1" :ctx="ctx" @change="(f) => def && (def.filter = f)" />
            </div>
          </CardBox>

          <CardBox :title="def.type === 'count' ? '집계와 임계치' : '발생 기준'">
            <div class="form-grid">
              <template v-if="def.type === 'count'">
                <FormField label="집계 함수" :error="errOf('aggregate.func', 'aggregate')">
                  <select :value="def.aggregate?.func ?? ''" data-testid="rule-agg-func" @change="setAggFunc(($event.target as HTMLSelectElement).value)">
                    <option v-for="a in m.aggregate_funcs" :key="a.func" :value="a.func">{{ AGG_LABEL[a.func] ?? a.func }}</option>
                  </select>
                </FormField>
                <FormField label="집계 필드" :error="errOf('aggregate.field')">
                  <template v-if="aggFields.length && def.aggregate">
                    <select v-model="def.aggregate.field" data-testid="rule-agg-field">
                      <option v-if="!aggFields.includes(def.aggregate.field ?? '')" :value="def.aggregate.field ?? ''">(선택)</option>
                      <option v-for="f in aggFields" :key="f" :value="f">{{ optLabel(f) }}</option>
                    </select>
                    <span v-if="availNote(def.aggregate.field)" class="warn-text">{{ availNote(def.aggregate.field) }}</span>
                  </template>
                  <span v-else class="muted small">이 함수는 필드를 쓰지 않습니다</span>
                </FormField>
                <FormField label="임계치 (이상)" :error="errOf('threshold')">
                  <input type="number" min="0" step="any" :value="def.threshold ?? ''" data-testid="rule-threshold" @input="def.threshold = numOrUndef(($event.target as HTMLInputElement).value)" />
                </FormField>
              </template>
              <FormField v-else label="최소 발생 수 (min_count)" :error="errOf('min_count')">
                <input type="number" min="1" step="1" :value="def.min_count ?? 1" data-testid="rule-min-count" @input="def.min_count = numOrUndef(($event.target as HTMLInputElement).value)" />
              </FormField>
              <FormField label="집계 창 (window)" :error="errOf('window')" hint="1분~1일, 하루를 나누어떨어지게 (예: 10m)">
                <input v-model="def.window" list="dur-window" data-testid="rule-window" />
              </FormField>
              <FormField label="평가 주기 (schedule)" :error="errOf('schedule')" hint="1분~1시간, 창은 주기의 배수">
                <input v-model="def.schedule" list="dur-schedule" data-testid="rule-schedule" />
              </FormField>
            </div>
            <datalist id="dur-window"><option v-for="d in DUR_WINDOW" :key="d" :value="d" /></datalist>
            <datalist id="dur-schedule"><option v-for="d in DUR_SCHEDULE" :key="d" :value="d" /></datalist>
            <datalist id="dur-suppress"><option v-for="d in DUR_SUPPRESS" :key="d" :value="d" /></datalist>
          </CardBox>

          <CardBox title="예외와 경보">
            <FormField label="예외 리스트 (exclude_lists) — 대상이 리스트에 있으면 히트에서 뺍니다" :error="errOf('exclude_lists')">
              <div class="checks" data-testid="rule-exclude-lists">
                <span v-if="!m.lists.length" class="muted small">리스트가 없습니다 (설정 › 리스트)</span>
                <label v-for="l in m.lists" :key="l.list_id" class="check" :title="l.description ?? ''">
                  <input type="checkbox" :checked="(def.exclude_lists ?? []).includes(l.list_id)" :data-testid="`rule-exclude-${l.list_id}`" @change="toggleExclude(l.list_id, ($event.target as HTMLInputElement).checked)" />
                  {{ l.list_id }} <span class="muted small">[{{ l.kind }}]</span>
                </label>
              </div>
            </FormField>
            <div class="form-grid">
              <FormField label="단독 경보 (alert_on_hit)" :error="errOf('alert_on_hit')" hint="켜면 순서도 없이 이 룰 히트만으로 경보를 만듭니다">
                <label class="check"><input v-model="def.alert_on_hit" type="checkbox" data-testid="rule-alert-on-hit" />히트 시 바로 경보</label>
              </FormField>
              <FormField label="등급" :error="errOf('severity')">
                <select v-model="def.severity" data-testid="rule-severity">
                  <option v-for="s in m.severities" :key="s" :value="s">{{ SEVERITY_LABEL[s] ?? s }} ({{ s }})</option>
                </select>
              </FormField>
              <FormField label="억제 시간 (suppress_for)" :error="errOf('suppress_for')" hint="같은 대상 경보를 다시 만들지 않는 시간">
                <input v-model="def.suppress_for" list="dur-suppress" placeholder="1h (기본)" data-testid="rule-suppress-for" />
              </FormField>
            </div>
            <FormField label="MITRE ATT&amp;CK 기법" :error="errOf('attack')" hint="이 룰이 보는 공격 기법. 경보와 탐지 커버리지(ATT&amp;CK 메뉴)에 쓰입니다">
              <AttackPicker :model-value="def.attack ?? []" :disabled="!canEdit" test-id="rule-attack" @update:model-value="setAttack" />
            </FormField>
            <FormField label="지정 대응방책 (MITRE D3FEND)" :error="errOf('d3fend')" hint="이 룰의 경보에서 할 대응 기법. 경보 상세의 대응방책에 지정으로 표시되고 사고처리 시스템에도 전달됩니다">
              <D3fendPicker :model-value="def.d3fend ?? []" :disabled="!canEdit" :suggest-for="def.attack ?? []" test-id="rule-d3fend" @update:model-value="setD3fend" />
            </FormField>
          </CardBox>
        </fieldset>
      </div>

      <div class="editor-right">
        <CardBox title="변환된 SQL">
          <template #actions>
            <span class="muted small" data-testid="rule-compile-state">
              {{ compiling ? '변환 중…' : compile ? (compile.ok ? '검증 통과' : `오류 ${errorCount}건`) : '' }}{{ warnCount ? ` · 경고 ${warnCount}건` : '' }}
            </span>
          </template>
          <NoticeBox v-if="!canEdit" kind="info">SQL 변환과 미리보기는 작성자(author) 이상만 쓸 수 있습니다.</NoticeBox>
          <ErrorBox :error="compileError" />
          <ul v-if="issues.length" class="issue-list" data-testid="rule-issues">
            <li v-for="(i, k) in issues" :key="k" :class="i.level"><code>{{ i.path || '(정의)' }}</code> {{ i.message }}</li>
          </ul>
          <pre class="code sql" data-testid="rule-sql">{{ compile?.sql || '-- 검증을 통과하면 SQL 이 보입니다' }}</pre>
        </CardBox>
        <CardBox title="미리보기 (저장 안 함)">
          <template #actions>
            <select v-model.number="previewHours">
              <option :value="1">최근 1시간</option>
              <option :value="6">최근 6시간</option>
              <option :value="24">최근 24시간</option>
              <option :value="72">최근 3일</option>
              <option :value="168">최근 7일</option>
            </select>
            <button class="primary" :disabled="previewBusy || !canEdit" data-testid="rule-preview" @click="runPreview">
              {{ previewBusy ? '실행 중…' : '미리보기' }}
            </button>
          </template>
          <ErrorBox :error="previewError" />
          <PreviewView v-if="preview" :p="preview" />
          <EmptyBox v-else>미리보기를 누르면 최근 구간에 실행한 결과가 나옵니다</EmptyBox>
        </CardBox>
      </div>
    </div>

    <CardBox>
      <TabBar v-model="tab" :tabs="tabs" />
      <div class="tab-body">
        <BacktestPanel v-if="tab === 'backtest' && canEdit" target-type="single_rule" :target-id="isNew ? '' : def.id" :get-definition="() => def" :disabled="isNew" />
        <NoticeBox v-if="tab === 'backtest' && isNew" kind="info">저장한 뒤 백테스트를 실행할 수 있습니다.</NoticeBox>
        <RuleVersionsTab v-if="tab === 'versions' && ruleId" :rule-id="ruleId" @load="loadVersion" />
        <RuleRunsTab v-if="tab === 'runs' && ruleId" :rule-id="ruleId" />
        <RuleHitsTab v-if="tab === 'hits' && ruleId" :rule-id="ruleId" />
      </div>
    </CardBox>

    <ChangeNoteModal v-if="saveOpen" :title="isNew ? '새 룰 저장' : '새 버전으로 저장'" :busy="saving" @close="saveOpen = false" @submit="save" />
  </div>
</template>
