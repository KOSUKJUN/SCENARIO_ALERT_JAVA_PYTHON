<script setup lang="ts">
// ATT&CK 버전 관리 (admin): 번들 올리기 / 서버 디렉터리에서 가져오기, 활성 버전과 비교(룰·순서도 영향), 활성화, 삭제.
// 폐쇄망 반입: 인터넷이 되는 PC 에서 scripts/fetch_attack 로 받은 enterprise-attack-<버전>.json 을 올리거나
// 서버의 ATTACK_DIR(기본 data/attack)에 복사한다.
import { computed, ref } from 'vue';
import { api, enc, upload } from '../../api';
import { STATUS_KO } from '../../attack';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import type { AttackDiffResult, AttackVersion } from '../../types';
import { fmtTime } from '../../util';

const admin = computed(() => has('admin'));
const vs = useAsync(() => api.get<{ versions: AttackVersion[]; active: Record<string, string> }>('/attack/versions'));
const files = useAsync(() =>
  admin.value ? api.get<{ dir: string; files: { file: string; size: number; imported: boolean; version: string | null }[] }>('/attack/files')
    : Promise.resolve(null));
const err = ref<unknown>(null);
const msg = ref<string | null>(null);
const busy = ref(false);
const file = ref<File | null>(null);
const verOverride = ref('');
const diff = ref<AttackDiffResult | null>(null);
const diffTarget = ref<AttackVersion | null>(null);
const DIFF_KEYS: [keyof AttackDiffResult, string][] = [
  ['added', '추가'], ['removed', '없어짐'], ['revoked', '폐기'], ['deprecated', '사용 중단'], ['renamed', '이름 변경'],
  ['tactics_changed', '전술 변경'],
];

/** fn 이 문장을 돌려주면 그것을, 아니면 ok 를 알림으로 보여 준다. */
async function act(fn: () => Promise<unknown>, ok: string) {
  busy.value = true;
  err.value = null;
  msg.value = null;
  try {
    const r = await fn();
    msg.value = typeof r === 'string' ? r : ok;
    vs.reload();
    files.reload();
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = false;
  }
}
function summaryText(r: { domain: string; version: string; status: string; is_active: boolean }) {
  const st = r.status === 'already_imported' ? '이미 가져온 파일입니다' : '가져왔습니다';
  return `${r.domain} ${r.version}: ${st}${r.is_active ? ' (활성)' : ''}`;
}
const doUpload = () =>
  act(async () => {
    if (!file.value) throw new Error('파일을 고르세요');
    const fd = new FormData();
    fd.append('file', file.value);
    const r = await upload<{ domain: string; version: string; status: string; is_active: boolean }>(
      '/attack/versions/import', fd, { version: verOverride.value.trim() || undefined });
    file.value = null;
    return summaryText(r);
  }, '가져왔습니다');
const importFile = (name: string) =>
  act(async () => {
    const r = await api.post<{ domain: string; version: string; status: string; is_active: boolean }>('/attack/files/import', { file: name });
    return summaryText(r);
  }, '가져왔습니다');
async function openDiff(v: AttackVersion) {
  err.value = null;
  diffTarget.value = v;
  diff.value = null;
  try {
    diff.value = await api.get<AttackDiffResult>(`/attack/versions/${enc(v.domain)}/${enc(v.version)}/diff`);
  } catch (e) {
    err.value = e;
    diffTarget.value = null;
  }
}
const activate = (v: AttackVersion) =>
  act(async () => {
    await api.post(`/attack/versions/${enc(v.domain)}/${enc(v.version)}/activate`);
    diffTarget.value = null;
  }, `${v.domain} ${v.version} 을 활성화했습니다. 새 경보부터 이 버전의 기법 정보를 씁니다`);
const remove = (v: AttackVersion) => {
  if (!window.confirm(`${v.domain} ${v.version} 을 지울까요? (경보에 저장된 기법 정보는 그대로 남습니다)`)) return;
  void act(() => api.del(`/attack/versions/${enc(v.domain)}/${enc(v.version)}`), '지웠습니다');
};
const mb = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;
</script>
<template>
  <div>
    <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
    <ErrorBox :error="err" closable @close="err = null" />
    <CardBox title="가져온 버전">
      <LoadingBox v-if="vs.loading.value" />
      <ErrorBox :error="vs.error.value" />
      <table v-if="vs.data.value" class="table" data-testid="attack-versions">
        <thead>
          <tr><th>도메인</th><th>버전</th><th>발표</th><th class="num">전술</th><th class="num">기법</th><th class="num">하위</th>
            <th class="num">완화</th><th class="num">그룹</th><th class="num">SW</th><th>가져온 사람·시각</th><th>파일 (sha256)</th><th /></tr>
        </thead>
        <tbody>
          <tr v-for="v in vs.data.value.versions" :key="`${v.domain}|${v.version}`" :data-testid="`attack-version-${v.version}`">
            <td>{{ v.domain }}</td>
            <td><strong>{{ v.version }}</strong> <span v-if="v.is_active" class="chip ok-chip">활성</span></td>
            <td class="small">{{ fmtTime(v.released_at) }}</td>
            <td class="num">{{ v.counts.tactic }}</td>
            <td class="num">{{ (v.counts.technique ?? 0) - (v.counts.subtechnique ?? 0) }}</td>
            <td class="num">{{ v.counts.subtechnique }}</td>
            <td class="num">{{ v.counts.mitigation }}</td>
            <td class="num">{{ v.counts.group }}</td>
            <td class="num">{{ v.counts.software }}</td>
            <td class="small">{{ v.imported_by }} {{ fmtTime(v.imported_at) }}</td>
            <td class="small" :title="v.source_sha256">{{ v.source_file }}<br /><span class="mono muted">{{ v.source_sha256.slice(0, 12) }}…</span></td>
            <td class="nowrap">
              <button v-if="!v.is_active" class="small" :disabled="busy" :data-testid="`attack-diff-${v.version}`" @click="openDiff(v)">비교·활성화</button>
              <button v-if="admin && !v.is_active" class="small danger" :disabled="busy" :data-testid="`attack-delete-${v.version}`" @click="remove(v)">삭제</button>
            </td>
          </tr>
          <tr v-if="!vs.data.value.versions.length"><td colspan="12" class="muted">가져온 버전이 없습니다. 아래에서 번들을 가져오세요.</td></tr>
        </tbody>
      </table>
    </CardBox>

    <div v-if="admin" class="grid-2">
      <CardBox title="번들 올리기">
        <p class="muted small">
          MITRE 공식 STIX 2.1 번들 (attack-stix-data 의 enterprise-attack-&lt;버전&gt;.json, ics-/mobile- 도 가능).
          같은 파일은 다시 넣지 않고, 같은 버전의 다른 파일은 거부합니다. 도메인에 활성 버전이 없으면 바로 활성화합니다.
        </p>
        <div class="form-row">
          <input type="file" accept=".json,application/json" data-testid="attack-upload-file" @change="file = ($event.target as HTMLInputElement).files?.[0] ?? null" />
          <input v-model="verOverride" placeholder="버전 (번들에 없을 때만)" style="width: 170px" />
          <button class="primary" :disabled="busy || !file" data-testid="attack-upload" @click="doUpload">가져오기</button>
        </div>
        <p v-if="busy" class="muted small">가져오는 중… (enterprise 번들은 수십 초 걸립니다)</p>
      </CardBox>
      <CardBox title="서버 디렉터리의 파일">
        <p class="muted small">서버의 <span class="mono">{{ files.data.value?.dir }}</span> 에 복사한 번들. init 때 새 파일을 자동으로 가져옵니다.</p>
        <table class="table">
          <tbody>
            <tr v-for="f in files.data.value?.files ?? []" :key="f.file">
              <td class="mono small">{{ f.file }}</td>
              <td class="num small">{{ mb(f.size) }}</td>
              <td>
                <span v-if="f.imported" class="muted small">가져옴 ({{ f.version }})</span>
                <button v-else class="small" :disabled="busy" :data-testid="`attack-import-${f.file}`" @click="importFile(f.file)">가져오기</button>
              </td>
            </tr>
            <tr v-if="!files.data.value?.files.length"><td class="muted small">파일 없음</td></tr>
          </tbody>
        </table>
      </CardBox>
    </div>

    <ModalDialog v-if="diffTarget" :title="`${diffTarget.domain} ${diffTarget.version} 비교`" wide @close="diffTarget = null">
      <LoadingBox v-if="!diff" />
      <div v-else data-testid="attack-diff">
        <p>
          활성 <strong>{{ diff.from ?? '(없음)' }}</strong> → <strong>{{ diff.to }}</strong>
          <span v-if="diff.summary" class="small">
            · <template v-for="[k, label] in DIFF_KEYS" :key="k">{{ label }} {{ diff.summary[k] ?? 0 }} · </template>설명 갱신 {{ diff.summary.updated ?? 0 }}
          </span>
        </p>
        <h4>현재 단일룰·순서도에 미치는 영향</h4>
        <NoticeBox v-if="!diff.impact.length" kind="ok">영향 없음: 참조하는 기법이 모두 {{ diff.to }} 에 그대로 있습니다.</NoticeBox>
        <table v-else class="table" data-testid="attack-impact">
          <thead><tr><th>기법</th><th>상태</th><th>대체</th><th>참조하는 곳</th></tr></thead>
          <tbody>
            <tr v-for="i in diff.impact" :key="i.technique">
              <td class="mono">{{ i.technique }}</td>
              <td><span :class="i.status === 'deprecated' ? 'warn-text' : 'err-text'">{{ STATUS_KO[i.status] }}</span></td>
              <td>{{ i.replacement ?? '-' }}</td>
              <td class="small">
                <div v-for="r in i.refs" :key="`${r.kind}${r.id}${r.detail}`">
                  <RouterLink :to="r.kind === 'rule' ? `/single-rules/${r.id}` : `/scenarios/${r.id}`">{{ r.id }}</RouterLink>
                  {{ r.name }} <StatusBadge :status="r.status" /> <span class="muted">{{ r.detail ?? '' }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-if="diff.impact.length" class="warn-text small">
          활성화해도 탐지는 그대로 동작합니다. 다만 위 룰·순서도는 다음에 저장할 때 기법을 고쳐야 합니다 (없는·폐기 기법은 저장 오류).
        </p>
        <template v-for="[k, label] in DIFF_KEYS" :key="k">
          <details v-if="Array.isArray(diff[k]) && (diff[k] as unknown[]).length">
            <summary>{{ label }} ({{ (diff[k] as unknown[]).length }})</summary>
            <ul class="small">
              <li v-for="x in (diff[k] as Record<string, unknown>[])" :key="String(x.id)">
                <span class="mono">{{ x.id }}</span> {{ x.name ?? `${x.from} → ${x.to}` }}
                <template v-if="x.revoked_by"> → {{ x.revoked_by }} {{ x.revoked_by_name }}</template>
                <template v-if="k === 'tactics_changed'"> ({{ (x.from as string[]).join(', ') }} → {{ (x.to as string[]).join(', ') }})</template>
              </li>
            </ul>
          </details>
        </template>
      </div>
      <template #footer>
        <button @click="diffTarget = null">닫기</button>
        <button v-if="admin && diff" class="primary" :disabled="busy" data-testid="attack-activate" @click="activate(diffTarget)">이 버전 활성화</button>
      </template>
    </ModalDialog>
  </div>
</template>
<style scoped>
.ok-chip { border-color: var(--ok); color: var(--ok); }
.nowrap { white-space: nowrap; }
details { margin-top: 8px; }
</style>
