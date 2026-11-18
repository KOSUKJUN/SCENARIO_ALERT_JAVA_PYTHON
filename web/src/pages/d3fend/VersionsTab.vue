<script setup lang="ts">
// D3FEND 버전 관리 (admin): 릴리스 올리기(온톨로지 + 매핑 CSV) / 서버 디렉터리에서 가져오기, 활성 버전과 비교(지정 대응방책 영향), 활성화, 삭제.
// 폐쇄망 반입: 인터넷이 되는 PC 에서 scripts/fetch_d3fend 로 받은 <버전>/d3fend.json, d3fend-full-mappings.csv 를 올리거나
// 서버의 D3FEND_DIR(기본 data/d3fend)/<버전>/ 에 복사한다.
// 다른 서버로 옮기기: 버전마다 "내보내기" 로 패키지(zip)를 받아, 받는 서버에서 "패키지 가져오기" 로 올리거나 D3FEND_DIR 에 둔다.
import { computed, ref } from 'vue';
import { api, download, enc, upload } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import type { D3fendDiffResult, D3fendVersion } from '../../types';
import { fmtTime } from '../../util';

interface DirEntry {
  name: string; package: boolean; size: number | null; ontology: number | null; mappings: number | null;
  complete: boolean; imported: boolean; version: string | null;
}
interface ImportResult { version: string; status: string; is_active: boolean }

const admin = computed(() => has('admin'));
const vs = useAsync(() => api.get<{ versions: D3fendVersion[]; active: string | null }>('/d3fend/versions'));
const files = useAsync(() => (admin.value ? api.get<{ dir: string; files: DirEntry[] }>('/d3fend/files') : Promise.resolve(null)));
const err = ref<unknown>(null);
const msg = ref<string | null>(null);
const busy = ref(false);
const ontology = ref<File | null>(null);
const mappings = ref<File | null>(null);
const verOverride = ref('');
const pkg = ref<File | null>(null);
const pkgKey = ref(0); // 올린 뒤 파일 입력을 비운다 (같은 파일을 다시 고를 수 있게)
const diff = ref<D3fendDiffResult | null>(null);
const diffTarget = ref<D3fendVersion | null>(null);
const DIFF_KEYS: [keyof D3fendDiffResult, string][] = [['added', '추가'], ['removed', '없어짐'], ['renamed', '이름 변경'], ['moved', '전술·상위 변경']];

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
const summaryText = (r: ImportResult) =>
  `D3FEND ${r.version}: ${r.status === 'already_imported' ? '이미 가져온 파일입니다' : '가져왔습니다'}${r.is_active ? ' (활성)' : ''}`;
const doUpload = () =>
  act(async () => {
    if (!ontology.value || !mappings.value) throw new Error('두 파일을 모두 고르세요');
    const fd = new FormData();
    fd.append('ontology', ontology.value);
    fd.append('mappings', mappings.value);
    const r = await upload<ImportResult>('/d3fend/versions/import', fd, { version: verOverride.value.trim() || undefined });
    ontology.value = null;
    mappings.value = null;
    return summaryText(r);
  }, '가져왔습니다');
const doUploadPackage = () =>
  act(async () => {
    if (!pkg.value) throw new Error('패키지 파일을 고르세요');
    const fd = new FormData();
    fd.append('file', pkg.value);
    const r = await upload<ImportResult>('/d3fend/versions/import-package', fd);
    pkg.value = null;
    pkgKey.value++;
    return summaryText(r);
  }, '가져왔습니다');
const exportVersion = (v: D3fendVersion) =>
  act(async () => {
    await download(`/d3fend/versions/${enc(v.version)}/export`, `d3fend_${v.version}.zip`);
    return `D3FEND ${v.version} 패키지를 내려받았습니다. 다른 서버의 D3FEND 대응 > 버전 관리에서 올리거나 D3FEND_DIR 에 두세요`;
  }, '내려받았습니다');
const importDir = (name: string) => act(async () => summaryText(await api.post<ImportResult>('/d3fend/files/import', { name })), '가져왔습니다');
async function openDiff(v: D3fendVersion) {
  err.value = null;
  diffTarget.value = v;
  diff.value = null;
  try {
    diff.value = await api.get<D3fendDiffResult>(`/d3fend/versions/${enc(v.version)}/diff`);
  } catch (e) {
    err.value = e;
    diffTarget.value = null;
  }
}
const activate = (v: D3fendVersion) =>
  act(async () => {
    await api.post(`/d3fend/versions/${enc(v.version)}/activate`);
    diffTarget.value = null;
  }, `D3FEND ${v.version} 을 활성화했습니다. 권고 대응방책과 새 경보의 지정 대응방책 이름에 이 버전을 씁니다`);
const remove = (v: D3fendVersion) => {
  if (!window.confirm(`D3FEND ${v.version} 을 지울까요? (경보에 저장된 대응방책 정보는 그대로 남습니다)`)) return;
  void act(() => api.del(`/d3fend/versions/${enc(v.version)}`), '지웠습니다');
};
const mb = (n: number | null) => (n == null ? '없음' : `${(n / 1024 / 1024).toFixed(1)} MB`);
</script>
<template>
  <div>
    <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
    <ErrorBox :error="err" closable @close="err = null" />
    <CardBox title="가져온 버전">
      <LoadingBox v-if="vs.loading.value" />
      <ErrorBox :error="vs.error.value" />
      <table v-if="vs.data.value" class="table" data-testid="d3fend-versions">
        <thead>
          <tr><th>버전</th><th>발표</th><th class="num">전술</th><th class="num">방어 기법</th><th class="num">ATT&amp;CK 매핑</th>
            <th class="num">매핑된 ATT&amp;CK</th><th class="num">완화 연결</th><th>가져온 사람·시각</th><th>출처 (sha256)</th><th /></tr>
        </thead>
        <tbody>
          <tr v-for="v in vs.data.value.versions" :key="v.version" :data-testid="`d3fend-version-${v.version}`">
            <td><strong>{{ v.version }}</strong> <span v-if="v.is_active" class="chip ok-chip">활성</span></td>
            <td class="small">{{ fmtTime(v.released_at) }}</td>
            <td class="num">{{ v.counts.tactic }}</td>
            <td class="num">{{ v.counts.technique }}</td>
            <td class="num">{{ v.counts.mapping }}</td>
            <td class="num">{{ v.counts.attack_technique }}</td>
            <td class="num">{{ v.counts.mitigation_link }}</td>
            <td class="small">{{ v.imported_by }} {{ fmtTime(v.imported_at) }}</td>
            <td class="small" :title="v.source_sha256">{{ v.source_files.source }}<br /><span class="mono muted">{{ v.source_sha256.slice(0, 12) }}…</span></td>
            <td class="nowrap">
              <button v-if="admin" class="small" :disabled="busy" :data-testid="`d3fend-export-${v.version}`"
                title="다른 서버로 옮길 패키지(zip) 내려받기" @click="exportVersion(v)">내보내기</button>
              <button v-if="!v.is_active" class="small" :disabled="busy" :data-testid="`d3fend-diff-${v.version}`" @click="openDiff(v)">비교·활성화</button>
              <button v-if="admin && !v.is_active" class="small danger" :disabled="busy" :data-testid="`d3fend-delete-${v.version}`" @click="remove(v)">삭제</button>
            </td>
          </tr>
          <tr v-if="!vs.data.value.versions.length"><td colspan="10" class="muted">가져온 버전이 없습니다. 아래에서 릴리스를 가져오세요.</td></tr>
        </tbody>
      </table>
    </CardBox>

    <div v-if="admin" class="grid-2">
      <CardBox title="릴리스 올리기">
        <p class="muted small">
          D3FEND 공식 릴리스의 두 파일: 온톨로지 <span class="mono">d3fend.json</span> (JSON-LD) 과 ATT&amp;CK 매핑
          <span class="mono">d3fend-full-mappings.csv</span>. 버전은 온톨로지에서 읽습니다. 같은 파일은 다시 넣지 않고, 같은 버전의 다른 파일은 거부합니다.
          활성 버전이 없으면 바로 활성화합니다.
        </p>
        <div class="form-row">
          <label class="small">온톨로지 <input type="file" accept=".json,application/json,application/ld+json" data-testid="d3fend-upload-ontology"
            @change="ontology = ($event.target as HTMLInputElement).files?.[0] ?? null" /></label>
          <label class="small">매핑 CSV <input type="file" accept=".csv,text/csv" data-testid="d3fend-upload-mappings"
            @change="mappings = ($event.target as HTMLInputElement).files?.[0] ?? null" /></label>
        </div>
        <div class="form-row">
          <input v-model="verOverride" placeholder="버전 (온톨로지에 없을 때만)" style="width: 200px" />
          <button class="primary" :disabled="busy || !ontology || !mappings" data-testid="d3fend-upload" @click="doUpload">가져오기</button>
        </div>
        <h4>다른 서버에서 내보낸 패키지</h4>
        <p class="muted small">
          다른 서버의 버전 목록에서 "내보내기" 로 받은 <span class="mono">d3fend_&lt;버전&gt;.zip</span>.
          원본 두 파일의 sha256 이 그대로 들어 있어, 같은 원본으로 이미 가져온 버전은 다시 넣지 않습니다.
        </p>
        <div class="form-row">
          <input :key="pkgKey" type="file" accept=".zip,application/zip" data-testid="d3fend-package-file" @change="pkg = ($event.target as HTMLInputElement).files?.[0] ?? null" />
          <button class="primary" :disabled="busy || !pkg" data-testid="d3fend-package-upload" @click="doUploadPackage">패키지 가져오기</button>
        </div>
        <p v-if="busy" class="muted small">처리 중… (매핑 CSV 는 십여 MB 라 수십 초 걸릴 수 있습니다)</p>
      </CardBox>
      <CardBox title="서버 디렉터리의 릴리스">
        <p class="muted small">
          서버의 <span class="mono">{{ files.data.value?.dir }}</span>/&lt;버전&gt;/ 에 복사한 두 파일, 또는 그 디렉터리에 둔 내보내기 패키지(.zip).
          init 때 새 버전을 자동으로 가져옵니다.
        </p>
        <table class="table">
          <tbody>
            <tr v-for="f in files.data.value?.files ?? []" :key="f.name">
              <td class="mono small">{{ f.package ? f.name : `${f.name}/` }} <span v-if="f.package" class="chip">패키지</span></td>
              <td class="small">{{ f.package ? mb(f.size) : `온톨로지 ${mb(f.ontology)} · 매핑 ${mb(f.mappings)}` }}</td>
              <td>
                <span v-if="f.imported" class="muted small">가져옴 ({{ f.version }})</span>
                <span v-else-if="!f.complete" class="warn-text small">{{ f.package ? 'D3FEND 패키지 아님' : '파일 부족' }}</span>
                <button v-else class="small" :disabled="busy" :data-testid="`d3fend-import-${f.name}`" @click="importDir(f.name)">가져오기</button>
              </td>
            </tr>
            <tr v-if="!files.data.value?.files.length"><td class="muted small">릴리스 없음</td></tr>
          </tbody>
        </table>
      </CardBox>
    </div>

    <ModalDialog v-if="diffTarget" :title="`D3FEND ${diffTarget.version} 비교`" wide @close="diffTarget = null">
      <LoadingBox v-if="!diff" />
      <div v-else data-testid="d3fend-diff">
        <p>
          활성 <strong>{{ diff.from ?? '(없음)' }}</strong> → <strong>{{ diff.to }}</strong>
          <span v-if="diff.summary" class="small">
            · <template v-for="[k, label] in DIFF_KEYS" :key="k">{{ label }} {{ diff.summary[k] ?? 0 }} · </template>
            정의 갱신 {{ diff.summary.updated ?? 0 }} · ATT&amp;CK 매핑 +{{ diff.summary.mappings_added ?? 0 }} / -{{ diff.summary.mappings_removed ?? 0 }}
          </span>
        </p>
        <h4>지정 대응방책에 미치는 영향</h4>
        <NoticeBox v-if="!diff.impact.length" kind="ok">영향 없음: 지정한 대응 기법이 모두 {{ diff.to }} 에 그대로 있습니다.</NoticeBox>
        <table v-else class="table" data-testid="d3fend-impact">
          <thead><tr><th>대응 기법</th><th>상태</th><th>지정한 곳</th></tr></thead>
          <tbody>
            <tr v-for="i in diff.impact" :key="i.technique">
              <td class="mono">{{ i.technique }}</td>
              <td class="err-text">없음</td>
              <td class="small">
                <div v-for="r in i.refs" :key="`${r.kind}${r.id}${r.detail}`">
                  <RouterLink :to="r.kind === 'rule' ? `/single-rules/${r.id}` : `/scenarios/${r.id}`">{{ r.id }}</RouterLink>
                  {{ r.name }} <StatusBadge :status="r.status" /> <span class="muted">{{ r.detail ?? '' }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-if="diff.impact.length" class="warn-text small">활성화해도 탐지·경보는 그대로 동작합니다. 위 룰·순서도는 다음에 저장할 때 대응 기법을 고쳐야 합니다.</p>
        <template v-for="[k, label] in DIFF_KEYS" :key="k">
          <details v-if="Array.isArray(diff[k]) && (diff[k] as unknown[]).length">
            <summary>{{ label }} ({{ (diff[k] as unknown[]).length }})</summary>
            <ul class="small">
              <li v-for="x in (diff[k] as Record<string, unknown>[])" :key="String(x.id)">
                <span class="mono">{{ x.id }}</span> {{ x.name ?? '' }}
                <template v-if="x.from !== undefined"> ({{ x.from }} → {{ x.to }})</template>
              </li>
            </ul>
          </details>
        </template>
      </div>
      <template #footer>
        <button @click="diffTarget = null">닫기</button>
        <button v-if="admin && diff" class="primary" :disabled="busy" data-testid="d3fend-activate" @click="activate(diffTarget)">이 버전 활성화</button>
      </template>
    </ModalDialog>
  </div>
</template>
<style scoped>
.ok-chip { border-color: var(--ok); color: var(--ok); }
.nowrap { white-space: nowrap; }
details { margin-top: 8px; }
</style>
