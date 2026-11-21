<script setup lang="ts">
// 이벤트 탐지모듈 관리 새 창 (시나리오 분석의 [이벤트 탐지모듈 관리]). 메뉴·상단 막대 없이 목록만 둔다.
// 모듈 이름이나 [+ 새 이벤트 탐지모듈] 을 누르면 이 창의 오른쪽 사이드 패널에서 상세를 보고 고친다
// (백테스트·버전·실행·히트 탭 포함). 시나리오 링크와 Snort 가져오기는 원래 창에서 연다.
import { computed, onBeforeUnmount, ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../../api';
import { useAsync } from '../../composables';
import ModuleIcon from '../../components/ModuleIcon.vue';
import type { RuleSummary, ScenarioSummary } from '../../types';
import RuleEditorPage from '../single-rules/RuleEditorPage.vue';
import DetectionList from './DetectionList.vue';

const router = useRouter();
const scenarios = useAsync(() => api.get<ScenarioSummary[]>('/scenarios'));
const rules = useAsync(() => api.get<RuleSummary[]>('/single-rules'));
const scenarioNames = computed<Record<string, string>>(() =>
  Object.fromEntries((scenarios.data.value ?? []).map((s) => [s.scenario_id, s.name])),
);
document.title = '이벤트 탐지모듈 관리 · 시나리오 탐지';

// ---- 사이드 패널
const panel = ref<{ key: number; ruleId?: string } | null>(null);
const panelDirty = ref(false);
let seq = 0;
function okToLeave(): boolean {
  return !panelDirty.value || window.confirm('이벤트 탐지모듈에 저장하지 않은 변경이 있습니다. 닫을까요?');
}
function openPanel(ruleId?: string) {
  if (panel.value && !okToLeave()) return;
  panelDirty.value = false;
  panel.value = { key: ++seq, ruleId };
}
function closePanel() {
  if (!okToLeave()) return;
  panel.value = null;
  panelDirty.value = false;
}
function onSaved() {
  rules.reload();
  scenarios.reload();
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && panel.value) closePanel();
}
window.addEventListener('keydown', onKey);
onBeforeUnmount(() => window.removeEventListener('keydown', onKey));

/** 목록 안의 링크: 모듈 상세·새 모듈은 이 창의 패널로, 그 밖(시나리오, Snort 가져오기)은 원래 창으로 */
function onClick(e: MouseEvent) {
  const a = (e.target as HTMLElement).closest('a');
  const href = a?.getAttribute('href');
  if (!href || !href.startsWith('/') || e.ctrlKey || e.metaKey || e.shiftKey) return;
  e.preventDefault();
  e.stopPropagation(); // RouterLink 가 이 창을 다른 화면으로 옮기지 않게 (캡처 단계에서 막는다)
  const m = /^\/scenarios\/detections\/([^/?#]+)$/.exec(href);
  if (m && m[1] !== 'import-snort') {
    openPanel(m[1] === 'new' ? undefined : decodeURIComponent(m[1]));
    return;
  }
  const opener = window.opener as Window | null;
  if (opener && !opener.closed) {
    opener.location.href = href;
    opener.focus();
  } else {
    void router.push(href);
  }
}
const openId = computed(() => panel.value?.ruleId ?? '');
</script>
<template>
  <div :class="['popup-page', { 'with-panel': panel }]" data-testid="modules-popup-page">
    <div class="popup-main" @click.capture="onClick">
      <div class="module-panel-head">
        <h2 class="mod-title"><ModuleIcon :size="20" /> 이벤트 탐지모듈 관리 <span class="seg-count">{{ rules.data.value?.length ?? '' }}</span></h2>
        <span class="spacer" />
        <button class="small" data-testid="modules-popup-reload" @click="rules.reload(), scenarios.reload()">새로고침</button>
      </div>
      <DetectionList :state="rules" :scenario-names="scenarioNames" :highlight="openId" />
    </div>
    <aside v-if="panel" class="popup-side" data-testid="module-side-panel">
      <RuleEditorPage
        :key="panel.key"
        :rule-id="panel.ruleId"
        embedded
        with-tabs
        @saved="onSaved"
        @close="closePanel"
        @dirty="(v) => (panelDirty = v)"
      />
    </aside>
  </div>
</template>
