<script setup lang="ts">
// 대응방책 연계 현황: 단일룰과 순서도 경보 노드마다 ATT&CK 기법과 지정 대응방책(D3FEND).
// ATT&CK 기법은 있는데 사고 대응(격리·퇴출·복구) 대응방책이 없는 곳을 찾아 보완하는 화면이다.
import { computed, ref } from 'vue';
import { api } from '../../api';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import CountermeasuresPanel from '../../components/CountermeasuresPanel.vue';
import D3fendTechniqueModal from '../../components/D3fendTechniqueModal.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import { TACTIC_KO } from '../../d3fend';
import type { D3fendLinkItem, D3fendLinks } from '../../types';

const r = useAsync(() => api.get<D3fendLinks>('/d3fend/links'));
const filter = ref<'all' | 'no-response' | 'none'>('all');
const q = ref('');
const detail = ref<string | null>(null);
const panel = ref<D3fendLinkItem | null>(null);
const items = computed(() =>
  (r.data.value?.items ?? []).filter((i) => {
    if (filter.value === 'no-response' && (i.response || !i.attack.length)) return false;
    if (filter.value === 'none' && i.d3fend.length) return false;
    const s = q.value.trim().toLowerCase();
    return !s || `${i.id} ${i.name} ${i.title ?? ''} ${i.attack.join(' ')} ${i.d3fend.map((d) => d.id).join(' ')}`.toLowerCase().includes(s);
  }),
);
</script>
<template>
  <div>
    <LoadingBox v-if="r.loading.value" />
    <ErrorBox :error="r.error.value" />
    <template v-if="r.data.value">
      <p class="small" data-testid="d3fend-links-summary">
        단일룰·순서도 경보 노드 {{ r.data.value.summary.total }}곳 · ATT&amp;CK 기법 있음 {{ r.data.value.summary.with_attack }} ·
        대응방책 지정 {{ r.data.value.summary.with_d3fend }} · 사고 대응(격리·퇴출·복구) 지정 {{ r.data.value.summary.with_response }}
        <span v-if="!r.data.value.version" class="warn-text">· 활성 D3FEND 버전이 없어 이름을 표시하지 못합니다</span>
      </p>
      <div class="form-row">
        <select v-model="filter" data-testid="d3fend-links-filter">
          <option value="all">전체</option>
          <option value="no-response">ATT&amp;CK 기법은 있는데 사고 대응 지정이 없는 곳</option>
          <option value="none">대응방책 지정이 없는 곳</option>
        </select>
        <input v-model="q" placeholder="거르기 (ID·이름·기법)" />
      </div>
      <CardBox>
        <table class="table" data-testid="d3fend-links">
          <thead>
            <tr><th>출처</th><th>등급</th><th>ATT&amp;CK</th><th>지정 대응방책</th><th class="num">D3FEND 매핑</th><th /></tr>
          </thead>
          <tbody>
            <tr v-for="i in items" :key="`${i.kind}${i.id}${i.node ?? ''}`" :data-testid="`d3fend-link-${i.id}${i.node ? '-' + i.node : ''}`">
              <td>
                {{ i.kind === 'rule' ? '단일룰' : '순서도' }}
                <RouterLink :to="i.kind === 'rule' ? `/single-rules/${i.id}` : `/scenarios/${i.id}`">{{ i.id }}</RouterLink>
                <span v-if="i.node" class="muted small"> 경보 노드 {{ i.node }}</span>
                <StatusBadge :status="i.status" />
                <div class="small">{{ i.title ?? i.name }}</div>
              </td>
              <td><SeverityBadge v-if="i.severity" :severity="i.severity" /></td>
              <td class="small mono">{{ i.attack.join(', ') || '-' }}</td>
              <td>
                <span class="chips">
                  <a v-for="d in i.d3fend" :key="d.id" href="#" class="chip small" :title="d.name ?? ''" @click.prevent="detail = d.id">
                    {{ d.id }} <span class="muted">{{ d.tactic ? TACTIC_KO[d.tactic] ?? d.tactic : '없음' }}</span>
                  </a>
                </span>
                <span v-if="!i.d3fend.length" class="muted small">-</span>
                <span v-else-if="!i.response && i.attack.length" class="warn-text small"> 사고 대응 없음</span>
              </td>
              <td class="num">{{ i.mapped }}</td>
              <td><button v-if="i.attack.length" class="small" :data-testid="`d3fend-link-open-${i.id}${i.node ? '-' + i.node : ''}`" @click="panel = i">권고 보기</button></td>
            </tr>
            <tr v-if="!items.length"><td colspan="6" class="muted">해당 없음</td></tr>
          </tbody>
        </table>
      </CardBox>
    </template>
    <D3fendTechniqueModal v-if="detail" :id="detail" @close="detail = null" />
    <ModalDialog v-if="panel" :title="`대응방책 권고: ${panel.id}${panel.node ? ' ' + panel.node : ''}`" wide @close="panel = null">
      <p class="small">ATT&amp;CK {{ panel.attack.join(', ') }} 기준. 지정하려면 {{ panel.kind === 'rule' ? '단일룰' : '순서도 경보 노드' }} 편집 화면의 "지정 대응방책" 에서 추가합니다.</p>
      <CountermeasuresPanel :attack="panel.attack" :designated="panel.d3fend.map((d) => d.id)" />
    </ModalDialog>
  </div>
</template>
