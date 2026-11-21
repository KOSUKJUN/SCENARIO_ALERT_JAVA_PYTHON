<script setup lang="ts">
// 시나리오 분석 왼쪽: 시나리오 그룹 (전체 / 그룹들 / 미분류). 작성자는 추가·이름 바꾸기·삭제를 한다.
// 그룹은 화면 분류일 뿐이라 바꿔도 순서도 버전은 올라가지 않는다.
import { nextTick, ref } from 'vue';
import { api } from '../../api';
import ErrorBox from '../../components/ErrorBox.vue';
import type { GroupKey, ScenarioGroupList } from '../../types';


const props = defineProps<{ data?: ScenarioGroupList; selected: GroupKey; canEdit: boolean }>();
const emit = defineEmits<{ select: [key: GroupKey]; changed: [] }>();

const adding = ref(false);
const newName = ref('');
const newCode = ref('');
const editing = ref<number | null>(null);
const editName = ref('');
const editCode = ref('');
const error = ref<unknown>(null);
const addInput = ref<HTMLInputElement | null>(null);

function startAdd() {
  adding.value = true;
  newName.value = '';
  newCode.value = '';
  void nextTick(() => addInput.value?.focus());
}
async function add() {
  const name = newName.value.trim();
  if (!name) {
    adding.value = false;
    return;
  }
  error.value = null;
  try {
    const g = await api.post<{ group_id: number }>('/scenario-groups', { name, grp_cd: newCode.value.trim() || undefined });
    adding.value = false;
    emit('changed');
    emit('select', g.group_id);
  } catch (e) {
    error.value = e;
  }
}
function startRename(id: number, name: string, code: string) {
  editCode.value = code;
  editing.value = id;
  editName.value = name;
}
async function rename(id: number) {
  const name = editName.value.trim();
  if (!name) {
    editing.value = null;
    return;
  }
  error.value = null;
  try {
    await api.put(`/scenario-groups/${id}`, { name, grp_cd: editCode.value.trim() || undefined });
    editing.value = null;
    emit('changed');
  } catch (e) {
    error.value = e;
  }
}
async function remove(id: number, name: string, count: number) {
  const msg = count ? `그룹 "${name}" 을(를) 지웁니다. 시나리오 ${count}개는 미분류가 됩니다.` : `그룹 "${name}" 을(를) 지웁니다.`;
  if (!window.confirm(msg)) return;
  error.value = null;
  try {
    await api.del(`/scenario-groups/${id}`);
    if (props.selected === id) emit('select', 'all');
    emit('changed');
  } catch (e) {
    error.value = e;
  }
}
</script>
<template>
  <aside class="group-panel" data-testid="group-panel">
    <div class="group-head">
      <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" aria-hidden="true">
        <path d="M1.8 4.2h4.3l1.4 1.6h6.7v7.4H1.8z" />
      </svg>
      시나리오 그룹
    </div>
    <ul class="group-list">
      <li :class="['group-item', { on: selected === 'all' }]" data-testid="group-item-all" @click="emit('select', 'all')">
        <svg class="gi" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><rect x="2" y="2" width="5" height="5" rx="1" /><rect x="9" y="2" width="5" height="5" rx="1" /><rect x="2" y="9" width="5" height="5" rx="1" /><rect x="9" y="9" width="5" height="5" rx="1" /></svg>
        <span class="gname">전체</span>
        <span class="gcount">{{ data?.total ?? '' }}</span>
      </li>
      <li
        v-for="g in data?.groups ?? []"
        :key="g.group_id"
        :class="['group-item', { on: selected === g.group_id }]"
        :data-testid="`group-item-${g.group_id}`"
        @click="editing !== g.group_id && emit('select', g.group_id)"
      >
        <svg class="gi" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" aria-hidden="true"><path d="M1.8 4.2h4.3l1.4 1.6h6.7v7.4H1.8z" /></svg>
        <template v-if="editing === g.group_id">
          <input
            v-model="editName"
            class="gedit"
            maxlength="100"
            :data-testid="`group-rename-input-${g.group_id}`"
            @click.stop
            @keydown.enter="rename(g.group_id)"
            @keydown.esc="editing = null"
          />
          <input
            v-model="editCode"
            class="gedit code"
            maxlength="32"
            placeholder="코드"
            title="그룹 코드 (경보 테이블 rull_grp_cd)"
            :data-testid="`group-code-input-${g.group_id}`"
            @click.stop
            @keydown.enter="rename(g.group_id)"
            @keydown.esc="editing = null"
          />
          <button class="tiny" :data-testid="`group-rename-save-${g.group_id}`" @click.stop="rename(g.group_id)">저장</button>
        </template>
        <template v-else>
          <span class="gname" :title="`${g.name} (그룹 코드 ${g.grp_cd})`">{{ g.name }}<small class="gcode" :data-testid="`group-code-${g.group_id}`">{{ g.grp_cd }}</small></span>
          <span v-if="canEdit" class="gtools">
            <button class="tiny ghost" title="이름 바꾸기" :data-testid="`group-rename-${g.group_id}`" @click.stop="startRename(g.group_id, g.name, g.grp_cd)">✎</button>
            <button class="tiny ghost danger-text" title="그룹 삭제" :data-testid="`group-delete-${g.group_id}`" @click.stop="remove(g.group_id, g.name, g.scenario_count)">✕</button>
          </span>
          <span class="gcount">{{ g.scenario_count }}</span>
        </template>
      </li>
      <li :class="['group-item', 'muted-item', { on: selected === 'none' }]" data-testid="group-item-none" @click="emit('select', 'none')">
        <svg class="gi" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-dasharray="2 1.6" stroke-linejoin="round" aria-hidden="true"><path d="M1.8 4.2h4.3l1.4 1.6h6.7v7.4H1.8z" /></svg>
        <span class="gname">미분류</span>
        <span class="gcount">{{ data?.ungrouped ?? '' }}</span>
      </li>
    </ul>
    <ErrorBox :error="error" closable @close="error = null" />
    <div v-if="canEdit" class="group-foot">
      <template v-if="adding">
        <input
          ref="addInput"
          v-model="newName"
          maxlength="100"
          placeholder="새 그룹 이름"
          data-testid="group-add-input"
          @keydown.enter="add"
          @keydown.esc="adding = false"
        />
        <input
          v-model="newCode"
          maxlength="32"
          placeholder="그룹 코드 (비우면 자동: SG001…)"
          title="경보 테이블(alert_integrated_all)의 rull_grp_cd 로 들어갑니다. 영문·숫자·_·- 1~32자"
          data-testid="group-add-code"
          @keydown.enter="add"
          @keydown.esc="adding = false"
        />
        <button class="small primary" data-testid="group-add-save" @click="add">저장</button>
        <button class="small" @click="adding = false">취소</button>
      </template>
      <button v-else class="small primary" data-testid="group-add" @click="startAdd">+ 추가</button>
    </div>
  </aside>
</template>
