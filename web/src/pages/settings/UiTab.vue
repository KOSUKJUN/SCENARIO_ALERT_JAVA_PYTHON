<script setup lang="ts">
// 화면 설정 (모든 사용자 공통, 관리자만 변경). 탐지 동작에는 영향이 없고 표시 여부만 바꾼다.
import { ref } from 'vue';
import { api } from '../../api';
import { auth } from '../../auth';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import type { UiSettings } from '../../types';

const busy = ref(false);
const error = ref<unknown>(null);
const saved = ref(false);

async function setShowIncident(on: boolean) {
  busy.value = true;
  error.value = null;
  saved.value = false;
  try {
    const ui = await api.put<UiSettings>('/ui-settings', { show_incident: on });
    if (auth.me) auth.me.ui = ui;
    saved.value = true;
  } catch (e) {
    error.value = e;
  } finally {
    busy.value = false;
  }
}
</script>
<template>
  <CardBox title="화면 표시">
    <label class="check" data-testid="ui-show-incident">
      <input
        type="checkbox"
        :checked="!!auth.me?.ui?.show_incident"
        :disabled="busy"
        @change="setShowIncident(($event.target as HTMLInputElement).checked)"
      />
      사고처리 관련 항목 표시
    </label>
    <p class="hint">
      판정(판정 등록·정탐률·오탐 상위), 사고 번호, 사고처리 시스템 전달 상태, 과거 사고와 백테스트 재현율을 보여 줍니다.
      끄면 화면에서만 숨기고 데이터와 경보 전달은 그대로 동작합니다. 모든 사용자에게 적용됩니다.
    </p>
    <ErrorBox :error="error" />
    <p v-if="saved" class="hint">저장했습니다.</p>
  </CardBox>
</template>
