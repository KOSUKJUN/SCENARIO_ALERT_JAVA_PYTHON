<script setup lang="ts">
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { has, showIncident } from '../../auth';
import TabBar from '../../components/TabBar.vue';
import AssetsTab from './AssetsTab.vue';
import AuditTab from './AuditTab.vue';
import IncidentsTab from './IncidentsTab.vue';
import ListsTab from './ListsTab.vue';
import OrgsTab from './OrgsTab.vue';
import RuleParamsTab from './RuleParamsTab.vue';
import UiTab from './UiTab.vue';
import UsersTab from './UsersTab.vue';

const props = defineProps<{ tab?: string }>();
const router = useRouter();
const active = computed(() => props.tab || 'orgs');
const tabs = computed(() => [
  { key: 'orgs', label: '기관' },
  { key: 'lists', label: '리스트·시그니처 분류' },
  { key: 'assets', label: '자산·태그' },
  { key: 'rule-params', label: '기관별 임계치' },
  { key: 'incidents', label: '과거 사고', hidden: !showIncident() },
  { key: 'users', label: '사용자', hidden: !has('admin') },
  { key: 'ui', label: '화면', hidden: !has('admin') },
  { key: 'audit', label: '감사 로그', hidden: !has('admin') },
]);
</script>
<template>
  <div class="page">
    <div class="page-head"><h2>설정</h2></div>
    <TabBar :model-value="active" :tabs="tabs" @update:model-value="(k) => router.push(`/settings/${k}`)" />
    <div class="tab-body">
      <OrgsTab v-if="active === 'orgs'" />
      <ListsTab v-else-if="active === 'lists'" />
      <AssetsTab v-else-if="active === 'assets'" />
      <RuleParamsTab v-else-if="active === 'rule-params'" />
      <IncidentsTab v-else-if="active === 'incidents' && showIncident()" />
      <UiTab v-else-if="active === 'ui' && has('admin')" />
      <UsersTab v-else-if="active === 'users' && has('admin')" />
      <AuditTab v-else-if="active === 'audit' && has('admin')" />
    </div>
  </div>
</template>
