import { onScopeDispose, ref, shallowRef, watch, type Ref, type ShallowRef, type WatchSource } from 'vue';
import { api } from './api';
import type { MetaFields } from './types';

export interface AsyncState<T> {
  data: ShallowRef<T | undefined>;
  error: Ref<unknown>;
  loading: Ref<boolean>;
  reload: () => void;
}

/** 비동기 조회. sources 가 바뀌면 다시 부른다 (늦게 온 이전 응답은 버린다). */
export function useAsync<T>(fn: () => Promise<T>, sources: WatchSource[] = []): AsyncState<T> {
  const data = shallowRef<T | undefined>(undefined);
  const error = ref<unknown>(null);
  const loading = ref(true);
  let seq = 0;
  const run = () => {
    const my = ++seq;
    loading.value = true;
    error.value = null;
    fn()
      .then((d) => {
        if (my === seq) data.value = d;
      })
      .catch((e: unknown) => {
        if (my === seq) error.value = e;
      })
      .finally(() => {
        if (my === seq) loading.value = false;
      });
  };
  if (sources.length) watch(sources, run, { immediate: true });
  else run();
  return { data, error, loading, reload: run };
}

let metaPromise: Promise<MetaFields> | null = null;

/** GET /meta/fields (필드·연산자·리스트·태그). 화면에 하드코딩하지 않고 여기서 받은 것만 쓴다. */
export function loadMeta(force = false): Promise<MetaFields> {
  if (!metaPromise || force) {
    metaPromise = api.get<MetaFields>('/meta/fields').catch((e: unknown) => {
      metaPromise = null;
      throw e;
    });
  }
  return metaPromise;
}

export function useMeta(): AsyncState<MetaFields> {
  return useAsync(() => loadMeta());
}

/** source 가 delay ms 동안 바뀌지 않으면 fn 을 부른다. */
export function watchDebounced<T>(source: WatchSource<T>, fn: (v: T) => void, delay: number): void {
  let t: ReturnType<typeof setTimeout> | undefined;
  watch(
    source,
    (v) => {
      if (t) clearTimeout(t);
      t = setTimeout(() => fn(v), delay);
    },
    { immediate: true },
  );
  onScopeDispose(() => t && clearTimeout(t));
}
