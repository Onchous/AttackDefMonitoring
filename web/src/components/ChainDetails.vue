<template>
  <div>
    <div class="d-flex align-center ga-2 px-4 py-1">
      <span class="text-caption"
        >Цепочка · {{ data.length || "…" }} сессий</span
      >
      <v-progress-circular v-if="loading" indeterminate size="16" width="2" />
      <v-btn
        v-if="!expanded"
        size="small"
        variant="text"
        @click="router.replace({ query: { ...route.query, chain: '1' } })"
        >Все запросы и ответы</v-btn
      >
      <v-spacer />
      <v-btn
        size="small"
        variant="tonal"
        :disabled="loading || !data.length"
        @click="copy"
        >Скопировать kill chain</v-btn
      >
      <v-btn
        size="small"
        variant="text"
        :disabled="loading || !data.length"
        @click="preview"
        >Python</v-btn
      >
      <v-btn
        size="small"
        variant="text"
        :disabled="loading || !data.length"
        @click="download"
        >.py</v-btn
      >
    </div>
    <v-alert v-if="error" type="error" density="compact" class="mx-4 my-1">{{
      error
    }}</v-alert>
    <template v-if="expanded">
      <div v-for="item in data" :key="item.Stream.ID" class="chain-step">
        <div class="text-caption px-4 py-1">
          #{{ item.Stream.ID }} · {{ item.Stream.Client.Host }}:{{
            item.Stream.Client.Port
          }}
          → {{ item.Stream.Server.Host }}:{{ item.Stream.Server.Port }}
        </div>
        <StreamData
          :data="item.Data"
          viewmode="cards"
          :presentation="presentation"
          :highlight-matches="highlightMatches"
          :url-decode="urlDecode"
        />
      </div>
    </template>
    <v-dialog v-model="dialog" max-width="1000">
      <v-card title="Kill chain · Python requests">
        <v-card-text>
          <p class="text-caption mb-2">
            Запуск: python3 replay-chain.py IP · Ответы выводятся через
            print(r.text, flush=True).
          </p>
          <v-textarea
            :model-value="code"
            readonly
            rows="20"
            class="replay-code"
          />
        </v-card-text>
        <v-card-actions
          ><v-btn @click="copy">Скопировать</v-btn
          ><v-btn @click="download">Скачать .py</v-btn><v-spacer /><v-btn
            @click="dialog = false"
            >Закрыть</v-btn
          ></v-card-actions
        >
      </v-card>
    </v-dialog>
    <textarea
      ref="copyArea"
      :value="code"
      readonly
      style="position: fixed; left: -10000px"
    />
  </div>
</template>
<script setup lang="ts">
import { ref, watch, onBeforeUnmount } from "vue";
import { useRoute, useRouter } from "vue-router";
import type { StreamData as StreamPayload, DataRegexes } from "@/apiClient";
import { loadChain } from "@/lib/chainLoader";
import { pythonReplay } from "@/lib/chains";
import StreamData from "./StreamData.vue";
import { EventBus } from "./EventBus";
const props = defineProps<{
  stream: StreamPayload;
  expanded: boolean;
  presentation: string;
  highlightMatches?: DataRegexes;
  urlDecode: boolean;
}>();
const route = useRoute();
const router = useRouter();
const data = ref<StreamPayload[]>([]);
const loading = ref(false);
const error = ref("");
const code = ref("");
const dialog = ref(false);
const copyArea = ref<HTMLTextAreaElement | null>(null);
let generation = 0;
onBeforeUnmount(() => {
  generation++;
});
watch(
  () => props.stream.Stream.ID,
  async (id) => {
    const current = ++generation;
    loading.value = true;
    error.value = "";
    data.value = [];
    code.value = "";
    try {
      const loaded = await loadChain(id, props.stream.Stream.Client.Host);
      if (generation === current) data.value = loaded;
    } catch (err) {
      if (generation === current) error.value = String(err);
    } finally {
      if (generation === current) loading.value = false;
    }
  },
  { immediate: true },
);
function generate() {
  try {
    code.value = pythonReplay(data.value);
    error.value = "";
    return true;
  } catch (err) {
    error.value = String(err);
    return false;
  }
}
function preview() {
  if (generate()) dialog.value = true;
}
async function copy() {
  if (!generate()) return;
  try {
    if (navigator.clipboard && window.isSecureContext)
      await navigator.clipboard.writeText(code.value);
    else {
      // Copy after Vue has updated the hidden textarea's value.
      if (copyArea.value) {
        copyArea.value.value = code.value;
        copyArea.value.select();
      }
      if (!document.execCommand("copy"))
        throw new Error("Не удалось скопировать; скачайте .py");
    }
    EventBus.emit(
      "showMessage",
      "Вся цепочка скопирована: IP берётся из sys.argv[1]",
    );
  } catch (err) {
    error.value = String(err);
  }
}
function download() {
  if (!generate()) return;
  const url = URL.createObjectURL(
    new Blob([code.value], { type: "text/x-python;charset=utf-8" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "replay-chain.py";
  a.click();
  URL.revokeObjectURL(url);
}
</script>
<style scoped>
.chain-step {
  border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
}
.replay-code :deep(textarea) {
  font-family: monospace;
  font-size: 12px;
}
</style>
