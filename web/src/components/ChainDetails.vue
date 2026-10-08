<template>
  <div>
    <div class="d-flex align-center flex-wrap ga-2 px-4 py-1">
      <span class="text-caption">
        Цепочка · {{ data.length || "…" }} соединений · {{ requestCount }}
        HTTP-запросов
      </span>
      <v-progress-circular v-if="loading" indeterminate size="16" width="2" />
      <v-btn
        v-if="!expanded"
        size="small"
        variant="text"
        @click="router.replace({ query: { ...route.query, chain: '1' } })"
      >
        Открыть цепочку
      </v-btn>
      <template v-else-if="data.length">
        <v-chip size="x-small" variant="tonal">
          выбрано {{ selectedData.length }}/{{ data.length }}
        </v-chip>
        <v-btn size="x-small" variant="text" @click="selectAll">Все</v-btn>
        <v-btn size="x-small" variant="text" @click="selectedIds = []">
          Снять
        </v-btn>
        <v-btn size="x-small" variant="text" @click="selectThroughFlag">
          До флага
        </v-btn>
        <v-btn size="x-small" variant="text" @click="removeStatic">
          Убрать статику
        </v-btn>
      </template>
      <v-spacer />
      <v-btn
        color="amber-darken-2"
        size="small"
        variant="flat"
        prepend-icon="mdi-creation"
        :disabled="loading || !selectedData.length"
        @click="aiDialog = true"
      >
        Разобрать с ИИ
      </v-btn>
      <v-btn
        size="small"
        variant="tonal"
        :disabled="loading || !selectedData.length"
        @click="copySelected"
      >
        Копировать выбранное
      </v-btn>
      <v-btn
        size="small"
        variant="text"
        :disabled="loading || !selectedData.length"
        @click="previewSelected"
      >
        Python
      </v-btn>
      <v-btn
        size="small"
        color="primary"
        variant="tonal"
        :disabled="loading || !data.length"
        @click="downloadFullChain"
      >
        Full chain .py
      </v-btn>
    </div>

    <v-alert v-if="error" type="error" density="compact" class="mx-4 my-1">
      {{ error }}
    </v-alert>

    <v-expansion-panels
      v-if="expanded && data.length"
      multiple
      variant="accordion"
      class="chain-panels"
    >
      <v-expansion-panel
        v-for="item in data"
        :key="item.Stream.ID"
        :value="item.Stream.ID"
      >
        <v-expansion-panel-title class="chain-title">
          <v-checkbox-btn
            color="primary"
            density="compact"
            :model-value="selectedIds.includes(item.Stream.ID)"
            :aria-label="'Выбрать соединение ' + item.Stream.ID"
            @click.stop
            @update:model-value="toggle(item.Stream.ID, Boolean($event))"
          />
          <span class="text-caption text-medium-emphasis mr-2">
            #{{ item.Stream.ID }}
          </span>
          <code class="chain-summary">
            {{ summaries.get(item.Stream.ID)?.text }}
          </code>
          <v-chip
            v-if="summaries.get(item.Stream.ID)?.status"
            size="x-small"
            variant="tonal"
            class="ml-2"
          >
            {{ summaries.get(item.Stream.ID)?.status }}
          </v-chip>
          <v-chip
            v-if="summaries.get(item.Stream.ID)?.flag"
            size="x-small"
            color="yellow-accent-2"
            class="ml-2 flag-chip"
          >
            FLAG
          </v-chip>
          <span class="text-caption text-medium-emphasis ml-auto mr-3">
            {{ item.Stream.Client.Host }} → {{ item.Stream.Server.Host }}:{{
              item.Stream.Server.Port
            }}
          </span>
        </v-expansion-panel-title>
        <v-expansion-panel-text>
          <StreamData
            :data="item.Data"
            viewmode="cards"
            :presentation="presentation"
            :highlight-matches="highlightMatches"
            :url-decode="urlDecode"
          />
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>

    <v-dialog v-model="dialog" max-width="1000">
      <v-card :title="previewTitle">
        <v-card-text>
          <p class="text-caption mb-2">
            Запуск: <code>python3 {{ filename }} IP</code>. Каждый ответ
            выводится через <code>print(r.text, flush=True)</code>.
          </p>
          <v-alert
            v-if="skipped.length"
            type="warning"
            density="compact"
            class="mb-2"
          >
            Пропущено неподдерживаемых соединений: {{ skipped.length }} ({{
              skippedLabel
            }}).
          </v-alert>
          <v-text-field
            v-model="filename"
            label="Имя файла для DestructiveFarm"
            density="compact"
          />
          <v-textarea
            :model-value="code"
            readonly
            rows="20"
            class="replay-code"
          />
        </v-card-text>
        <v-card-actions>
          <v-btn @click="copyCode">Скопировать</v-btn>
          <v-btn @click="downloadCode">Скачать .py</v-btn>
          <v-btn
            color="primary"
            prepend-icon="mdi-folder-arrow-right"
            :loading="exporting"
            @click="exportToFarm"
          >
            В DestructiveFarm
          </v-btn>
          <v-spacer />
          <v-btn @click="dialog = false">Закрыть</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <AiExploitDialog v-model="aiDialog" :streams="selectedData" />
    <textarea
      ref="copyArea"
      :value="code"
      readonly
      style="position: fixed; left: -10000px"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from "vue";
import { useRoute, useRouter } from "vue-router";
import APIClient, {
  type StreamData as StreamPayload,
  type DataRegexes,
} from "@/apiClient";
import { loadChain } from "@/lib/chainLoader";
import {
  parseRequests,
  pythonReplayDetailed,
  type ReplaySkip,
} from "@/lib/chains";
import AiExploitDialog from "./AiExploitDialog.vue";
import StreamData from "./StreamData.vue";
import { EventBus } from "./EventBus";

const FLAG_RE = /[A-Z0-9]{31}=/;
const STATIC_RE =
  /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:\?|$)/i;

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
const selectedIds = ref<number[]>([]);
const loading = ref(false);
const exporting = ref(false);
const error = ref("");
const code = ref("");
const skipped = ref<ReplaySkip[]>([]);
const filename = ref("replay-chain.py");
const previewTitle = ref("Kill chain · Python requests");
const dialog = ref(false);
const aiDialog = ref(false);
const copyArea = ref<HTMLTextAreaElement | null>(null);
let generation = 0;

const selectedData = computed(() => {
  const ids = new Set(selectedIds.value);
  return data.value.filter((item) => ids.has(item.Stream.ID));
});

const summaries = computed(
  () => new Map(data.value.map((item) => [item.Stream.ID, summarize(item)])),
);

const requestCount = computed(() =>
  [...summaries.value.values()].reduce((sum, item) => sum + item.requests, 0),
);

const skippedLabel = computed(() =>
  skipped.value.map((item) => "#" + item.streamId).join(", "),
);

onBeforeUnmount(() => {
  generation++;
});

watch(
  () => props.stream.Stream.ID,
  async () => {
    const current = ++generation;
    loading.value = true;
    error.value = "";
    data.value = [];
    selectedIds.value = [];
    code.value = "";
    try {
      const loaded = await loadChain(props.stream);
      if (generation === current) {
        data.value = loaded;
        selectAll();
      }
    } catch (err) {
      if (generation === current) error.value = message(err);
    } finally {
      if (generation === current) loading.value = false;
    }
  },
  { immediate: true },
);

function decoded(item: StreamPayload, direction: number) {
  return item.Data.filter((chunk) => chunk.Direction === direction)
    .map((chunk) => {
      try {
        return atob(chunk.Content);
      } catch {
        return "";
      }
    })
    .join("");
}

function summarize(item: StreamPayload) {
  let requests = 0;
  let text = item.Stream.Protocol + " " + item.Stream.Server.Port;
  try {
    const parsed = parseRequests(item);
    requests = parsed.length;
    if (parsed.length) {
      text = parsed
        .slice(0, 2)
        .map((request) => request.method + " " + request.target)
        .join(" · ");
      if (parsed.length > 2) text += " · +" + (parsed.length - 2);
    }
  } catch {
    text = item.Stream.Protocol + " · не HTTP/1.x";
  }
  const response = decoded(item, 1);
  return {
    text,
    requests,
    status: /HTTP\/1\.[01]\s+(\d{3})/.exec(response)?.[1] ?? "",
    flag: FLAG_RE.test(response),
  };
}

function toggle(id: number, value: boolean) {
  const ids = new Set(selectedIds.value);
  if (value) ids.add(id);
  else ids.delete(id);
  selectedIds.value = [...ids];
}

function selectAll() {
  selectedIds.value = data.value.map((item) => item.Stream.ID);
}

function selectThroughFlag() {
  let last = -1;
  data.value.forEach((item, index) => {
    if (summaries.value.get(item.Stream.ID)?.flag) last = index;
  });
  selectedIds.value = data.value
    .slice(0, last >= 0 ? last + 1 : data.value.length)
    .map((item) => item.Stream.ID);
  if (last < 0)
    EventBus.emit(
      "showMessage",
      "Флаг в ответах не найден — выбрана вся цепочка",
    );
}

function removeStatic() {
  selectedIds.value = selectedData.value
    .filter((item) => {
      try {
        const requests = parseRequests(item);
        return !(
          requests.length > 0 &&
          requests.every(
            (request) =>
              request.method === "GET" && STATIC_RE.test(request.target),
          )
        );
      } catch {
        return true;
      }
    })
    .map((item) => item.Stream.ID);
}

function makeFilename(streams: StreamPayload[]) {
  const port = streams[0]?.Stream.Server.Port ?? "service";
  const id = streams[0]?.Stream.ID ?? Date.now();
  return "exploit_" + port + "_" + id + ".py";
}

function generate(streams: StreamPayload[], title: string) {
  try {
    const result = pythonReplayDetailed(streams);
    code.value = result.code;
    skipped.value = result.skipped;
    filename.value = makeFilename(streams);
    previewTitle.value = title;
    error.value = "";
    return true;
  } catch (err) {
    error.value = message(err);
    return false;
  }
}

function previewSelected() {
  if (generate(selectedData.value, "Выбранные события · Python requests"))
    dialog.value = true;
}

async function writeClipboard(value: string) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  if (copyArea.value) {
    copyArea.value.value = value;
    copyArea.value.select();
  }
  if (!document.execCommand("copy"))
    throw new Error("Не удалось скопировать; скачайте .py");
}

async function copySelected() {
  if (!generate(selectedData.value, "Выбранные события · Python requests"))
    return;
  if (skipped.value.length) {
    dialog.value = true;
    EventBus.emit(
      "showMessage",
      "Часть выбранных соединений нельзя перевести в requests — проверьте предупреждение перед копированием",
    );
    return;
  }
  await copyCode();
}

async function copyCode() {
  try {
    await writeClipboard(code.value);
    EventBus.emit(
      "showMessage",
      "Python-цепочка скопирована: IP берётся из sys.argv[1]",
    );
  } catch (err) {
    error.value = message(err);
  }
}

function saveBlob() {
  const url = URL.createObjectURL(
    new Blob([code.value], { type: "text/x-python;charset=utf-8" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = filename.value;
  link.click();
  URL.revokeObjectURL(url);
}

function downloadCode() {
  saveBlob();
}

function downloadFullChain() {
  if (!generate(data.value, "Полная цепочка · Python requests")) return;
  if (skipped.value.length) {
    dialog.value = true;
    EventBus.emit(
      "showMessage",
      "Часть соединений нельзя перевести в requests — проверьте предупреждение перед скачиванием",
    );
    return;
  }
  saveBlob();
}

async function exportToFarm() {
  exporting.value = true;
  try {
    const result = await APIClient.exportToFarm(filename.value, code.value);
    EventBus.emit(
      "showMessage",
      "Сохранено в DestructiveFarm/client: " +
        (result.Filename ?? filename.value) +
        ". Запуск: python3 start_sploit.py " +
        (result.Filename ?? filename.value),
    );
  } catch (err) {
    error.value = message(err);
  } finally {
    exporting.value = false;
  }
}

function message(errorValue: unknown) {
  const apiMessage = (
    errorValue as { response?: { data?: { Error?: string } } }
  )?.response?.data?.Error;
  return apiMessage || String(errorValue);
}
</script>

<style scoped>
.chain-panels {
  border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
}
.chain-title {
  min-height: 40px;
  padding-top: 2px;
  padding-bottom: 2px;
}
.chain-summary {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.flag-chip {
  color: #111 !important;
  font-weight: 800;
}
.replay-code :deep(textarea) {
  font-family: monospace;
  font-size: 12px;
}
</style>
