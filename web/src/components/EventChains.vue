<template>
  <v-table density="compact" hover>
    <thead>
      <tr>
        <th class="text-left">Tags</th>
        <th class="text-left">Client</th>
        <th>Сессии</th>
        <th class="text-left">Bytes</th>
        <th class="text-left">Server</th>
        <th class="text-left">Bytes</th>
        <th class="text-right">Duration</th>
        <th class="text-right">Time</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      <tr
        v-for="chain in chains"
        :key="`${chain.client}-${chain.start}`"
        class="chain-row"
        :class="{
          selected: chain.streams.some(
            (s) => String(s.Stream.ID) === route.params.streamId,
          ),
        }"
        tabindex="0"
        role="link"
        @click="open(chain)"
        @keydown.enter="open(chain)"
      >
        <td>
          <v-chip
            v-for="tag in [...new Set(chain.streams.flatMap((s) => s.Tags))]"
            :key="tag"
            size="small"
            variant="flat"
            :color="tagColors[tag]"
            :style="{
              color: tagColors[tag]
                ? getContrastTextColor(tagColors[tag])
                : undefined,
            }"
            >{{ tagify(tag, "name") }}</v-chip
          >
        </td>
        <td>{{ chain.client }}:{{ chain.streams[0].Stream.Client.Port }}</td>
        <td>
          <v-chip
            size="x-small"
            variant="tonal"
            :title="`${chain.streams.length} соединений в цепочке этого IP`"
            >{{ chain.streams.length
            }}<v-progress-circular
              v-if="loading"
              indeterminate
              size="10"
              width="1"
              class="ml-1"
          /></v-chip>
        </td>
        <td>
          {{
            prettyBytes(total(chain, "Client"), {
              binary: true,
              maximumFractionDigits: 1,
            })
          }}
        </td>
        <td>
          {{
            [
              ...new Set(
                chain.streams.map(
                  (s) => `${s.Stream.Server.Host}:${s.Stream.Server.Port}`,
                ),
              ),
            ].join(", ")
          }}
        </td>
        <td>
          {{
            prettyBytes(total(chain, "Server"), {
              binary: true,
              maximumFractionDigits: 1,
            })
          }}
        </td>
        <td class="text-right">
          {{
            formatDateDifference(
              new Date(chain.end).toISOString(),
              new Date(chain.start).toISOString(),
            )
          }}
        </td>
        <td
          class="text-right"
          :title="formatDateLong(new Date(chain.start).toISOString())"
        >
          {{ formatDate(new Date(chain.start).toISOString()) }}
        </td>
        <td><v-icon size="small">mdi-chevron-right</v-icon></td>
      </tr>
    </tbody>
  </v-table>
</template>
<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useRootStore } from "@/stores";
import type { Result } from "@/apiClient";
import { groupChains, type Chain } from "@/lib/chains";
import { clientStreams } from "@/lib/chainLoader";
import {
  formatDate,
  formatDateLong,
  formatDateDifference,
  tagify,
} from "@/filters";
import { getContrastTextColor } from "@/lib/colors";
import prettyBytes from "pretty-bytes";
import { EventBus } from "./EventBus";
const props = defineProps<{ results: Result[] }>();
const route = useRoute();
const router = useRouter();
const store = useRootStore();
const full = ref<Result[]>([]);
const loading = ref(false);
let generation = 0;
const chains = computed(() => {
  const ids = new Set(props.results.map((s) => s.Stream.ID));
  const merged = new Map(
    [...full.value, ...props.results].map((s) => [s.Stream.ID, s]),
  );
  return groupChains([...merged.values()]).filter((c) =>
    c.streams.some((s) => ids.has(s.Stream.ID)),
  );
});
const tagColors = computed(() =>
  Object.fromEntries((store.tags ?? []).map((t) => [t.Name, t.Color])),
);
watch(
  () => props.results,
  async (results) => {
    const current = ++generation;
    full.value = [];
    loading.value = true;
    const hosts = [...new Set(results.map((s) => s.Stream.Client.Host))];
    try {
      for (let i = 0; i < hosts.length; i += 4) {
        const batch = await Promise.all(
          hosts.slice(i, i + 4).map(clientStreams),
        );
        if (current !== generation) return;
        full.value.push(...batch.flat());
      }
    } catch (err) {
      if (current === generation)
        EventBus.emit(
          "showError",
          `Не удалось загрузить полные цепочки: ${String(err)}`,
        );
    } finally {
      if (current === generation) loading.value = false;
    }
  },
  { immediate: true },
);
onBeforeUnmount(() => {
  generation++;
});
function total(chain: Chain, side: "Client" | "Server") {
  return chain.streams.reduce((sum, s) => sum + s.Stream[side].Bytes, 0);
}
function open(chain: Chain) {
  if (window.getSelection()?.type === "Range") return;
  void router.push({
    name: "stream",
    params: { streamId: chain.streams[0].Stream.ID },
    query: { ...route.query, chain: "1" },
  });
}
</script>
<style scoped>
.chain-row {
  cursor: pointer;
}
.chain-row.selected td {
  background: rgba(var(--v-theme-primary), var(--v-border-opacity));
}
</style>
