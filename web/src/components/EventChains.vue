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
        @mouseenter="ensureCount(chain)"
        @focus="ensureCount(chain)"
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
            :title="sessionCountTitle(chain)"
            >{{ sessionCountLabel(chain) }}</v-chip
          >
        </td>
        <td>
          {{
            prettyBytes(total(chain, "Client"), {
              binary: true,
              maximumFractionDigits: 1,
            })
          }}
        </td>
        <td :title="servers(chain).join(', ')">{{ serverLabel(chain) }}</td>
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
import { computed, onBeforeUnmount, reactive } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useRootStore } from "@/stores";
import type { Result } from "@/apiClient";
import { groupChains, type Chain } from "@/lib/chains";
import { completeChainStreams } from "@/lib/chainLoader";
import {
  formatDate,
  formatDateLong,
  formatDateDifference,
  tagify,
} from "@/filters";
import { getContrastTextColor } from "@/lib/colors";
import prettyBytes from "pretty-bytes";
const props = defineProps<{ results: Result[] }>();
const route = useRoute();
const router = useRouter();
const store = useRootStore();
const chains = computed(() => {
  return groupChains(props.results);
});

type CountCacheEntry = {
  count: number;
  exact: boolean;
  expiresAt: number;
  touchedAt: number;
};
type CountTask = { seed: Result; localCount: number };

const CACHE_TTL = 15_000;
const ERROR_TTL = 5_000;
const MAX_CACHE_ENTRIES = 2_000;
const MAX_CONCURRENT_LOADS = 4;
const countCache = reactive(new Map<number, CountCacheEntry>());
const queued = new Set<number>();
const active = new Set<number>();
let queue: CountTask[] = [];
let disposed = false;

function chainSeed(chain: Chain): Result {
  return chain.streams[0];
}

function sessionCount(chain: Chain): number {
  const cached = countCache.get(chainSeed(chain).Stream.ID);
  return Math.max(chain.streams.length, cached?.count ?? 0);
}

function sessionCountLabel(chain: Chain): string {
  const cached = countCache.get(chainSeed(chain).Stream.ID);
  return cached?.exact
    ? String(sessionCount(chain))
    : `≥${chain.streams.length}`;
}

function sessionCountTitle(chain: Chain): string {
  const seedID = chainSeed(chain).Stream.ID;
  const cached = countCache.get(seedID);
  if (queued.has(seedID) || active.has(seedID))
    return `${sessionCount(chain)} соединений; уточняется по полной цепочке`;
  if (cached?.exact)
    return `${sessionCount(chain)} соединений в полной цепочке этого IP`;
  if (cached)
    return `${sessionCount(chain)} соединений на этой странице; полную цепочку загрузить не удалось`;
  return `Не меньше ${sessionCount(chain)} соединений; наведите, чтобы уточнить полную цепочку`;
}

function pruneCountCache() {
  if (countCache.size <= MAX_CACHE_ENTRIES) return;
  const removable = [...countCache.entries()]
    .filter(([id]) => !active.has(id))
    .sort((a, b) => a[1].touchedAt - b[1].touchedAt);
  for (const [id] of removable) {
    if (countCache.size <= MAX_CACHE_ENTRIES) break;
    countCache.delete(id);
  }
}

function cacheCount(ids: number[], count: number, exact: boolean, ttl: number) {
  const now = Date.now();
  const entry = { count, exact, expiresAt: now + ttl, touchedAt: now };
  for (const id of ids) countCache.set(id, entry);
  pruneCountCache();
}

async function resolveCount(task: CountTask) {
  const seedID = task.seed.Stream.ID;
  try {
    const results = await completeChainStreams(task.seed.Stream);
    if (!results.some((result) => result.Stream.ID === seedID))
      results.push(task.seed);
    const fullChain = groupChains(results).find((chain) =>
      chain.streams.some((result) => result.Stream.ID === seedID),
    );
    if (!fullChain) throw new Error("Chain not found");
    cacheCount(
      fullChain.streams.map((result) => result.Stream.ID),
      fullChain.streams.length,
      true,
      CACHE_TTL,
    );
    // Keep the visible seed cached even if a very large chain was pruned.
    cacheCount([seedID], fullChain.streams.length, true, CACHE_TTL);
  } catch {
    cacheCount([seedID], task.localCount, false, ERROR_TTL);
  }
}

function pumpCountQueue() {
  while (!disposed && active.size < MAX_CONCURRENT_LOADS && queue.length) {
    const task = queue.shift();
    if (!task) return;
    const seedID = task.seed.Stream.ID;
    queued.delete(seedID);
    active.add(seedID);
    void resolveCount(task).finally(() => {
      active.delete(seedID);
      pumpCountQueue();
    });
  }
}

function enqueueCount(chain: Chain) {
  const seed = chainSeed(chain);
  const seedID = seed.Stream.ID;
  if (queued.has(seedID) || active.has(seedID)) return;
  queued.add(seedID);
  queue.push({ seed, localCount: chain.streams.length });
  pumpCountQueue();
}

function ensureCount(chain: Chain) {
  const cached = countCache.get(chainSeed(chain).Stream.ID);
  if (cached && cached.expiresAt > Date.now()) {
    cached.touchedAt = Date.now();
    return;
  }
  enqueueCount(chain);
}

onBeforeUnmount(() => {
  disposed = true;
  queue = [];
  queued.clear();
});

const tagColors = computed(() =>
  Object.fromEntries((store.tags ?? []).map((t) => [t.Name, t.Color])),
);
function total(chain: Chain, side: "Client" | "Server") {
  return chain.streams.reduce((sum, s) => sum + s.Stream[side].Bytes, 0);
}
function servers(chain: Chain): string[] {
  return [
    ...new Set(
      chain.streams.map(
        (item) => `${item.Stream.Server.Host}:${item.Stream.Server.Port}`,
      ),
    ),
  ];
}
function serverLabel(chain: Chain): string {
  const values = servers(chain);
  return (
    values.slice(0, 2).join(", ") +
    (values.length > 2 ? ` · ещё ${values.length - 2}` : "")
  );
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
