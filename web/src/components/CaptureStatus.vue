<template>
  <div v-if="status" class="mb-2">
    <v-alert v-if="status.UploadError" type="error" density="compact"
      >Загрузка трафика: {{ status.UploadError }} · файлов в очереди:
      {{ status.PendingFiles }}</v-alert
    >
    <v-table v-if="status.Sources.length" density="compact">
      <thead>
        <tr>
          <th>Захват сервиса</th>
          <th>Интерфейс</th>
          <th>Порты</th>
          <th>Состояние</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="source in status.Sources" :key="source.Name">
          <td>{{ source.Name }}</td>
          <td>{{ source.Interface }}</td>
          <td>{{ source.Ports.join(", ") }}</td>
          <td>
            <v-icon :color="source.Running ? 'success' : 'error'" size="small"
              >mdi-circle</v-icon
            >
            {{
              source.Running
                ? "Трафик собирается"
                : source.Error || "Остановлен"
            }}
          </td>
          <td class="text-right">
            <v-btn
              size="small"
              variant="text"
              @click="
                EventBus.emit(
                  'showServiceCapture',
                  source.Name,
                  source.Ports.join(','),
                )
              "
              >Изменить</v-btn
            ><v-btn
              size="small"
              variant="text"
              :disabled="busy"
              @click="stop(source.Name)"
              >Остановить</v-btn
            >
          </td>
        </tr>
      </tbody>
    </v-table>
  </div>
</template>
<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from "vue";
import APIClient, { type CaptureStatus } from "@/apiClient";
import { EventBus } from "./EventBus";
const status = ref<CaptureStatus | null>(null);
const busy = ref(false);
let timer: ReturnType<typeof setInterval>;
async function refresh() {
  try {
    status.value = await APIClient.getCaptureStatus();
  } catch {
    status.value = null;
  }
}
onMounted(() => {
  void refresh();
  timer = setInterval(() => void refresh(), 3000);
});
onBeforeUnmount(() => clearInterval(timer));
async function stop(name: string) {
  busy.value = true;
  try {
    status.value = await APIClient.stopCapture(name);
    EventBus.emit("showMessage", `Захват ${name} остановлен`);
  } catch (err) {
    EventBus.emit("showError", String(err));
  } finally {
    busy.value = false;
  }
}
</script>
