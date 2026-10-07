<template>
  <v-dialog v-model="visible" width="500" @keydown.enter="submitCurrent">
    <v-card>
      <v-card-title>
        <span class="text-h5">CTF Setup Wizards</span>
      </v-card-title>
      <v-tabs v-model="tab" stacked color="primary">
        <v-tab value="tab_flag_regex">
          Setup Flag tags
          <v-icon>mdi-flag</v-icon>
        </v-tab>
        <v-tab value="tab_service_by_port">
          Setup Service ports
          <v-icon>mdi-cloud-outline</v-icon>
        </v-tab>
      </v-tabs>
      <v-tabs-window v-model="tab">
        <v-tabs-window-item value="tab_service_by_port">
          <v-form @submit.prevent="createService">
            <v-card-text>
              Укажите порт и интерфейс — захват трафика начнётся сразу.
              Несколько портов: 7070,8080-8081.

              <v-text-field
                v-model="serviceName"
                label="Service name"
                autofocus
                :rules="[() => serviceName != '']"
              ></v-text-field>
              <v-select
                v-model="serviceInterface"
                :items="captureStatus?.Interfaces ?? []"
                label="Сетевой интерфейс"
                :loading="interfacesLoading"
                hint="lo — localhost; eth0 — входящие соединения по сети"
                persistent-hint
              />
              <v-alert
                v-if="captureError"
                type="error"
                density="compact"
                class="mb-3"
                >{{ captureError }}</v-alert
              >
              <v-text-field
                v-model="servicePorts"
                label="Service ports"
                example="80,8080-8081"
                :rules="[() => goodServicePorts]"
              ></v-text-field>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn variant="text" @click="visible = false">Cancel</v-btn>
              <v-btn
                variant="text"
                :disabled="
                  serviceName == '' ||
                  !goodServicePorts ||
                  !serviceInterface ||
                  !captureStatus ||
                  service_by_port_loading
                "
                :loading="service_by_port_loading"
                :color="service_by_port_error ? 'error' : 'primary'"
                type="submit"
                >Сохранить и запустить захват</v-btn
              >
            </v-card-actions>
          </v-form>
        </v-tabs-window-item>
        <v-tabs-window-item value="tab_flag_regex">
          <v-form @submit.prevent="createFlagTags">
            <v-card-text>
              This wizard will create the two tags {{ flagInName }} and
              {{ flagOutName }} with the specified regex below if they don't
              already exist.

              <v-text-field
                v-model="flagRegex"
                label="Flag Regex"
                example="flag_[a-fA-F0-9]{32}"
                autofocus
                :rules="[() => goodFlagRegex]"
              ></v-text-field>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn variant="text" @click="visible = false">Cancel</v-btn>
              <v-btn
                variant="text"
                :disabled="!goodFlagRegex || flag_regex_loading"
                :loading="flag_regex_loading"
                :color="flag_regex_error ? 'error' : 'primary'"
                type="submit"
                >Create Flag tags</v-btn
              >
            </v-card-actions>
          </v-form>
        </v-tabs-window-item>
      </v-tabs-window>
    </v-card>
  </v-dialog>
</template>

<script lang="ts" setup>
import { EventBus } from "./EventBus";
import { ref, computed } from "vue";
import { useRootStore } from "@/stores";
import { randomColor } from "@/lib/colors";
import APIClient, { type CaptureStatus } from "@/apiClient";
import { parsePorts } from "@/lib/capture";
import axios from "axios";

const store = useRootStore();
const visible = ref(false);
const tab = ref("");

const flag_regex_loading = ref(false);
const flag_regex_error = ref(false);
const flagRegex = ref("[A-Z0-9]{31}=");

const service_by_port_loading = ref(false);
const service_by_port_error = ref(false);
const serviceName = ref("");
const servicePorts = ref("");
const serviceInterface = ref("");
const captureStatus = ref<CaptureStatus | null>(null);
const interfacesLoading = ref(false);
const captureError = ref("");
EventBus.on("showServiceCapture", (name, ports) => {
  openDialog();
  tab.value = "tab_service_by_port";
  serviceName.value = name;
  servicePorts.value = ports;
});

const tagPrefix = "tag/";
const servicePrefix = "service/";
const flagInName = "flag_in";
const flagInColor = "#66ff66";
const flagInPrefix = "cdata:";
const flagOutName = "flag_out";
const flagOutColor = "#ff6666";
const flagOutPrefix = "sdata:";

EventBus.on("showCTFWizard", openDialog);

const goodServicePorts = computed(() => {
  try {
    parsePorts(servicePorts.value);
    return true;
  } catch {
    return false;
  }
});

const goodFlagRegex = computed(() => {
  const v = flagRegex.value;
  if (v === "" || v.includes(" ")) return false;
  try {
    RegExp(v);
  } catch {
    return false;
  }
  return true;
});

function openDialog() {
  visible.value = true;
  tab.value = "tab_flag_regex";
  void loadInterfaces();

  flag_regex_loading.value = false;
  flag_regex_error.value = false;

  service_by_port_loading.value = false;
  service_by_port_error.value = false;
}

function submitCurrent() {
  switch (tab.value) {
    case "tab_flag_regex":
      createFlagTags();
      break;
    case "tab_service_by_port":
      void createService();
      break;
  }
}

async function loadInterfaces() {
  interfacesLoading.value = true;
  captureError.value = "";
  captureStatus.value = null;
  try {
    captureStatus.value = await APIClient.getCaptureStatus();
    const existing = captureStatus.value.Sources.find(
      (s) => s.Name === serviceName.value.trim(),
    );
    serviceInterface.value =
      existing?.Interface ??
      (captureStatus.value.Interfaces.includes("eth0") ? "eth0" : "lo");
  } catch (err) {
    captureError.value = axios.isAxiosError(err)
      ? (err.response?.data?.Error ?? err.response?.data ?? err.message)
      : String(err);
  } finally {
    interfacesLoading.value = false;
  }
}

async function createService() {
  if (
    service_by_port_loading.value ||
    !goodServicePorts.value ||
    !serviceInterface.value ||
    !captureStatus.value ||
    !serviceName.value.trim()
  )
    return;
  service_by_port_loading.value = true;
  service_by_port_error.value = false;
  captureError.value = "";
  try {
    const ports = parsePorts(servicePorts.value);
    const name = serviceName.value.trim();
    const tagName = servicePrefix + name;
    const query = `sport:${ports.join(",")}`;
    const status = await APIClient.startCapture(
      name,
      serviceInterface.value,
      ports,
    );
    if (!status.Sources.find((s) => s.Name === name)?.Running)
      throw new Error("Захват не запустился");
    if (store.tags?.some((tag) => tag.Name === tagName))
      await store.changeTagDefinition(tagName, query);
    else await store.addTag(tagName, query, randomColor());
    await store.updateTags();
    visible.value = false;
    EventBus.emit(
      "showMessage",
      `Захват ${name}: ${serviceInterface.value}, порты ${ports.join(", ")} запущен`,
    );
  } catch (err) {
    service_by_port_error.value = true;
    captureError.value = axios.isAxiosError(err)
      ? (err.response?.data?.Error ?? err.response?.data ?? err.message)
      : String(err);
  } finally {
    service_by_port_loading.value = false;
  }
}

function createFlagTags() {
  if (flag_regex_loading.value || !goodFlagRegex.value) return;
  flag_regex_loading.value = true;
  flag_regex_error.value = false;
  Promise.allSettled([
    store.addTag(
      tagPrefix + flagInName,
      flagInPrefix + flagRegex.value,
      flagInColor,
    ),
    store.addTag(
      tagPrefix + flagOutName,
      flagOutPrefix + flagRegex.value,
      flagOutColor,
    ),
  ])
    .then((res) => {
      const rejected = res.filter((r) => r.status === "rejected");
      if (rejected.length != 0) {
        throw new Error(rejected.map((r) => r.reason as string).join("; "));
      }
      visible.value = false;
      flag_regex_loading.value = false;
    })
    .catch((err: Error) => {
      flag_regex_error.value = true;
      flag_regex_loading.value = false;
      EventBus.emit("showError", err.message);
    });
}
</script>
