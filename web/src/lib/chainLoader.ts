import APIClient, {
  type Result,
  type Stream,
  type StreamData,
} from "@/apiClient";
import { groupChains } from "./chains";
const MAX_PAGES = 50;
const MAX_CHAIN_WINDOWS = 20;

export async function clientStreams(stream: Stream): Promise<Result[]> {
  if (!/^[0-9a-fA-F:.]+$/.test(stream.Client.Host))
    throw new Error("Invalid stream address");
  const all: Result[] = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const result = await APIClient.searchChainStreams(stream, page);
    if ("Error" in result) throw new Error(result.Error);
    all.push(...result.Results);
    if (!result.MoreResults) break;
    if (!result.Results.length) throw new Error("Empty page in chain search");
    if (page === MAX_PAGES - 1)
      throw new Error("Too many events in the 62-second chain window");
  }
  return all;
}

/**
 * Follow a one-second client-IP chain across the edges of each bounded search
 * window. Endpoint windows are fetched until both sides end at a real gap.
 */
export async function completeChainStreams(stream: Stream): Promise<Result[]> {
  const merged = new Map<number, Result>();
  const fetchedAnchors = new Set<number>();
  let anchors: Stream[] = [stream];
  let windows = 0;

  while (anchors.length) {
    if (windows + anchors.length > MAX_CHAIN_WINDOWS)
      throw new Error("Chain exceeds the 20-window safety limit");
    windows += anchors.length;
    const batches = await Promise.all(anchors.map(clientStreams));
    for (const anchor of anchors) fetchedAnchors.add(anchor.ID);
    for (const result of batches.flat()) merged.set(result.Stream.ID, result);
    if (!merged.has(stream.ID))
      merged.set(stream.ID, { Stream: stream, Tags: [] });

    const chain = groupChains([...merged.values()]).find((candidate) =>
      candidate.streams.some((result) => result.Stream.ID === stream.ID),
    );
    if (!chain) throw new Error("Цепочка не найдена; обновите результаты");

    const endpoints = [
      chain.streams[0]?.Stream,
      chain.streams[chain.streams.length - 1]?.Stream,
    ].filter((candidate): candidate is Stream => candidate !== undefined);
    anchors = endpoints.filter(
      (candidate, index) =>
        !fetchedAnchors.has(candidate.ID) &&
        endpoints.findIndex((item) => item.ID === candidate.ID) === index,
    );
    if (!anchors.length) return chain.streams;
  }
  throw new Error("Цепочка не найдена; обновите результаты");
}

export async function loadChain(seed: StreamData): Promise<StreamData[]> {
  const results = await completeChainStreams(seed.Stream);
  if (!results.some((item) => item.Stream.ID === seed.Stream.ID))
    results.push({ Stream: seed.Stream, Tags: seed.Tags });
  const groups = groupChains(results);
  const chain = groups.find((c) =>
    c.streams.some((s) => s.Stream.ID === seed.Stream.ID),
  );
  if (!chain) throw new Error("Цепочка не найдена; обновите результаты");
  const data: StreamData[] = [];
  for (let i = 0; i < chain.streams.length; i += 6) {
    data.push(
      ...(await Promise.all(
        chain.streams
          .slice(i, i + 6)
          .map((result) => APIClient.getStream(result.Stream.ID, "none")),
      )),
    );
  }
  return data;
}
