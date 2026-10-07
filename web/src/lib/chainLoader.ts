import APIClient, { type Result, type StreamData } from "@/apiClient";
import { groupChains } from "./chains";
export async function clientStreams(host: string): Promise<Result[]> {
  if (!/^[0-9a-fA-F:.]+$/.test(host)) throw new Error("Invalid client IP");
  const all: Result[] = [];
  for (let page = 0; ; page++) {
    const result = await APIClient.searchChainStreams(host, page);
    if ("Error" in result) throw new Error(result.Error);
    all.push(...result.Results);
    if (!result.MoreResults) break;
    if (!result.Results.length) throw new Error("Empty page in chain search");
  }
  return all;
}
export async function loadChain(
  streamId: number,
  host: string,
): Promise<StreamData[]> {
  const groups = groupChains(await clientStreams(host));
  const chain = groups.find((c) =>
    c.streams.some((s) => s.Stream.ID === streamId),
  );
  if (!chain) throw new Error("Цепочка не найдена; обновите результаты");
  const data: StreamData[] = [];
  for (const result of chain.streams)
    data.push(await APIClient.getStream(result.Stream.ID, "none"));
  return data;
}
