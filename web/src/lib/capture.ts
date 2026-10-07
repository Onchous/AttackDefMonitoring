export function parsePorts(text: string): number[] {
  const ports = new Set<number>();
  for (const item of text.split(",")) {
    const match = /^\s*(\d+)(?:\s*[-:]\s*(\d+))?\s*$/.exec(item);
    if (!match) throw new Error("Укажите порт или диапазон: 7070,8080-8081");
    const first = Number(match[1]);
    const last = Number(match[2] ?? match[1]);
    if (first < 1 || last > 65535 || first > last)
      throw new Error("Порты: 1–65535, начало диапазона не больше конца");
    if (last - first >= 1024)
      throw new Error("Не больше 1024 портов на сервис");
    for (let port = first; port <= last; port++) ports.add(port);
    if (ports.size > 1024) throw new Error("Не больше 1024 портов на сервис");
  }
  return [...ports].sort((a, b) => a - b);
}
