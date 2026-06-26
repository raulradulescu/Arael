export interface ResourceSampler {
  stop(): number | null;
}

export function startResourceSampler(intervalMs = 100): ResourceSampler {
  let peakRss = process.memoryUsage().rss;
  const handle = setInterval(() => {
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }, intervalMs);

  return {
    stop(): number | null {
      clearInterval(handle);
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
      return peakRss / 1024 / 1024;
    }
  };
}
