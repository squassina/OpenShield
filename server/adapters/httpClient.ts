const MAX_BODY_BYTES = 1_048_576; // 1 MiB cap per OpenShield P0 spec

export interface BoundedFetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export async function boundedFetchJson<T>(
  url: string,
  options: BoundedFetchOptions = {},
): Promise<{ status: number; ok: boolean; data: T }> {
  const timeoutMs = Math.max(1000, Math.min(options.timeoutMs ?? 5000, 15000));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: options.method ?? 'GET',
      headers: {
        Accept: 'application/json',
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options.headers ?? {}),
      },
      body: options.body,
      signal: controller.signal,
    });

    const contentLength = Number(response.headers.get('content-length') ?? '0');
    if (contentLength > MAX_BODY_BYTES) {
      throw new Error(`Resposta excedeu o limite seguro de 1 MiB (${contentLength} bytes).`);
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return { status: response.status, ok: response.ok, data: {} as T };
    }

    const chunks: Uint8Array[] = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.byteLength;
        if (received > MAX_BODY_BYTES) {
          controller.abort();
          throw new Error('Corpo da resposta excedeu o limite seguro de 1 MiB durante leitura.');
        }
        chunks.push(value);
      }
    }

    const merged = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const text = new TextDecoder().decode(merged).trim();
    const data = (text ? JSON.parse(text) : {}) as T;
    return { status: response.status, ok: response.ok, data };
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`Timeout de ${timeoutMs}ms excedido ao conectar em ${new URL(url).host}.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export async function boundedFetchText(
  url: string,
  options: BoundedFetchOptions = {},
): Promise<{ status: number; ok: boolean; text: string }> {
  const timeoutMs = Math.max(1000, Math.min(options.timeoutMs ?? 5000, 15000));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: options.method ?? 'GET',
      headers: {
        Accept: 'text/plain, application/openmetrics-text;version=0.0.1, */*',
        ...(options.headers ?? {}),
      },
      body: options.body,
      signal: controller.signal,
    });

    const contentLength = Number(response.headers.get('content-length') ?? '0');
    if (contentLength > MAX_BODY_BYTES) {
      throw new Error(`Resposta excedeu o limite seguro de 1 MiB (${contentLength} bytes).`);
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return { status: response.status, ok: response.ok, text: '' };
    }

    const chunks: Uint8Array[] = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.byteLength;
        if (received > MAX_BODY_BYTES) {
          controller.abort();
          throw new Error('Corpo da resposta excedeu o limite seguro de 1 MiB durante leitura.');
        }
        chunks.push(value);
      }
    }

    const merged = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const text = new TextDecoder().decode(merged);
    return { status: response.status, ok: response.ok, text };
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`Timeout de ${timeoutMs}ms excedido ao conectar em ${new URL(url).host}.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
