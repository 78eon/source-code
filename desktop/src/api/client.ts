let origin = "http://127.0.0.1:8765";
export function configureOrigin(value: string) {
  if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(value))
    throw new Error("Backend must use loopback");
  origin = value;
}
export async function get<T>(
  path: string,
  token: string,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(origin + "/api/" + path, {
    headers: { Authorization: "Bearer " + token },
    signal,
  });
  if (!response.ok)
    throw new Error(
      response.status === 401
        ? "Authentication required"
        : response.status === 503
          ? "Data source unavailable"
          : "Request failed (" + response.status + ")",
    );
  return response.json() as Promise<T>;
}

export async function post<T>(path: string, token: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(origin + "/api/" + path, {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok) throw new Error("Preview unavailable or input rejected (" + response.status + ")");
  return response.json() as Promise<T>;
}
