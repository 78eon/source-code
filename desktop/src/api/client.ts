import { invoke, isTauri } from "@tauri-apps/api/core";
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
  if (!response.ok) {
    const error = await response.json().catch(() => null) as {detail?: unknown} | null;
    const detail = typeof error?.detail === "string" ? ": " + error.detail.slice(0, 300) : "";
    throw new Error("Request rejected (" + response.status + ")" + detail);
  }
  return response.json() as Promise<T>;
}

export async function downloadReport(path: string, token: string, filename: string): Promise<string | null> {
  const response = await fetch(origin + "/api/" + path, {headers: {Authorization: "Bearer " + token}});
  if (!response.ok) throw new Error("Stored report export unavailable (" + response.status + ")");
  const blob = await response.blob();
  const expected = {pdf:"application/pdf",html:"text/html",json:"application/json"}[filename.split(".").pop() ?? ""];
  if (!expected || blob.type.split(";")[0] !== expected) throw new Error("Unexpected report content type");
  if (isTauri()) {
    if (blob.size > 32 * 1024 * 1024) throw new Error("Report exceeds the native export size limit");
    return invoke<string | null>("save_report", {filename, bytes:Array.from(new Uint8Array(await blob.arrayBuffer()))});
  }
  const url = URL.createObjectURL(blob);
  try {const link = document.createElement("a"); link.href=url; link.download=filename; link.click();}
  finally {setTimeout(()=>URL.revokeObjectURL(url),1000);}
  return null;
}
