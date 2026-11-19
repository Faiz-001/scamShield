// In development Vite proxies /api to the Express server, so BASE is empty.
// In production, set VITE_API_URL to the deployed API address.
const BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

export class ApiError extends Error {}

/** Send a message to the checker. Resolves with the result object or throws an ApiError with a user-friendly message. */
export async function checkMessage(message, { signal } = {}) {
  let res;
  try {
    res = await fetch(`${BASE}/api/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
      signal,
    });
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError(
      "We couldn't reach the checker. Please check your internet connection and try again."
    );
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    // The server sent something that is not JSON; handled below.
  }

  if (!res.ok) {
    throw new ApiError(
      (data && data.error) ||
        (res.status === 429
          ? 'Too many checks in a short time. Please wait a few minutes and try again.'
          : 'Something went wrong on our side. Please try again.')
    );
  }
  if (!data || !data.verdict) {
    throw new ApiError('We got an unexpected reply. Please try again.');
  }
  return data;
}
