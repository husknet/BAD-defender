// utils/fingerprint.js

export async function collectFingerprintAndSend(ip) {
  // Dynamically load the FingerprintJS script
  const fpModule = await import('https://openfpcdn.io/fingerprintjs/v3');

  const fpPromise = fpModule.default.load();
  const fp = await fpPromise;
  const result = await fp.get();

  const fingerprintScore = result.bot?.probability || 0;

  const payload = {
    ip, // this must be passed from your backend or client IP library
    user_agent: navigator.userAgent,
    fingerprint_score: fingerprintScore,
  };

  try {
    const response = await fetch('/pages/api/detect_bot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Bot detection request failed:', error);
    return null;
  }
}
