/**
 * GET /api/auth/login
 * Kicks off TikTok OAuth flow
 */
export async function onRequestGet(context) {
  const { env } = context;

  const clientKey = env.TIKTOK_CLIENT_KEY;
  const redirectUri = env.TIKTOK_REDIRECT_URI; // e.g. https://bigdogclub.vip/api/auth/callback

  // PKCE code verifier + challenge
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // State for CSRF protection
  const state = crypto.randomUUID();

  // Scopes — add user.social.following.write if Follow API is approved
  const scopes = [
    'user.info.basic',
    'user.info.profile',
  ].join(',');

  const authUrl = new URL('https://www.tiktok.com/v2/auth/authorize');
  authUrl.searchParams.set('client_key', clientKey);
  authUrl.searchParams.set('scope', scopes);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  // Store verifier + state in a short-lived cookie
  const cookieValue = JSON.stringify({ codeVerifier, state });
  const encoded = btoa(cookieValue);

  return new Response(null, {
    status: 302,
    headers: {
      'Location': authUrl.toString(),
      'Set-Cookie': `tt_oauth=${encoded}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
    },
  });
}

// ── PKCE helpers ──

function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(buffer) {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
