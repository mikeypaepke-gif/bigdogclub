/**
 * GET /api/auth/callback
 * Handles TikTok OAuth callback — exchanges code for token, auto-follows, sets session
 */

const TIKTOK_ACCOUNTS_TO_FOLLOW = [
  // Add open_id values here once known, OR use usernames via the API
  // For now we attempt follow by username lookup after auth
];

const FOLLOW_USERNAMES = ['patrickbigdog', 'bigdogclub']; // update 2nd handle when confirmed

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  // Handle user denial
  if (error) {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=denied`, 302);
  }

  if (!code) {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=no_code`, 302);
  }

  // Retrieve + validate PKCE cookie
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookieMatch = cookieHeader.match(/tt_oauth=([^;]+)/);
  if (!cookieMatch) {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=session_expired`, 302);
  }

  let codeVerifier, state;
  try {
    const decoded = JSON.parse(atob(cookieMatch[1]));
    codeVerifier = decoded.codeVerifier;
    state = decoded.state;
  } catch {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=invalid_session`, 302);
  }

  // CSRF state check
  if (state !== returnedState) {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=state_mismatch`, 302);
  }

  // ── Exchange code for access token ──
  let tokenData;
  try {
    const tokenRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key: env.TIKTOK_CLIENT_KEY,
        client_secret: env.TIKTOK_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: env.TIKTOK_REDIRECT_URI,
        code_verifier: codeVerifier,
      }),
    });
    tokenData = await tokenRes.json();
  } catch (err) {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=token_exchange_failed`, 302);
  }

  if (!tokenData.access_token) {
    return Response.redirect(`${env.APP_BASE_URL}/join?error=no_token`, 302);
  }

  const { access_token, open_id } = tokenData;

  // ── Fetch user info ──
  let userInfo = {};
  try {
    const userRes = await fetch(
      'https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,username',
      { headers: { Authorization: `Bearer ${access_token}` } }
    );
    const userData = await userRes.json();
    userInfo = userData?.data?.user || {};
  } catch {}

  // ── Attempt auto-follow (requires user.social.following.write scope) ──
  // This will silently fail if the scope isn't approved yet
  for (const username of FOLLOW_USERNAMES) {
    try {
      await fetch('https://open.tiktokapis.com/v2/user/following/', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username }),
      });
    } catch {}
  }

  // ── Create session cookie ──
  const session = {
    open_id,
    display_name: userInfo.display_name || '',
    avatar_url: userInfo.avatar_url || '',
    joined_at: Date.now(),
  };
  const sessionEncoded = btoa(JSON.stringify(session));

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.APP_BASE_URL}/welcome`,
      'Set-Cookie': [
        // Clear the OAuth temp cookie
        `tt_oauth=; Path=/; HttpOnly; Secure; Max-Age=0`,
        // Set session
        `bdc_session=${sessionEncoded}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`,
      ].join(', '),
    },
  });
}
