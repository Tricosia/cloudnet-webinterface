import { cookies } from "next/headers";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");

  if (!code) {
    return new Response("No code provided", { status: 400 });
  }

  if (!state) {
    return new Response("No state provided", { status: 400 });
  }

  const cookie = await cookies();
  const storedState = cookie.get("state")?.value;

  if (storedState !== state) {
    return new Response("State mismatch", { status: 400 });
  }

  const keycloakUrl = process.env.KEYCLOAK_URL;
  const keycloakRealm = process.env.KEYCLOAK_REALM;
  const keycloakClientId = process.env.KEYCLOAK_CLIENT_ID;
  const keycloakClientSecret = process.env.KEYCLOAK_CLIENT_SECRET;

  const origin = process.env.NEXT_PUBLIC_DOMAIN;
  const redirectUri = `${origin}/api/auth/callback`;

  const tokenUrl = `${keycloakUrl}/realms/${keycloakRealm}/protocol/openid-connect/token`;
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: keycloakClientId,
      client_secret: keycloakClientSecret,
      code: code,
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    return new Response("Failed to fetch token", { status: 500 });
  }

  const data = await response.json();

  if (!data.access_token) {
    return new Response("No access token provided", { status: 500 });
  }

  const base64Payload = data.access_token.split(".")[1];
  const payload = JSON.parse(atob(base64Payload));

  const roles = payload["resource_access"]?.[keycloakClientId]?.roles;

  let username = null;
  let password = null;

  if (roles && roles.includes("cloudnet-admin")) {
    username = process.env.CLOUDNET_ADMIN_USERNAME;
    password = process.env.CLOUDNET_ADMIN_PASSWORD;
  } else if (roles && roles.includes("cloudnet-access")) {
    username = process.env.CLOUDNET_ACCESS_USERNAME;
    password = process.env.CLOUDNET_ACCESS_PASSWORD;
  }

  const signinResponse = await fetch(`http://127.0.0.1:3000/api/auth/signin`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: request.headers.get("cookie") || "",
    },
    body: JSON.stringify({ username, password }),
  });

  if (!signinResponse.ok) {
    return new Response("Failed to sign in", {
      status: 500,
    });
  }

  const responseHeaders = new Headers();
  const setCookieHeaders = signinResponse.headers.getSetCookie();

  for (const cookie of setCookieHeaders) {
    responseHeaders.append("Set-Cookie", cookie);
  }

  responseHeaders.set("Location", `${origin}/dashboard`);
  return new Response(null, {
    status: 302,
    headers: responseHeaders,
  });
}
