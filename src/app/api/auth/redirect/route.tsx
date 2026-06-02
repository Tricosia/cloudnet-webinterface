import { randomBytes } from "crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const keycloakUrl = process.env.KEYCLOAK_URL;
  const keycloakRealm = process.env.KEYCLOAK_REALM;
  const keycloakClientId = process.env.KEYCLOAK_CLIENT_ID;
  const redirectUri = `${process.env.NEXT_PUBLIC_DOMAIN}/api/auth/callback`;

  const state = randomBytes(32).toString("hex");

  const cookie = await cookies();
  cookie.set("state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 60 * 5,
    path: "/",
  });

  const queryParams = new URLSearchParams({
    client_id: keycloakClientId,
    redirect_uri: redirectUri,
    scope: "openid profile email",
    response_type: "code",
    state: state,
  }).toString();

  return NextResponse.redirect(
    `${keycloakUrl}/realms/${keycloakRealm}/protocol/openid-connect/auth?${queryParams}`,
    302,
  );
}
