import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import net from "net";

/**
 * This route is used to sign in the user and set the cookies.
 */
export async function POST(request: NextRequest) {
  const cookie = await cookies();
  // if POST is not json, return 400
  if (request.headers.get("content-type") !== "application/json") {
    return NextResponse.json({ error: "Invalid content type", status: 400 });
  }
  if (!request.body) {
    return NextResponse.json({ error: "No body provided", status: 400 });
  }

  const domainUrl = new URL(process.env.NEXT_PUBLIC_DOMAIN);
  const isSecure = domainUrl.protocol === "https:";

  const setCookie = async (
    name: string,
    value: string,
    expiresIn: number,
    httpOnly: boolean = true,
  ) => {
    cookie.set(name, value, {
      httpOnly: httpOnly,
      secure: isSecure,
      sameSite: "strict",
      maxAge: expiresIn,
      path: "/",
    });
  };

  let { username, password } = await request.json();

  const address = process.env.CLOUDNET_REST_ENDPOINT;

  const normalizeAndValidateAddress = (rawAddress: string): string => {
    if (typeof rawAddress !== "string" || rawAddress.trim() === "") {
      throw new Error("Invalid address");
    }

    let addr = rawAddress.trim();

    // Ensure a scheme is present so URL parsing is reliable
    // IP addresses default to http (CloudNet REST API), domains to https
    if (!addr.startsWith("http://") && !addr.startsWith("https://")) {
      const hostPart = addr.split("/")[0].split(":")[0];
      addr = net.isIP(hostPart) ? `http://${addr}` : `https://${addr}`;
    }

    let url: URL;
    try {
      url = new URL(addr);
    } catch {
      throw new Error("Invalid address");
    }

    // Only allow http/https
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("Invalid address protocol");
    }

    // Ensure path ends with /api/v3
    if (!url.pathname.endsWith("/api/v3")) {
      // Trim any trailing slash then append /api/v3
      const basePath = url.pathname.replace(/\/+$/, "");
      url.pathname = basePath + "/api/v3";
    }

    // Clear hash to avoid confusing downstream logic
    url.hash = "";

    return url.toString().replace(/\/+$/, "");
  };

  let validatedAddress: string;
  try {
    validatedAddress = normalizeAndValidateAddress(address);
  } catch (e) {
    return NextResponse.json(
      { error: "Incorrect address!", status: 400 },
      { status: 400 },
    );
  }

  try {
    const basicAuth = Buffer.from(`${username}:${password}`).toString("base64");
    const response = await fetch(`${validatedAddress}/auth`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/json",
      },
    });

    const dataResponse = await response.json();

    if (dataResponse.name === "SyntaxError") {
      return NextResponse.json({ error: "Invalid response", status: 404 });
    }

    if (dataResponse.status === 401) {
      return NextResponse.json({ error: "Invalid credentials", status: 401 });
    }

    const expirationAccessTime = Number(
      new Date(Date.now() + dataResponse.accessToken.expiresIn),
    );
    const expirationRefreshTime = Number(
      new Date(Date.now() + dataResponse.refreshToken.expiresIn),
    );

    await setCookie(
      "add",
      validatedAddress,
      dataResponse.refreshToken.expiresIn,
    );
    await setCookie("at", dataResponse.accessToken.token, expirationAccessTime);
    await setCookie(
      "rt",
      dataResponse.refreshToken.token,
      expirationRefreshTime,
    );
    await setCookie(
      "permissions",
      JSON.stringify(dataResponse.scopes),
      expirationAccessTime,
    );

    return NextResponse.json(dataResponse);
  } catch (error) {
    if (error.message === "fetch failed") {
      return NextResponse.json(
        { error: "Incorrect address!", status: 404 },
        { status: 404 },
      );
    }
    return NextResponse.json(
      { error: error.message || "Internal server error" },
      { status: 500 },
    );
  }
}
