const ALLOWED_ORIGINS = "*";

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGINS,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    try {
      const url = new URL(request.url);

      // Проверка Worker
      if (url.pathname === "/" && request.method === "GET") {
        return json(
          {
            ok: true,
            service: "Pipisgram Media",
            status: "working",
          },
          200,
          corsHeaders,
        );
      }

      // POST /upload
      if (url.pathname === "/upload" && request.method === "POST") {
        return await uploadFile(request, env, corsHeaders);
      }

      // GET /file?key=...
      if (url.pathname === "/file" && request.method === "GET") {
        return await downloadFile(request, env, corsHeaders);
      }

      return json(
        {
          ok: false,
          error: "Not found",
        },
        404,
        corsHeaders,
      );
    } catch (error) {
      return json(
        {
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        },
        500,
        corsHeaders,
      );
    }
  },
};

async function uploadFile(request, env, corsHeaders) {
  const url = new URL(request.url);

  const originalName =
    url.searchParams.get("filename") || "file";

  const contentType =
    request.headers.get("Content-Type") ||
    "application/octet-stream";

  if (!request.body) {
    return json(
      {
        ok: false,
        error: "Request body is empty",
      },
      400,
      corsHeaders,
    );
  }

  // Не даём пользователю засунуть в key совсем уж абсурдный путь.
  const safeName = originalName
    .replace(/\\/g, "_")
    .replace(/\//g, "_")
    .replace(/[^\w.\-() ]/g, "_")
    .slice(0, 150);

  const key =
    `${Date.now()}-${crypto.randomUUID()}-${safeName}`;

  const body = await request.arrayBuffer();

  const response = await s3Request(
    env,
    "PUT",
    key,
    body,
    contentType,
  );

  if (!response.ok) {
    const errorText = await response.text();

    return json(
      {
        ok: false,
        error: "Filebase upload failed",
        details: errorText,
      },
      502,
      corsHeaders,
    );
  }

  return json(
    {
      ok: true,
      key,
      filename: safeName,
      contentType,
    },
    200,
    corsHeaders,
  );
}

async function downloadFile(request, env, corsHeaders) {
  const url = new URL(request.url);
  const key = url.searchParams.get("key");

  if (!key) {
    return json(
      {
        ok: false,
        error: "Missing key",
      },
      400,
      corsHeaders,
    );
  }

  const response = await s3Request(
    env,
    "GET",
    key,
    null,
    null,
  );

  if (!response.ok) {
    const errorText = await response.text();

    return json(
      {
        ok: false,
        error: "Filebase download failed",
        details: errorText,
      },
      response.status === 404 ? 404 : 502,
      corsHeaders,
    );
  }

  const headers = new Headers(response.headers);

  headers.set(
    "Access-Control-Allow-Origin",
    ALLOWED_ORIGINS,
  );

  return new Response(response.body, {
    status: response.status,
    headers,
  });
}

async function s3Request(
  env,
  method,
  key,
  body,
  contentType,
) {
  const endpoint = env.FILEBASE_ENDPOINT;
  const bucket = env.FILEBASE_BUCKET;

  const endpointUrl = new URL(endpoint);

  const encodedKey = key
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  const pathname =
    `/${bucket}/${encodedKey}`;

  const host = endpointUrl.host;

  const now = new Date();

  const amzDate = now
    .toISOString()
    .replace(/[:-]|\.\d{3}/g, "");

  const dateStamp = amzDate.slice(0, 8);

  let payloadHash;

  if (body instanceof ArrayBuffer) {
    payloadHash = await sha256Hex(body);
  } else {
    payloadHash =
      "e3b0c44298fc1c149afbf4c8996fb924" +
      "27ae41e4649b934ca495991b7852b855";
  }

  const headers = {
    host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };

  if (contentType) {
    headers["content-type"] = contentType;
  }

  const canonicalHeaders =
    Object.keys(headers)
      .sort()
      .map(
        (name) =>
          `${name.toLowerCase()}:${String(headers[name]).trim()}\n`,
      )
      .join("");

  const signedHeaders =
    Object.keys(headers)
      .sort()
      .map((name) => name.toLowerCase())
      .join(";");

  const canonicalRequest = [
    method,
    pathname,
    "",
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope =
    `${dateStamp}/us-east-1/s3/aws4_request`;

  const canonicalRequestHash =
    await sha256Hex(
      new TextEncoder().encode(canonicalRequest),
    );

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    canonicalRequestHash,
  ].join("\n");

  const signingKey =
    await getSignatureKey(
      env.FILEBASE_SECRET_KEY,
      dateStamp,
      "us-east-1",
      "s3",
    );

  const signature =
    await hmacHex(
      signingKey,
      stringToSign,
    );

  const authorization =
    `AWS4-HMAC-SHA256 ` +
    `Credential=${env.FILEBASE_ACCESS_KEY}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, ` +
    `Signature=${signature}`;

  const requestHeaders = new Headers();

  for (const [name, value] of Object.entries(headers)) {
    requestHeaders.set(name, value);
  }

  requestHeaders.set(
    "Authorization",
    authorization,
  );

  const requestUrl =
    `${endpoint}${pathname}`;

  return fetch(requestUrl, {
    method,
    headers: requestHeaders,
    body: body instanceof ArrayBuffer ? body : undefined,
  });
}

async function sha256Hex(data) {
  const buffer =
    await crypto.subtle.digest(
      "SHA-256",
      data,
    );

  return [...new Uint8Array(buffer)]
    .map((byte) =>
      byte.toString(16).padStart(2, "0"),
    )
    .join("");
}

async function hmac(key, data) {
  const cryptoKey =
    await crypto.subtle.importKey(
      "raw",
      key,
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign"],
    );

  return crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(data),
  );
}

async function hmacHex(key, data) {
  const result =
    await hmac(key, data);

  return [...new Uint8Array(result)]
    .map((byte) =>
      byte.toString(16).padStart(2, "0"),
    )
    .join("");
}

async function getSignatureKey(
  secret,
  dateStamp,
  region,
  service,
) {
  const kDate =
    await hmac(
      new TextEncoder().encode(
        `AWS4${secret}`,
      ),
      dateStamp,
    );

  const kRegion =
    await hmac(
      kDate,
      region,
    );

  const kService =
    await hmac(
      kRegion,
      service,
    );

  return hmac(
    kService,
    "aws4_request",
  );
}

function json(data, status, extraHeaders = {}) {
  return new Response(
    JSON.stringify(data, null, 2),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        ...extraHeaders,
      },
    },
  );
}