const ALLOWED_ORIGINS = "*";

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGINS,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    try {
      const url = new URL(request.url);

      // GET /health
      if (url.pathname === "/health" && request.method === "GET") {
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

      // POST /economy/clicker/tap
      if (
        url.pathname === "/economy/clicker/tap" &&
        request.method === "POST"
      ) {
        return await clickerTap(request, env, corsHeaders);
      }

      // POST /economy/clicker/cashout
      if (
        url.pathname === "/economy/clicker/cashout" &&
        request.method === "POST"
      ) {
        return await clickerCashOut(request, env, corsHeaders);
      }

      // POST /economy/guess
      if (
        url.pathname === "/economy/guess" &&
        request.method === "POST"
      ) {
        return await guessNumber(request, env, corsHeaders);
      }

      // POST /economy/dino/cashout
      if (
        url.pathname === "/economy/dino/cashout" &&
        request.method === "POST"
      ) {
        return await dinoCashOut(request, env, corsHeaders);
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
      if (error instanceof HttpError) {
        return json(
          {
            ok: false,
            error: error.message,
          },
          error.status,
          corsHeaders,
        );
      }

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


async function requireFirebaseUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    throw new HttpError(401, "Missing Firebase ID token");
  }

  if (!env.FIREBASE_PROJECT_ID) {
    throw new HttpError(503, "FIREBASE_PROJECT_ID is not configured");
  }

  const idToken = auth.slice("Bearer ".length).trim();
  if (!idToken) {
    throw new HttpError(401, "Missing Firebase ID token");
  }

  const response = await fetch(
    "https://oauth2.googleapis.com/tokeninfo?id_token=" +
      encodeURIComponent(idToken),
  );

  if (!response.ok) {
    throw new HttpError(401, "Invalid Firebase ID token");
  }

  const token = await response.json();

  const expectedIssuer =
    "https://securetoken.google.com/" + env.FIREBASE_PROJECT_ID;

  if (
    token.aud !== env.FIREBASE_PROJECT_ID ||
    token.iss !== expectedIssuer ||
    !token.user_id
  ) {
    throw new HttpError(401, "Invalid Firebase ID token");
  }

  const exp = Number(token.exp);
  if (!Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) {
    throw new HttpError(401, "Firebase ID token expired");
  }

  return token.user_id;
}

async function getFirestoreAccessToken(env) {
  if (
    !env.FIREBASE_SERVICE_ACCOUNT_EMAIL ||
    !env.FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY
  ) {
    throw new HttpError(
      503,
      "Firebase service account is not configured",
    );
  }

  const now = Math.floor(Date.now() / 1000);

  const header = base64UrlJson({
    alg: "RS256",
    typ: "JWT",
  });

  const claim = base64UrlJson({
    iss: env.FIREBASE_SERVICE_ACCOUNT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  });

  const unsigned = header + "." + claim;
  const keyData = pemToArrayBuffer(
    env.FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY,
  );

  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned),
  );

  const assertion =
    unsigned + "." + base64UrlBytes(new Uint8Array(signature));

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type:
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    },
  );

  if (!response.ok) {
    throw new HttpError(
      503,
      "Failed to obtain Firestore access token",
    );
  }

  const data = await response.json();
  if (!data.access_token) {
    throw new HttpError(
      503,
      "Firestore access token is missing",
    );
  }

  return data.access_token;
}

async function firestoreRequest(
  env,
  accessToken,
  path,
  method,
  body,
) {
  const url =
    "https://firestore.googleapis.com/v1/projects/" +
    encodeURIComponent(env.FIREBASE_PROJECT_ID) +
    "/databases/(default)/documents" +
    path;

  const response = await fetch(url, {
    method,
    headers: {
      Authorization: "Bearer " + accessToken,
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    const message =
      data?.error?.message || "Firestore request failed";
    throw new HttpError(502, message);
  }

  return data;
}

function firestoreDocumentName(env, collection, docId) {
  return (
    "projects/" +
    env.FIREBASE_PROJECT_ID +
    "/databases/(default)/documents/" +
    collection +
    "/" +
    docId
  );
}

function firestoreInt(value) {
  return {
    integerValue: String(value),
  };
}

function readFirestoreInt(document, fieldName, fallback = 0) {
  const value = document?.fields?.[fieldName];

  if (!value) return fallback;

  if (value.integerValue !== undefined) {
    return Number(value.integerValue);
  }

  if (value.doubleValue !== undefined) {
    return Math.trunc(Number(value.doubleValue));
  }

  return fallback;
}

async function runFirestoreTransaction(
  env,
  accessToken,
  documents,
  buildWrites,
) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const started = await firestoreRequest(
      env,
      accessToken,
      ":beginTransaction",
      "POST",
      {
        options: {
          readWrite: {},
        },
      },
    );

    const transaction = started.transaction;

    const batch = await firestoreRequest(
      env,
      accessToken,
      ":batchGet",
      "POST",
      {
        documents,
        transaction,
      },
    );

    const found = Array.isArray(batch)
      ? batch.filter((item) => item.found).map((item) => item.found)
      : [];

    const writes = buildWrites(found);

    if (!writes) {
      return null;
    }

    try {
      return await firestoreRequest(
        env,
        accessToken,
        ":commit",
        "POST",
        {
          transaction,
          writes,
        },
      );
    } catch (error) {
      if (
        error instanceof HttpError &&
        error.status === 409 &&
        attempt < 2
      ) {
        continue;
      }
      throw error;
    }
  }

  throw new HttpError(409, "Firestore transaction conflict");
}

async function clickerTap(request, env, corsHeaders) {
  const uid = await requireFirebaseUser(request, env);

  let payload = {};
  try {
    payload = await request.json();
  } catch (_) {
    payload = {};
  }

  const date = String(payload.date || "");
  if (!isReasonableClientDate(date)) {
    return json(
      {
        ok: false,
        error: "Invalid or stale clicker date",
      },
      400,
      corsHeaders,
    );
  }

  const accessToken = await getFirestoreAccessToken(env);
  const gameDocId = uid + "_clicker_" + date;

  const gameName = firestoreDocumentName(
    env,
    "gameStats",
    gameDocId,
  );

  let accepted = false;
  let taps = 0;

  await runFirestoreTransaction(
    env,
    accessToken,
    [gameName],
    (found) => {
      const game = found.find(
        (document) => document.name === gameName,
      );

      const current = readFirestoreInt(game, "taps");
      taps = current;
      if (current >= 1000) {
        return [];
      }

      accepted = true;
      taps = current + 1;

      return [
        {
          update: {
            name: gameName,
            fields: {
              taps: firestoreInt(current + 1),
            },
          },
          updateMask: {
            fieldPaths: ["taps"],
          },
        },
      ];
    },
  );

  return json(
    {
      ok: true,
      accepted,
      taps,
    },
    200,
    corsHeaders,
  );
}

async function clickerCashOut(request, env, corsHeaders) {
  const uid = await requireFirebaseUser(request, env);

  let payload = {};
  try {
    payload = await request.json();
  } catch (_) {
    payload = {};
  }

  const date = String(payload.date || "");
  if (!isReasonableClientDate(date)) {
    return json(
      {
        ok: false,
        error: "Invalid or stale clicker date",
      },
      400,
      corsHeaders,
    );
  }

  const accessToken = await getFirestoreAccessToken(env);

  const gameDocId = uid + "_clicker_" + date;
  const gameName = firestoreDocumentName(
    env,
    "gameStats",
    gameDocId,
  );
  const userName = firestoreDocumentName(
    env,
    "users",
    uid,
  );

  let payout = 0;
  let remainingTaps = 0;

  const result = await runFirestoreTransaction(
    env,
    accessToken,
    [gameName, userName],
    (found) => {
      const game = found.find(
        (document) => document.name === gameName,
      );
      const user = found.find(
        (document) => document.name === userName,
      );

      const taps = Math.max(
        0,
        Math.min(1000, readFirestoreInt(game, "taps")),
      );
      const cashedOutTaps = Math.max(
        0,
        Math.min(taps, readFirestoreInt(game, "cashedOutTaps")),
      );
      const availableTaps = taps - cashedOutTaps;

      payout = Math.floor((availableTaps * 3) / 10);
      if (payout <= 0 || !user) {
        remainingTaps = availableTaps;
        return [];
      }

      const tapsToCashOut = Math.floor(
        (payout * 10) / 3,
      );

      const stars = Math.max(
        0,
        readFirestoreInt(user, "shadowStars"),
      );

      remainingTaps =
        availableTaps - tapsToCashOut;

      return [
        {
          update: {
            name: userName,
            fields: {
              shadowStars: firestoreInt(stars + payout),
            },
          },
          updateMask: {
            fieldPaths: ["shadowStars"],
          },
        },
        {
          update: {
            name: gameName,
            fields: {
              cashedOutTaps: firestoreInt(
                cashedOutTaps + tapsToCashOut,
              ),
            },
          },
          updateMask: {
            fieldPaths: ["cashedOutTaps"],
          },
        },
      ];
    },
  );

  if (result === null) {
    payout = 0;
  }

  return json(
    {
      ok: true,
      stars: payout,
      remainingTaps,
    },
    200,
    corsHeaders,
  );
}

async function guessNumber(request, env, corsHeaders) {
  const uid = await requireFirebaseUser(request, env);

  let payload = {};
  try {
    payload = await request.json();
  } catch (_) {
    payload = {};
  }

  const date = String(payload.date || "");
  const number = Number(payload.number);

  if (!isReasonableClientDate(date)) {
    return json(
      {
        ok: false,
        error: "Invalid or stale guess date",
      },
      400,
      corsHeaders,
    );
  }

  if (!Number.isInteger(number) || number < 1 || number > 15) {
    return json(
      {
        ok: false,
        error: "Guess must be an integer from 1 to 15",
      },
      400,
      corsHeaders,
    );
  }

  const accessToken = await getFirestoreAccessToken(env);
  const gameDocId = uid + "_guess_" + date;
  const gameName = firestoreDocumentName(env, "gameStats", gameDocId);
  const userName = firestoreDocumentName(env, "users", uid);

  // Секрет генерируется на сервере, а не в APK.
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  const secretNumber = (random[0] % 15) + 1;
  const won = number === secretNumber;

  let attempts = 0;
  let attemptsLeft = 0;

  const result = await runFirestoreTransaction(
    env,
    accessToken,
    [gameName, userName],
    (found) => {
      const game = found.find((document) => document.name === gameName);
      const user = found.find((document) => document.name === userName);

      const used = Math.max(
        0,
        Math.min(3, readFirestoreInt(game, "attempts")),
      );

      if (used >= 3) {
        attempts = used;
        attemptsLeft = 0;
        return [];
      }

      if (won && !user) {
        throw new HttpError(500, "User document not found");
      }

      attempts = used + 1;
      attemptsLeft = 3 - attempts;

      const writes = [
        {
          update: {
            name: gameName,
            fields: {
              attempts: firestoreInt(attempts),
            },
          },
          updateMask: {
            fieldPaths: ["attempts"],
          },
        },
      ];

      if (won) {
        const stars = Math.max(
          0,
          readFirestoreInt(user, "shadowStars"),
        );

        writes.push({
          update: {
            name: userName,
            fields: {
              shadowStars: firestoreInt(stars + 1),
            },
          },
          updateMask: {
            fieldPaths: ["shadowStars"],
          },
        });
      }

      return writes;
    },
  );

  return json(
    {
      ok: true,
      accepted: attempts > 0,
      won: attempts > 0 && won,
      secretNumber: attempts > 0 ? secretNumber : null,
      attemptsLeft,
      starsAwarded: attempts > 0 && won ? 1 : 0,
    },
    200,
    corsHeaders,
  );
}

async function dinoCashOut(request, env, corsHeaders) {
  const uid = await requireFirebaseUser(request, env);

  let payload = {};
  try {
    payload = await request.json();
  } catch (_) {
    payload = {};
  }

  const jumps = Number(payload.jumps);

  if (!Number.isInteger(jumps) || jumps <= 0 || jumps > 10000) {
    return json(
      {
        ok: false,
        error: "Invalid jumps",
      },
      400,
      corsHeaders,
    );
  }

  const payout = Math.floor(jumps / 2);
  if (payout <= 0) {
    return json(
      {
        ok: true,
        stars: 0,
        accepted: true,
      },
      200,
      corsHeaders,
    );
  }

  const accessToken = await getFirestoreAccessToken(env);
  const userName = firestoreDocumentName(env, "users", uid);

  let stars = 0;

  await runFirestoreTransaction(
    env,
    accessToken,
    [userName],
    (found) => {
      const user = found.find((document) => document.name === userName);
      if (!user) {
        throw new HttpError(500, "User document not found");
      }

      const currentStars = Math.max(
        0,
        readFirestoreInt(user, "shadowStars"),
      );

      stars = currentStars + payout;

      return [
        {
          update: {
            name: userName,
            fields: {
              shadowStars: firestoreInt(stars),
            },
          },
          updateMask: {
            fieldPaths: ["shadowStars"],
          },
        },
      ];
    },
  );

  return json(
    {
      ok: true,
      stars: payout,
      accepted: true,
    },
    200,
    corsHeaders,
  );
}

function isReasonableClientDate(value) {
  if (!/^\d{4}-\d{1,2}-\d{1,2}$/.test(value)) {
    return false;
  }

  const [year, month, day] = value
    .split("-")
    .map(Number);

  const date = new Date(
    Date.UTC(year, month - 1, day),
  );

  if (
    Number.isNaN(date.getTime()) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return false;
  }

  const now = new Date();
  const today = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  );
  const supplied = date.getTime();

  return Math.abs(today - supplied) <= 86400000;
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function base64UrlBytes(bytes) {
  let binary = "";
  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunk),
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlJson(value) {
  return base64UrlBytes(
    new TextEncoder().encode(JSON.stringify(value)),
  );
}

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

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

  const region = env.FILEBASE_REGION || "auto";

const credentialScope =
  `${dateStamp}/${region}/s3/aws4_request`;

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
    region,
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