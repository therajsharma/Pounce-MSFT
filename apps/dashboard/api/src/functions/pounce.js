const { app } = require('@azure/functions');

const JSON_HEADERS = {
  'Content-Type': 'application/json'
};

function upstreamBaseUrl() {
  return (process.env.POUNCE_SENTINEL_API_BASE_URL || 'http://localhost:7071/api').replace(/\/$/, '');
}

async function proxy(request, context, upstreamPath) {
  const apiKey = process.env.POUNCE_SENTINEL_API_KEY;
  const headers = {
    'Content-Type': 'application/json',
    ...(apiKey ? { 'x-functions-key': apiKey } : {})
  };

  const init = {
    method: request.method,
    headers
  };

  if (!['GET', 'HEAD'].includes(request.method)) {
    init.body = await request.text();
  }

  try {
    const response = await fetch(`${upstreamBaseUrl()}${upstreamPath}`, init);
    const body = await response.text();
    return {
      status: response.status,
      headers: {
        'Content-Type': response.headers.get('content-type') || 'application/json'
      },
      body
    };
  } catch (error) {
    context.error('Pounce dashboard proxy failed', error);
    return {
      status: 502,
      headers: JSON_HEADERS,
      jsonBody: {
        error: 'Pounce policy API is unreachable',
        detail: error instanceof Error ? error.message : String(error)
      }
    };
  }
}

app.http('status', {
  route: 'v1/status',
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: (request, context) => proxy(request, context, '/v1/status')
});

app.http('verdicts', {
  route: 'v1/verdicts',
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: (request, context) => proxy(request, context, '/v1/verdicts')
});

app.http('exceptions', {
  route: 'v1/exceptions',
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: (request, context) => proxy(request, context, '/v1/exceptions')
});

app.http('vetDependency', {
  route: 'v1/vet-dependency',
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: (request, context) => proxy(request, context, '/v1/vet-dependency')
});

app.http('scanManifest', {
  route: 'v1/scan-manifest',
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: (request, context) => proxy(request, context, '/v1/scan-manifest')
});
