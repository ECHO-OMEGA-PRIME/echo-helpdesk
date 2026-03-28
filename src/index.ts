/**
 * Echo Helpdesk v1.0.0 — AI-Powered Customer Support Platform
 * =============================================================
 * Ticket management, SLA tracking, AI auto-responses, knowledge base,
 * multi-channel support, agent assignment, automations, CSAT surveys.
 * Competes with Zendesk, Freshdesk, Intercom at 1/10th the cost.
 */

import { Hono } from 'hono';

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  SPEAK_CLOUD: Fetcher;
  ECHO_API_KEY: string;
}

type HonoEnv = { Bindings: Env };

const app = new Hono<HonoEnv>();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
});

// Structured logger
function log(level: 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-helpdesk', message, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

function generateId(): string { return crypto.randomUUID(); }

function parsePagination(c: { req: { query: (k: string) => string | undefined } }) {
  const limit = Math.min(parseInt(c.req.query('limit') || '50') || 50, 200);
  const offset = parseInt(c.req.query('offset') || '0') || 0;
  return { limit, offset };
}

// ─── Rate Limiting ──────────────────────────────────────────────────
interface RLState { c: number; t: number }
async function checkRateLimit(kv: KVNamespace, key: string, limit: number, windowSec: number): Promise<{ allowed: boolean; remaining: number; reset: number }> {
  const rlKey = `rl:${key}`;
  const now = Math.floor(Date.now() / 1000);
  const raw = await kv.get(rlKey, 'json') as RLState | null;
  let count: number, windowStart: number;
  if (!raw || (now - raw.t) >= windowSec) { count = 1; windowStart = now; }
  else { const elapsed = now - raw.t; const decay = Math.max(0, 1 - elapsed / windowSec); count = Math.floor(raw.c * decay) + 1; windowStart = raw.t; }
  const allowed = count <= limit;
  await kv.put(rlKey, JSON.stringify({ c: count, t: windowStart } as RLState), { expirationTtl: windowSec * 2 });
  return { allowed, remaining: Math.max(0, limit - count), reset: windowSec - (now - windowStart) };
}

function sanitize(input: string, maxLen = 5000): string {
  if (typeof input !== 'string') return '';
  return input.slice(0, maxLen).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

function sanitizeBody(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) {
    out[k] = typeof v === 'string' ? sanitize(v) : v;
  }
  return out;
}

// ─── CORS ───────────────────────────────────────────────────────────
app.use('*', async (c, next) => {
  await next();
  const origin = c.req.header('Origin') || '';
  const allowed = ['https://echo-ept.com', 'https://www.echo-ept.com', 'https://echo-op.com', 'http://localhost:3000'];
  if (origin && allowed.includes(origin)) {
    c.header('Access-Control-Allow-Origin', origin);
    c.header('Vary', 'Origin');
  } else if (!origin) {
    c.header('Access-Control-Allow-Origin', allowed[0]);
  }
  c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, X-Echo-API-Key, Authorization, X-Tenant-ID');
});
app.options('*', (c) => c.body(null, 204));

// ─── Rate Limiting Middleware ───────────────────────────────────────
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/') return next();
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(c.req.method);
  const { allowed, remaining, reset } = await checkRateLimit(c.env.CACHE, `hd:${ip}:${isWrite ? 'w' : 'r'}`, isWrite ? 60 : 200, 60);
  if (!allowed) return c.json({ error: 'Rate limit exceeded', retry_after: reset }, 429);
  c.header('X-RateLimit-Remaining', String(remaining));
  return next();
});

// ─── Auth Middleware ────────────────────────────────────────────────
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  const method = c.req.method;
  // Public: GET, OPTIONS, health
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health') return next();
  // Writes require API key
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return c.json({ error: 'Unauthorized', message: 'Valid X-Echo-API-Key or Bearer token required for write operations' }, 401);
  }
  return next();
});

// ─── Tenant extraction ──────────────────────────────────────────────
function getTenantId(c: { req: { header: (n: string) => string | undefined; query: (n: string) => string | undefined } }): string {
  return c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || 'default';
}

// ─── Health ─────────────────────────────────────────────────────────
app.get('/', (c) => c.redirect('/health'));
app.get('/health', async (c) => {
  try {
    await c.env.DB.prepare('SELECT 1').first();
    return c.json({ ok: true, service: 'echo-helpdesk', version: '1.0.0', d1: 'connected', ts: new Date().toISOString() });
  } catch {
    return c.json({ ok: false, service: 'echo-helpdesk', d1: 'error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// TENANTS
// ═══════════════════════════════════════════════════════════════════
app.get('/tenants', async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM tenants ORDER BY created_at DESC').all();
  return c.json({ tenants: rows.results });
});

app.post('/tenants', async (c) => {
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO tenants (id, name, domain, plan) VALUES (?, ?, ?, ?)').bind(id, body.name, body.domain || null, body.plan || 'starter').run();
  return c.json({ id, created: true }, 201);
});

// ═══════════════════════════════════════════════════════════════════
// AGENTS
// ═══════════════════════════════════════════════════════════════════
app.get('/agents', async (c) => {
  const tid = getTenantId(c);
  const status = c.req.query('status');
  let sql = 'SELECT * FROM agents WHERE tenant_id = ?';
  const params: unknown[] = [tid];
  if (status) { sql += ' AND status = ?'; params.push(status); }
  sql += ' ORDER BY name ASC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ agents: rows.results });
});

app.post('/agents', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO agents (id, tenant_id, name, email, role, specialties, max_tickets) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, tid, body.name, body.email, body.role || 'agent', JSON.stringify(body.specialties || []), body.max_tickets || 20).run();
  return c.json({ id, created: true }, 201);
});

app.get('/agents/:id', async (c) => {
  const tid = getTenantId(c);
  const agent = await c.env.DB.prepare('SELECT * FROM agents WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
  if (!agent) return c.json({ error: 'Agent not found' }, 404);
  const open = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE assigned_agent_id = ? AND status IN ('open','pending')").bind(agent.id).first();
  const resolved = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE assigned_agent_id = ? AND status = 'resolved'").bind(agent.id).first();
  const avgSat = await c.env.DB.prepare('SELECT AVG(rating) as avg_rating FROM satisfaction_surveys WHERE agent_id = ?').bind(agent.id).first();
  return c.json({ ...agent, open_tickets: (open as Record<string, unknown>)?.cnt || 0, resolved_tickets: (resolved as Record<string, unknown>)?.cnt || 0, avg_satisfaction: (avgSat as Record<string, unknown>)?.avg_rating || null });
});

app.put('/agents/:id', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const fields: string[] = [];
  const vals: unknown[] = [];
  for (const [k, v] of Object.entries(body)) {
    if (['name', 'email', 'role', 'status', 'avatar_url', 'signature', 'is_active', 'max_tickets'].includes(k)) {
      fields.push(`${k} = ?`);
      vals.push(v);
    }
    if (k === 'specialties') { fields.push('specialties = ?'); vals.push(JSON.stringify(v)); }
  }
  if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);
  vals.push(c.req.param('id'), tid);
  await c.env.DB.prepare(`UPDATE agents SET ${fields.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();
  return c.json({ updated: true });
});

app.delete('/agents/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('UPDATE tickets SET assigned_agent_id = NULL WHERE assigned_agent_id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  await c.env.DB.prepare('DELETE FROM team_members WHERE agent_id = ?').bind(c.req.param('id')).run();
  await c.env.DB.prepare('DELETE FROM agents WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// TEAMS
// ═══════════════════════════════════════════════════════════════════
app.get('/teams', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare('SELECT * FROM teams WHERE tenant_id = ? ORDER BY name').bind(tid).all();
  return c.json({ teams: rows.results });
});

app.post('/teams', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO teams (id, tenant_id, name, description, lead_agent_id) VALUES (?, ?, ?, ?, ?)').bind(id, tid, body.name, body.description || null, body.lead_agent_id || null).run();
  return c.json({ id, created: true }, 201);
});

app.post('/teams/:id/members', async (c) => {
  const body = await c.req.json() as Record<string, unknown>;
  await c.env.DB.prepare('INSERT OR IGNORE INTO team_members (team_id, agent_id) VALUES (?, ?)').bind(c.req.param('id'), body.agent_id).run();
  return c.json({ added: true }, 201);
});

app.delete('/teams/:id/members/:agentId', async (c) => {
  await c.env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND agent_id = ?').bind(c.req.param('id'), c.req.param('agentId')).run();
  return c.json({ removed: true });
});

app.get('/teams/:id/members', async (c) => {
  const rows = await c.env.DB.prepare('SELECT a.* FROM agents a JOIN team_members tm ON a.id = tm.agent_id WHERE tm.team_id = ?').bind(c.req.param('id')).all();
  return c.json({ members: rows.results });
});

app.delete('/teams/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM team_members WHERE team_id = ?').bind(c.req.param('id')).run();
  await c.env.DB.prepare('DELETE FROM teams WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// CUSTOMERS
// ═══════════════════════════════════════════════════════════════════
app.get('/customers', async (c) => {
  const tid = getTenantId(c);
  const { limit, offset } = parsePagination(c);
  const search = c.req.query('search');
  let sql = 'SELECT * FROM customers WHERE tenant_id = ?';
  const params: unknown[] = [tid];
  if (search) { sql += " AND (name LIKE ? OR email LIKE ? OR company LIKE ?)"; const s = `%${search}%`; params.push(s, s, s); }
  sql += ' ORDER BY updated_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  const total = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM customers WHERE tenant_id = ?').bind(tid).first();
  return c.json({ customers: rows.results, total: (total as Record<string, unknown>)?.cnt || 0, limit, offset });
});

app.post('/customers', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO customers (id, tenant_id, name, email, phone, company, channel, timezone, language, tags, custom_fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(id, tid, body.name, body.email || null, body.phone || null, body.company || null, body.channel || 'email', body.timezone || null, body.language || 'en', JSON.stringify(body.tags || []), JSON.stringify(body.custom_fields || {})).run();
  return c.json({ id, created: true }, 201);
});

app.get('/customers/:id', async (c) => {
  const tid = getTenantId(c);
  const cust = await c.env.DB.prepare('SELECT * FROM customers WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
  if (!cust) return c.json({ error: 'Customer not found' }, 404);
  const tickets = await c.env.DB.prepare('SELECT id, ticket_number, subject, status, priority, created_at FROM tickets WHERE customer_id = ? ORDER BY created_at DESC LIMIT 10').bind(cust.id).all();
  return c.json({ ...cust, recent_tickets: tickets.results });
});

app.put('/customers/:id', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const fields: string[] = [];
  const vals: unknown[] = [];
  for (const [k, v] of Object.entries(body)) {
    if (['name', 'email', 'phone', 'company', 'avatar_url', 'channel', 'timezone', 'language'].includes(k)) {
      fields.push(`${k} = ?`); vals.push(v);
    }
    if (k === 'tags' || k === 'custom_fields') { fields.push(`${k} = ?`); vals.push(JSON.stringify(v)); }
  }
  if (fields.length === 0) return c.json({ error: 'No fields' }, 400);
  fields.push("updated_at = datetime('now')");
  vals.push(c.req.param('id'), tid);
  await c.env.DB.prepare(`UPDATE customers SET ${fields.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();
  return c.json({ updated: true });
});

app.delete('/customers/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('UPDATE tickets SET customer_id = NULL WHERE customer_id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  await c.env.DB.prepare('DELETE FROM customers WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// TICKETS
// ═══════════════════════════════════════════════════════════════════
app.get('/tickets', async (c) => {
  const tid = getTenantId(c);
  const { limit, offset } = parsePagination(c);
  const status = c.req.query('status');
  const priority = c.req.query('priority');
  const channel = c.req.query('channel');
  const agent = c.req.query('agent_id');
  const team = c.req.query('team_id');
  const customer = c.req.query('customer_id');
  const search = c.req.query('search');

  let sql = `SELECT t.*, c.name as customer_name, c.email as customer_email, a.name as agent_name
    FROM tickets t LEFT JOIN customers c ON t.customer_id = c.id LEFT JOIN agents a ON t.assigned_agent_id = a.id
    WHERE t.tenant_id = ?`;
  const params: unknown[] = [tid];

  if (status) { sql += ' AND t.status = ?'; params.push(status); }
  if (priority) { sql += ' AND t.priority = ?'; params.push(priority); }
  if (channel) { sql += ' AND t.channel = ?'; params.push(channel); }
  if (agent) { sql += ' AND t.assigned_agent_id = ?'; params.push(agent); }
  if (team) { sql += ' AND t.assigned_team_id = ?'; params.push(team); }
  if (customer) { sql += ' AND t.customer_id = ?'; params.push(customer); }
  if (search) { sql += ' AND (t.subject LIKE ? OR t.description LIKE ?)'; const s = `%${search}%`; params.push(s, s); }

  sql += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const rows = await c.env.DB.prepare(sql).bind(...params).all();

  let countSql = 'SELECT COUNT(*) as cnt FROM tickets WHERE tenant_id = ?';
  const countParams: unknown[] = [tid];
  if (status) { countSql += ' AND status = ?'; countParams.push(status); }
  const total = await c.env.DB.prepare(countSql).bind(...countParams).first();

  return c.json({ tickets: rows.results, total: (total as Record<string, unknown>)?.cnt || 0, limit, offset });
});

// Ticket board — grouped by status
app.get('/tickets/board', async (c) => {
  const tid = getTenantId(c);
  const statuses = ['open', 'pending', 'in_progress', 'waiting', 'resolved', 'closed'];
  const board: Record<string, unknown[]> = {};
  for (const s of statuses) {
    const rows = await c.env.DB.prepare(`SELECT t.*, c.name as customer_name, a.name as agent_name FROM tickets t LEFT JOIN customers c ON t.customer_id = c.id LEFT JOIN agents a ON t.assigned_agent_id = a.id WHERE t.tenant_id = ? AND t.status = ? ORDER BY CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, t.created_at DESC LIMIT 50`).bind(tid, s).all();
    board[s] = rows.results;
  }
  return c.json({ board });
});

app.post('/tickets', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();

  // Auto-increment ticket number with retry for race condition safety
  let ticketNumber = 0;
  for (let attempt = 0; attempt < 5; attempt++) {
    const last = await c.env.DB.prepare('SELECT MAX(ticket_number) as max_num FROM tickets WHERE tenant_id = ?').bind(tid).first();
    ticketNumber = ((last as Record<string, unknown>)?.max_num as number || 0) + 1 + attempt;
    break; // ticket_number has no UNIQUE constraint, so no retry needed — but offset by attempt if we ever add one
  }

  // Find applicable SLA
  let slaId: string | null = null;
  let firstResponseDue: string | null = null;
  let resolutionDue: string | null = null;
  const priority = (body.priority as string) || 'medium';
  const sla = await c.env.DB.prepare('SELECT * FROM sla_policies WHERE tenant_id = ? AND priority = ? LIMIT 1').bind(tid, priority).first();
  if (sla) {
    slaId = sla.id as string;
    const now = new Date();
    firstResponseDue = new Date(now.getTime() + (sla.first_response_minutes as number) * 60000).toISOString();
    resolutionDue = new Date(now.getTime() + (sla.resolution_minutes as number) * 60000).toISOString();
  }

  await c.env.DB.prepare(`INSERT INTO tickets (id, tenant_id, ticket_number, subject, description, status, priority, channel, customer_id, assigned_agent_id, assigned_team_id, category, tags, custom_fields, sla_policy_id, first_response_due, resolution_due) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, tid, ticketNumber, body.subject, body.description || null, priority, body.channel || 'email',
    body.customer_id || null, body.assigned_agent_id || null, body.assigned_team_id || null,
    body.category || null, JSON.stringify(body.tags || []), JSON.stringify(body.custom_fields || {}),
    slaId, firstResponseDue, resolutionDue
  ).run();

  // Update customer ticket count
  if (body.customer_id) {
    await c.env.DB.prepare('UPDATE customers SET total_tickets = total_tickets + 1, last_contacted_at = datetime(\'now\'), updated_at = datetime(\'now\') WHERE id = ?').bind(body.customer_id).run();
  }

  // Auto-assign if not specified
  if (!body.assigned_agent_id && !body.assigned_team_id) {
    const available = await c.env.DB.prepare("SELECT a.id, COUNT(t.id) as load FROM agents a LEFT JOIN tickets t ON a.id = t.assigned_agent_id AND t.status IN ('open','pending','in_progress') WHERE a.tenant_id = ? AND a.is_active = 1 AND a.status = 'online' GROUP BY a.id HAVING load < a.max_tickets ORDER BY load ASC LIMIT 1").bind(tid).first();
    if (available) {
      await c.env.DB.prepare('UPDATE tickets SET assigned_agent_id = ? WHERE id = ?').bind(available.id, id).run();
    }
  }

  // Log activity
  await c.env.DB.prepare('INSERT INTO activity_log (id, tenant_id, entity_type, entity_id, action, actor_type, actor_id) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(generateId(), tid, 'ticket', id, 'created', 'system', 'api').run();

  log('info', 'Ticket created', { ticket_id: id, ticket_number: ticketNumber, tenant_id: tid });
  return c.json({ id, ticket_number: ticketNumber, created: true }, 201);
});

app.get('/tickets/:id', async (c) => {
  const tid = getTenantId(c);
  const ticket = await c.env.DB.prepare(`SELECT t.*, c.name as customer_name, c.email as customer_email, a.name as agent_name FROM tickets t LEFT JOIN customers c ON t.customer_id = c.id LEFT JOIN agents a ON t.assigned_agent_id = a.id WHERE t.id = ? AND t.tenant_id = ?`).bind(c.req.param('id'), tid).first();
  if (!ticket) return c.json({ error: 'Ticket not found' }, 404);

  const messages = await c.env.DB.prepare('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC').bind(ticket.id).all();
  const activity = await c.env.DB.prepare("SELECT * FROM activity_log WHERE entity_type = 'ticket' AND entity_id = ? ORDER BY created_at DESC LIMIT 20").bind(ticket.id).all();

  return c.json({ ...ticket, messages: messages.results, activity: activity.results });
});

app.put('/tickets/:id', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const fields: string[] = [];
  const vals: unknown[] = [];

  for (const [k, v] of Object.entries(body)) {
    if (['subject', 'description', 'status', 'priority', 'channel', 'category', 'subcategory', 'customer_id', 'assigned_agent_id', 'assigned_team_id', 'is_spam'].includes(k)) {
      fields.push(`${k} = ?`); vals.push(v);
    }
    if (k === 'tags' || k === 'custom_fields') { fields.push(`${k} = ?`); vals.push(JSON.stringify(v)); }
  }

  // Auto-set timestamps on status changes
  if (body.status === 'resolved') { fields.push("resolved_at = datetime('now')"); }
  if (body.status === 'closed') { fields.push("closed_at = datetime('now')"); }
  if (body.status === 'open') {
    const ticket = await c.env.DB.prepare('SELECT status FROM tickets WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
    if (ticket && (ticket.status === 'resolved' || ticket.status === 'closed')) {
      fields.push('reopened_count = reopened_count + 1');
    }
  }

  if (fields.length === 0) return c.json({ error: 'No fields' }, 400);
  fields.push("updated_at = datetime('now')");
  vals.push(c.req.param('id'), tid);
  await c.env.DB.prepare(`UPDATE tickets SET ${fields.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();

  // Log
  await c.env.DB.prepare('INSERT INTO activity_log (id, tenant_id, entity_type, entity_id, action, details) VALUES (?, ?, ?, ?, ?, ?)').bind(generateId(), tid, 'ticket', c.req.param('id'), 'updated', JSON.stringify(body)).run();

  return c.json({ updated: true });
});

// Assign ticket
app.post('/tickets/:id/assign', async (c) => {
  const tid = getTenantId(c);
  const body = await c.req.json() as Record<string, unknown>;
  const fields: string[] = ["updated_at = datetime('now')"];
  const vals: unknown[] = [];
  if (body.agent_id) { fields.push('assigned_agent_id = ?'); vals.push(body.agent_id); }
  if (body.team_id) { fields.push('assigned_team_id = ?'); vals.push(body.team_id); }
  vals.push(c.req.param('id'), tid);
  await c.env.DB.prepare(`UPDATE tickets SET ${fields.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();
  await c.env.DB.prepare('INSERT INTO activity_log (id, tenant_id, entity_type, entity_id, action, details) VALUES (?, ?, ?, ?, ?, ?)').bind(generateId(), tid, 'ticket', c.req.param('id'), 'assigned', JSON.stringify(body)).run();
  return c.json({ assigned: true });
});

// Merge tickets
app.post('/tickets/:id/merge', async (c) => {
  const tid = getTenantId(c);
  const body = await c.req.json() as { merge_ticket_id: string };
  await c.env.DB.prepare("UPDATE tickets SET merged_into_id = ?, status = 'closed', closed_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND tenant_id = ?").bind(c.req.param('id'), body.merge_ticket_id, tid).run();
  // Move messages
  await c.env.DB.prepare('UPDATE ticket_messages SET ticket_id = ? WHERE ticket_id = ?').bind(body.merge_ticket_id, c.req.param('id')).run();
  return c.json({ merged: true });
});

app.delete('/tickets/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM ticket_messages WHERE ticket_id = ?').bind(c.req.param('id')).run();
  await c.env.DB.prepare('DELETE FROM satisfaction_surveys WHERE ticket_id = ?').bind(c.req.param('id')).run();
  await c.env.DB.prepare("DELETE FROM activity_log WHERE entity_type = 'ticket' AND entity_id = ?").bind(c.req.param('id')).run();
  await c.env.DB.prepare('DELETE FROM tickets WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// TICKET MESSAGES (replies)
// ═══════════════════════════════════════════════════════════════════
app.get('/tickets/:id/messages', async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC').bind(c.req.param('id')).all();
  return c.json({ messages: rows.results });
});

app.post('/tickets/:id/messages', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  const ticketId = c.req.param('id');

  await c.env.DB.prepare('INSERT INTO ticket_messages (id, ticket_id, sender_type, sender_id, sender_name, body, body_html, is_internal, channel, ai_generated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
    id, ticketId, body.sender_type || 'agent', body.sender_id || null, body.sender_name || null,
    body.body, body.body_html || null, body.is_internal ? 1 : 0, body.channel || 'email', body.ai_generated ? 1 : 0
  ).run();

  // Track first response time
  if ((body.sender_type === 'agent') && !body.is_internal) {
    const ticket = await c.env.DB.prepare('SELECT first_response_at FROM tickets WHERE id = ?').bind(ticketId).first();
    if (ticket && !ticket.first_response_at) {
      await c.env.DB.prepare("UPDATE tickets SET first_response_at = datetime('now'), updated_at = datetime('now') WHERE id = ?").bind(ticketId).run();
    }
  }

  // Update ticket status
  if (body.sender_type === 'agent' && !body.is_internal) {
    await c.env.DB.prepare("UPDATE tickets SET status = 'pending', updated_at = datetime('now') WHERE id = ? AND status = 'open'").bind(ticketId).run();
  } else if (body.sender_type === 'customer') {
    await c.env.DB.prepare("UPDATE tickets SET status = 'open', updated_at = datetime('now') WHERE id = ? AND status IN ('pending','waiting')").bind(ticketId).run();
  }

  await c.env.DB.prepare('INSERT INTO activity_log (id, tenant_id, entity_type, entity_id, action, actor_type, actor_id) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(generateId(), tid, 'ticket', ticketId, body.is_internal ? 'internal_note' : 'reply', body.sender_type || 'agent', body.sender_id || 'api').run();

  return c.json({ id, created: true }, 201);
});

// ═══════════════════════════════════════════════════════════════════
// AI FEATURES
// ═══════════════════════════════════════════════════════════════════

// AI auto-categorize ticket
app.post('/tickets/:id/ai/categorize', async (c) => {
  const tid = getTenantId(c);
  const ticket = await c.env.DB.prepare('SELECT subject, description FROM tickets WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
  if (!ticket) return c.json({ error: 'Ticket not found' }, 404);

  try {
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'CS01', query: `Categorize this support ticket. Subject: ${ticket.subject}. Description: ${(ticket.description as string || '').slice(0, 500)}. Return JSON with fields: category, subcategory, priority (low/medium/high/urgent), sentiment (positive/neutral/negative/frustrated).` })
    });
    const data = await resp.json() as Record<string, unknown>;
    const answer = (data.answer as string) || '';
    const jsonMatch = answer.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      await c.env.DB.prepare("UPDATE tickets SET ai_category = ?, ai_sentiment = ?, category = COALESCE(category, ?), updated_at = datetime('now') WHERE id = ?").bind(
        parsed.category || null, parsed.sentiment || null, parsed.category || null, c.req.param('id')
      ).run();
      return c.json({ categorized: true, ...parsed });
    }
    return c.json({ categorized: false, raw: answer });
  } catch (e) {
    log('error', 'AI categorize failed', { error: (e as Error).message });
    return c.json({ error: 'AI categorization failed' }, 500);
  }
});

// AI suggest response
app.post('/tickets/:id/ai/suggest', async (c) => {
  const tid = getTenantId(c);
  const ticket = await c.env.DB.prepare('SELECT subject, description, category FROM tickets WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
  if (!ticket) return c.json({ error: 'Ticket not found' }, 404);

  // Get conversation history
  const messages = await c.env.DB.prepare('SELECT sender_type, body FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC LIMIT 10').bind(c.req.param('id')).all();
  const history = (messages.results || []).map((m: Record<string, unknown>) => `[${m.sender_type}]: ${(m.body as string).slice(0, 200)}`).join('\n');

  // Search KB for relevant articles
  const kbResults = await c.env.DB.prepare("SELECT title, body FROM kb_articles WHERE tenant_id = ? AND status = 'published' AND (title LIKE ? OR body LIKE ?) LIMIT 3").bind(tid, `%${(ticket.subject as string).split(' ').slice(0, 3).join('%')}%`, `%${(ticket.subject as string).split(' ').slice(0, 3).join('%')}%`).all();
  const kbContext = (kbResults.results || []).map((a: Record<string, unknown>) => `Article: ${a.title}\n${(a.body as string).slice(0, 300)}`).join('\n\n');

  try {
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'CS01', query: `You are a professional support agent. Suggest a response to this ticket.\n\nSubject: ${ticket.subject}\nDescription: ${(ticket.description as string || '').slice(0, 500)}\nCategory: ${ticket.category || 'unknown'}\n\nConversation:\n${history}\n\nRelevant KB articles:\n${kbContext || 'None'}\n\nWrite a professional, empathetic response.` })
    });
    const data = await resp.json() as Record<string, unknown>;
    const suggestion = (data.answer as string) || 'Unable to generate suggestion';

    await c.env.DB.prepare("UPDATE tickets SET ai_suggested_response = ?, updated_at = datetime('now') WHERE id = ?").bind(suggestion, c.req.param('id')).run();
    return c.json({ suggestion });
  } catch (e) {
    log('error', 'AI suggest failed', { error: (e as Error).message });
    return c.json({ error: 'AI suggestion failed' }, 500);
  }
});

// AI summarize ticket
app.post('/tickets/:id/ai/summarize', async (c) => {
  const tid = getTenantId(c);
  const ticket = await c.env.DB.prepare('SELECT subject, description FROM tickets WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
  if (!ticket) return c.json({ error: 'Ticket not found' }, 404);

  const messages = await c.env.DB.prepare('SELECT sender_type, body, created_at FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC').bind(c.req.param('id')).all();
  const convo = (messages.results || []).map((m: Record<string, unknown>) => `[${m.sender_type} ${m.created_at}]: ${(m.body as string).slice(0, 300)}`).join('\n');

  try {
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'CS01', query: `Summarize this support ticket in 2-3 sentences.\n\nSubject: ${ticket.subject}\nDescription: ${(ticket.description as string || '').slice(0, 300)}\n\nConversation (${messages.results?.length || 0} messages):\n${convo.slice(0, 2000)}` })
    });
    const data = await resp.json() as Record<string, unknown>;
    const summary = (data.answer as string) || '';
    await c.env.DB.prepare("UPDATE tickets SET ai_summary = ?, updated_at = datetime('now') WHERE id = ?").bind(summary, c.req.param('id')).run();
    return c.json({ summary });
  } catch (e) {
    log('error', 'AI summarize failed', { error: (e as Error).message });
    return c.json({ error: 'AI summarization failed' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// SLA POLICIES
// ═══════════════════════════════════════════════════════════════════
app.get('/sla', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare('SELECT * FROM sla_policies WHERE tenant_id = ? ORDER BY priority').bind(tid).all();
  return c.json({ policies: rows.results });
});

app.post('/sla', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO sla_policies (id, tenant_id, name, description, priority, first_response_minutes, resolution_minutes, business_hours_only, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(id, tid, body.name, body.description || null, body.priority, body.first_response_minutes, body.resolution_minutes, body.business_hours_only ? 1 : 0, body.is_default ? 1 : 0).run();
  return c.json({ id, created: true }, 201);
});

app.delete('/sla/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM sla_policies WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// SLA breach check
app.get('/sla/breaches', async (c) => {
  const tid = getTenantId(c);
  const now = new Date().toISOString();
  const responseBreaches = await c.env.DB.prepare("SELECT t.id, t.ticket_number, t.subject, t.priority, t.first_response_due, t.assigned_agent_id, a.name as agent_name FROM tickets t LEFT JOIN agents a ON t.assigned_agent_id = a.id WHERE t.tenant_id = ? AND t.first_response_at IS NULL AND t.first_response_due < ? AND t.status NOT IN ('resolved','closed') ORDER BY t.first_response_due ASC").bind(tid, now).all();
  const resolutionBreaches = await c.env.DB.prepare("SELECT t.id, t.ticket_number, t.subject, t.priority, t.resolution_due, t.assigned_agent_id, a.name as agent_name FROM tickets t LEFT JOIN agents a ON t.assigned_agent_id = a.id WHERE t.tenant_id = ? AND t.resolved_at IS NULL AND t.resolution_due < ? AND t.status NOT IN ('resolved','closed') ORDER BY t.resolution_due ASC").bind(tid, now).all();
  return c.json({ response_breaches: responseBreaches.results, resolution_breaches: resolutionBreaches.results });
});

// ═══════════════════════════════════════════════════════════════════
// CANNED RESPONSES
// ═══════════════════════════════════════════════════════════════════
app.get('/canned', async (c) => {
  const tid = getTenantId(c);
  const category = c.req.query('category');
  let sql = 'SELECT * FROM canned_responses WHERE tenant_id = ?';
  const params: unknown[] = [tid];
  if (category) { sql += ' AND category = ?'; params.push(category); }
  sql += ' ORDER BY use_count DESC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ responses: rows.results });
});

app.post('/canned', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO canned_responses (id, tenant_id, title, body, category, shortcut) VALUES (?, ?, ?, ?, ?, ?)').bind(id, tid, body.title, body.body, body.category || null, body.shortcut || null).run();
  return c.json({ id, created: true }, 201);
});

app.put('/canned/:id', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  await c.env.DB.prepare('UPDATE canned_responses SET title = COALESCE(?, title), body = COALESCE(?, body), category = COALESCE(?, category), shortcut = COALESCE(?, shortcut) WHERE id = ? AND tenant_id = ?').bind(body.title || null, body.body || null, body.category || null, body.shortcut || null, c.req.param('id'), tid).run();
  return c.json({ updated: true });
});

app.post('/canned/:id/use', async (c) => {
  await c.env.DB.prepare('UPDATE canned_responses SET use_count = use_count + 1 WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ used: true });
});

app.delete('/canned/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM canned_responses WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// TAGS
// ═══════════════════════════════════════════════════════════════════
app.get('/tags', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare('SELECT * FROM tags WHERE tenant_id = ? ORDER BY name').bind(tid).all();
  return c.json({ tags: rows.results });
});

app.post('/tags', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO tags (id, tenant_id, name, color) VALUES (?, ?, ?, ?)').bind(id, tid, body.name, body.color || '#6366f1').run();
  return c.json({ id, created: true }, 201);
});

app.delete('/tags/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM tags WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// KNOWLEDGE BASE
// ═══════════════════════════════════════════════════════════════════
app.get('/kb', async (c) => {
  const tid = getTenantId(c);
  const { limit, offset } = parsePagination(c);
  const status = c.req.query('status') || 'published';
  const category = c.req.query('category');
  const search = c.req.query('search');
  let sql = 'SELECT id, title, slug, category, status, view_count, helpful_count, not_helpful_count, created_at, updated_at FROM kb_articles WHERE tenant_id = ?';
  const params: unknown[] = [tid];
  if (status !== 'all') { sql += ' AND status = ?'; params.push(status); }
  if (category) { sql += ' AND category = ?'; params.push(category); }
  if (search) { sql += ' AND (title LIKE ? OR body LIKE ?)'; const s = `%${search}%`; params.push(s, s); }
  sql += ' ORDER BY view_count DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ articles: rows.results });
});

app.post('/kb', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  const slug = (body.title as string).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  await c.env.DB.prepare('INSERT INTO kb_articles (id, tenant_id, title, slug, body, category, status, author_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(id, tid, body.title, slug, body.body, body.category || null, body.status || 'draft', body.author_id || null).run();
  return c.json({ id, slug, created: true }, 201);
});

app.get('/kb/:slug', async (c) => {
  const tid = getTenantId(c);
  const article = await c.env.DB.prepare('SELECT * FROM kb_articles WHERE (slug = ? OR id = ?) AND tenant_id = ?').bind(c.req.param('slug'), c.req.param('slug'), tid).first();
  if (!article) return c.json({ error: 'Article not found' }, 404);
  // Increment views
  await c.env.DB.prepare('UPDATE kb_articles SET view_count = view_count + 1 WHERE id = ?').bind(article.id).run();
  return c.json(article);
});

app.put('/kb/:id', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const fields: string[] = [];
  const vals: unknown[] = [];
  for (const [k, v] of Object.entries(body)) {
    if (['title', 'body', 'category', 'status'].includes(k)) {
      fields.push(`${k} = ?`); vals.push(v);
    }
  }
  if (body.title) { fields.push('slug = ?'); vals.push((body.title as string).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')); }
  fields.push("updated_at = datetime('now')");
  vals.push(c.req.param('id'), tid);
  await c.env.DB.prepare(`UPDATE kb_articles SET ${fields.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();
  return c.json({ updated: true });
});

app.post('/kb/:id/feedback', async (c) => {
  const body = await c.req.json() as { helpful: boolean };
  const col = body.helpful ? 'helpful_count' : 'not_helpful_count';
  await c.env.DB.prepare(`UPDATE kb_articles SET ${col} = ${col} + 1 WHERE id = ?`).bind(c.req.param('id')).run();
  return c.json({ recorded: true });
});

app.delete('/kb/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM kb_articles WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// SATISFACTION SURVEYS
// ═══════════════════════════════════════════════════════════════════
app.post('/tickets/:id/satisfaction', async (c) => {
  const tid = getTenantId(c);
  const body = await c.req.json() as Record<string, unknown>;
  const ticket = await c.env.DB.prepare('SELECT customer_id, assigned_agent_id FROM tickets WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).first();
  if (!ticket) return c.json({ error: 'Ticket not found' }, 404);

  const id = generateId();
  await c.env.DB.prepare("INSERT INTO satisfaction_surveys (id, tenant_id, ticket_id, customer_id, rating, comment, agent_id, responded_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))").bind(
    id, tid, c.req.param('id'), ticket.customer_id, body.rating, body.comment || null, ticket.assigned_agent_id
  ).run();

  await c.env.DB.prepare("UPDATE tickets SET satisfaction_rating = ?, satisfaction_comment = ?, updated_at = datetime('now') WHERE id = ?").bind(body.rating, body.comment || null, c.req.param('id')).run();

  // Update customer satisfaction score
  if (ticket.customer_id) {
    const avg = await c.env.DB.prepare('SELECT AVG(rating) as avg_r FROM satisfaction_surveys WHERE customer_id = ?').bind(ticket.customer_id).first();
    if (avg) await c.env.DB.prepare('UPDATE customers SET satisfaction_score = ? WHERE id = ?').bind((avg as Record<string, unknown>).avg_r, ticket.customer_id).run();
  }

  return c.json({ id, recorded: true }, 201);
});

app.get('/satisfaction', async (c) => {
  const tid = getTenantId(c);
  const { limit, offset } = parsePagination(c);
  const rows = await c.env.DB.prepare('SELECT s.*, t.ticket_number, t.subject FROM satisfaction_surveys s JOIN tickets t ON s.ticket_id = t.id WHERE s.tenant_id = ? ORDER BY s.created_at DESC LIMIT ? OFFSET ?').bind(tid, limit, offset).all();
  return c.json({ surveys: rows.results });
});

// ═══════════════════════════════════════════════════════════════════
// AUTOMATIONS
// ═══════════════════════════════════════════════════════════════════
app.get('/automations', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare('SELECT * FROM automations WHERE tenant_id = ? ORDER BY created_at DESC').bind(tid).all();
  return c.json({ automations: rows.results });
});

app.post('/automations', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO automations (id, tenant_id, name, trigger_event, conditions, actions, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, tid, body.name, body.trigger_event, JSON.stringify(body.conditions || []), JSON.stringify(body.actions || []), body.is_active !== false ? 1 : 0).run();
  return c.json({ id, created: true }, 201);
});

app.put('/automations/:id', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const fields: string[] = [];
  const vals: unknown[] = [];
  if (body.name) { fields.push('name = ?'); vals.push(body.name); }
  if (body.trigger_event) { fields.push('trigger_event = ?'); vals.push(body.trigger_event); }
  if (body.conditions) { fields.push('conditions = ?'); vals.push(JSON.stringify(body.conditions)); }
  if (body.actions) { fields.push('actions = ?'); vals.push(JSON.stringify(body.actions)); }
  if (body.is_active !== undefined) { fields.push('is_active = ?'); vals.push(body.is_active ? 1 : 0); }
  vals.push(c.req.param('id'), tid);
  await c.env.DB.prepare(`UPDATE automations SET ${fields.join(', ')} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();
  return c.json({ updated: true });
});

app.delete('/automations/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM automations WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// WEBHOOKS
// ═══════════════════════════════════════════════════════════════════
app.get('/webhooks', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare('SELECT * FROM webhooks WHERE tenant_id = ? ORDER BY created_at DESC').bind(tid).all();
  return c.json({ webhooks: rows.results });
});

app.post('/webhooks', async (c) => {
  const tid = getTenantId(c);
  const body = sanitizeBody(await c.req.json()) as Record<string, unknown>;
  const id = generateId();
  await c.env.DB.prepare('INSERT INTO webhooks (id, tenant_id, url, events, secret, is_active) VALUES (?, ?, ?, ?, ?, ?)').bind(id, tid, body.url, JSON.stringify(body.events || ['ticket.created', 'ticket.updated']), body.secret || null, 1).run();
  return c.json({ id, created: true }, 201);
});

app.delete('/webhooks/:id', async (c) => {
  const tid = getTenantId(c);
  await c.env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND tenant_id = ?').bind(c.req.param('id'), tid).run();
  return c.json({ deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════════
app.get('/analytics/overview', async (c) => {
  const tid = getTenantId(c);
  const open = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE tenant_id = ? AND status IN ('open','pending','in_progress','waiting')").bind(tid).first();
  const resolved = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE tenant_id = ? AND status = 'resolved'").bind(tid).first();
  const closed = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE tenant_id = ? AND status = 'closed'").bind(tid).first();
  const avgFirstResponse = await c.env.DB.prepare("SELECT AVG(CAST((julianday(first_response_at) - julianday(created_at)) * 24 * 60 AS REAL)) as avg_mins FROM tickets WHERE tenant_id = ? AND first_response_at IS NOT NULL").bind(tid).first();
  const avgResolution = await c.env.DB.prepare("SELECT AVG(CAST((julianday(resolved_at) - julianday(created_at)) * 24 * 60 AS REAL)) as avg_mins FROM tickets WHERE tenant_id = ? AND resolved_at IS NOT NULL").bind(tid).first();
  const avgSat = await c.env.DB.prepare('SELECT AVG(rating) as avg_rating, COUNT(*) as total FROM satisfaction_surveys WHERE tenant_id = ?').bind(tid).first();
  const todayTickets = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE tenant_id = ? AND created_at >= datetime('now', '-1 day')").bind(tid).first();
  const weekTickets = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE tenant_id = ? AND created_at >= datetime('now', '-7 days')").bind(tid).first();

  return c.json({
    open_tickets: (open as Record<string, unknown>)?.cnt || 0,
    resolved_tickets: (resolved as Record<string, unknown>)?.cnt || 0,
    closed_tickets: (closed as Record<string, unknown>)?.cnt || 0,
    avg_first_response_minutes: Math.round(((avgFirstResponse as Record<string, unknown>)?.avg_mins as number) || 0),
    avg_resolution_minutes: Math.round(((avgResolution as Record<string, unknown>)?.avg_mins as number) || 0),
    avg_satisfaction: ((avgSat as Record<string, unknown>)?.avg_rating as number || 0).toFixed(1),
    total_surveys: (avgSat as Record<string, unknown>)?.total || 0,
    tickets_today: (todayTickets as Record<string, unknown>)?.cnt || 0,
    tickets_this_week: (weekTickets as Record<string, unknown>)?.cnt || 0,
  });
});

app.get('/analytics/by-channel', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare("SELECT channel, COUNT(*) as count, AVG(CASE WHEN satisfaction_rating IS NOT NULL THEN satisfaction_rating END) as avg_satisfaction FROM tickets WHERE tenant_id = ? GROUP BY channel ORDER BY count DESC").bind(tid).all();
  return c.json({ channels: rows.results });
});

app.get('/analytics/by-agent', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare(`SELECT a.id, a.name, COUNT(t.id) as total_tickets, SUM(CASE WHEN t.status = 'resolved' THEN 1 ELSE 0 END) as resolved, AVG(CASE WHEN t.satisfaction_rating IS NOT NULL THEN t.satisfaction_rating END) as avg_satisfaction, AVG(CASE WHEN t.first_response_at IS NOT NULL THEN CAST((julianday(t.first_response_at) - julianday(t.created_at)) * 24 * 60 AS REAL) END) as avg_response_mins FROM agents a LEFT JOIN tickets t ON a.id = t.assigned_agent_id WHERE a.tenant_id = ? GROUP BY a.id ORDER BY total_tickets DESC`).bind(tid).all();
  return c.json({ agents: rows.results });
});

app.get('/analytics/by-category', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare("SELECT COALESCE(category, 'uncategorized') as category, COUNT(*) as count, AVG(CASE WHEN satisfaction_rating IS NOT NULL THEN satisfaction_rating END) as avg_satisfaction FROM tickets WHERE tenant_id = ? GROUP BY category ORDER BY count DESC").bind(tid).all();
  return c.json({ categories: rows.results });
});

app.get('/analytics/trends', async (c) => {
  const tid = getTenantId(c);
  const rows = await c.env.DB.prepare("SELECT DATE(created_at) as date, COUNT(*) as created, SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved FROM tickets WHERE tenant_id = ? AND created_at >= datetime('now', '-30 days') GROUP BY DATE(created_at) ORDER BY date").bind(tid).all();
  return c.json({ trends: rows.results });
});

// ═══════════════════════════════════════════════════════════════════
// ACTIVITY LOG
// ═══════════════════════════════════════════════════════════════════
app.get('/activity', async (c) => {
  const tid = getTenantId(c);
  const { limit, offset } = parsePagination(c);
  const entityType = c.req.query('entity_type');
  const entityId = c.req.query('entity_id');
  let sql = 'SELECT * FROM activity_log WHERE tenant_id = ?';
  const params: unknown[] = [tid];
  if (entityType) { sql += ' AND entity_type = ?'; params.push(entityType); }
  if (entityId) { sql += ' AND entity_id = ?'; params.push(entityId); }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ activity: rows.results });
});

// ═══════════════════════════════════════════════════════════════════
// CRON: Daily SLA breach alerts
// ═══════════════════════════════════════════════════════════════════
async function cronHandler(env: Env) {
  log('info', 'Cron: SLA breach check');
  const now = new Date().toISOString();

  // Find all SLA breaches
  const responseBreaches = await env.DB.prepare("SELECT t.id, t.tenant_id, t.ticket_number, t.subject, t.priority, t.assigned_agent_id FROM tickets t WHERE t.first_response_at IS NULL AND t.first_response_due < ? AND t.status NOT IN ('resolved','closed')").bind(now).all();
  const resolutionBreaches = await env.DB.prepare("SELECT t.id, t.tenant_id, t.ticket_number, t.subject, t.priority, t.assigned_agent_id FROM tickets t WHERE t.resolved_at IS NULL AND t.resolution_due < ? AND t.status NOT IN ('resolved','closed')").bind(now).all();

  const totalBreaches = (responseBreaches.results?.length || 0) + (resolutionBreaches.results?.length || 0);

  // Report to Shared Brain
  if (totalBreaches > 0) {
    try {
      await env.SHARED_BRAIN.fetch('https://brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'echo-helpdesk',
          role: 'assistant',
          content: `HELPDESK SLA ALERT: ${responseBreaches.results?.length || 0} first-response breaches, ${resolutionBreaches.results?.length || 0} resolution breaches.`,
          importance: 7,
          tags: ['helpdesk', 'sla', 'alert']
        })
      });
    } catch (e) {
      log('warn', 'Brain ingest failed', { error: (e as Error).message });
    }
  }

  log('info', 'Cron complete', { response_breaches: responseBreaches.results?.length || 0, resolution_breaches: resolutionBreaches.results?.length || 0 });
}

// ─── Global Error Handlers ──────────────────────────────────────────
app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-helpdesk] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// ─── Export ─────────────────────────────────────────────────────────
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(cronHandler(env));
  },
};
