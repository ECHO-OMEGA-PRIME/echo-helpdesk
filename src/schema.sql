-- Echo Helpdesk v1.0.0 Schema

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT,
  plan TEXT DEFAULT 'starter',
  settings TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT DEFAULT 'agent',
  avatar_url TEXT,
  status TEXT DEFAULT 'online',
  max_tickets INTEGER DEFAULT 20,
  specialties TEXT DEFAULT '[]',
  signature TEXT,
  is_active INTEGER DEFAULT 1,
  last_active_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_agents_tenant ON agents(tenant_id);
CREATE INDEX idx_agents_email ON agents(tenant_id, email);
CREATE INDEX idx_agents_status ON agents(tenant_id, status);

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  lead_agent_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (lead_agent_id) REFERENCES agents(id)
);
CREATE INDEX idx_teams_tenant ON teams(tenant_id);

CREATE TABLE IF NOT EXISTS team_members (
  team_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  PRIMARY KEY (team_id, agent_id),
  FOREIGN KEY (team_id) REFERENCES teams(id),
  FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  company TEXT,
  avatar_url TEXT,
  channel TEXT DEFAULT 'email',
  timezone TEXT,
  language TEXT DEFAULT 'en',
  tags TEXT DEFAULT '[]',
  custom_fields TEXT DEFAULT '{}',
  satisfaction_score REAL,
  total_tickets INTEGER DEFAULT 0,
  last_contacted_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_customers_tenant ON customers(tenant_id);
CREATE INDEX idx_customers_email ON customers(tenant_id, email);
CREATE INDEX idx_customers_company ON customers(tenant_id, company);

CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  ticket_number INTEGER,
  subject TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'open',
  priority TEXT DEFAULT 'medium',
  channel TEXT DEFAULT 'email',
  customer_id TEXT,
  assigned_agent_id TEXT,
  assigned_team_id TEXT,
  category TEXT,
  subcategory TEXT,
  tags TEXT DEFAULT '[]',
  custom_fields TEXT DEFAULT '{}',
  sla_policy_id TEXT,
  first_response_at TEXT,
  first_response_due TEXT,
  resolution_due TEXT,
  resolved_at TEXT,
  closed_at TEXT,
  reopened_count INTEGER DEFAULT 0,
  satisfaction_rating INTEGER,
  satisfaction_comment TEXT,
  source_url TEXT,
  source_message_id TEXT,
  merged_into_id TEXT,
  is_spam INTEGER DEFAULT 0,
  ai_summary TEXT,
  ai_suggested_response TEXT,
  ai_category TEXT,
  ai_sentiment TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (customer_id) REFERENCES customers(id),
  FOREIGN KEY (assigned_agent_id) REFERENCES agents(id),
  FOREIGN KEY (assigned_team_id) REFERENCES teams(id)
);
CREATE INDEX idx_tickets_tenant ON tickets(tenant_id);
CREATE INDEX idx_tickets_status ON tickets(tenant_id, status);
CREATE INDEX idx_tickets_priority ON tickets(tenant_id, priority);
CREATE INDEX idx_tickets_customer ON tickets(customer_id);
CREATE INDEX idx_tickets_agent ON tickets(assigned_agent_id);
CREATE INDEX idx_tickets_team ON tickets(assigned_team_id);
CREATE INDEX idx_tickets_number ON tickets(tenant_id, ticket_number);
CREATE INDEX idx_tickets_created ON tickets(tenant_id, created_at);
CREATE INDEX idx_tickets_sla ON tickets(tenant_id, sla_policy_id, status);
CREATE INDEX idx_tickets_channel ON tickets(tenant_id, channel);

CREATE TABLE IF NOT EXISTS ticket_messages (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL,
  sender_type TEXT NOT NULL,
  sender_id TEXT,
  sender_name TEXT,
  body TEXT NOT NULL,
  body_html TEXT,
  is_internal INTEGER DEFAULT 0,
  attachments TEXT DEFAULT '[]',
  channel TEXT DEFAULT 'email',
  ai_generated INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (ticket_id) REFERENCES tickets(id)
);
CREATE INDEX idx_messages_ticket ON ticket_messages(ticket_id);
CREATE INDEX idx_messages_sender ON ticket_messages(sender_type, sender_id);

CREATE TABLE IF NOT EXISTS sla_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  priority TEXT NOT NULL,
  first_response_minutes INTEGER NOT NULL,
  resolution_minutes INTEGER NOT NULL,
  business_hours_only INTEGER DEFAULT 1,
  is_default INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_sla_tenant ON sla_policies(tenant_id);

CREATE TABLE IF NOT EXISTS canned_responses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  category TEXT,
  shortcut TEXT,
  use_count INTEGER DEFAULT 0,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_canned_tenant ON canned_responses(tenant_id);
CREATE INDEX idx_canned_shortcut ON canned_responses(tenant_id, shortcut);

CREATE TABLE IF NOT EXISTS tags (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  color TEXT DEFAULT '#6366f1',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_tags_tenant ON tags(tenant_id);

CREATE TABLE IF NOT EXISTS automations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  trigger_event TEXT NOT NULL,
  conditions TEXT DEFAULT '[]',
  actions TEXT DEFAULT '[]',
  is_active INTEGER DEFAULT 1,
  run_count INTEGER DEFAULT 0,
  last_run_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_automations_tenant ON automations(tenant_id);
CREATE INDEX idx_automations_trigger ON automations(tenant_id, trigger_event);

CREATE TABLE IF NOT EXISTS kb_articles (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  slug TEXT NOT NULL,
  body TEXT NOT NULL,
  category TEXT,
  status TEXT DEFAULT 'draft',
  author_id TEXT,
  view_count INTEGER DEFAULT 0,
  helpful_count INTEGER DEFAULT 0,
  not_helpful_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_kb_tenant ON kb_articles(tenant_id);
CREATE INDEX idx_kb_slug ON kb_articles(tenant_id, slug);
CREATE INDEX idx_kb_status ON kb_articles(tenant_id, status);
CREATE INDEX idx_kb_category ON kb_articles(tenant_id, category);

CREATE TABLE IF NOT EXISTS satisfaction_surveys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  ticket_id TEXT NOT NULL,
  customer_id TEXT,
  rating INTEGER,
  comment TEXT,
  agent_id TEXT,
  responded_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (ticket_id) REFERENCES tickets(id)
);
CREATE INDEX idx_surveys_tenant ON satisfaction_surveys(tenant_id);
CREATE INDEX idx_surveys_ticket ON satisfaction_surveys(ticket_id);
CREATE INDEX idx_surveys_agent ON satisfaction_surveys(agent_id);

CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  events TEXT DEFAULT '[]',
  secret TEXT,
  is_active INTEGER DEFAULT 1,
  last_triggered_at TEXT,
  failure_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_type TEXT,
  actor_id TEXT,
  details TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_activity_tenant ON activity_log(tenant_id, created_at);
CREATE INDEX idx_activity_entity ON activity_log(entity_type, entity_id);
