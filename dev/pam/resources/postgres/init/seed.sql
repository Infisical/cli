CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title VARCHAR(200) NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com'),
    ('carol', 'carol@example.com');

INSERT INTO posts (user_id, title, body) VALUES
    (1, 'First post', 'Hello from Alice.'),
    (1, 'SQL tips', 'Use CTEs for readability.'),
    (2, 'On databases', 'Postgres is great.'),
    (3, 'Quick note', 'Short and sweet.');

-- ---------------------------------------------------------------------------
-- products — diverse scalar types, JSON, arrays, enums
-- ---------------------------------------------------------------------------

CREATE TYPE product_status AS ENUM ('draft', 'active', 'archived');

CREATE TABLE products (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(200) NOT NULL,
    price         NUMERIC(12, 2) NOT NULL,
    list_price    MONEY,
    weight_kg     REAL,
    precision_val DOUBLE PRECISION,
    stock         SMALLINT DEFAULT 0,
    global_sku    BIGINT,
    available     BOOLEAN DEFAULT TRUE,
    status        product_status DEFAULT 'draft',
    tags          TEXT[],
    metadata      JSONB,
    extra         JSON,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO products (id, name, price, list_price, weight_kg, precision_val, stock, global_sku, available, status, tags, metadata, extra) VALUES
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'Widget A', 19.99, '$24.99', 0.75, 3.141592653589793, 150, 9000000000000001, TRUE,  'active',   ARRAY['sale', 'new'],      '{"color": "red", "sizes": [1, 2, 3]}',   '{"note": "first product"}'),
    ('b1ffcd00-ad1c-5fa9-cc7e-7ccace491b22', 'Widget B', 5.50,  NULL,     NULL,  2.718281828459045, 0,   9000000000000002, FALSE, 'draft',    ARRAY['clearance'],        '{"color": "blue"}',                       NULL),
    ('c2aade11-be2d-6ab0-dd8f-8ddbdf502c33', 'Gizmo',    999.00,'$1,099.00', 12.5, NULL,           3200, NULL,              TRUE,  'active',   NULL,                      NULL,                                      '{"warehouse": "EU-1"}'),
    ('d3bbef22-cf3e-7bc1-ee90-9eece6613d44', 'Thingamajig', 0.01, '$0.01', 0.001, 1e-15,          32767, 9223372036854775807, NULL, 'archived', ARRAY[]::TEXT[],           '{"empty": {}}',                           '[]');

-- ---------------------------------------------------------------------------
-- network_events — date/time, network, binary, and range types
-- ---------------------------------------------------------------------------

CREATE TABLE network_events (
    id          BIGSERIAL PRIMARY KEY,
    event_date  DATE NOT NULL,
    event_time  TIME NOT NULL,
    duration    INTERVAL,
    source_ip   INET,
    network     CIDR,
    device_mac  MACADDR,
    port_range  INT4RANGE,
    payload     BYTEA,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO network_events (event_date, event_time, duration, source_ip, network, device_mac, port_range, payload) VALUES
    ('2025-06-15', '14:30:00',       '2 hours 30 minutes',  '192.168.1.1',   '192.168.1.0/24', '08:00:2b:01:02:03', '[1024, 65535)', E'\\xDEADBEEF'),
    ('2025-12-31', '23:59:59.999999','1 year 2 months',     '10.0.0.1',      '10.0.0.0/8',     'AA:BB:CC:DD:EE:FF', '[80, 443]',     E'\\x00FF00FF'),
    ('2026-01-01', '00:00:00',       NULL,                  '::1',           '::1/128',         NULL,                NULL,            NULL),
    ('2026-02-12', '08:15:30.123456','3 days 4 hours',      '172.16.0.100',  NULL,              '00:1A:2B:3C:4D:5E', '[3000, 3010)', E'\\x48656C6C6F');

-- ---------------------------------------------------------------------------
-- employee_profiles — wide table (26 columns) for RowDescription stress test
-- ---------------------------------------------------------------------------

CREATE TABLE employee_profiles (
    id              BIGSERIAL PRIMARY KEY,                    -- 1
    employee_uuid   UUID DEFAULT gen_random_uuid(),           -- 2
    first_name      VARCHAR(100) NOT NULL,                    -- 3
    last_name       VARCHAR(100) NOT NULL,                    -- 4
    initials        CHAR(3),                                  -- 5
    email           VARCHAR(200) NOT NULL,                    -- 6
    active          BOOLEAN DEFAULT TRUE,                     -- 7
    department      VARCHAR(100),                             -- 8
    title           TEXT,                                     -- 9
    salary          NUMERIC(12, 2),                           -- 10
    bonus           MONEY,                                    -- 11
    rating          REAL,                                     -- 12
    performance     DOUBLE PRECISION,                         -- 13
    level           SMALLINT,                                 -- 14
    badge_number    BIGINT,                                   -- 15
    hire_date       DATE,                                     -- 16
    shift_start     TIME,                                     -- 17
    tenure          INTERVAL,                                 -- 18
    office_ip       INET,                                     -- 19
    desk_mac        MACADDR,                                  -- 20
    tags            TEXT[],                                    -- 21
    preferences     JSONB,                                    -- 22
    notes           JSON,                                     -- 23
    avatar          BYTEA,                                    -- 24
    manager_id      BIGINT REFERENCES employee_profiles(id),  -- 25
    updated_at      TIMESTAMPTZ DEFAULT NOW()                 -- 26
);

INSERT INTO employee_profiles
    (employee_uuid, first_name, last_name, initials, email, active, department, title, salary, bonus, rating, performance, level, badge_number, hire_date, shift_start, tenure, office_ip, desk_mac, tags, preferences, notes, avatar, manager_id)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'Ada',   'Lovelace', 'AL ', 'ada@example.com',   TRUE,  'Engineering', 'Principal Engineer',   185000.00,  '$15,000.00', 4.9,  0.98,  7, 1000001, '2020-03-15', '09:00:00', '5 years 10 months', '10.1.1.10',   '00:11:22:33:44:55', ARRAY['mentor', 'lead'],  '{"theme": "dark", "lang": "en"}',  '{"bio": "Pioneering programmer"}', E'\\x89504E47', NULL),
    ('22222222-2222-2222-2222-222222222222', 'Grace', 'Hopper',   'GH ', 'grace@example.com', TRUE,  'Engineering', 'Distinguished Fellow', 210000.50,  '$25,000.00', 5.0,  0.995, 8, 1000002, '2018-07-01', '08:30:00', '7 years 7 months',  '10.1.1.11',   'AA:BB:CC:DD:EE:FF', ARRAY['compiler'],        '{"theme": "light"}',               NULL,                               E'\\xFFD8FFE0', 1),
    ('33333333-3333-3333-3333-333333333333', 'Taro',  'Yamada',   NULL,  'taro@example.com',  FALSE, 'Finance',     'Analyst',              15000000.00, NULL,        NULL, NULL,  3, NULL,    '2024-01-10', NULL,       '1 year 1 month',    NULL,          NULL,                NULL,                     NULL,                               '{"notes": []}',                    NULL,          NULL);


-- ==========================================================================
-- Section 2: ~32 additional tables for table-editor demo
-- ==========================================================================

-- -------------------------------------------------------------------------
-- DOMAIN A: HR  (5 tables, extends existing `users`)
-- -------------------------------------------------------------------------

CREATE TABLE departments (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,
    code        CHAR(4) NOT NULL UNIQUE,
    budget      NUMERIC(14, 2),
    active      BOOLEAN DEFAULT TRUE,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO departments (name, code, budget, active, metadata) VALUES
    ('Engineering',       'ENGR', 2500000.00, TRUE,  '{"head_count_cap": 120}'),
    ('Product',           'PROD', 1200000.00, TRUE,  '{"head_count_cap": 40}'),
    ('Design',            'DSGN', 800000.00,  TRUE,  NULL),
    ('Marketing',         'MKTG', 950000.00,  TRUE,  '{"region": "global"}'),
    ('Sales',             'SALE', 1800000.00, TRUE,  '{"quota_model": "tiered"}'),
    ('Finance',           'FINA', 600000.00,  TRUE,  NULL),
    ('Legal',             'LEGL', 500000.00,  TRUE,  NULL),
    ('Human Resources',   'HRSV', 400000.00,  TRUE,  '{"vendor": "workday"}'),
    ('Data Science',      'DTSC', 1100000.00, TRUE,  '{"gpu_budget": 200000}'),
    ('Operations',        'OPRS', 700000.00,  FALSE, NULL);

CREATE TABLE salary_history (
    id          BIGSERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    period      DATERANGE NOT NULL,
    amount      NUMERIC(12, 2) NOT NULL,
    currency    CHAR(3) DEFAULT 'USD'
);

DO $$
DECLARE
    uids INT[] := ARRAY(SELECT id FROM users);
    u INT;
    yr INT;
    base NUMERIC;
BEGIN
    FOR i IN 1..500 LOOP
        u := uids[1 + floor(random() * array_length(uids, 1))::int];
        yr := 2018 + floor(random() * 7)::int;
        base := 40000 + floor(random() * 160000);
        INSERT INTO salary_history (user_id, period, amount, currency)
        VALUES (
            u,
            daterange(make_date(yr, 1, 1), make_date(yr, 12, 31), '[]'),
            base,
            (ARRAY['USD','EUR','GBP','JPY','CAD'])[1 + floor(random() * 5)::int]
        );
    END LOOP;
END $$;

CREATE TABLE time_entries (
    id          BIGSERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    entry_date  DATE NOT NULL,
    duration    INTERVAL NOT NULL,
    project     VARCHAR(80),
    billable    BOOLEAN DEFAULT TRUE,
    notes       TEXT
);

DO $$
DECLARE
    uids INT[] := ARRAY(SELECT id FROM users);
    u INT;
    d DATE;
BEGIN
    FOR i IN 1..500 LOOP
        u := uids[1 + floor(random() * array_length(uids, 1))::int];
        d := '2025-01-01'::date + (floor(random() * 365))::int;
        INSERT INTO time_entries (user_id, entry_date, duration, project, billable, notes)
        VALUES (
            u, d,
            (1 + floor(random() * 8))::int * INTERVAL '1 hour',
            (ARRAY['Apollo','Beacon','Catalyst','Delta','Echo'])[1 + floor(random() * 5)::int],
            random() > 0.15,
            CASE WHEN random() < 0.3 THEN NULL ELSE 'Work session #' || i END
        );
    END LOOP;
END $$;

CREATE TABLE office_locations (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    city        TEXT NOT NULL,
    country     CHAR(2) NOT NULL,
    coords      POINT,
    open_hours  TSRANGE
);

INSERT INTO office_locations (name, city, country, coords, open_hours) VALUES
    ('HQ Tower',        'San Francisco', 'US', POINT(-122.4194, 37.7749), tsrange('2025-01-01 08:00', '2025-01-01 18:00')),
    ('London Hub',      'London',        'GB', POINT(-0.1278, 51.5074),   tsrange('2025-01-01 09:00', '2025-01-01 17:30')),
    ('Berlin Lab',      'Berlin',        'DE', POINT(13.4050, 52.5200),   tsrange('2025-01-01 08:30', '2025-01-01 17:00')),
    ('Tokyo Office',    'Tokyo',         'JP', POINT(139.6917, 35.6895),  tsrange('2025-01-01 09:00', '2025-01-01 18:00')),
    ('Sydney Branch',   'Sydney',        'AU', POINT(151.2093, -33.8688), tsrange('2025-01-01 08:00', '2025-01-01 16:30')),
    ('Toronto Studio',  'Toronto',       'CA', POINT(-79.3832, 43.6532),  tsrange('2025-01-01 09:00', '2025-01-01 17:00')),
    ('Mumbai Center',   'Mumbai',        'IN', POINT(72.8777, 19.0760),   NULL),
    ('São Paulo Annex', 'São Paulo',     'BR', POINT(-46.6333, -23.5505), tsrange('2025-01-01 09:00', '2025-01-01 18:00'));

CREATE TABLE skills (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(80) NOT NULL,
    difficulty  SMALLINT CHECK (difficulty BETWEEN 1 AND 10)
);

DO $$
DECLARE
    names TEXT[] := ARRAY[
        'Go','Rust','Python','TypeScript','Java','C++','SQL','Kubernetes',
        'Docker','Terraform','AWS','GCP','Azure','React','Vue','Angular',
        'PostgreSQL','Redis','Kafka','gRPC','REST','GraphQL','Linux',
        'Networking','Security','ML','NLP','CV','Data Engineering',
        'Product Management','Figma','Sketch','Technical Writing',
        'Agile','DevOps','CI/CD','Monitoring','Incident Response',
        'Compliance','Cryptography','Distributed Systems','Microservices',
        'Event Sourcing','CQRS','DDD','TDD','Load Testing','Chaos Eng',
        'WebAssembly','Swift','Kotlin','Ruby','Elixir','Haskell','Scala',
        'R','Julia','Perl','PHP','Objective-C','Assembly','VHDL','SystemVerilog',
        'Unity','Unreal','Blender','OpenGL','Vulkan','WebGL','Three.js',
        'D3.js','Pandas','NumPy','SciPy','PyTorch','TensorFlow','JAX',
        'Spark','Hadoop','Airflow','dbt','Snowflake','BigQuery','Redshift',
        'DynamoDB','MongoDB','Cassandra','Neo4j','ClickHouse','TimescaleDB',
        'Prometheus','Grafana','Datadog','PagerDuty','Sentry','OpenTelemetry',
        'OAuth','SAML','OIDC','JWT','mTLS','WireGuard','eBPF','Cilium',
        'Envoy','Istio','Consul','Vault','Argo CD'
    ];
BEGIN
    FOR i IN 1..LEAST(100, array_length(names, 1)) LOOP
        INSERT INTO skills (name, difficulty)
        VALUES (names[i], 1 + floor(random() * 10)::int);
    END LOOP;
END $$;


-- -------------------------------------------------------------------------
-- DOMAIN B: E-Commerce  (6 tables, extends existing `products`)
-- -------------------------------------------------------------------------

CREATE TABLE product_categories (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    description TEXT
);

INSERT INTO product_categories (name, description) VALUES
    ('Electronics',    'Consumer electronics and accessories'),
    ('Clothing',       'Apparel and fashion items'),
    ('Home & Garden',  'Furniture, decor, and garden supplies'),
    ('Books',          'Physical and digital books'),
    ('Sports',         'Sporting goods and fitness equipment'),
    ('Toys',           'Games, toys, and hobby items'),
    ('Food & Drink',   'Groceries, beverages, and specialty food'),
    ('Health',         'Health, wellness, and personal care'),
    ('Automotive',     'Vehicle parts and accessories'),
    ('Software',       'Digital software and subscriptions');

-- Add category FK to existing products table
ALTER TABLE products ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES product_categories(id);

-- Insert ~496 more products (existing table has 4)
DO $$
DECLARE
    cats INT[] := ARRAY(SELECT id FROM product_categories);
    statuses product_status[] := ARRAY['draft','active','archived'];
    tag_pool TEXT[] := ARRAY['new','sale','featured','limited','eco','premium','budget','trending'];
    nm TEXT;
    cat INT;
BEGIN
    FOR i IN 1..496 LOOP
        cat := cats[1 + floor(random() * array_length(cats, 1))::int];
        nm := (ARRAY['Alpha','Beta','Gamma','Delta','Omega','Nova','Pulse','Flux','Core','Edge',
                      'Prime','Ultra','Mini','Mega','Nano','Turbo','Aero','Pixel','Craft','Bolt']
              )[1 + floor(random() * 20)::int]
              || ' ' ||
              (ARRAY['Widget','Gadget','Device','Tool','Kit','Pack','Set','Unit','Module','Block']
              )[1 + floor(random() * 10)::int]
              || ' ' || i;
        INSERT INTO products (name, price, list_price, weight_kg, stock, available, status, tags, metadata, category_id)
        VALUES (
            nm,
            round((1 + random() * 999)::numeric, 2),
            CASE WHEN random() < 0.3 THEN NULL ELSE ('$' || round((1 + random() * 1200)::numeric, 2)::text)::money END,
            CASE WHEN random() < 0.2 THEN NULL ELSE round((0.01 + random() * 50)::numeric, 2)::real END,
            floor(random() * 10000)::smallint,
            random() > 0.1,
            statuses[1 + floor(random() * 3)::int],
            CASE WHEN random() < 0.15 THEN NULL
                 ELSE ARRAY[tag_pool[1 + floor(random() * 8)::int], tag_pool[1 + floor(random() * 8)::int]]
            END,
            CASE WHEN random() < 0.25 THEN NULL
                 ELSE jsonb_build_object('color', (ARRAY['red','blue','green','black','white'])[1 + floor(random() * 5)::int],
                                         'rating', round((1 + random() * 4)::numeric, 1))
            END,
            cat
        );
    END LOOP;
END $$;

CREATE TABLE product_reviews (
    id          BIGSERIAL PRIMARY KEY,
    product_id  UUID NOT NULL REFERENCES products(id),
    rating      SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
    body        TEXT,
    verified    BOOLEAN DEFAULT FALSE,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    pids UUID[] := ARRAY(SELECT id FROM products);
    p UUID;
BEGIN
    FOR i IN 1..500 LOOP
        p := pids[1 + floor(random() * array_length(pids, 1))::int];
        INSERT INTO product_reviews (product_id, rating, body, verified, metadata, created_at)
        VALUES (
            p,
            1 + floor(random() * 5)::int,
            CASE WHEN random() < 0.1 THEN NULL
                 ELSE (ARRAY['Great product!','Solid quality.','Not bad.','Could be better.','Amazing value.',
                             'Exceeded expectations.','Decent for the price.','Would buy again.','Meh.',
                             'Fantastic craftsmanship.'])[1 + floor(random() * 10)::int]
            END,
            random() > 0.4,
            CASE WHEN random() < 0.7 THEN NULL
                 ELSE jsonb_build_object('helpful_votes', floor(random() * 50)::int)
            END,
            NOW() - (floor(random() * 365) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE inventory_logs (
    id          BIGSERIAL PRIMARY KEY,
    product_id  UUID NOT NULL REFERENCES products(id),
    qty_change  INTEGER NOT NULL,
    reason      VARCHAR(40),
    logged_at   TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    pids UUID[] := ARRAY(SELECT id FROM products);
    p UUID;
BEGIN
    FOR i IN 1..500 LOOP
        p := pids[1 + floor(random() * array_length(pids, 1))::int];
        INSERT INTO inventory_logs (product_id, qty_change, reason, logged_at)
        VALUES (
            p,
            (-50 + floor(random() * 200))::int,
            (ARRAY['restock','sale','return','adjustment','damage','audit'])[1 + floor(random() * 6)::int],
            NOW() - (floor(random() * 180) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE coupons (
    id          SERIAL PRIMARY KEY,
    code        VARCHAR(20) NOT NULL UNIQUE,
    discount    NUMERIC(5, 2) NOT NULL,
    valid_range TSTZRANGE,
    max_uses    INTEGER,
    used_count  INTEGER DEFAULT 0,
    applies_to  INT[],
    rules       JSONB
);

DO $$
BEGIN
    FOR i IN 1..50 LOOP
        INSERT INTO coupons (code, discount, valid_range, max_uses, applies_to, rules)
        VALUES (
            'PROMO' || lpad(i::text, 3, '0'),
            round((5 + random() * 45)::numeric, 2),
            tstzrange(NOW() - interval '30 days', NOW() + (floor(random() * 90) || ' days')::interval),
            CASE WHEN random() < 0.3 THEN NULL ELSE (50 + floor(random() * 950))::int END,
            CASE WHEN random() < 0.5 THEN NULL
                 ELSE ARRAY[floor(random() * 10 + 1)::int, floor(random() * 10 + 1)::int]
            END,
            CASE WHEN random() < 0.4 THEN NULL
                 ELSE jsonb_build_object('min_order', floor(random() * 100)::int, 'stackable', random() > 0.5)
            END
        );
    END LOOP;
END $$;

CREATE TABLE price_history (
    id          BIGSERIAL PRIMARY KEY,
    product_id  UUID NOT NULL REFERENCES products(id),
    price       NUMERIC(12, 2) NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL,
    reason      VARCHAR(40)
);

DO $$
DECLARE
    pids UUID[] := ARRAY(SELECT id FROM products);
    p UUID;
BEGIN
    FOR i IN 1..500 LOOP
        p := pids[1 + floor(random() * array_length(pids, 1))::int];
        INSERT INTO price_history (product_id, price, changed_at, reason)
        VALUES (
            p,
            round((1 + random() * 999)::numeric, 2),
            NOW() - (floor(random() * 365) || ' days')::interval,
            (ARRAY['initial','promo','seasonal','cost_adjust','competitor','msrp_update'])[1 + floor(random() * 6)::int]
        );
    END LOOP;
END $$;


-- -------------------------------------------------------------------------
-- DOMAIN C: Content  (4 tables)
-- -------------------------------------------------------------------------

CREATE TABLE authors (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(120) NOT NULL,
    bio         TEXT,
    social      JSONB,
    joined_at   TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    fnames TEXT[] := ARRAY['James','Maria','Chen','Fatima','Olga','Raj','Emma','Lars','Yuki','Ahmed',
                           'Sara','Ivan','Ling','Rosa','Pavel','Aisha','Erik','Mei','Oscar','Nina'];
    lnames TEXT[] := ARRAY['Smith','Garcia','Wang','Ali','Petrov','Kumar','Brown','Johansson','Tanaka','Hassan',
                           'Fischer','Kim','Santos','Murphy','Novak','Okafor','Berg','Liu','Reyes','Andersen'];
BEGIN
    FOR i IN 1..50 LOOP
        INSERT INTO authors (name, bio, social, joined_at)
        VALUES (
            fnames[1 + floor(random() * 20)::int] || ' ' || lnames[1 + floor(random() * 20)::int],
            CASE WHEN random() < 0.2 THEN NULL
                 ELSE 'Author bio #' || i || '. Writes about technology and culture.'
            END,
            CASE WHEN random() < 0.3 THEN NULL
                 ELSE jsonb_build_object('twitter', '@author' || i, 'website', 'https://author' || i || '.example.com')
            END,
            NOW() - (floor(random() * 1000) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TYPE article_status AS ENUM ('draft', 'review', 'published', 'archived');

CREATE TABLE articles (
    id          BIGSERIAL PRIMARY KEY,
    title       VARCHAR(300) NOT NULL,
    body        TEXT NOT NULL,
    author_id   INTEGER NOT NULL REFERENCES authors(id),
    tags        TEXT[],
    status      article_status DEFAULT 'draft',
    published_at TIMESTAMPTZ,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    aids INT[] := ARRAY(SELECT id FROM authors);
    a INT;
    statuses article_status[] := ARRAY['draft','review','published','archived'];
    tag_pool TEXT[] := ARRAY['tech','culture','science','opinion','tutorial','review','news','deep-dive'];
    st article_status;
BEGIN
    FOR i IN 1..500 LOOP
        a := aids[1 + floor(random() * array_length(aids, 1))::int];
        st := statuses[1 + floor(random() * 4)::int];
        INSERT INTO articles (title, body, author_id, tags, status, published_at, metadata)
        VALUES (
            'Article #' || i || ': ' || (ARRAY['The Future of','Understanding','Deep Dive into','A Guide to',
                'Rethinking','Building Better','Why We Need','Exploring'])[1 + floor(random() * 8)::int]
                || ' ' || (ARRAY['AI','Databases','Security','DevOps','Cloud','APIs','Testing','Design'])[1 + floor(random() * 8)::int],
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. '
                || 'Paragraph ' || i || ' content continues here with more detail about the topic at hand.',
            a,
            ARRAY[tag_pool[1 + floor(random() * 8)::int], tag_pool[1 + floor(random() * 8)::int]],
            st,
            CASE WHEN st = 'published' THEN NOW() - (floor(random() * 200) || ' days')::interval ELSE NULL END,
            CASE WHEN random() < 0.4 THEN NULL
                 ELSE jsonb_build_object('views', floor(random() * 50000)::int, 'read_time_min', 2 + floor(random() * 20)::int)
            END
        );
    END LOOP;
END $$;

CREATE TABLE media_uploads (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename    VARCHAR(255) NOT NULL,
    size_bytes  BIGINT NOT NULL,
    checksum    BYTEA,
    mime_type   TEXT NOT NULL,
    location    POINT,
    uploaded_at TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    exts TEXT[] := ARRAY['jpg','png','gif','mp4','pdf','webp','svg','mp3','wav','doc'];
    mimes TEXT[] := ARRAY['image/jpeg','image/png','image/gif','video/mp4','application/pdf',
                          'image/webp','image/svg+xml','audio/mpeg','audio/wav','application/msword'];
BEGIN
    FOR i IN 1..100 LOOP
        INSERT INTO media_uploads (filename, size_bytes, checksum, mime_type, location, uploaded_at)
        VALUES (
            'file_' || i || '.' || exts[1 + floor(random() * 10)::int],
            (1024 + floor(random() * 104857600))::bigint,
            CASE WHEN random() < 0.2 THEN NULL ELSE decode(md5(random()::text), 'hex') END,
            mimes[1 + floor(random() * 10)::int],
            CASE WHEN random() < 0.4 THEN NULL ELSE POINT((-180 + random() * 360), (-90 + random() * 180)) END,
            NOW() - (floor(random() * 365) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE tags_directory (
    id          SERIAL PRIMARY KEY,
    label       VARCHAR(60) NOT NULL UNIQUE,
    usage_count INTEGER DEFAULT 0
);

INSERT INTO tags_directory (label, usage_count) VALUES
    ('technology', 1520), ('science', 980), ('opinion', 740), ('tutorial', 1100),
    ('news', 2300), ('deep-dive', 460), ('review', 890), ('culture', 670),
    ('security', 1230), ('ai', 3100), ('database', 560), ('devops', 820),
    ('cloud', 940), ('open-source', 710), ('career', 430), ('startup', 580),
    ('mobile', 390), ('web', 1640), ('api', 770), ('testing', 510),
    ('design', 680), ('performance', 440), ('architecture', 620), ('data', 1050),
    ('ml', 870), ('blockchain', 210), ('iot', 340), ('edge', 190),
    ('serverless', 280), ('containers', 520);


-- -------------------------------------------------------------------------
-- DOMAIN D: Networking  (5 tables)
-- -------------------------------------------------------------------------

CREATE TABLE servers (
    id          SERIAL PRIMARY KEY,
    hostname    VARCHAR(120) NOT NULL,
    ip_address  INET NOT NULL,
    mac_address MACADDR,
    os_type     SMALLINT,  -- 1=linux, 2=windows, 3=bsd, 4=macos
    cpu_load    REAL,
    network     CIDR,
    active      BOOLEAN DEFAULT TRUE,
    provisioned_at TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    hosts TEXT[] := ARRAY['web','api','db','cache','queue','worker','proxy','monitor','build','log'];
    envs TEXT[] := ARRAY['prod','staging','dev','qa','perf'];
BEGIN
    FOR i IN 1..100 LOOP
        INSERT INTO servers (hostname, ip_address, mac_address, os_type, cpu_load, network, active, provisioned_at)
        VALUES (
            hosts[1 + floor(random() * 10)::int] || '-' || envs[1 + floor(random() * 5)::int] || '-' || lpad(i::text, 3, '0'),
            ('10.' || floor(random() * 256)::int || '.' || floor(random() * 256)::int || '.' || (1 + floor(random() * 254))::int)::inet,
            (lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
            lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
            lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
            lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
            lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
            lpad(to_hex(floor(random() * 256)::int), 2, '0'))::macaddr,
            1 + floor(random() * 4)::int,
            round((random() * 100)::numeric, 1)::real,
            ('10.' || floor(random() * 256)::int || '.' || floor(random() * 256)::int || '.0/24')::cidr,
            random() > 0.1,
            NOW() - (floor(random() * 730) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE network_interfaces (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(20) NOT NULL,
    ip_address  INET,
    mac_address MACADDR,
    server_id   INTEGER NOT NULL REFERENCES servers(id),
    enabled     BOOLEAN DEFAULT TRUE,
    speed_mbps  SMALLINT
);

DO $$
DECLARE
    sids INT[] := ARRAY(SELECT id FROM servers);
    s INT;
    iface_names TEXT[] := ARRAY['eth0','eth1','lo','wlan0','bond0','br0','veth0','ens192'];
BEGIN
    FOR i IN 1..100 LOOP
        s := sids[1 + floor(random() * array_length(sids, 1))::int];
        INSERT INTO network_interfaces (name, ip_address, mac_address, server_id, enabled, speed_mbps)
        VALUES (
            iface_names[1 + floor(random() * 8)::int],
            ('10.' || floor(random() * 256)::int || '.' || floor(random() * 256)::int || '.' || (1 + floor(random() * 254))::int)::inet,
            CASE WHEN random() < 0.1 THEN NULL::macaddr
                 ELSE (lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
                       lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
                       lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
                       lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
                       lpad(to_hex(floor(random() * 256)::int), 2, '0') || ':' ||
                       lpad(to_hex(floor(random() * 256)::int), 2, '0'))::macaddr
            END,
            s,
            random() > 0.05,
            (ARRAY[100, 1000, 2500, 10000, 25000])[1 + floor(random() * 5)::int]::smallint
        );
    END LOOP;
END $$;

CREATE TABLE firewall_rules (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    source_cidr CIDR NOT NULL,
    port_range  INT4RANGE,
    protocol    SMALLINT,  -- 6=TCP, 17=UDP, 1=ICMP
    allow       BOOLEAN NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    rule_names TEXT[] := ARRAY['allow-http','allow-https','allow-ssh','block-telnet','allow-dns',
                               'allow-db','allow-redis','block-smb','allow-grpc','allow-metrics'];
    ports INT[] := ARRAY[22, 80, 443, 3000, 5432, 6379, 8080, 8443, 9090, 9200];
    lo INT;
    hi INT;
BEGIN
    FOR i IN 1..100 LOOP
        lo := ports[1 + floor(random() * 10)::int];
        hi := ports[1 + floor(random() * 10)::int] + floor(random() * 100)::int;
        INSERT INTO firewall_rules (name, source_cidr, port_range, protocol, allow, created_at)
        VALUES (
            rule_names[1 + floor(random() * 10)::int] || '-' || i,
            ('10.' || floor(random() * 256)::int || '.0.0/16')::cidr,
            int4range(LEAST(lo, hi), GREATEST(lo, hi), '[)'),
            (ARRAY[1, 6, 17])[1 + floor(random() * 3)::int],
            random() > 0.3,
            NOW() - (floor(random() * 365) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE dns_records (
    id          SERIAL PRIMARY KEY,
    hostname    VARCHAR(255) NOT NULL,
    record_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER DEFAULT 3600,
    priority    SMALLINT,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    domains TEXT[] := ARRAY['example.com','api.example.com','mail.example.com','cdn.example.com',
                            'staging.example.com','dev.example.com','docs.example.com','status.example.com'];
    rtypes TEXT[] := ARRAY['A','AAAA','CNAME','MX','TXT','NS','SRV','CAA'];
BEGIN
    FOR i IN 1..100 LOOP
        INSERT INTO dns_records (hostname, record_type, value, ttl, priority, updated_at)
        VALUES (
            (ARRAY['app','www','api','mail','ftp','ssh','vpn','git','ci','grafana'])[1 + floor(random() * 10)::int]
                || '.' || domains[1 + floor(random() * 8)::int],
            rtypes[1 + floor(random() * 8)::int],
            CASE WHEN random() < 0.5
                 THEN '10.' || floor(random() * 256)::int || '.' || floor(random() * 256)::int || '.' || (1 + floor(random() * 254))::int
                 ELSE 'target-' || i || '.example.com'
            END,
            (ARRAY[60, 300, 900, 3600, 86400])[1 + floor(random() * 5)::int],
            CASE WHEN random() < 0.6 THEN NULL ELSE floor(random() * 100)::smallint END,
            NOW() - (floor(random() * 180) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE access_logs (
    id          BIGSERIAL PRIMARY KEY,
    source_ip   INET NOT NULL,
    method      VARCHAR(10) NOT NULL,
    path        TEXT NOT NULL,
    status_code SMALLINT NOT NULL,
    latency_ms  REAL,
    bytes_sent  BIGINT,
    logged_at   TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    methods TEXT[] := ARRAY['GET','GET','GET','POST','PUT','DELETE','PATCH','HEAD'];
    paths TEXT[] := ARRAY['/api/v1/users','/api/v1/products','/api/v1/orders','/health','/metrics',
                          '/api/v2/search','/graphql','/api/v1/auth/login','/api/v1/uploads','/dashboard'];
    codes SMALLINT[] := ARRAY[200,200,200,201,204,301,400,401,403,404,500,502,503];
BEGIN
    FOR i IN 1..500 LOOP
        INSERT INTO access_logs (source_ip, method, path, status_code, latency_ms, bytes_sent, logged_at)
        VALUES (
            (floor(random() * 223 + 1)::int || '.' || floor(random() * 256)::int || '.' ||
             floor(random() * 256)::int || '.' || (1 + floor(random() * 254))::int)::inet,
            methods[1 + floor(random() * 8)::int],
            paths[1 + floor(random() * 10)::int] || CASE WHEN random() < 0.3 THEN '/' || floor(random() * 1000)::int ELSE '' END,
            codes[1 + floor(random() * 13)::int],
            round((0.5 + random() * 2000)::numeric, 2)::real,
            (100 + floor(random() * 500000))::bigint,
            NOW() - (floor(random() * 30 * 24 * 60) || ' minutes')::interval
        );
    END LOOP;
END $$;


-- -------------------------------------------------------------------------
-- DOMAIN E: Finance  (5 tables)
-- -------------------------------------------------------------------------

CREATE TABLE accounts (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(120) NOT NULL,
    account_num VARCHAR(20) NOT NULL UNIQUE,
    currency    CHAR(3) DEFAULT 'USD',
    balance     NUMERIC(16, 2) NOT NULL DEFAULT 0,
    active      BOOLEAN DEFAULT TRUE,
    opened_on   DATE NOT NULL,
    metadata    JSONB
);

DO $$
DECLARE
    types TEXT[] := ARRAY['Checking','Savings','Business','Investment','Escrow'];
    owners TEXT[] := ARRAY['Acme Corp','Globex Inc','Initech','Umbrella Ltd','Stark Industries',
                           'Wayne Enterprises','Cyberdyne','Soylent Corp','Wonka Industries','Aperture Science'];
BEGIN
    FOR i IN 1..50 LOOP
        INSERT INTO accounts (name, account_num, currency, balance, active, opened_on, metadata)
        VALUES (
            owners[1 + floor(random() * 10)::int] || ' ' || types[1 + floor(random() * 5)::int],
            'ACC' || lpad(i::text, 8, '0'),
            (ARRAY['USD','EUR','GBP','JPY','CHF'])[1 + floor(random() * 5)::int],
            round((100 + random() * 9999900)::numeric, 2),
            random() > 0.1,
            '2015-01-01'::date + (floor(random() * 3650))::int,
            CASE WHEN random() < 0.4 THEN NULL
                 ELSE jsonb_build_object('tier', (ARRAY['basic','silver','gold','platinum'])[1 + floor(random() * 4)::int])
            END
        );
    END LOOP;
END $$;

CREATE TABLE transactions (
    id          BIGSERIAL PRIMARY KEY,
    tx_ref      UUID DEFAULT gen_random_uuid(),
    account_id  INTEGER NOT NULL REFERENCES accounts(id),
    amount      NUMERIC(14, 2) NOT NULL,
    currency    CHAR(3) DEFAULT 'USD',
    tx_type     VARCHAR(20) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    aids INT[] := ARRAY(SELECT id FROM accounts);
    a INT;
    tx_types TEXT[] := ARRAY['credit','debit','transfer','fee','interest','refund','adjustment','dividend'];
BEGIN
    FOR i IN 1..500 LOOP
        a := aids[1 + floor(random() * array_length(aids, 1))::int];
        INSERT INTO transactions (account_id, amount, currency, tx_type, description, created_at)
        VALUES (
            a,
            round((-10000 + random() * 20000)::numeric, 2),
            (ARRAY['USD','EUR','GBP','JPY','CHF'])[1 + floor(random() * 5)::int],
            tx_types[1 + floor(random() * 8)::int],
            CASE WHEN random() < 0.3 THEN NULL ELSE 'Transaction memo #' || i END,
            NOW() - (floor(random() * 365) || ' days')::interval
        );
    END LOOP;
END $$;

CREATE TABLE exchange_rates (
    id          SERIAL PRIMARY KEY,
    base_cur    CHAR(3) NOT NULL,
    quote_cur   CHAR(3) NOT NULL,
    rate        NUMERIC(12, 6) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    source      VARCHAR(40)
);

DO $$
DECLARE
    currencies CHAR(3)[] := ARRAY['USD','EUR','GBP','JPY','CHF','CAD','AUD','CNY','INR','BRL'];
    b CHAR(3);
    q CHAR(3);
BEGIN
    FOR i IN 1..100 LOOP
        b := currencies[1 + floor(random() * 10)::int];
        q := currencies[1 + floor(random() * 10)::int];
        IF b = q THEN q := currencies[1 + (floor(random() * 9)::int + 1) % 10]; END IF;
        INSERT INTO exchange_rates (base_cur, quote_cur, rate, recorded_at, source)
        VALUES (
            b, q,
            round((0.01 + random() * 150)::numeric, 6),
            NOW() - (floor(random() * 365 * 24) || ' hours')::interval,
            (ARRAY['reuters','bloomberg','ecb','fed','manual'])[1 + floor(random() * 5)::int]
        );
    END LOOP;
END $$;

CREATE TABLE invoices (
    id          SERIAL PRIMARY KEY,
    invoice_num VARCHAR(20) NOT NULL UNIQUE,
    account_id  INTEGER NOT NULL REFERENCES accounts(id),
    total       MONEY NOT NULL,
    due_date    DATE NOT NULL,
    issued_at   TIMESTAMPTZ DEFAULT NOW(),
    line_items  JSONB
);

DO $$
DECLARE
    aids INT[] := ARRAY(SELECT id FROM accounts);
    a INT;
BEGIN
    FOR i IN 1..100 LOOP
        a := aids[1 + floor(random() * array_length(aids, 1))::int];
        INSERT INTO invoices (invoice_num, account_id, total, due_date, issued_at, line_items)
        VALUES (
            'INV-' || lpad(i::text, 6, '0'),
            a,
            (round((10 + random() * 99990)::numeric, 2)::text || '')::money,
            CURRENT_DATE + (floor(random() * 90))::int,
            NOW() - (floor(random() * 60) || ' days')::interval,
            CASE WHEN random() < 0.2 THEN NULL
                 ELSE jsonb_build_array(
                     jsonb_build_object('item', 'Service A', 'qty', 1 + floor(random() * 10)::int, 'unit_price', round((10 + random() * 500)::numeric, 2)),
                     jsonb_build_object('item', 'Service B', 'qty', 1 + floor(random() * 5)::int, 'unit_price', round((50 + random() * 1000)::numeric, 2))
                 )
            END
        );
    END LOOP;
END $$;

CREATE TABLE audit_trail (
    id          BIGSERIAL PRIMARY KEY,
    table_name  VARCHAR(80) NOT NULL,
    record_id   BIGINT NOT NULL,
    action      VARCHAR(10) NOT NULL,  -- INSERT, UPDATE, DELETE
    changes     JSONB,
    performed_at TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    tables TEXT[] := ARRAY['accounts','transactions','invoices','users','products','orders','servers'];
    actions TEXT[] := ARRAY['INSERT','UPDATE','UPDATE','UPDATE','DELETE'];
BEGIN
    FOR i IN 1..500 LOOP
        INSERT INTO audit_trail (table_name, record_id, action, changes, performed_at)
        VALUES (
            tables[1 + floor(random() * 7)::int],
            (1 + floor(random() * 500))::bigint,
            actions[1 + floor(random() * 5)::int],
            CASE WHEN random() < 0.15 THEN NULL
                 ELSE jsonb_build_object(
                     'field', (ARRAY['name','status','amount','email','active'])[1 + floor(random() * 5)::int],
                     'old', 'value_' || floor(random() * 100)::int,
                     'new', 'value_' || floor(random() * 100)::int
                 )
            END,
            NOW() - (floor(random() * 365 * 24 * 60) || ' minutes')::interval
        );
    END LOOP;
END $$;


-- -------------------------------------------------------------------------
-- DOMAIN F: IoT / Sensors  (5 tables)
-- -------------------------------------------------------------------------

CREATE TABLE sensor_types (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(60) NOT NULL,
    unit            VARCHAR(20) NOT NULL,
    precision_val   DOUBLE PRECISION
);

INSERT INTO sensor_types (name, unit, precision_val) VALUES
    ('Temperature',     '°C',     0.1),
    ('Humidity',        '%RH',    0.5),
    ('Pressure',        'hPa',    0.01),
    ('CO2',             'ppm',    1.0),
    ('Light',           'lux',    5.0),
    ('Vibration',       'mm/s',   0.001),
    ('Sound Level',     'dB',     0.5),
    ('Wind Speed',      'm/s',    0.1);

CREATE TABLE sensors (
    id              SERIAL PRIMARY KEY,
    label           VARCHAR(80) NOT NULL,
    sensor_type_id  INTEGER NOT NULL REFERENCES sensor_types(id),
    location        POINT,
    installed_on    DATE,
    active          BOOLEAN DEFAULT TRUE,
    firmware_ver    SMALLINT,
    last_seen       TIMESTAMPTZ
);

DO $$
DECLARE
    stids INT[] := ARRAY(SELECT id FROM sensor_types);
    zones TEXT[] := ARRAY['warehouse-A','warehouse-B','office-1','office-2','server-room','rooftop','lobby','parking','lab','garden'];
BEGIN
    FOR i IN 1..100 LOOP
        INSERT INTO sensors (label, sensor_type_id, location, installed_on, active, firmware_ver, last_seen)
        VALUES (
            zones[1 + floor(random() * 10)::int] || '/sensor-' || lpad(i::text, 3, '0'),
            stids[1 + floor(random() * array_length(stids, 1))::int],
            POINT((-180 + random() * 360), (-90 + random() * 180)),
            '2020-01-01'::date + (floor(random() * 1800))::int,
            random() > 0.08,
            (1 + floor(random() * 12))::smallint,
            CASE WHEN random() < 0.05 THEN NULL ELSE NOW() - (floor(random() * 48) || ' hours')::interval END
        );
    END LOOP;
END $$;

CREATE TABLE sensor_readings (
    id          BIGSERIAL PRIMARY KEY,
    sensor_id   INTEGER NOT NULL REFERENCES sensors(id),
    value       DOUBLE PRECISION NOT NULL,
    accuracy    REAL,
    raw_data    BYTEA,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
DECLARE
    sids INT[] := ARRAY(SELECT id FROM sensors);
    s INT;
BEGIN
    FOR i IN 1..500 LOOP
        s := sids[1 + floor(random() * array_length(sids, 1))::int];
        INSERT INTO sensor_readings (sensor_id, value, accuracy, raw_data, recorded_at)
        VALUES (
            s,
            round((-20 + random() * 120)::numeric, 4)::double precision,
            CASE WHEN random() < 0.1 THEN NULL ELSE round((0.8 + random() * 0.2)::numeric, 3)::real END,
            CASE WHEN random() < 0.7 THEN NULL ELSE decode(md5(random()::text), 'hex') END,
            NOW() - (floor(random() * 7 * 24 * 60) || ' minutes')::interval
        );
    END LOOP;
END $$;

CREATE TABLE alerts (
    id          SERIAL PRIMARY KEY,
    sensor_id   INTEGER NOT NULL REFERENCES sensors(id),
    severity    SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 5),
    message     TEXT NOT NULL,
    acknowledged BOOLEAN DEFAULT FALSE,
    ack_by      VARCHAR(80),
    triggered_at TIMESTAMPTZ DEFAULT NOW()
);

DO $$
DECLARE
    sids INT[] := ARRAY(SELECT id FROM sensors);
    s INT;
    msgs TEXT[] := ARRAY['Threshold exceeded','Sensor offline','Anomaly detected','Battery low',
                         'Calibration needed','Connection lost','Data gap','Firmware outdated',
                         'Value out of range','Repeated failures'];
BEGIN
    FOR i IN 1..100 LOOP
        s := sids[1 + floor(random() * array_length(sids, 1))::int];
        INSERT INTO alerts (sensor_id, severity, message, acknowledged, ack_by, triggered_at)
        VALUES (
            s,
            1 + floor(random() * 5)::int,
            msgs[1 + floor(random() * 10)::int],
            random() > 0.4,
            CASE WHEN random() < 0.5 THEN NULL ELSE 'ops-' || (ARRAY['alice','bob','carol','dave','eve'])[1 + floor(random() * 5)::int] END,
            NOW() - (floor(random() * 30 * 24) || ' hours')::interval
        );
    END LOOP;
END $$;

CREATE TABLE maintenance_schedules (
    id          SERIAL PRIMARY KEY,
    sensor_id   INTEGER NOT NULL REFERENCES sensors(id),
    maint_window TSTZRANGE NOT NULL,
    description TEXT,
    technician  VARCHAR(80),
    completed   BOOLEAN DEFAULT FALSE
);

DO $$
DECLARE
    sids INT[] := ARRAY(SELECT id FROM sensors);
    s INT;
    start_ts TIMESTAMPTZ;
BEGIN
    FOR i IN 1..50 LOOP
        s := sids[1 + floor(random() * array_length(sids, 1))::int];
        start_ts := NOW() + (floor(random() * 90) || ' days')::interval;
        INSERT INTO maintenance_schedules (sensor_id, maint_window, description, technician, completed)
        VALUES (
            s,
            tstzrange(start_ts, start_ts + interval '4 hours'),
            CASE WHEN random() < 0.2 THEN NULL
                 ELSE (ARRAY['Calibration','Firmware update','Battery replacement','Full inspection','Cleaning'])[1 + floor(random() * 5)::int]
            END,
            CASE WHEN random() < 0.3 THEN NULL
                 ELSE 'tech-' || (ARRAY['kim','pat','sam','alex','jordan'])[1 + floor(random() * 5)::int]
            END,
            random() < 0.2
        );
    END LOOP;
END $$;


-- -------------------------------------------------------------------------
-- DOMAIN G: Type Showcases  (2 tables)
-- -------------------------------------------------------------------------

CREATE TABLE geometric_shapes (
    id          SERIAL PRIMARY KEY,
    label       VARCHAR(60),
    pt          POINT,
    ln          LINE,
    seg         LSEG,
    bx          BOX,
    pth         PATH,
    poly        POLYGON,
    circ        CIRCLE
);

DO $$
DECLARE
    x1 DOUBLE PRECISION; y1 DOUBLE PRECISION;
    x2 DOUBLE PRECISION; y2 DOUBLE PRECISION;
BEGIN
    FOR i IN 1..50 LOOP
        x1 := round((-100 + random() * 200)::numeric, 2)::double precision;
        y1 := round((-100 + random() * 200)::numeric, 2)::double precision;
        x2 := round((-100 + random() * 200)::numeric, 2)::double precision;
        y2 := round((-100 + random() * 200)::numeric, 2)::double precision;
        INSERT INTO geometric_shapes (label, pt, ln, seg, bx, pth, poly, circ)
        VALUES (
            'shape-' || i,
            POINT(x1, y1),
            LINE(POINT(x1, y1), POINT(x2, y2)),
            LSEG(POINT(x1, y1), POINT(x2, y2)),
            BOX(POINT(x1, y1), POINT(x2, y2)),
            ('((' || x1 || ',' || y1 || '),(' || x2 || ',' || y2 || '),(' || (x1+10) || ',' || (y2+10) || '))')::path,
            ('((' || x1 || ',' || y1 || '),(' || x2 || ',' || y1 || '),(' || x2 || ',' || y2 || '),(' || x1 || ',' || y2 || '))')::polygon,
            CIRCLE(POINT(x1, y1), abs(x2 - x1) + 1)
        );
    END LOOP;
END $$;

CREATE TABLE kitchen_sink (
    id              SERIAL PRIMARY KEY,
    -- numeric types
    col_smallint    SMALLINT,
    col_integer     INTEGER,
    col_bigint      BIGINT,
    col_numeric     NUMERIC(20, 8),
    col_real        REAL,
    col_double      DOUBLE PRECISION,
    col_money       MONEY,
    -- character types
    col_char        CHAR(10),
    col_varchar     VARCHAR(200),
    col_text        TEXT,
    -- binary
    col_bytea       BYTEA,
    -- date/time
    col_date        DATE,
    col_time        TIME,
    col_timetz      TIMETZ,
    col_timestamp   TIMESTAMP,
    col_timestamptz TIMESTAMPTZ,
    col_interval    INTERVAL,
    -- boolean
    col_boolean     BOOLEAN,
    -- network
    col_inet        INET,
    col_cidr        CIDR,
    col_macaddr     MACADDR,
    -- uuid
    col_uuid        UUID,
    -- json
    col_json        JSON,
    col_jsonb       JSONB,
    -- arrays
    col_text_arr    TEXT[],
    col_int_arr     INT[],
    -- geometric
    col_point       POINT,
    col_box         BOX,
    col_circle      CIRCLE,
    -- range
    col_int4range   INT4RANGE,
    col_tstzrange   TSTZRANGE,
    col_daterange   DATERANGE,
    -- xml
    col_xml         XML,
    -- bit
    col_bit         BIT(8),
    col_varbit      BIT VARYING(16)
);

INSERT INTO kitchen_sink (
    col_smallint, col_integer, col_bigint, col_numeric, col_real, col_double, col_money,
    col_char, col_varchar, col_text, col_bytea,
    col_date, col_time, col_timetz, col_timestamp, col_timestamptz, col_interval,
    col_boolean,
    col_inet, col_cidr, col_macaddr,
    col_uuid, col_json, col_jsonb,
    col_text_arr, col_int_arr,
    col_point, col_box, col_circle,
    col_int4range, col_tstzrange, col_daterange,
    col_xml, col_bit, col_varbit
) VALUES
    -- Row 1: all non-null
    (32767, 2147483647, 9223372036854775807, 12345678.12345678, 3.14, 2.718281828459045, '$1,234.56',
     'ABCDEFGHIJ', 'The quick brown fox', 'Lorem ipsum dolor sit amet', E'\\xDEADBEEF',
     '2025-06-15', '14:30:00', '14:30:00+05:30', '2025-06-15 14:30:00', '2025-06-15 14:30:00+00', '1 year 2 months 3 days',
     TRUE,
     '192.168.1.1', '10.0.0.0/8', '08:00:2b:01:02:03',
     'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', '{"key": "value"}', '{"nested": {"array": [1,2,3]}}',
     ARRAY['hello','world'], ARRAY[1,2,3,4,5],
     POINT(10, 20), BOX(POINT(0,0), POINT(100,100)), CIRCLE(POINT(50,50), 25),
     '[1,100)', tstzrange('2025-01-01', '2025-12-31'), daterange('2025-01-01', '2025-06-30'),
     '<root><item id="1">Test</item></root>', B'10101010', B'1100110011'),

    -- Row 2: min/edge values
    (-32768, -2147483648, -9223372036854775808, -99999999.99999999, -3.4e38, -1.7e308, '-$999,999.99',
     '          ', '', '', E'\\x00',
     '0001-01-01', '00:00:00', '00:00:00+00', '0001-01-01 00:00:00', '0001-01-01 00:00:00+00', '0 seconds',
     FALSE,
     '0.0.0.0', '0.0.0.0/0', '00:00:00:00:00:00',
     '00000000-0000-0000-0000-000000000000', '[]', '{}',
     ARRAY[]::TEXT[], ARRAY[]::INT[],
     POINT(0, 0), BOX(POINT(0,0), POINT(0,0)), CIRCLE(POINT(0,0), 0),
     'empty', tstzrange(NULL, NULL), daterange(NULL, NULL),
     '<empty/>', B'00000000', B'0'),

    -- Row 3: mostly nulls
    (NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     NULL,
     NULL, NULL, NULL,
     NULL, NULL, NULL,
     NULL, NULL,
     NULL, NULL, NULL,
     NULL, NULL, NULL,
     NULL, NULL, NULL),

    -- Row 4: mixed values
    (1, 42, 1000000, 3.14159265, 2.5, 1e-10, '$0.01',
     'test      ', 'Mixed row with various data', 'A longer text field that contains more content for testing purposes.',
     E'\\x48656C6C6F576F726C64',
     '2026-03-20', '23:59:59.999999', '23:59:59.999999-05', '2026-03-20 12:00:00', NOW(), '2 hours 30 minutes',
     TRUE,
     '::1', '::1/128', 'FF:FF:FF:FF:FF:FF',
     gen_random_uuid(), '{"arr": [1, "two", null, true]}', '{"tags": ["a","b"], "count": 42}',
     ARRAY['one','two','three'], ARRAY[100, 200, 300],
     POINT(-122.4194, 37.7749), BOX(POINT(-10,-10), POINT(10,10)), CIRCLE(POINT(0,0), 100),
     '[10,20]', tstzrange(NOW(), NOW() + interval '1 year'), daterange('2026-01-01', '2026-12-31'),
     '<data><val type="num">42</val></data>', B'11111111', B'1010'),

    -- Row 5: large values
    (100, 999999, 9999999999, 99999999.99, 1e10, 1e100, '$99,999.99',
     'ZZZZZZZZZZ', repeat('x', 200), repeat('Long text. ', 50),
     decode(repeat('FF', 32), 'hex'),
     '9999-12-31', '12:00:00', '12:00:00+12', '9999-12-31 23:59:59', '9999-12-31 23:59:59+00', '100 years',
     TRUE,
     '255.255.255.255', '192.168.0.0/16', 'AB:CD:EF:01:23:45',
     'ffffffff-ffff-ffff-ffff-ffffffffffff', '{"deeply": {"nested": {"object": {"key": "val"}}}}',
     '{"list": [1,2,3,4,5,6,7,8,9,10]}',
     ARRAY['alpha','beta','gamma','delta','epsilon'], ARRAY[1,1,2,3,5,8,13,21,34,55],
     POINT(180, 90), BOX(POINT(-1000,-1000), POINT(1000,1000)), CIRCLE(POINT(0,0), 9999),
     '[0,2147483647)', tstzrange('2000-01-01', '2099-12-31'), daterange('2000-01-01', '2099-12-31'),
     '<doc xmlns="urn:test"><p>Hello</p></doc>', B'01010101', B'1111111111111111'),

    -- Rows 6-10: varied
    (10, 100, 1000, 1.5, 0.5, 0.001, '$10.00',
     'ROW6      ', 'Sixth row', NULL, NULL,
     '2025-03-15', '09:30:00', NULL, '2025-03-15 09:30:00', NOW() - interval '100 days', '3 months',
     FALSE, '172.16.0.1', '172.16.0.0/12', NULL, gen_random_uuid(), NULL, '{"row": 6}',
     ARRAY['x'], ARRAY[6], POINT(1,1), NULL, CIRCLE(POINT(1,1), 1),
     '[1,10)', NULL, daterange('2025-01-01', '2025-12-31'), NULL, B'00001111', B'10'),

    (20, 200, 2000, 2.5, 1.5, 0.002, '$20.00',
     'ROW7      ', 'Seventh row', 'Some notes here', E'\\xCAFEBABE',
     '2025-07-04', '17:00:00', '17:00:00-07', '2025-07-04 17:00:00', NOW() - interval '50 days', '6 months 15 days',
     TRUE, '10.10.10.10', '10.10.0.0/16', '11:22:33:44:55:66', gen_random_uuid(), '{"flag": true}', '{"row": 7, "active": true}',
     ARRAY['a','b','c'], ARRAY[7,14,21], POINT(-50, 50), BOX(POINT(-5,-5), POINT(5,5)), NULL,
     '[100,200)', tstzrange(NOW(), NOW() + interval '6 months'), NULL, '<r7/>', B'11110000', B'01'),

    (30, 300, 3000, 3.5, 2.5, 0.003, '$30.00',
     NULL, 'Eighth row', 'More text', NULL,
     '2025-11-11', '06:00:00', NULL, NULL, NOW() - interval '10 days', NULL,
     NULL, '192.0.2.1', NULL, NULL, gen_random_uuid(), NULL, NULL,
     NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL),

    (40, 400, 4000, 4.5, 3.5, 0.004, '$40.00',
     'ROW9      ', 'Ninth row', 'Testing', E'\\x0102030405',
     CURRENT_DATE, CURRENT_TIME, CURRENT_TIME, CURRENT_TIMESTAMP, NOW(), '1 day 12 hours',
     TRUE, '198.51.100.1', '198.51.100.0/24', 'DE:AD:BE:EF:CA:FE', gen_random_uuid(),
     '{"timestamp": "now"}', '{"meta": {"version": 9}}',
     ARRAY['test','data'], ARRAY[9,99,999], POINT(42, -42), BOX(POINT(0,0), POINT(42,42)), CIRCLE(POINT(42,42), 42),
     '[9,99)', tstzrange(NOW() - interval '1 day', NOW() + interval '1 day'), daterange(CURRENT_DATE, CURRENT_DATE + 30),
     '<row num="9"/>', B'10011001', B'110011'),

    (50, 500, 5000, 5.5, 4.5, 0.005, '$50.00',
     'ROW10     ', 'Tenth row', 'Final row in the kitchen sink', E'\\xFF',
     '2026-12-25', '00:00:01', '00:00:01+00', '2026-12-25 00:00:01', '2026-12-25 00:00:01+00', '999 days',
     FALSE, '203.0.113.1', '203.0.113.0/24', '01:02:03:04:05:06', gen_random_uuid(),
     '[1, "two", 3.0, null, false]', '{"final": true, "items": [{"id": 1}, {"id": 2}]}',
     ARRAY['last','row','here'], ARRAY[10,20,30,40,50], POINT(0, 0), BOX(POINT(-99,-99), POINT(99,99)), CIRCLE(POINT(0,0), 50),
     '[0,1000000)', tstzrange('1970-01-01', '2038-01-19'), daterange('2026-01-01', '2027-01-01'),
     '<final>done</final>', B'11001100', B'0101010101');


-- =========================================================================
-- NON-PUBLIC SCHEMAS  (for multi-schema table-editor testing)
-- =========================================================================

-- -------------------------------------------------------------------------
-- SCHEMA: analytics  (3 tables) — website/product analytics
-- -------------------------------------------------------------------------

CREATE SCHEMA analytics;

CREATE TABLE analytics.events (
    id          BIGSERIAL PRIMARY KEY,
    event_name  VARCHAR(100) NOT NULL,
    user_id     INTEGER,
    session_id  VARCHAR(64),
    properties  JSONB,
    page_url    TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO analytics.events (event_name, user_id, session_id, properties, page_url, occurred_at) VALUES
    ('page_view',    1, 'sess_a1b2c3', '{"referrer": "google.com"}',        '/pricing',           '2026-03-01 08:00:00+00'),
    ('page_view',    1, 'sess_a1b2c3', NULL,                                 '/signup',            '2026-03-01 08:02:00+00'),
    ('signup',       1, 'sess_a1b2c3', '{"plan": "free"}',                  '/signup',            '2026-03-01 08:03:00+00'),
    ('page_view',    2, 'sess_d4e5f6', '{"referrer": "twitter.com"}',       '/',                  '2026-03-01 09:00:00+00'),
    ('page_view',    2, 'sess_d4e5f6', NULL,                                 '/docs',              '2026-03-01 09:05:00+00'),
    ('page_view',    NULL, 'sess_g7h8', '{"referrer": "reddit.com"}',       '/blog/intro',        '2026-03-01 10:00:00+00'),
    ('page_view',    NULL, 'sess_g7h8', NULL,                                '/blog/tutorial',     '2026-03-01 10:02:00+00'),
    ('page_view',    3, 'sess_i9j0k1', NULL,                                 '/dashboard',         '2026-03-02 07:00:00+00'),
    ('feature_used', 3, 'sess_i9j0k1', '{"feature": "export_csv"}',         '/dashboard',         '2026-03-02 07:10:00+00'),
    ('feature_used', 3, 'sess_i9j0k1', '{"feature": "table_editor"}',       '/dashboard/tables',  '2026-03-02 07:15:00+00'),
    ('page_view',    1, 'sess_l2m3n4', NULL,                                 '/settings',          '2026-03-02 08:00:00+00'),
    ('plan_upgrade', 1, 'sess_l2m3n4', '{"from": "free", "to": "pro"}',    '/settings/billing',  '2026-03-02 08:05:00+00'),
    ('page_view',    NULL, 'sess_o5p6', '{"referrer": "bing.com"}',         '/pricing',           '2026-03-02 11:00:00+00'),
    ('page_view',    NULL, 'sess_o5p6', NULL,                                '/docs/install',      '2026-03-02 11:03:00+00'),
    ('signup',       NULL, 'sess_o5p6', '{"plan": "pro"}',                  '/signup',            '2026-03-02 11:10:00+00'),
    ('page_view',    2, 'sess_q7r8s9', NULL,                                 '/dashboard',         '2026-03-03 06:30:00+00'),
    ('feature_used', 2, 'sess_q7r8s9', '{"feature": "sql_runner"}',         '/dashboard/sql',     '2026-03-03 06:45:00+00'),
    ('error',        2, 'sess_q7r8s9', '{"code": 500, "message": "timeout"}', '/dashboard/sql',   '2026-03-03 06:46:00+00'),
    ('page_view',    1, 'sess_t0u1v2', NULL,                                 '/docs/api',          '2026-03-03 09:00:00+00'),
    ('page_view',    1, 'sess_t0u1v2', NULL,                                 '/docs/api/auth',     '2026-03-03 09:05:00+00'),
    ('page_view',    NULL, 'sess_w3x4', '{"referrer": "github.com"}',       '/',                  '2026-03-03 12:00:00+00'),
    ('page_view',    NULL, 'sess_w3x4', NULL,                                '/pricing',           '2026-03-03 12:01:00+00'),
    ('page_view',    3, 'sess_y5z6a7', NULL,                                 '/dashboard',         '2026-03-04 07:00:00+00'),
    ('feature_used', 3, 'sess_y5z6a7', '{"feature": "schema_browser"}',     '/dashboard/schemas', '2026-03-04 07:05:00+00'),
    ('feature_used', 3, 'sess_y5z6a7', '{"feature": "table_editor"}',       '/dashboard/tables',  '2026-03-04 07:20:00+00'),
    ('page_view',    2, 'sess_b8c9d0', NULL,                                 '/settings',          '2026-03-04 10:00:00+00'),
    ('page_view',    2, 'sess_b8c9d0', NULL,                                 '/settings/team',     '2026-03-04 10:02:00+00'),
    ('invite_sent',  2, 'sess_b8c9d0', '{"invitee_email": "dave@acme.co"}', '/settings/team',     '2026-03-04 10:05:00+00'),
    ('page_view',    1, 'sess_e1f2g3', NULL,                                 '/changelog',         '2026-03-04 14:00:00+00'),
    ('logout',       1, 'sess_e1f2g3', NULL,                                 '/changelog',         '2026-03-04 14:10:00+00');

CREATE TABLE analytics.daily_active_users (
    id              SERIAL PRIMARY KEY,
    report_date     DATE NOT NULL UNIQUE,
    total_users     INTEGER NOT NULL DEFAULT 0,
    new_signups     INTEGER NOT NULL DEFAULT 0,
    returning_users INTEGER NOT NULL DEFAULT 0,
    churned_users   INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO analytics.daily_active_users (report_date, total_users, new_signups, returning_users, churned_users) VALUES
    ('2026-03-01', 142, 8,  134, 3),
    ('2026-03-02', 155, 12, 143, 1),
    ('2026-03-03', 148, 5,  143, 4),
    ('2026-03-04', 161, 15, 146, 2),
    ('2026-03-05', 158, 9,  149, 5),
    ('2026-03-06', 130, 4,  126, 6),
    ('2026-03-07', 115, 3,  112, 2),
    ('2026-03-08', 165, 11, 154, 3),
    ('2026-03-09', 170, 14, 156, 1),
    ('2026-03-10', 168, 10, 158, 4);

CREATE TABLE analytics.campaigns (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    channel         VARCHAR(50) NOT NULL,
    budget_cents    INTEGER NOT NULL DEFAULT 0,
    spent_cents     INTEGER NOT NULL DEFAULT 0,
    clicks          INTEGER NOT NULL DEFAULT 0,
    conversions     INTEGER NOT NULL DEFAULT 0,
    start_date      DATE NOT NULL,
    end_date        DATE,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO analytics.campaigns (name, channel, budget_cents, spent_cents, clicks, conversions, start_date, end_date, is_active) VALUES
    ('Spring Launch',       'google_ads',  500000, 320000, 4200, 84,  '2026-03-01', '2026-03-31', TRUE),
    ('Dev Newsletter Q1',   'email',       50000,  50000,  1800, 120, '2026-01-15', '2026-03-15', FALSE),
    ('Twitter Awareness',   'twitter_ads', 200000, 145000, 2100, 35,  '2026-02-01', '2026-04-01', TRUE),
    ('Blog SEO Content',    'organic',     0,      0,      8500, 210, '2025-06-01', NULL,         TRUE),
    ('Product Hunt Launch', 'product_hunt', 0,     0,      12000, 450, '2026-02-20', '2026-02-20', FALSE);

-- -------------------------------------------------------------------------
-- SCHEMA: billing  (3 tables) — subscriptions and invoicing
-- -------------------------------------------------------------------------

CREATE SCHEMA billing;

CREATE TABLE billing.customers (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    email           VARCHAR(200) NOT NULL UNIQUE,
    company         VARCHAR(200),
    stripe_id       VARCHAR(50),
    tax_id          VARCHAR(50),
    address_line1   VARCHAR(200),
    address_city    VARCHAR(100),
    address_country CHAR(2),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO billing.customers (name, email, company, stripe_id, tax_id, address_line1, address_city, address_country) VALUES
    ('Alice Johnson',  'alice@acme.co',      'Acme Corp',        'cus_abc123', 'US12-3456789', '123 Main St',     'San Francisco', 'US'),
    ('Bob Smith',      'bob@widgets.io',     'Widgets Inc',      'cus_def456', NULL,           '456 Oak Ave',     'Austin',        'US'),
    ('Carol Chen',     'carol@startup.dev',  'Startup Dev LLC',  'cus_ghi789', 'DE123456789',  'Berliner Str 10', 'Berlin',        'DE'),
    ('Dave Kumar',     'dave@bigcorp.com',   'BigCorp',          'cus_jkl012', 'GB123456789',  '10 Downing St',   'London',        'GB'),
    ('Eve Santos',     'eve@solo.dev',       NULL,               'cus_mno345', NULL,           NULL,              NULL,            NULL),
    ('Frank Liu',      'frank@techco.cn',    'TechCo',           'cus_pqr678', NULL,           '789 Tech Blvd',   'Shanghai',      'CN'),
    ('Grace Park',     'grace@design.kr',    'Design Studio',    'cus_stu901', 'KR1234567890', '55 Gangnam Rd',   'Seoul',         'KR'),
    ('Hiro Tanaka',    'hiro@agency.jp',     'Digital Agency',   'cus_vwx234', 'JP1234567890', '1-2-3 Shibuya',   'Tokyo',         'JP'),
    ('Ines Martin',    'ines@consulting.fr', 'Consulting SA',    'cus_yza567', 'FR12345678901','20 Rue de Rivoli','Paris',         'FR'),
    ('Jack Wilson',    'jack@freelance.com', NULL,               'cus_bcd890', NULL,           '88 Remote Ln',    'Portland',      'US');

CREATE TABLE billing.subscriptions (
    id              SERIAL PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES billing.customers(id),
    plan_name       VARCHAR(50) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    price_cents     INTEGER NOT NULL,
    billing_cycle   VARCHAR(10) NOT NULL DEFAULT 'monthly',
    trial_ends_at   DATE,
    current_period_start DATE NOT NULL,
    current_period_end   DATE NOT NULL,
    canceled_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO billing.subscriptions (customer_id, plan_name, status, price_cents, billing_cycle, trial_ends_at, current_period_start, current_period_end, canceled_at) VALUES
    (1, 'pro',        'active',    2900, 'monthly',  NULL,          '2026-03-01', '2026-04-01', NULL),
    (2, 'team',       'active',    7900, 'monthly',  NULL,          '2026-03-15', '2026-04-15', NULL),
    (3, 'pro',        'trialing',  2900, 'monthly',  '2026-04-01', '2026-03-01', '2026-04-01', NULL),
    (4, 'enterprise', 'active',    49900, 'yearly',  NULL,          '2026-01-01', '2027-01-01', NULL),
    (5, 'free',       'active',    0,    'monthly',  NULL,          '2026-03-01', '2026-04-01', NULL),
    (6, 'pro',        'active',    2900, 'monthly',  NULL,          '2026-03-10', '2026-04-10', NULL),
    (7, 'team',       'canceled',  7900, 'monthly',  NULL,          '2026-02-01', '2026-03-01', '2026-02-20 14:30:00+00'),
    (8, 'pro',        'past_due',  2900, 'monthly',  NULL,          '2026-02-15', '2026-03-15', NULL),
    (9, 'enterprise', 'active',    49900, 'yearly',  NULL,          '2025-09-01', '2026-09-01', NULL),
    (10, 'free',      'active',    0,    'monthly',  NULL,          '2026-03-01', '2026-04-01', NULL);

CREATE TABLE billing.invoices (
    id              SERIAL PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES billing.customers(id),
    subscription_id INTEGER REFERENCES billing.subscriptions(id),
    invoice_number  VARCHAR(20) NOT NULL UNIQUE,
    status          VARCHAR(20) NOT NULL DEFAULT 'draft',
    subtotal_cents  INTEGER NOT NULL,
    tax_cents       INTEGER NOT NULL DEFAULT 0,
    total_cents     INTEGER NOT NULL,
    currency        CHAR(3) NOT NULL DEFAULT 'USD',
    due_date        DATE,
    paid_at         TIMESTAMPTZ,
    description     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO billing.invoices (customer_id, subscription_id, invoice_number, status, subtotal_cents, tax_cents, total_cents, currency, due_date, paid_at, description) VALUES
    (1, 1, 'INV-2026-0001', 'paid',    2900,  0,    2900,  'USD', '2026-03-01', '2026-03-01 00:05:00+00', 'Pro plan - March 2026'),
    (2, 2, 'INV-2026-0002', 'paid',    7900,  0,    7900,  'USD', '2026-03-15', '2026-03-15 00:03:00+00', 'Team plan - March 2026'),
    (3, 3, 'INV-2026-0003', 'draft',   2900,  551,  3451,  'EUR', '2026-04-01', NULL,                     'Pro plan - first invoice after trial'),
    (4, 4, 'INV-2026-0004', 'paid',    49900, 9980, 59880, 'GBP', '2026-01-01', '2026-01-01 09:00:00+00', 'Enterprise plan - annual 2026'),
    (6, 6, 'INV-2026-0005', 'paid',    2900,  0,    2900,  'USD', '2026-03-10', '2026-03-10 02:00:00+00', 'Pro plan - March 2026'),
    (7, 7, 'INV-2026-0006', 'void',    7900,  0,    7900,  'USD', '2026-03-01', NULL,                     'Team plan - voided after cancellation'),
    (8, 8, 'INV-2026-0007', 'overdue', 2900,  0,    2900,  'USD', '2026-03-15', NULL,                     'Pro plan - payment failed'),
    (9, 9, 'INV-2025-0050', 'paid',    49900, 9381, 59281, 'EUR', '2025-09-01', '2025-09-01 08:15:00+00', 'Enterprise plan - annual 2025-2026'),
    (1, 1, 'INV-2026-0008', 'paid',    2900,  0,    2900,  'USD', '2026-02-01', '2026-02-01 00:04:00+00', 'Pro plan - February 2026'),
    (2, 2, 'INV-2026-0009', 'paid',    7900,  0,    7900,  'USD', '2026-02-15', '2026-02-15 00:02:00+00', 'Team plan - February 2026'),
    (1, 1, 'INV-2026-0010', 'paid',    2900,  0,    2900,  'USD', '2026-01-01', '2026-01-01 00:06:00+00', 'Pro plan - January 2026'),
    (8, 8, 'INV-2026-0011', 'paid',    2900,  0,    2900,  'USD', '2026-02-15', '2026-02-16 10:30:00+00', 'Pro plan - February 2026');

-- -------------------------------------------------------------------------
-- SCHEMA: staging  (2 tables) — ETL staging area
-- -------------------------------------------------------------------------

CREATE SCHEMA staging;

CREATE TABLE staging.raw_imports (
    id           BIGSERIAL PRIMARY KEY,
    source_name  VARCHAR(100) NOT NULL,
    file_name    VARCHAR(255),
    row_data     JSONB NOT NULL,
    is_processed BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    imported_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO staging.raw_imports (source_name, file_name, row_data, is_processed, error_message, imported_at) VALUES
    ('salesforce', 'contacts_export_20260301.csv', '{"name": "Alice Johnson", "email": "alice@acme.co", "title": "CTO"}',            TRUE,  NULL, '2026-03-01 06:00:00+00'),
    ('salesforce', 'contacts_export_20260301.csv', '{"name": "Bob Smith", "email": "bob@widgets.io", "title": "VP Eng"}',             TRUE,  NULL, '2026-03-01 06:00:01+00'),
    ('salesforce', 'contacts_export_20260301.csv', '{"name": "", "email": "unknown@test.com", "title": ""}',                          FALSE, 'Missing required field: name', '2026-03-01 06:00:02+00'),
    ('hubspot',    'deals_20260301.json',          '{"deal_name": "Acme Renewal", "amount": 15000, "stage": "closed_won"}',           TRUE,  NULL, '2026-03-01 07:00:00+00'),
    ('hubspot',    'deals_20260301.json',          '{"deal_name": "Widgets Upsell", "amount": 8000, "stage": "negotiation"}',         TRUE,  NULL, '2026-03-01 07:00:01+00'),
    ('hubspot',    'deals_20260301.json',          '{"deal_name": null, "amount": -500, "stage": "invalid"}',                         FALSE, 'Invalid deal_name and amount', '2026-03-01 07:00:02+00'),
    ('stripe',     NULL,                           '{"event": "invoice.paid", "customer": "cus_abc123", "amount": 2900}',             TRUE,  NULL, '2026-03-01 08:00:00+00'),
    ('stripe',     NULL,                           '{"event": "invoice.paid", "customer": "cus_def456", "amount": 7900}',             TRUE,  NULL, '2026-03-01 08:00:01+00'),
    ('stripe',     NULL,                           '{"event": "charge.failed", "customer": "cus_vwx234", "amount": 2900}',            TRUE,  NULL, '2026-03-01 08:00:02+00'),
    ('manual',     'corrections_march.xlsx',       '{"customer_email": "dave@bigcorp.com", "action": "update_plan", "new_plan": "enterprise"}', TRUE, NULL, '2026-03-02 10:00:00+00'),
    ('salesforce', 'contacts_export_20260308.csv', '{"name": "Carol Chen", "email": "carol@startup.dev", "title": "Founder"}',       TRUE,  NULL, '2026-03-08 06:00:00+00'),
    ('salesforce', 'contacts_export_20260308.csv', '{"name": "Dave Kumar", "email": "dave@bigcorp.com", "title": "Director"}',        TRUE,  NULL, '2026-03-08 06:00:01+00'),
    ('hubspot',    'deals_20260308.json',          '{"deal_name": "Startup Dev Onboard", "amount": 2900, "stage": "closed_won"}',     TRUE,  NULL, '2026-03-08 07:00:00+00'),
    ('stripe',     NULL,                           '{"event": "subscription.updated", "customer": "cus_ghi789", "plan": "pro"}',      TRUE,  NULL, '2026-03-08 08:00:00+00'),
    ('stripe',     NULL,                           '{"event": "invoice.payment_failed", "customer": "cus_vwx234", "amount": 2900}',   FALSE, 'Retry scheduled', '2026-03-15 08:00:00+00'),
    ('manual',     'q1_adjustments.csv',           '{"customer_email": "eve@solo.dev", "action": "apply_credit", "amount_cents": 1500}', TRUE, NULL, '2026-03-10 14:00:00+00'),
    ('salesforce', 'contacts_export_20260315.csv', '{"name": "Frank Liu", "email": "frank@techco.cn", "title": "Engineering Lead"}',  TRUE,  NULL, '2026-03-15 06:00:00+00'),
    ('hubspot',    'deals_20260315.json',          '{"deal_name": "TechCo Expansion", "amount": 25000, "stage": "proposal"}',         TRUE,  NULL, '2026-03-15 07:00:00+00'),
    ('stripe',     NULL,                           '{"event": "invoice.paid", "customer": "cus_pqr678", "amount": 2900}',             TRUE,  NULL, '2026-03-15 08:00:01+00'),
    ('manual',     NULL,                           '{"note": "Test import - ignore", "action": "none"}',                               FALSE, 'Skipped: test record', '2026-03-15 09:00:00+00');

CREATE TABLE staging.sync_log (
    id          BIGSERIAL PRIMARY KEY,
    source_name VARCHAR(100) NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status      VARCHAR(20) NOT NULL DEFAULT 'running',
    rows_total  INTEGER,
    rows_ok     INTEGER,
    rows_failed INTEGER,
    error_detail TEXT
);

INSERT INTO staging.sync_log (source_name, started_at, finished_at, status, rows_total, rows_ok, rows_failed, error_detail) VALUES
    ('salesforce', '2026-03-01 06:00:00+00', '2026-03-01 06:00:10+00', 'completed', 3,  2,  1,  NULL),
    ('hubspot',    '2026-03-01 07:00:00+00', '2026-03-01 07:00:05+00', 'completed', 3,  2,  1,  NULL),
    ('stripe',     '2026-03-01 08:00:00+00', '2026-03-01 08:00:03+00', 'completed', 3,  3,  0,  NULL),
    ('manual',     '2026-03-02 10:00:00+00', '2026-03-02 10:00:01+00', 'completed', 1,  1,  0,  NULL),
    ('salesforce', '2026-03-08 06:00:00+00', '2026-03-08 06:00:08+00', 'completed', 2,  2,  0,  NULL),
    ('hubspot',    '2026-03-08 07:00:00+00', '2026-03-08 07:00:04+00', 'completed', 1,  1,  0,  NULL),
    ('stripe',     '2026-03-08 08:00:00+00', '2026-03-08 08:00:02+00', 'completed', 1,  1,  0,  NULL),
    ('manual',     '2026-03-10 14:00:00+00', '2026-03-10 14:00:01+00', 'completed', 1,  1,  0,  NULL),
    ('salesforce', '2026-03-15 06:00:00+00', '2026-03-15 06:00:06+00', 'completed', 1,  1,  0,  NULL),
    ('stripe',     '2026-03-15 08:00:00+00', '2026-03-15 08:00:04+00', 'completed', 2,  1,  1,  'Payment retry pending for cus_vwx234');

-- -------------------------------------------------------------------------
-- SCHEMA: internal  (2 tables) — app configuration & operational data
-- -------------------------------------------------------------------------

CREATE SCHEMA internal;

CREATE TABLE internal.feature_flags (
    id          SERIAL PRIMARY KEY,
    flag_name   VARCHAR(100) NOT NULL UNIQUE,
    enabled     BOOLEAN DEFAULT FALSE,
    description TEXT,
    metadata    JSONB,
    updated_by  VARCHAR(100),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO internal.feature_flags (flag_name, enabled, description, metadata, updated_by) VALUES
    ('dark_mode',        TRUE,  'Enable dark mode toggle in UI',              '{"default": "system"}',                       'alice'),
    ('table_editor_v2',  TRUE,  'New table editor with inline editing',       '{"rollout_pct": 100}',                        'bob'),
    ('schema_browser',   TRUE,  'Multi-schema navigation sidebar',           '{"supported_dbs": ["postgres", "mysql"]}',    'alice'),
    ('ai_sql_assist',    FALSE, 'AI-powered SQL autocomplete',               '{"model": "claude-sonnet-4-6", "max_tokens": 2048}', 'carol'),
    ('export_parquet',   FALSE, 'Export query results as Parquet files',      '{"blocked_by": "dependency on arrow lib"}',   'bob'),
    ('realtime_collab',  FALSE, 'Collaborative editing with presence',        '{"rollout_pct": 5}',                          'dave'),
    ('sso_login',        TRUE,  'Single sign-on via SAML/OIDC',              '{"providers": ["okta", "auth0"]}',            'alice'),
    ('rate_limiting_v2', TRUE,  'Token-bucket rate limiting',                 '{"rpm": 1000, "burst": 50}',                  'carol'),
    ('audit_log_v2',     FALSE, 'Structured audit log with search',          '{"migration_required": true}',                'dave'),
    ('csv_import',       TRUE,  'Import data from CSV files',                 NULL,                                          'bob');

CREATE TABLE internal.migrations (
    id          SERIAL PRIMARY KEY,
    version     VARCHAR(20) NOT NULL UNIQUE,
    name        VARCHAR(255) NOT NULL,
    applied_at  TIMESTAMPTZ DEFAULT NOW(),
    duration_ms INTEGER,
    success     BOOLEAN DEFAULT TRUE
);

INSERT INTO internal.migrations (version, name, applied_at, duration_ms, success) VALUES
    ('001', 'create_users_table',        '2024-01-01 00:00:01+00', 45,   TRUE),
    ('002', 'create_posts_table',        '2024-01-01 00:00:02+00', 32,   TRUE),
    ('003', 'create_products_table',     '2024-01-01 00:00:03+00', 28,   TRUE),
    ('004', 'add_user_email_index',      '2024-01-15 10:00:00+00', 120,  TRUE),
    ('005', 'create_network_events',     '2024-02-01 08:00:00+00', 55,   TRUE),
    ('006', 'add_posts_fulltext_search', '2024-02-15 09:00:00+00', 210,  TRUE),
    ('007', 'create_departments',        '2024-03-01 10:00:00+00', 38,   TRUE),
    ('008', 'create_salary_history',     '2024-03-01 10:00:01+00', 42,   TRUE),
    ('009', 'add_product_tags_column',   '2024-04-01 08:00:00+00', 85,   TRUE),
    ('010', 'create_audit_log_table',    '2024-05-01 12:00:00+00', 65,   TRUE),
    ('011', 'create_analytics_schema',   '2024-07-01 08:00:00+00', 150,  TRUE),
    ('012', 'create_billing_schema',     '2024-08-01 08:00:00+00', 180,  TRUE),
    ('013', 'create_staging_schema',     '2024-09-01 08:00:00+00', 95,   FALSE),
    ('013_v2', 'create_staging_schema_retry', '2024-09-02 08:00:00+00', 110, TRUE),
    ('014', 'add_subscription_status_check', '2024-10-01 08:00:00+00', 25, TRUE);

-- -------------------------------------------------------------------------
-- Edge-case PK tables (named to make their purpose obvious)
-- -------------------------------------------------------------------------

-- No primary key at all
CREATE TABLE table_without_primary_key (
    event_name  VARCHAR(100) NOT NULL,
    user_id     INTEGER,
    payload     JSONB,
    logged_at   TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO table_without_primary_key (event_name, user_id, payload, logged_at) VALUES
    ('click',       1,    '{"button": "signup"}',       '2026-03-01 08:00:00+00'),
    ('click',       1,    '{"button": "pricing"}',      '2026-03-01 08:01:00+00'),
    ('impression',  NULL, '{"ad_id": "banner_1"}',      '2026-03-01 08:02:00+00'),
    ('click',       2,    '{"button": "docs"}',         '2026-03-01 09:00:00+00'),
    ('scroll',      2,    '{"depth_pct": 75}',          '2026-03-01 09:01:00+00'),
    ('impression',  NULL, '{"ad_id": "banner_2"}',      '2026-03-02 10:00:00+00'),
    ('click',       3,    '{"button": "login"}',        '2026-03-02 10:05:00+00'),
    ('error',       3,    '{"code": 403}',              '2026-03-02 10:06:00+00'),
    ('click',       1,    '{"button": "dashboard"}',    '2026-03-03 07:00:00+00'),
    ('scroll',      1,    '{"depth_pct": 100}',         '2026-03-03 07:05:00+00');

-- Composite (two-column) primary key
CREATE TABLE table_with_composite_primary_key (
    customer_id INTEGER NOT NULL,
    tag_name    VARCHAR(50) NOT NULL,
    added_by    VARCHAR(100),
    added_at    TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (customer_id, tag_name)
);

INSERT INTO table_with_composite_primary_key (customer_id, tag_name, added_by) VALUES
    (1, 'enterprise',   'alice'),
    (1, 'early-adopter','alice'),
    (2, 'startup',      'bob'),
    (2, 'high-growth',  'bob'),
    (3, 'startup',      'carol'),
    (3, 'trial',        'carol'),
    (4, 'enterprise',   'dave'),
    (4, 'annual',       'dave'),
    (5, 'free-tier',    'eve'),
    (6, 'startup',      'frank');

-- Primary key column named something other than "id"
CREATE TABLE table_with_non_id_primary_key (
    setting_key   VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    description   TEXT,
    updated_by    VARCHAR(100),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO table_with_non_id_primary_key (setting_key, setting_value, description, updated_by) VALUES
    ('app.name',              'Gateway',           'Application display name',          'admin'),
    ('app.version',           '2.4.1',             'Current deployed version',          'ci-bot'),
    ('auth.session_ttl_sec',  '86400',             'Session timeout in seconds',        'admin'),
    ('auth.max_attempts',     '5',                 'Max login attempts before lockout', 'admin'),
    ('db.pool_size',          '20',                'Connection pool size',              'admin'),
    ('db.statement_timeout',  '30000',             'Query timeout in ms',               'admin'),
    ('email.from_address',    'noreply@gateway.io','Default sender address',            'admin'),
    ('email.smtp_host',       'smtp.gateway.io',   'SMTP server hostname',             'admin'),
    ('ui.default_page_size',  '50',                'Default rows per page',             'admin'),
    ('ui.max_export_rows',    '100000',            'Max rows for CSV export',           'admin');

-- =========================================================================
-- Done. Totals:
--   Section 1: 5 tables (users, posts, products, network_events, employee_profiles)
--   Section 2: 35 new tables + ALTER on products + 10 tables in 4 schemas
--   Grand total: 50 tables across 5 schemas (public, analytics, billing, staging, internal)
-- =========================================================================
