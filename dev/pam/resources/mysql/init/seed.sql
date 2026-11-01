CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    title VARCHAR(200) NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
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
-- products — diverse scalar types, JSON, enums
-- ---------------------------------------------------------------------------

CREATE TABLE products (
    id            CHAR(36) PRIMARY KEY,
    name          VARCHAR(200) NOT NULL,
    price         DECIMAL(12, 2) NOT NULL,
    list_price    DECIMAL(12, 2),
    weight_kg     FLOAT,
    precision_val DOUBLE,
    stock         SMALLINT DEFAULT 0,
    global_sku    BIGINT,
    available     BOOLEAN DEFAULT TRUE,
    status        ENUM('draft', 'active', 'archived') DEFAULT 'draft',
    tags          JSON,
    metadata      JSON,
    extra         JSON,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO products (id, name, price, list_price, weight_kg, precision_val, stock, global_sku, available, status, tags, metadata, extra) VALUES
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'Widget A', 19.99, 24.99, 0.75, 3.141592653589793, 150, 9000000000000001, TRUE,  'active',   '["sale", "new"]',      '{"color": "red", "sizes": [1, 2, 3]}',   '{"note": "first product"}'),
    ('b1ffcd00-ad1c-5fa9-cc7e-7ccace491b22', 'Widget B', 5.50,  NULL,  NULL, 2.718281828459045, 0,   9000000000000002, FALSE, 'draft',    '["clearance"]',        '{"color": "blue"}',                       NULL),
    ('c2aade11-be2d-6ab0-dd8f-8ddbdf502c33', 'Gizmo',    999.00, 1099.00, 12.5, NULL,           3200, NULL,              TRUE,  'active',   NULL,                   NULL,                                      '{"warehouse": "EU-1"}'),
    ('d3bbef22-cf3e-7bc1-ee90-9eece6613d44', 'Thingamajig', 0.01, 0.01, 0.001, 1e-15,          32767, 9223372036854775807, NULL, 'archived', '[]',                  '{"empty": {}}',                           '[]');

-- ---------------------------------------------------------------------------
-- employee_profiles — wide table (22 columns) for RowDescription stress test
-- ---------------------------------------------------------------------------

CREATE TABLE employee_profiles (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,              -- 1
    employee_uuid   CHAR(36),                                       -- 2
    first_name      VARCHAR(100) NOT NULL,                          -- 3
    last_name       VARCHAR(100) NOT NULL,                          -- 4
    initials        CHAR(3),                                        -- 5
    email           VARCHAR(200) NOT NULL,                          -- 6
    active          BOOLEAN DEFAULT TRUE,                           -- 7
    department      VARCHAR(100),                                   -- 8
    title           TEXT,                                            -- 9
    salary          DECIMAL(12, 2),                                 -- 10
    bonus           DECIMAL(12, 2),                                 -- 11
    rating          FLOAT,                                          -- 12
    performance     DOUBLE,                                         -- 13
    level           SMALLINT,                                       -- 14
    badge_number    BIGINT,                                         -- 15
    hire_date       DATE,                                           -- 16
    shift_start     TIME,                                           -- 17
    tags            JSON,                                            -- 18
    preferences     JSON,                                            -- 19
    notes           JSON,                                            -- 20
    avatar          VARBINARY(1024),                                -- 21
    manager_id      BIGINT,                                         -- 22
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES employee_profiles(id)
);

INSERT INTO employee_profiles
    (employee_uuid, first_name, last_name, initials, email, active, department, title, salary, bonus, rating, performance, level, badge_number, hire_date, shift_start, tags, preferences, notes, avatar, manager_id)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'Ada',   'Lovelace', 'AL ', 'ada@example.com',   TRUE,  'Engineering', 'Principal Engineer',   185000.00,  15000.00, 4.9,  0.98,  7, 1000001, '2020-03-15', '09:00:00', '["mentor", "lead"]',  '{"theme": "dark", "lang": "en"}',  '{"bio": "Pioneering programmer"}', 0x89504E47, NULL),
    ('22222222-2222-2222-2222-222222222222', 'Grace', 'Hopper',   'GH ', 'grace@example.com', TRUE,  'Engineering', 'Distinguished Fellow', 210000.50,  25000.00, 5.0,  0.995, 8, 1000002, '2018-07-01', '08:30:00', '["compiler"]',        '{"theme": "light"}',               NULL,                               0xFFD8FFE0, 1),
    ('33333333-3333-3333-3333-333333333333', 'Taro',  'Yamada',   NULL,  'taro@example.com',  FALSE, 'Finance',     'Analyst',              15000000.00, NULL,    NULL, NULL,  3, NULL,    '2024-01-10', NULL,       NULL,                  NULL,                               '{"notes": []}',                    NULL,       NULL);
