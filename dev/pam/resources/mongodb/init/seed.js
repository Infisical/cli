// Switch to the target database (set by MONGO_INITDB_DATABASE)
db = db.getSiblingDB('infisical');

// Create a non-root user for the infisical database
db.createUser({
  user: 'infisical',
  pwd: 'Infisical@123',
  roles: [{ role: 'readWrite', db: 'infisical' }]
});

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------
db.users.insertMany([
  { username: 'alice', email: 'alice@example.com', created_at: new Date() },
  { username: 'bob',   email: 'bob@example.com',   created_at: new Date() },
  { username: 'carol', email: 'carol@example.com', created_at: new Date() }
]);

// ---------------------------------------------------------------------------
// posts
// ---------------------------------------------------------------------------
db.posts.insertMany([
  { user: 'alice', title: 'First post',    body: 'Hello from Alice.',          created_at: new Date() },
  { user: 'alice', title: 'SQL tips',      body: 'Use CTEs for readability.',  created_at: new Date() },
  { user: 'bob',   title: 'On databases',  body: 'Postgres is great.',         created_at: new Date() },
  { user: 'carol', title: 'Quick note',    body: 'Short and sweet.',           created_at: new Date() }
]);

// ---------------------------------------------------------------------------
// products — diverse types, nested objects, arrays
// ---------------------------------------------------------------------------
db.products.insertMany([
  {
    name: 'Widget A', price: 19.99, list_price: 24.99, weight_kg: 0.75,
    precision_val: 3.141592653589793, stock: 150, global_sku: NumberLong('9000000000000001'),
    available: true, status: 'active', tags: ['sale', 'new'],
    metadata: { color: 'red', sizes: [1, 2, 3] }, extra: { note: 'first product' },
    created_at: new Date()
  },
  {
    name: 'Widget B', price: 5.50, list_price: null, weight_kg: null,
    precision_val: 2.718281828459045, stock: 0, global_sku: NumberLong('9000000000000002'),
    available: false, status: 'draft', tags: ['clearance'],
    metadata: { color: 'blue' }, extra: null,
    created_at: new Date()
  },
  {
    name: 'Gizmo', price: 999.00, list_price: 1099.00, weight_kg: 12.5,
    precision_val: null, stock: 3200, global_sku: null,
    available: true, status: 'active', tags: null,
    metadata: null, extra: { warehouse: 'EU-1' },
    created_at: new Date()
  },
  {
    name: 'Thingamajig', price: 0.01, list_price: 0.01, weight_kg: 0.001,
    precision_val: 1e-15, stock: 32767, global_sku: NumberLong('9223372036854775807'),
    available: null, status: 'archived', tags: [],
    metadata: { empty: {} }, extra: [],
    created_at: new Date()
  }
]);

// ---------------------------------------------------------------------------
// network_events
// ---------------------------------------------------------------------------
db.network_events.insertMany([
  {
    event_date: new Date('2025-06-15'), event_time: '14:30:00',
    duration: '2 hours 30 minutes', source_ip: '192.168.1.1',
    network: '192.168.1.0/24', device_mac: '08:00:2b:01:02:03',
    port_range: { min: 1024, max: 65535 }, payload: BinData(0, '3q2+7w=='),
    recorded_at: new Date()
  },
  {
    event_date: new Date('2025-12-31'), event_time: '23:59:59.999999',
    duration: '1 year 2 months', source_ip: '10.0.0.1',
    network: '10.0.0.0/8', device_mac: 'AA:BB:CC:DD:EE:FF',
    port_range: { min: 80, max: 443 }, payload: BinData(0, 'AP8A/w=='),
    recorded_at: new Date()
  },
  {
    event_date: new Date('2026-01-01'), event_time: '00:00:00',
    duration: null, source_ip: '::1',
    network: '::1/128', device_mac: null,
    port_range: null, payload: null,
    recorded_at: new Date()
  },
  {
    event_date: new Date('2026-02-12'), event_time: '08:15:30.123456',
    duration: '3 days 4 hours', source_ip: '172.16.0.100',
    network: null, device_mac: '00:1A:2B:3C:4D:5E',
    port_range: { min: 3000, max: 3010 }, payload: BinData(0, 'SGVsbG8='),
    recorded_at: new Date()
  }
]);

// ---------------------------------------------------------------------------
// employee_profiles — wide document for stress testing
// ---------------------------------------------------------------------------
db.employee_profiles.insertMany([
  {
    employee_uuid: '11111111-1111-1111-1111-111111111111',
    first_name: 'Ada', last_name: 'Lovelace', initials: 'AL',
    email: 'ada@example.com', active: true,
    department: 'Engineering', title: 'Principal Engineer',
    salary: 185000.00, bonus: 15000.00,
    rating: 4.9, performance: 0.98, level: 7,
    badge_number: NumberLong('1000001'),
    hire_date: new Date('2020-03-15'), shift_start: '09:00:00',
    tenure: '5 years 10 months', office_ip: '10.1.1.10',
    desk_mac: '00:11:22:33:44:55',
    tags: ['mentor', 'lead'],
    preferences: { theme: 'dark', lang: 'en' },
    notes: { bio: 'Pioneering programmer' },
    avatar: BinData(0, 'iVBORw=='),
    manager_id: null,
    updated_at: new Date()
  },
  {
    employee_uuid: '22222222-2222-2222-2222-222222222222',
    first_name: 'Grace', last_name: 'Hopper', initials: 'GH',
    email: 'grace@example.com', active: true,
    department: 'Engineering', title: 'Distinguished Fellow',
    salary: 210000.50, bonus: 25000.00,
    rating: 5.0, performance: 0.995, level: 8,
    badge_number: NumberLong('1000002'),
    hire_date: new Date('2018-07-01'), shift_start: '08:30:00',
    tenure: '7 years 7 months', office_ip: '10.1.1.11',
    desk_mac: 'AA:BB:CC:DD:EE:FF',
    tags: ['compiler'],
    preferences: { theme: 'light' },
    notes: null,
    avatar: BinData(0, '/9j/4A=='),
    manager_id: null,
    updated_at: new Date()
  },
  {
    employee_uuid: '33333333-3333-3333-3333-333333333333',
    first_name: 'Taro', last_name: 'Yamada', initials: null,
    email: 'taro@example.com', active: false,
    department: 'Finance', title: 'Analyst',
    salary: 15000000.00, bonus: null,
    rating: null, performance: null, level: 3,
    badge_number: null,
    hire_date: new Date('2024-01-10'), shift_start: null,
    tenure: '1 year 1 month', office_ip: null,
    desk_mac: null,
    tags: null,
    preferences: null,
    notes: { notes: [] },
    avatar: null,
    manager_id: null,
    updated_at: new Date()
  }
]);
