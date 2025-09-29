const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Client } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDatabase() {
  try {
    await client.connect();
    console.log('Connected to PostgreSQL database');
    
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      name TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    await client.query(`CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      role TEXT NOT NULL,
      name TEXT NOT NULL,
      login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    await client.query(`CREATE TABLE IF NOT EXISTS handovers (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Read admin password from environment variable
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'temporaryDefaultPassword';
const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);

await client.query(`INSERT INTO users (username, password_hash, role, name)
                    VALUES ('admin', $1, 'admin', 'System Administrator')
                    ON CONFLICT (username) DO NOTHING`, [adminHash]);
            
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

initDatabase();

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const user = result.rows[0];
    if (bcrypt.compareSync(password, user.password_hash)) {
      const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      await client.query('INSERT INTO sessions (session_id, username, role, name) VALUES ($1, $2, $3, $4)',
        [sessionId, user.username, user.role, user.name]);
        
      res.json({
        sessionId,
        user: {
          username: user.username,
          role: user.role,
          name: user.name
        }
      });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const { sessionId } = req.body;
    await client.query('DELETE FROM sessions WHERE session_id = $1', [sessionId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.post('/api/auth/validate', async (req, res) => {
  try {
    const { sessionId } = req.body;
    const result = await client.query('SELECT * FROM sessions WHERE session_id = $1', [sessionId]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    const session = result.rows[0];
    res.json({
      username: session.username,
      role: session.role,
      name: session.name,
      loginTime: session.login_time
    });
  } catch (err) {
    console.error('Validation error:', err);
    res.status(401).json({ error: 'Invalid session' });
  }
});

async function authenticate(req, res, next) {
  try {
    const sessionId = req.headers['x-session-id'] || req.body.sessionId;
    if (!sessionId) {
      return res.status(401).json({ error: 'No session provided' });
    }
    
    const result = await client.query('SELECT * FROM sessions WHERE session_id = $1', [sessionId]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    const session = result.rows[0];
    req.user = {
      username: session.username,
      role: session.role,
      name: session.name
    };
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(401).json({ error: 'Authentication failed' });
  }
}

function authenticateAdmin(req, res, next) {
  authenticate(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
}

app.get('/api/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await client.query('SELECT username, role, name, created_at FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authenticateAdmin, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    if (!username || !password || !name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const passwordHash = bcrypt.hashSync(password, 10);
    await client.query('INSERT INTO users (username, password_hash, role, name) VALUES ($1, $2, $3, $4)',
      [username, passwordHash, role || 'user', name]);
      
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error('Create user error:', err);
    res.status(500).json({ error: 'User creation failed' });
  }
});

app.delete('/api/users/:username', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    if (username === 'admin') {
      return res.status(403).json({ error: 'Cannot delete admin user' });
    }
    
    await client.query('DELETE FROM sessions WHERE username = $1', [username]);
    const result = await client.query('DELETE FROM users WHERE username = $1', [username]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'User deletion failed' });
  }
});

app.get('/api/handover/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await client.query('SELECT * FROM handovers WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Handover not found' });
    }
    
    res.json(JSON.parse(result.rows[0].data));
  } catch (err) {
    console.error('Fetch handover error:', err);
    res.status(500).json({ error: 'Failed to fetch handover' });
  }
});

app.post('/api/handover/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const data = req.body;
    const dataString = JSON.stringify(data);
    
    await client.query(`INSERT INTO handovers (id, data, last_updated) 
                       VALUES ($1, $2, CURRENT_TIMESTAMP)
                       ON CONFLICT (id) 
                       DO UPDATE SET data = $2, last_updated = CURRENT_TIMESTAMP`,
      [id, dataString]);
      
    res.json({ success: true });
  } catch (err) {
    console.error('Save handover error:', err);
    res.status(500).json({ error: 'Failed to save handover' });
  }
});

app.get('/api/handovers', authenticate, async (req, res) => {
  try {
    const result = await client.query('SELECT id, last_updated FROM handovers ORDER BY last_updated DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch handovers error:', err);
    res.status(500).json({ error: 'Failed to fetch handovers' });
  }
});

app.use(express.static('public'));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

