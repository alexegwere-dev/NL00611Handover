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
    
    await client.query(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', name TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL, name TEXT NOT NULL, login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS handovers (id TEXT PRIMARY KEY, data TEXT NOT NULL, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    
    const adminHash = bcrypt.hashSync('admin123', 10);
    await client.query(`INSERT INTO users (username, password_hash, role, name) VALUES ('admin', $1, 'admin', 'System Administrator') ON CONFLICT DO NOTHING`, [adminHash]);
    
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database error:', err);
  }
}

initDatabase();

// Add all your API routes here (login, logout, validate, etc.)
