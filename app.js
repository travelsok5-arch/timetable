const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

// Simple hash functions
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function comparePassword(password, hashedPassword) {
    return hashPassword(password) === hashedPassword;
}

const app = express();
const port = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(require('express-session')({
    secret: 'your-session-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Database setup - PERMANENT FILE DATABASE
const dbPath = path.join(__dirname, 'timetable.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to SQLite database:', dbPath);
        initializeDatabase();
    }
});

// FIXED: Check and add missing columns
function checkAndAddColumns() {
    return new Promise((resolve, reject) => {
        // Check if profile_picture column exists
        db.all("PRAGMA table_info(users)", (err, rows) => {
            if (err) {
                console.error('Error checking table structure:', err);
                reject(err);
                return;
            }

            // FIX: rows is an array, not a single object
            const columns = rows.map(row => row.name);
            const missingColumns = [];

            if (!columns.includes('profile_picture')) {
                missingColumns.push('profile_picture');
            }

            if (missingColumns.length === 0) {
                console.log('All required columns exist in users table');
                resolve();
                return;
            }

            console.log('Adding missing columns:', missingColumns);

            // Add missing columns
            const promises = missingColumns.map(column => {
                return new Promise((resolveCol, rejectCol) => {
                    if (column === 'profile_picture') {
                        db.run(`ALTER TABLE users ADD COLUMN profile_picture TEXT`, (err) => {
                            if (err) {
                                console.error(`Error adding ${column} column:`, err);
                                rejectCol(err);
                            } else {
                                console.log(`Successfully added ${column} column`);
                                resolveCol();
                            }
                        });
                    }
                });
            });

            Promise.all(promises)
                .then(() => {
                    console.log('All missing columns added successfully');
                    resolve();
                })
                .catch(reject);
        });
    });
}

// Initialize database tables with admin system
function initializeDatabase() {
    db.serialize(() => {
        // Enhanced Users table with profile_picture
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            phone TEXT,
            date_of_birth TEXT,
            password TEXT NOT NULL,
            profile_picture TEXT,
            role TEXT DEFAULT 'user',
            is_active BOOLEAN DEFAULT 1,
            is_verified BOOLEAN DEFAULT 0,
            login_attempts INTEGER DEFAULT 0,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err);
            } else {
                console.log('Users table checked/created');
                // Check and add missing columns after table creation
                checkAndAddColumns().then(() => {
                    createDefaultData();
                }).catch(err => {
                    console.error('Error adding columns:', err);
                });
            }
        });

        // Other tables...
        db.run(`CREATE TABLE IF NOT EXISTS prayers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            time TEXT NOT NULL,
            notification_enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            description TEXT,
            category TEXT DEFAULT 'general',
            priority TEXT DEFAULT 'medium',
            completed BOOLEAN DEFAULT 0,
            date TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'medium',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES support_tickets (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity_type TEXT NOT NULL,
            description TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);
    });
}

function createDefaultData() {
    // Create default admin user
    const hashedPassword = hashPassword('Admin@2024');
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role, is_verified, is_active) VALUES (?, ?, ?, ?, ?, ?)`, 
        ['admin', 'admin@timetable.com', hashedPassword, 'admin', 1, 1], function(err) {
            if (err) {
                console.log('Admin user creation error:', err);
            } else {
                console.log('Default admin user created: username=admin, password=Admin@2024');
            }
        });

    // Create default prayer times
    const defaultPrayers = [
        ['Fajr', '05:00'],
        ['Dhuhr', '12:30'], 
        ['Asr', '15:30'],
        ['Maghrib', '18:30'],
        ['Isha', '20:00']
    ];

    defaultPrayers.forEach(([name, time]) => {
        db.run(`INSERT OR IGNORE INTO prayers (name, time) VALUES (?, ?)`, [name, time], function(err) {
            if (err) {
                console.log(`Prayer ${name} creation error:`, err);
            }
        });
    });

    console.log('Database initialized successfully');
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware  
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Log user activity
function logUserActivity(userId, activityType, description, req = null) {
    const ip = req ? req.ip : 'unknown';
    const userAgent = req ? req.get('User-Agent') : 'unknown';
    
    db.run(`INSERT INTO user_activity (user_id, activity_type, description, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)`,
        [userId, activityType, description, ip, userAgent], function(err) {
            if (err) {
                console.error('Error logging activity:', err);
            }
        });
}

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, phone, date_of_birth, password } = req.body;
        console.log('Registration attempt:', { username, email, phone, date_of_birth });

        if (!username || !password || !phone || !date_of_birth) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user exists
        db.get('SELECT id FROM users WHERE username = ? OR email = ? OR phone = ?', 
            [username, email, phone], async (err, row) => {
            if (err) {
                console.error('Database error in registration:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            if (row) {
                return res.status(400).json({ error: 'Username, email or phone already exists' });
            }

            // Hash password and create user
            const hashedPassword = hashPassword(password);
            db.run(
                'INSERT INTO users (username, email, phone, date_of_birth, password) VALUES (?, ?, ?, ?, ?)',
                [username, email || '', phone, date_of_birth, hashedPassword],
                function(err) {
                    if (err) {
                        console.error('User creation error:', err);
                        return res.status(500).json({ error: 'Failed to create user' });
                    }

                    console.log('User created successfully with ID:', this.lastID);
                    logUserActivity(this.lastID, 'REGISTER', 'User registered successfully', req);
                    
                    const token = jwt.sign({ 
                        userId: this.lastID, 
                        username: username,
                        role: 'user'
                    }, JWT_SECRET, { expiresIn: '24h' });
                    
                    res.status(201).json({
                        message: 'User created successfully',
                        token,
                        user: { 
                            id: this.lastID, 
                            username, 
                            email,
                            phone,
                            date_of_birth,
                            role: 'user'
                        }
                    });
                }
            );
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIXED LOGIN ROUTE WITH PROPER INACTIVE USER CHECK
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    console.log('Login attempt for user:', username);

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            console.error('Database error in login:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            console.log('User not found:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // FIXED: Proper inactive user check - SQLite stores booleans as 0/1 integers
        if (user.is_active === 0 || user.is_active === false) {
            console.log('Inactive user login attempt:', username);
            logUserActivity(user.id, 'LOGIN_BLOCKED', 'Login attempt blocked - user inactive', req);
            return res.status(403).json({ error: 'Your account has been deactivated. Please contact administrator.' });
        }

        // Compare passwords
        if (comparePassword(password, user.password)) {
            // Reset login attempts and update last login
            db.run('UPDATE users SET login_attempts = 0, last_login = datetime("now") WHERE id = ?', [user.id]);
            
            // Generate token
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    username: user.username,
                    role: user.role 
                }, 
                JWT_SECRET, 
                { expiresIn: '24h' }
            );

            logUserActivity(user.id, 'LOGIN', 'User logged in successfully', req);

            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    phone: user.phone,
                    date_of_birth: user.date_of_birth,
                    profile_picture: user.profile_picture
                }
            });
        } else {
            // Increment login attempts
            db.run('UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?', [user.id]);
            
            logUserActivity(user.id, 'LOGIN_FAILED', 'Failed login attempt', req);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// Get current user - FIXED VERSION
app.get('/api/auth/me', authenticateToken, (req, res) => {
    db.get('SELECT id, username, email, phone, role, date_of_birth, is_active, profile_picture FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        if (err) {
            console.error('Database error in auth/me:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    });
});

// Logout route
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    // Log user activity
    logUserActivity(req.user.userId, 'LOGOUT', 'User logged out', req);
    res.json({ message: 'Logged out successfully' });
});

// Password reset routes
app.post('/api/auth/verify-user', (req, res) => {
    const { username, phone, date_of_birth } = req.body;
    console.log('Verify user attempt:', { username, phone, date_of_birth });

    if (!username || !phone || !date_of_birth) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    db.get('SELECT id, username FROM users WHERE username = ? AND phone = ? AND date_of_birth = ?', 
        [username, phone, date_of_birth], (err, user) => {
        if (err) {
            console.error('Database error in verify-user:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found or information does not match' });
        }

        // Create reset session
        const resetSession = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            success: true,
            resetSession,
            user: { username: user.username }
        });
    });
});

app.post('/api/auth/reset-password-direct', (req, res) => {
    const { resetSession, newPassword } = req.body;

    if (!resetSession || !newPassword) {
        return res.status(400).json({ error: 'Reset session and new password are required' });
    }

    try {
        const decoded = jwt.verify(resetSession, JWT_SECRET);
        const userId = decoded.userId;

        const hashedPassword = hashPassword(newPassword);
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], function(err) {
            if (err) {
                console.error('Password reset error:', err);
                return res.status(500).json({ error: 'Failed to reset password' });
            }

            logUserActivity(userId, 'PASSWORD_RESET', 'Password reset via direct method', req);
            res.json({ success: true, message: 'Password reset successfully' });
        });
    } catch (error) {
        console.error('Reset session error:', error);
        return res.status(500).json({ error: 'Invalid or expired reset session' });
    }
});

// Profile Picture Routes - FIXED VERSION
app.post('/api/profile/picture', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { imageData } = req.body;
    
    console.log('Updating profile picture for user:', userId);
    
    if (!imageData) {
        return res.status(400).json({ error: 'Image data is required' });
    }
    
    // Simple validation
    if (!imageData.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Invalid image format' });
    }
    
    // Update user profile picture in database
    db.run(
        'UPDATE users SET profile_picture = ?, updated_at = datetime("now") WHERE id = ?',
        [imageData, userId],
        function(err) {
            if (err) {
                console.error('Profile picture update error:', err);
                return res.status(500).json({ error: 'Failed to update profile picture: ' + err.message });
            }
            
            console.log('Profile picture updated successfully for user:', userId);
            
            logUserActivity(userId, 'PROFILE_PICTURE_UPDATE', 'Profile picture updated', req);
            
            res.json({ 
                success: true,
                message: 'Profile picture updated successfully',
                profile_picture: imageData
            });
        }
    );
});

app.get('/api/profile/picture', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    
    db.get('SELECT profile_picture FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('Database error fetching profile picture:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            success: true,
            profilePicture: user.profile_picture 
        });
    });
});

// Delete profile picture
app.delete('/api/profile/picture', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    
    db.run(
        'UPDATE users SET profile_picture = NULL, updated_at = datetime("now") WHERE id = ?',
        [userId],
        function(err) {
            if (err) {
                console.error('Profile picture delete error:', err);
                return res.status(500).json({ error: 'Failed to delete profile picture' });
            }
            
            console.log('Profile picture deleted for user:', userId);
            logUserActivity(userId, 'PROFILE_PICTURE_DELETE', 'Profile picture deleted', req);
            
            res.json({ 
                success: true,
                message: 'Profile picture deleted successfully'
            });
        }
    );
});

// Admin Profile Picture Routes - FIXED AND COMPLETE
app.get('/api/admin/users/:id/profile-picture', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    
    db.get('SELECT profile_picture FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('Database error fetching user profile picture:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            success: true,
            profilePicture: user.profile_picture 
        });
    });
});

app.post('/api/admin/users/:id/profile-picture', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    const { imageData } = req.body;
    
    console.log('Admin updating profile picture for user:', userId);
    
    if (!imageData) {
        return res.status(400).json({ error: 'Image data is required' });
    }
    
    // Simple validation
    if (!imageData.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Invalid image format' });
    }
    
    // Update user profile picture in database
    db.run(
        'UPDATE users SET profile_picture = ?, updated_at = datetime("now") WHERE id = ?',
        [imageData, userId],
        function(err) {
            if (err) {
                console.error('Admin profile picture update error:', err);
                return res.status(500).json({ error: 'Failed to update profile picture: ' + err.message });
            }
            
            console.log('Admin updated profile picture for user:', userId);
            
            logUserActivity(req.user.userId, 'ADMIN_PROFILE_PICTURE_UPDATE', 
                `Admin updated profile picture for user ${userId}`, req);
            
            res.json({ 
                success: true,
                message: 'Profile picture updated successfully',
                profile_picture: imageData
            });
        }
    );
});

// Admin Profile Picture Delete Route
app.delete('/api/admin/users/:id/profile-picture', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    
    db.run(
        'UPDATE users SET profile_picture = NULL, updated_at = datetime("now") WHERE id = ?',
        [userId],
        function(err) {
            if (err) {
                console.error('Admin profile picture delete error:', err);
                return res.status(500).json({ error: 'Failed to delete profile picture' });
            }
            
            console.log('Admin deleted profile picture for user:', userId);
            
            logUserActivity(req.user.userId, 'ADMIN_PROFILE_PICTURE_DELETE', 
                `Admin deleted profile picture for user ${userId}`, req);
            
            res.json({ 
                success: true,
                message: 'Profile picture deleted successfully'
            });
        }
    );
});

// Reports & Analytics Routes
app.get('/api/reports/weekly', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { startDate, endDate } = req.query;
    
    // Default to last 7 days if no dates provided
    const endDateActual = endDate || new Date().toISOString().split('T')[0];
    const startDateActual = startDate || (() => {
        const date = new Date();
        date.setDate(date.getDate() - 7);
        return date.toISOString().split('T')[0];
    })();
    
    // Get weekly task statistics
    db.all(`
        SELECT 
            date,
            COUNT(*) as total_tasks,
            SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) as completed_tasks,
            SUM(CASE WHEN priority = 'high' THEN 1 ELSE 0 END) as high_priority,
            SUM(CASE WHEN priority = 'medium' THEN 1 ELSE 0 END) as medium_priority,
            SUM(CASE WHEN priority = 'low' THEN 1 ELSE 0 END) as low_priority
        FROM tasks 
        WHERE user_id = ? AND date BETWEEN ? AND ?
        GROUP BY date
        ORDER BY date
    `, [userId, startDateActual, endDateActual], (err, stats) => {
        if (err) {
            console.error('Weekly report error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(stats);
    });
});

app.get('/api/reports/productivity', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { days = 30 } = req.query;
    
    const endDate = new Date().toISOString().split('T')[0];
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    const startDateStr = startDate.toISOString().split('T')[0];
    
    db.all(`
        SELECT 
            date,
            COUNT(*) as total_tasks,
            SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) as completed_tasks,
            ROUND((SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2) as completion_rate
        FROM tasks 
        WHERE user_id = ? AND date BETWEEN ? AND ?
        GROUP BY date
        ORDER BY date
    `, [userId, startDateStr, endDate], (err, stats) => {
        if (err) {
            console.error('Productivity analytics error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(stats);
    });
});

app.get('/api/reports/export', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { format = 'csv', startDate, endDate } = req.query;
    
    let query = `
        SELECT 
            date, name, start_time, end_time, description, priority, 
            CASE WHEN completed = 1 THEN 'Yes' ELSE 'No' END as completed
        FROM tasks 
        WHERE user_id = ?
    `;
    let params = [userId];
    
    if (startDate && endDate) {
        query += ' AND date BETWEEN ? AND ?';
        params.push(startDate, endDate);
    }
    
    query += ' ORDER BY date, start_time';
    
    db.all(query, params, (err, tasks) => {
        if (err) {
            console.error('Export data error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (format === 'csv') {
            // Generate CSV
            const csvHeader = 'Date,Task Name,Start Time,End Time,Description,Priority,Completed\n';
            const csvData = tasks.map(task => 
                `"${task.date}","${task.name}","${task.start_time}","${task.end_time}","${task.description || ''}","${task.priority}","${task.completed}"`
            ).join('\n');
            
            const csvContent = csvHeader + csvData;
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=tasks-export-${new Date().toISOString().split('T')[0]}.csv`);
            res.send(csvContent);
        } else if (format === 'json') {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename=tasks-export-${new Date().toISOString().split('T')[0]}.json`);
            res.json(tasks);
        } else {
            res.json(tasks);
        }
    });
});

// Dashboard routes
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const today = new Date().toISOString().split('T')[0];
    
    db.get(`
        SELECT 
            COUNT(*) as totalTasks,
            SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) as completedTasks
        FROM tasks 
        WHERE user_id = ? AND date = ?
    `, [userId, today], (err, taskStats) => {
        if (err) {
            console.error('Dashboard stats error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({
            totalTasks: taskStats.totalTasks || 0,
            completedTasks: taskStats.completedTasks || 0,
            prayerCount: 5 // Default prayer count
        });
    });
});

// Tasks routes
app.get('/api/tasks', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { date } = req.query;
    
    let query = 'SELECT * FROM tasks WHERE user_id = ?';
    let params = [userId];
    
    if (date) {
        query += ' AND date = ?';
        params.push(date);
    }
    
    query += ' ORDER BY start_time ASC';
    
    db.all(query, params, (err, tasks) => {
        if (err) {
            console.error('Tasks fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(tasks);
    });
});

app.post('/api/tasks', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { name, start_time, end_time, description, date, priority } = req.body;
    
    if (!name || !start_time || !end_time || !date) {
        return res.status(400).json({ error: 'All required fields must be provided' });
    }
    
    db.run(
        `INSERT INTO tasks (user_id, name, start_time, end_time, description, date, priority) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, name, start_time, end_time, description, date, priority || 'medium'],
        function(err) {
            if (err) {
                console.error('Task creation error:', err);
                return res.status(500).json({ error: 'Failed to create task' });
            }
            
            res.status(201).json({
                id: this.lastID,
                message: 'Task created successfully'
            });
        }
    );
});

app.put('/api/tasks/:id', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const taskId = req.params.id;
    const { name, start_time, end_time, description, date, priority, completed } = req.body;
    
    let query = 'UPDATE tasks SET ';
    let params = [];
    let updates = [];
    
    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (start_time !== undefined) { updates.push('start_time = ?'); params.push(start_time); }
    if (end_time !== undefined) { updates.push('end_time = ?'); params.push(end_time); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (date !== undefined) { updates.push('date = ?'); params.push(date); }
    if (priority !== undefined) { updates.push('priority = ?'); params.push(priority); }
    if (completed !== undefined) { updates.push('completed = ?'); params.push(completed); }
    
    if (updates.length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
    }
    
    query += updates.join(', ') + ' WHERE id = ? AND user_id = ?';
    params.push(taskId, userId);
    
    db.run(query, params, function(err) {
        if (err) {
            console.error('Task update error:', err);
            return res.status(500).json({ error: 'Failed to update task' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json({ message: 'Task updated successfully' });
    });
});

app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const taskId = req.params.id;
    
    db.run('DELETE FROM tasks WHERE id = ? AND user_id = ?', [taskId, userId], function(err) {
        if (err) {
            console.error('Task delete error:', err);
            return res.status(500).json({ error: 'Failed to delete task' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json({ message: 'Task deleted successfully' });
    });
});

// Prayers routes
app.get('/api/prayers', authenticateToken, (req, res) => {
    db.all('SELECT * FROM prayers ORDER BY name', (err, prayers) => {
        if (err) {
            console.error('Prayers fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(prayers);
    });
});

app.post('/api/prayers', authenticateToken, (req, res) => {
    const { name, time } = req.body;
    
    if (!name || !time) {
        return res.status(400).json({ error: 'Prayer name and time are required' });
    }
    
    db.run(
        'INSERT OR REPLACE INTO prayers (name, time) VALUES (?, ?)',
        [name, time],
        function(err) {
            if (err) {
                console.error('Prayer save error:', err);
                return res.status(500).json({ error: 'Failed to save prayer time' });
            }
            res.json({ message: 'Prayer time saved successfully' });
        }
    );
});

app.delete('/api/prayers/:name', authenticateToken, (req, res) => {
    const prayerName = req.params.name;
    
    db.run('DELETE FROM prayers WHERE name = ?', [prayerName], function(err) {
        if (err) {
            console.error('Prayer delete error:', err);
            return res.status(500).json({ error: 'Failed to delete prayer time' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Prayer not found' });
        }
        
        res.json({ message: 'Prayer time deleted successfully' });
    });
});

// Support routes - USER SIDE
app.get('/api/support/tickets', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    
    db.all(`
        SELECT st.*, u.username 
        FROM support_tickets st 
        JOIN users u ON st.user_id = u.id 
        WHERE st.user_id = ? 
        ORDER BY st.created_at DESC
    `, [userId], (err, tickets) => {
        if (err) {
            console.error('Support tickets fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(tickets);
    });
});

app.post('/api/support/tickets', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { subject, message, priority } = req.body;
    
    console.log('Creating support ticket for user:', userId, subject);
    
    if (!subject || !message) {
        return res.status(400).json({ error: 'Subject and message are required' });
    }
    
    db.run(
        'INSERT INTO support_tickets (user_id, subject, message, priority) VALUES (?, ?, ?, ?)',
        [userId, subject, message, priority || 'medium'],
        function(err) {
            if (err) {
                console.error('Support ticket creation error:', err);
                return res.status(500).json({ error: 'Failed to create support ticket' });
            }
            
            console.log('Support ticket created with ID:', this.lastID);
            
            res.status(201).json({
                id: this.lastID,
                message: 'Support ticket created successfully'
            });
        }
    );
});

app.get('/api/support/tickets/:id', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const ticketId = req.params.id;
    
    db.get(`
        SELECT st.*, u.username 
        FROM support_tickets st 
        JOIN users u ON st.user_id = u.id 
        WHERE st.id = ? AND st.user_id = ?
    `, [ticketId, userId], (err, ticket) => {
        if (err) {
            console.error('Support ticket fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        res.json(ticket);
    });
});

// Support messages routes - USER SIDE
app.get('/api/support/tickets/:id/messages', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const ticketId = req.params.id;
    
    // Check if user has access to this ticket
    db.get('SELECT id FROM support_tickets WHERE id = ? AND user_id = ?', [ticketId, userId], (err, ticket) => {
        if (err) {
            console.error('Support ticket access check error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!ticket) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Get messages for this ticket
        db.all(`
            SELECT sm.*, u.username, u.role 
            FROM support_messages sm 
            JOIN users u ON sm.user_id = u.id 
            WHERE sm.ticket_id = ? 
            ORDER BY sm.created_at ASC
        `, [ticketId], (err, messages) => {
            if (err) {
                console.error('Support messages fetch error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(messages);
        });
    });
});

app.post('/api/support/tickets/:id/messages', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const ticketId = req.params.id;
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Message is required' });
    }
    
    // Check if user has access to this ticket
    db.get('SELECT id FROM support_tickets WHERE id = ? AND user_id = ?', [ticketId, userId], (err, ticket) => {
        if (err) {
            console.error('Support ticket access check error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!ticket) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Add message
        db.run(
            'INSERT INTO support_messages (ticket_id, user_id, message) VALUES (?, ?, ?)',
            [ticketId, userId, message],
            function(err) {
                if (err) {
                    console.error('Support message creation error:', err);
                    return res.status(500).json({ error: 'Failed to send message' });
                }
                
                // Update ticket updated_at
                db.run('UPDATE support_tickets SET updated_at = datetime("now") WHERE id = ?', [ticketId]);
                
                console.log('Support message saved for ticket:', ticketId);
                
                res.status(201).json({
                    id: this.lastID,
                    message: 'Message sent successfully'
                });
            }
        );
    });
});

// Profile routes
app.put('/api/profile', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { email, phone, date_of_birth } = req.body;
    
    db.run(
        'UPDATE users SET email = ?, phone = ?, date_of_birth = ?, updated_at = datetime("now") WHERE id = ?',
        [email, phone, date_of_birth, userId],
        function(err) {
            if (err) {
                console.error('Profile update error:', err);
                return res.status(500).json({ error: 'Failed to update profile' });
            }
            
            logUserActivity(userId, 'PROFILE_UPDATE', 'Profile updated successfully', req);
            res.json({ message: 'Profile updated successfully' });
        }
    );
});

app.post('/api/profile/change-password', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password are required' });
    }
    
    // Get current user
    db.get('SELECT password FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('Password change error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Verify current password
        if (!comparePassword(currentPassword, user.password)) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }
        
        // Update password
        const hashedNewPassword = hashPassword(newPassword);
        db.run('UPDATE users SET password = ?, updated_at = datetime("now") WHERE id = ?', [hashedNewPassword, userId], function(err) {
            if (err) {
                console.error('Password update error:', err);
                return res.status(500).json({ error: 'Failed to change password' });
            }
            
            logUserActivity(userId, 'PASSWORD_CHANGE', 'Password changed successfully', req);
            res.json({ message: 'Password changed successfully' });
        });
    });
});

// Admin routes
app.get('/api/admin/statistics', authenticateToken, requireAdmin, (req, res) => {
    db.get(`
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users,
            (SELECT COUNT(*) FROM tasks) as total_tasks,
            (SELECT COUNT(*) FROM user_activity WHERE DATE(created_at) = DATE('now')) as recent_activity,
            (SELECT COUNT(*) FROM support_tickets WHERE status = 'open') as open_tickets
        FROM users
    `, (err, stats) => {
        if (err) {
            console.error('Admin stats error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(stats);
    });
});

app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const { page = 1, limit = 10, search = '' } = req.query;
    const offset = (page - 1) * limit;
    
    let query = 'SELECT id, username, email, phone, role, is_active, date_of_birth, profile_picture, last_login, created_at FROM users WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as total FROM users WHERE 1=1';
    let params = [];
    
    if (search) {
        query += ' AND (username LIKE ? OR email LIKE ? OR phone LIKE ?)';
        countQuery += ' AND (username LIKE ? OR email LIKE ? OR phone LIKE ?)';
        const searchParam = `%${search}%`;
        params = [searchParam, searchParam, searchParam];
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    
    // Get total count
    db.get(countQuery, params, (err, countResult) => {
        if (err) {
            console.error('Admin users count error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        // Get users
        db.all(query, [...params, parseInt(limit), offset], (err, users) => {
            if (err) {
                console.error('Admin users fetch error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            res.json({
                users,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: countResult.total,
                    pages: Math.ceil(countResult.total / limit)
                }
            });
        });
    });
});

app.get('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    
    db.get('SELECT id, username, email, phone, role, is_active, date_of_birth, profile_picture FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('Admin user fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    });
});

app.put('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    const { username, email, phone, role, is_active } = req.body;
    
    db.run(
        'UPDATE users SET username = ?, email = ?, phone = ?, role = ?, is_active = ?, updated_at = datetime("now") WHERE id = ?',
        [username, email, phone, role, is_active, userId],
        function(err) {
            if (err) {
                console.error('Admin user update error:', err);
                return res.status(500).json({ error: 'Failed to update user' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({ message: 'User updated successfully' });
        }
    );
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    
    db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
        if (err) {
            console.error('Admin user delete error:', err);
            return res.status(500).json({ error: 'Failed to delete user' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ message: 'User deleted successfully' });
    });
});

app.post('/api/admin/users/:id/reset-password', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    const { newPassword } = req.body;
    
    if (!newPassword) {
        return res.status(400).json({ error: 'New password is required' });
    }
    
    const hashedPassword = hashPassword(newPassword);
    db.run('UPDATE users SET password = ?, updated_at = datetime("now") WHERE id = ?', [hashedPassword, userId], function(err) {
        if (err) {
            console.error('Admin password reset error:', err);
            return res.status(500).json({ error: 'Failed to reset password' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ message: 'Password reset successfully' });
    });
});

app.get('/api/admin/activity', authenticateToken, requireAdmin, (req, res) => {
    const { limit = 10 } = req.query;
    
    db.all(`
        SELECT ua.*, u.username 
        FROM user_activity ua 
        JOIN users u ON ua.user_id = u.id 
        ORDER BY ua.created_at DESC 
        LIMIT ?
    `, [parseInt(limit)], (err, activities) => {
        if (err) {
            console.error('Admin activity fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(activities);
    });
});

// Admin support routes
app.get('/api/admin/support/tickets', authenticateToken, requireAdmin, (req, res) => {
    const { status = '' } = req.query;
    
    let query = `
        SELECT st.*, u.username, u.email 
        FROM support_tickets st 
        JOIN users u ON st.user_id = u.id 
    `;
    let params = [];
    
    if (status) {
        query += ' WHERE st.status = ?';
        params.push(status);
    }
    
    query += ' ORDER BY st.created_at DESC';
    
    db.all(query, params, (err, tickets) => {
        if (err) {
            console.error('Admin support tickets fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(tickets);
    });
});

app.get('/api/admin/support/tickets/:id', authenticateToken, requireAdmin, (req, res) => {
    const ticketId = req.params.id;
    
    db.get(`
        SELECT st.*, u.username, u.email, u.phone 
        FROM support_tickets st 
        JOIN users u ON st.user_id = u.id 
        WHERE st.id = ?
    `, [ticketId], (err, ticket) => {
        if (err) {
            console.error('Admin support ticket fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        res.json(ticket);
    });
});

app.put('/api/admin/support/tickets/:id', authenticateToken, requireAdmin, (req, res) => {
    const ticketId = req.params.id;
    const { status } = req.body;
    
    db.run(
        'UPDATE support_tickets SET status = ?, updated_at = datetime("now") WHERE id = ?',
        [status, ticketId],
        function(err) {
            if (err) {
                console.error('Admin support ticket update error:', err);
                return res.status(500).json({ error: 'Failed to update support ticket' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Ticket not found' });
            }
            
            res.json({ message: 'Support ticket updated successfully' });
        }
    );
});

// Admin support messages routes
app.get('/api/admin/support/tickets/:id/messages', authenticateToken, requireAdmin, (req, res) => {
    const ticketId = req.params.id;
    
    db.all(`
        SELECT sm.*, u.username, u.role 
        FROM support_messages sm 
        JOIN users u ON sm.user_id = u.id 
        WHERE sm.ticket_id = ? 
        ORDER BY sm.created_at ASC
    `, [ticketId], (err, messages) => {
        if (err) {
            console.error('Admin support messages fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(messages);
    });
});

app.post('/api/admin/support/tickets/:id/messages', authenticateToken, requireAdmin, (req, res) => {
    const adminId = req.user.userId;
    const ticketId = req.params.id;
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Message is required' });
    }
    
    // Add admin message
    db.run(
        'INSERT INTO support_messages (ticket_id, user_id, message) VALUES (?, ?, ?)',
        [ticketId, adminId, message],
        function(err) {
            if (err) {
                console.error('Admin support message creation error:', err);
                return res.status(500).json({ error: 'Failed to send message' });
            }
            
            // Update ticket updated_at
            db.run('UPDATE support_tickets SET updated_at = datetime("now") WHERE id = ?', [ticketId]);
            
            res.status(201).json({
                id: this.lastID,
                message: 'Message sent successfully'
            });
        }
    );
});

// Serve main pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/timetable', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'timetable.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 404 handler
app.use((req, res) => {
    console.log('404 - Route not found:', req.method, req.url);
    res.status(404).json({ error: 'Route not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
    console.log(`🔐 Admin credentials: username: admin, password: Admin@2024`);
    console.log(`💾 Database file: timetable.db`);
    console.log(`⏰ Timetable & Prayer Management System - COMPLETE FIXED VERSION`);
    console.log(`🎯 Features: Tasks, Prayers, Profile Pictures, Support Chat, Reports & Analytics, Admin Panel`);
    console.log(`👑 Admin Features: User Management with Profile Pictures`);
    console.log(`🔒 FIXED: Inactive users cannot login to the system`);
    console.log(`🖼️  Profile Picture Management: Fully functional in Admin Panel`);
});