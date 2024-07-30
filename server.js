const express = require('express');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const forge = require('node-forge');
const fs = require('fs');

const app = express();
const port = 8080;

// Đọc biến môi trường từ file .env
dotenv.config();

// Kết nối đến MySQL
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: 3306
});

db.connect(err => {
    if (err) {
        logError('Error connecting to MySQL', err);
        return;
    }
    console.log('Connected as id ' + db.threadId);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cấu hình Express để phục vụ các file tĩnh từ thư mục 'public'
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Log lỗi vào file error.log
function logError(message, err) {
    const errorMessage = `[${new Date().toISOString()}] ${message}: ${err.stack || err}\n`;
    console.error(errorMessage);
    fs.appendFile('error.log', errorMessage, (err) => {
        if (err) console.error('Error writing to log file', err);
    });
}

// Cung cấp trang HTML khi truy cập vào root '/'
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Đăng ký người dùng
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Tạo UID ngẫu nhiên
    const uid = Math.floor(100000000 + Math.random() * 900000000).toString();

    // Tạo cặp khóa công khai và bí mật
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {
        if (err) {
            logError('Error generating key pair', err);
            return res.status(500).send('Error generating key pair');
        }

        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
        const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

        // Mã hóa mật khẩu
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                logError('Error hashing password', err);
                return res.status(500).send('Error hashing password');
            }

            const query = 'INSERT INTO users (username, password, public_key, private_key, uid) VALUES (?, ?, ?, ?, ?)';
            db.query(query, [username, hashedPassword, publicKeyPem, privateKeyPem, uid], (err, results) => {
                if (err) {
                    logError('Error registering user', err);
                    return res.status(500).send('Error registering user');
                }
                res.send({ message: 'User registered successfully', uid });
            });
        });
    });
});

// Đăng nhập người dùng
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            logError('Error logging in user', err);
            return res.status(500).send('Error logging in user');
        }

        if (results.length === 0) {
            return res.status(401).send('Invalid username or password');
        }

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                logError('Error comparing passwords', err);
                return res.status(500).send('Error comparing passwords');
            }

            if (!isMatch) {
                return res.status(401).send('Invalid username or password');
            }

            req.session.user = username;
            res.send({ message: 'Login successful', privateKey: user.private_key, uid: user.uid });
        });
    });
});

// Lấy khóa công khai của người nhận
app.get('/getPublicKey', (req, res) => {
    const { username } = req.query;

    const query = 'SELECT public_key FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            logError('Error fetching public key', err);
            return res.status(500).send('Error fetching public key');
        }

        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        res.send(results[0].public_key);
    });
});

// Lấy tất cả tin nhắn
app.get('/messages', (req, res) => {
    const query = 'SELECT * FROM messages';
    db.query(query, (err, results) => {
        if (err) {
            logError('Error fetching messages', err);
            return res.status(500).send('Error fetching messages');
        }

        res.json(results);
    });
});

// Xóa tất cả tin nhắn
app.delete('/messages', (req, res) => {
    const query = 'DELETE FROM messages';
    db.query(query, (err, results) => {
        if (err) {
            logError('Error clearing messages', err);
            return res.status(500).send('Error clearing messages');
        }

        res.send('Messages cleared successfully');
    });
});

// Thiết lập server HTTP và WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', ws => {
    ws.on('message', message => {
        console.log('Received message from client:', message);

        const data = JSON.parse(message);
        if (data.type === 'message') {
            app.emit('message', data);

            // Lưu tin nhắn vào cơ sở dữ liệu
            const query = 'INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)';
            db.query(query, [data.sender, data.recipient, data.message], (err, results) => {
                if (err) {
                    logError('Error inserting message', err);
                } else {
                    console.log('Message inserted into database:', data);
                }
            });
        }
    });
});

app.on('message', message => {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
        }
    });
});

server.listen(port, '0.0.0.0', () => {
    console.log(`Server is listening on http://localhost:${port}`);
});
