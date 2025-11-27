import express, { json, urlencoded } from 'express';
import { createPool } from 'mysql2/promise';
import { validateEmail, validatePassword, computePassword, generateTokenForUser } from './js/Utils.js';
import { authenticateToken } from './js/auth.js';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(json());
app.use(urlencoded({ extended: true }));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const pool = createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    }
});

// public routes
app.post('/user/register', async (req, res) => {
    const { email, pwd } = req.body;

    if (!validateEmail(email)) return res.status(400).send('Invalid email format');
    if (!validatePassword(pwd)) return res.status(400).send('Weak password');

    const hashedPwd = computePassword(pwd);

    try {
        await pool.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPwd]);
        res.status(201).send('User created');
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('User already exists');
        console.error(err);
        res.status(500).send('Database error');
    }
});

app.post('/user/login', async (req, res) => {
    const { email, pwd } = req.body;
    const hashedPwd = computePassword(pwd);

    try {
        const conn = await pool.getConnection();

        try {
            const [users] = await conn.execute('SELECT id FROM users WHERE email = ? AND password = ? LIMIT 1', [email, hashedPwd]);

            if (users.length === 0) {
                conn.release();
                return res.status(404).send('User not found');
            }

            const userID = users[0].id;

            const [tokens] = await conn.execute('SELECT id, content, created_at FROM tokens WHERE user_id = ? LIMIT 1', [userID]);

            let finalToken;

            if (tokens.length > 0) {
                const dbToken = tokens[0];
                const tokenDate = new Date(dbToken.created_at);
                const now = new Date();

                const diffTime = Math.abs(now - tokenDate);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

                if (diffDays <= 30) {
                    await conn.execute('UPDATE tokens SET created_at = NOW() WHERE id = ?', [dbToken.id]);
                    finalToken = dbToken.content;
                } else {
                    await conn.execute('DELETE FROM tokens WHERE id = ?', [dbToken.id]);
                    finalToken = generateTokenForUser(userID);
                    await conn.execute('INSERT INTO tokens (user_id, content) VALUES (?, ?)', [userID, finalToken]);
                }
            } else {
                finalToken = generateTokenForUser(userID);
                await conn.execute('INSERT INTO tokens (user_id, content) VALUES (?, ?)', [userID, finalToken]);
            }

            res.status(200).send({ token: finalToken });
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        } finally {
            conn.release();
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

app.post('/user/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!validateEmail(email)) return res.status(400).send('Invalid email format');

    try {
        const [users] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);

        if (users.length === 0) return res.status(404).send('User not found');

        const userID = users[0].id;
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        await pool.query('DELETE FROM password_resets WHERE user_id = ?', [userID]);
        await pool.query('INSERT INTO password_resets (user_id, code, expires_at) VALUES (?, ?, ?)', [userID, code, expiresAt]);

        const mailOptions = {
            from: process.env.MAIL_USER,
            to: email,
            subject: 'Password reset code',
            text: `Your password reset code is: ${code}. It will expire in 15 minutes.`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send('Password reset code sent');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

app.post('/user/reset-password', async (req, res) => {
    const { email, code, newPwd } = req.body;

    if (!validatePassword(newPwd)) return res.status(400).send('Weak password');

    try {
        const [rows] = await pool.query(
            `SELECT r.user_id
            FROM password_resets r
            JOIN users u ON r.user_id = u.id
            WHERE u.email = ? AND r.code = ? AND r.expires_at > NOW()`,
            [email, code]
        );

        if (rows.length === 0) return res.status(400).send('Invalid or expired code');

        const userID = rows[0].user_id;
        const hashedPwd = computePassword(newPwd);

        await pool.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [hashedPwd, userID]);
        await pool.query('DELETE FROM password_resets WHERE user_id = ?', [userID]);

        res.status(200).send('Password successfully reset');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// private routes
const userRouter = express.Router();
userRouter.use(authenticateToken);
app.use('/user', userRouter);

userRouter.put('/', async (req, res) => {
    const { newPwd } = req.body;

        if (!validatePassword(newPwd)) return res.status(400).send('Weak password');

        const hashedPwd = computePassword(newPwd);

        try {
            await pool.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [hashedPwd, req.userId]);
            res.status(200).send('Password updated');
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        }
    });

userRouter.delete('/', async (req, res) => {
    try {
        const conn = await pool.getConnection();

        try {
            await conn.execute('DELETE FROM tokens WHERE user_id = ?', [req.userId]);
            await conn.execute('DELETE FROM scores WHERE user_id = ?', [req.userId]);
            const [result] = await conn.execute('DELETE FROM users WHERE id = ? LIMIT 1', [req.userId]);

            if (result.affectedRows === 0)
                return res.status(404).send('User not found');

            res.send('User deleted');
        } finally {
            conn.release();
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

userRouter.get('/validate', (req, res) => {
    res.status(200).send('Token valid');
});

userRouter.route('/score')
    .get(async (req, res) => {
        try {
            const [rows] = await pool.query('SELECT highscore FROM scores WHERE user_id = ? LIMIT 1', [req.userId]);

            if (rows.length === 0)
                return res.status(404).send('No highscore for this user');

            res.status(200).json({ highscore: rows[0].highscore });
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        }
    })
    .post(async (req, res) => {
        const { highscore } = req.body;

        if (typeof highscore !== 'number' || highscore < 0)
            return res.status(400).send('Invalid highscore');

        try {
            const [rows] = await pool.query('SELECT highscore FROM scores WHERE user_id = ? LIMIT 1', [req.userId]);

            if (rows.length === 0) {
                await pool.query('INSERT INTO scores (user_id, highscore) VALUES (?, ?)', [req.userId, highscore]);
            } else {
                if (rows[0].highscore > highscore)
                    return res.status(400).send('Not your best score');

                await pool.query('UPDATE scores SET highscore = ? WHERE user_id = ?', [highscore, req.userId]);
            }

            res.status(201).send('Highscore updated');
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        }
    });

app.listen(port, () => {
    console.log(`Server running on https://slptr-emilien-fps-apiserver.onrender.com`);
});