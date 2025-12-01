import express, { json, urlencoded } from 'express';
import { createPool } from 'mysql2/promise';
import { validateEmail, validatePassword, computePassword, generateTokenForUser } from './js/Utils.js';
import { authenticateToken } from './js/auth.js';
import dotenv from 'dotenv';
import brevo from '@getbrevo/brevo';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(json());
app.use(urlencoded({ extended: true }));

const apiInstance = new brevo.TransactionalEmailsApi();
apiInstance.setApiKey(brevo.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY);

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
        const conn = await pool.getConnection();
        try {
            const [result] = await conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPwd]);
            const newUserID = result.insertId;

            const token = generateTokenForUser(newUserID);
            await conn.execute('INSERT INTO tokens (user_id, content) VALUES (?, ?)', [newUserID, token]);

            res.status(201).send({ token: token });
        } catch (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('User already exists');
            throw err;
        } finally {
            conn.release();
        }
    } catch (err) {
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

            const NewToken = generateTokenForUser(userID);

            await conn.execute('INSERT INTO tokens (user_id, content) VALUES (?, ?)', [userID, NewToken]);

            await conn.execute('DELETE FROM tokens WHERE user_id = ? AND created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)', [userID]);

            res.status(200).send({ token: finalToken });
        } catch (err) {
            throw err;
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

        const [existingRequest] = await pool.query('SELECT expires_at FROM password_resets WHERE user_id = ? LIMIT 1', [userID]);

        if (existingRequest.length > 0) {
            const expiresAt = new Date(existingRequest[0].expires_at);
            const createdAt = new Date(expiresAt.getTime() - 15 * 60 * 1000);
            const now = new Date();

            const diffSeconds = (now - createdAt) / 1000;

            if (diffSeconds < 60) {
                const timeToWait = Math.ceil(60 - diffSeconds);
                return res.status(429).send(`Please wait ${timeToWait} seconds before requesting a new code.`);
            }
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        await pool.query('DELETE FROM password_resets WHERE user_id = ?', [userID]);
        await pool.query('INSERT INTO password_resets (user_id, code, expires_at) VALUES (?, ?, ?)', [userID, code, expiresAt]);

        const sendSmtpEmail = new brevo.SendSmtpEmail();

        sendSmtpEmail.sender = { "name": "Test Unit", "email": process.env.SENDER_EMAIL };

        sendSmtpEmail.to = [{ "email": email }];

        sendSmtpEmail.subject = "Reset your password";
        sendSmtpEmail.htmlContent = `
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>Password Reset</title>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
                <table role="presentation" style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 20px 0; text-align: center;">
                            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: left;">
                                <div style="background-color: #3b82f6; padding: 30px; text-align: center;">
                                    <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: bold;">Password Reset Request</h1>
                                </div>
                                <div style="padding: 40px 30px;">
                                    <p style="margin: 0 0 20px; color: #333333; font-size: 16px; line-height: 1.5;">Hello,</p>
                                    <p style="margin: 0 0 20px; color: #555555; font-size: 16px; line-height: 1.5;">
                                        We received a request to reset the password for your account. Please use the verification code below to proceed:
                                    </p>
                                    <div style="margin: 30px 0; text-align: center;">
                                        <span style="display: inline-block; background-color: #eff6ff; border: 1px solid #dbeafe; border-radius: 6px; padding: 15px 30px; font-size: 32px; font-weight: bold; color: #1e40af; letter-spacing: 5px;">
                                            ${code}
                                        </span>
                                    </div>
                                    <p style="margin: 0 0 20px; color: #555555; font-size: 14px; line-height: 1.5;">
                                        This code will expire in <strong>15 minutes</strong>.
                                    </p>
                                    <hr style="border: none; border-top: 1px solid #eeeeee; margin: 30px 0;">
                                    <p style="margin: 0; color: #999999; font-size: 13px;">
                                        If you did not request a password reset, please ignore this email or contact support if you have concerns.
                                    </p>
                                </div>
                                <div style="background-color: #f9fafb; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
                                    <p style="margin: 0; color: #888888; font-size: 12px;">
                                        &copy; ${new Date().getFullYear()} Test Unit. All rights reserved.
                                    </p>
                                </div>
                            </div>
                        </td>
                    </tr>
                </table>
            </body>
        </html>`;

        await apiInstance.sendTransacEmail(sendSmtpEmail);

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
        } catch (err) {
            throw err;
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

userRouter.post('/logout', async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader.split(' ')[1];

    if (!token) return res.sendStatus(200);

    try {
        await pool.query('DELETE FROM tokens WHERE content = ?', [token]);

        res.status(200).send('Logged out successfully');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

app.listen(port, () => {
    console.log(`Server running on https://slptr-emilien-fps-apiserver.onrender.com`);
});