import express, { json, urlencoded } from 'express';
import { createPool } from 'mysql2/promise';
import { validateEmail, validatePassword, computePassword, generateTokenForUser } from './js/Utils.js';
import { authenticateToken } from './js/auth.js';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(json());
app.use(urlencoded({ extended: true }));

const pool = createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10
});

const userRouter = express.Router();
userRouter.use(authenticateToken);
app.use('/user', userRouter);

app.route('/user')
    .get(async (req, res) => {
        try {
            const [rows] = await pool.query('SELECT * from users');
            res.json(rows);
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        }
    })
    .post(async (req, res) => {
        const { email, pwd } = req.body;

        if (!validateEmail(email))
            return res.status(400).send('Invalid email format');

        if (!validatePassword(pwd))
            return res.status(400).send('Weak password');

        const hashedPwd = computePassword(pwd);

        try {
            await pool.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPwd]);
            res.status(201).send('User created');
        } catch (err) {
            if (err.code === 'ER_DUP_ENTRY')
                return res.status(409).send('User already exists');

            console.error(err);
            res.status(500).send('Database error');
        }
    })
    .put(async (req, res) => {
        const { email, pwd } = req.body;

        if (!validateEmail(email))
            return res.status(400).send('Invalid email');

        if (!validatePassword(pwd))
            return res.status(400).send('Invalid password');

        const hashedPwd = computePassword(pwd);

        try {
            const [result] = await pool.query('UPDATE users SET password = ?, updated_at = NOW() WHERE email = ? LIMIT 1', [hashedPwd, email]);
            if (result.affectedRows === 0)
                return res.status(404).send('User not found');

            res.send('Password updated');
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        }
    })
    .delete(async (req, res) => {
        const { email } = req.body;

        if (!validateEmail(email))
            return res.status(400).send('Invalid email');

        try {
            const [result] = await pool.query('DELETE FROM users WHERE email = ? LIMIT 1', [email]);
            if (result.affectedRows === 0)
                return res.status(404).send('User not found');

            res.send('User deleted');
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
            const [row] = await conn.execute('SELECT id FROM users WHERE email = ? AND password = ? LIMIT 1', [email, hashedPwd]);

            if (row.length === 0) {
                conn.release();
                return res.status(404).send('User not found');
            }

            const userID = row[0].id;

            const [tokenInTable] = await conn.execute('SELECT id FROM tokens WHERE user_id = ? LIMIT 1', [userID]);

            if (tokenInTable.length > 0) {
                await conn.execute('DELETE FROM tokens WHERE user_id = ?', [userID]);
            }

            const token = generateTokenForUser(userID);

            await conn.execute('INSERT INTO tokens (content, user_id) VALUES (?, ?)', [token, userID]);

            res.status(201).send({ token: token });
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

userRouter.route('/score')
    .get(async (req, res) => {
        try {
            const [row] = await pool.query('SELECT highscore FROM scores WHERE user_id = ? LIMIT 1', [req.userId]);

            if (row.length === 0)
                return res.status(404).send('No highscore for this user');

            res.status(200).json({ highscore: row[0].highscore });
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
            const [row] = await pool.query('SELECT highscore FROM scores WHERE user_id = ? LIMIT 1', [req.userId]);

            if (row.length === 0) {
                await pool.query('INSERT INTO scores (user_id, highscore) VALUES (?, ?)', [req.userId, highscore]);
            } else {
                if (row[0].highscore > highscore)
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
    console.log(`Server running on http://localhost:${port}`);
});