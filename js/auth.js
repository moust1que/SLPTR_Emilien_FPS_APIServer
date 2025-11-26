import { createPool } from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

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

export async function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Missing or invalid authorization header');
    }

    const token = authHeader.split(' ')[1];

    try {
        const [rows] = await pool.query('SELECT user_id, created_at, revoked_at FROM tokens WHERE content = ? LIMIT 1', [token]);

        if (rows.length === 0)
            return res.status(403).send('Invalid token');

        if (rows[0].revoked_at !== null)
            return res.status(403).send('Token revoked');

        const tokenDate = new Date(rows[0].created_at);
        const now = new Date();

        const diffTime = Math.abs(now - tokenDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays > 30) {
            await pool.query('UPDATE tokens SET revoked_at = NOW() WHERE content = ?', [token]);
            return res.status(403).send('Token expired');
        }

        req.userId = rows[0].user_id;

        next();
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal server error');
    }
}