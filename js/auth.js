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
        const [row] = await pool.query('SELECT user_id FROM tokens WHERE content = ? LIMIT 1', [token]);

        if (row.length === 0)
            return res.status(403).send('Invalid or expired token');

        req.userId = row[0].user_id;

        next();
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal server error');
    }
}