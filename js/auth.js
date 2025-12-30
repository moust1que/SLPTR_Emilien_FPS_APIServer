import { createPool } from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

// Create a secure connection pool to the database using environment variables
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

// Middleware function to verify the user's token before allowing access to private routes
export async function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    // Check if the Authorization header exists and follows the 'Bearer [token]' format
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Missing or invalid authorization header');
    }

    // Extract the token string by removing the 'Bearer ' prefix
    const token = authHeader.split(' ')[1];

    try {
        // Retrieve token details (user ID, creation date) from the database
        const [rows] = await pool.query('SELECT user_id, created_at, revoked_at FROM tokens WHERE content = ? LIMIT 1', [token]);

        // If the token is not found in the database, deny access
        if (rows.length === 0)
            return res.status(403).send('Invalid token');

        // Calculate the age of the token in days to check for expiration
        const tokenDate = new Date(rows[0].created_at);
        const now = new Date();
        const diffTime = Math.abs(now - tokenDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        // If the token is older than 30 days or was revoked, delete it and deny access
        if (diffDays > 30 || rows[0].revoked_at !== null) {
            await pool.query('DELETE FROM tokens WHERE content = ?', [token]);
            return res.status(403).send('Token revoked');
        }

        // Attach the User ID to the request so specific routes know who is performing the action
        req.userId = rows[0].user_id;

        // Proceed to the next step of the request
        next();
    } catch (err) {
        // Log the error and return a generic server error message
        console.error(err);
        res.status(500).send('Internal server error');
    }
}