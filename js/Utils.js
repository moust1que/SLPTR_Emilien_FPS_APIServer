import crypto from 'crypto';

// Verifies if the email format is correct using a regular expression
export function validateEmail(email) {
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailPattern.test(email);
}

// Ensures the password meets security requirements (8+ chars, upper, lower, number, special char)
export function validatePassword(password) {
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$/;
    return passwordPattern.test(password);
}

// Hashes the password combined with a SALT from the environment for secure storage
export function computePassword(password) {
    let data = password + process.env.SALT;
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Generates a unique session token based on user ID, timestamp, and random bytes
export function generateTokenForUser(userID) {
    return crypto
        .createHash('sha256')
        .update(`${userID}-${Date.now()}-${crypto.randomBytes(16).toString('hex')}`)
        .digest('hex');
}