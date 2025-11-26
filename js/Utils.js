import crypto from 'crypto';

export function validateEmail(email) {
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailPattern.test(email);
}

export function validatePassword(password) {
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$/;
    return passwordPattern.test(password);
}

export function computePassword(password) {
    let data = password + process.env.SALT;
    return crypto.createHash('sha256').update(data).digest('hex');
}

export function generateTokenForUser(userID) {
    return crypto
        .createHash('sha256')
        .update(`${userID}-${Date.now()}-${crypto.randomBytes(16).toString('hex')}`)
        .digest('hex');
}