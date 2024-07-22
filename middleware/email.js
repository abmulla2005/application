const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const forgetpassword = require('../controllers/user')

const sendVerifyMail = async (name, email, userId) => {
    try {
        const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const verificationUrl = `${process.env.CLIENT_URL}/verify-email/${token}`;

        const htmlMessage = `
            <p>Hello ${name},</p>
            <p>Please verify your email by clicking on the following link:</p>
            <p><a href="${verificationUrl}">${verificationUrl}</a></p>
        `;

        const textMessage = `Hello ${name},\n\nPlease verify your email by clicking on the following link:\n\n${verificationUrl}`;

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: 'Email Verification',
            text: textMessage,
            html: htmlMessage // Include HTML version of the email
        });

        console.log(`Verification email sent to ${email}`);
    } catch (error) {
        console.error('Error sending verification email:', error);
        throw error; // Re-throw the error to handle it upstream
    }
};

const sendmail = async (req, email, otp) => {
    try {
        const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/resetpassword/${otp}`;
        const message = `You are receiving this email because you (or someone else) have requested the reset of a password.\n Please use the following OTP to reset your password:  ${otp}.\n PLEASE DO NOT SHEARE OTP ANYONE !`;

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        await transporter.sendMail({
            from: 'no-reply@example.com',
            to: email,
            subject: 'Password Reset OTP',
            text: message
        });

        console.log(`Password reset email sent to ${email}`);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
};


module.exports = {
    sendVerifyMail,
    sendmail
}
