const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('../models/User');
const {sendVerifyMail,sendmail} = require('../middleware/email.js');

// Signup
const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const userExists = await User.findOne({ email });

        // console.log("cvcvc",userExists)

        if (userExists) {
            if (!userExists.isVerified) {
                await sendVerifyMail(name, email, userExists._id);
                return res.status(400).json({ message: 'User already exists. Verification email resent. Please verify your email' });
            }
            return res.status(400).json({ message: 'User already exists. Please login' });
        }

        const newUser = await User.create({ name, email, password });

        await sendVerifyMail(name, email, newUser._id);

       
        return res.status(201).json({ message: "User Signup Successful. Verification email sent." });
    } catch (error) {
        console.error('Signup error:', error);
        // Handle server errors
        res.status(500).json({ message: 'SIGNUP ERROR !' });
    }
};



const generateTokens = (user) => {
    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

    return { accessToken, refreshToken };
};

const storeRefreshToken = async (user, refreshToken) => {
    user.refreshToken = refreshToken;
    await user.save();
};

const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'User Not Exists' });
        }

        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Password Miss Match' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Please verify your email to log in' });
        }

        const { accessToken, refreshToken } = generateTokens(user);
        await storeRefreshToken(user, refreshToken);

        res.status(200).json({ message: 'Successfully logged in', accessToken, refreshToken });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'LOGIN ERROR!' });
    }
};

const refreshToken = async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(401).json({ message: 'Refresh token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || user.refreshToken !== token) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const { accessToken, refreshToken } = generateTokens(user);
        await storeRefreshToken(user, refreshToken);

        res.status(200).json({ accessToken, refreshToken });
    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(403).json({ message: 'Invalid refresh token' });
    }
};


//  LogOut 
const logout = async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token must be provided' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        user.refreshToken = undefined;
        await user.save();

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};


// Forget Password
const generateOTP = (length = 6) => {
    const otp = crypto.randomInt(0, Math.pow(10, length)).toString().padStart(length, '0');
    return otp;
};

const forgetpassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate OTP and update the user
        const otp = generateOTP();
        user.resetPasswordToken = otp; // Store OTP temporarily
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send OTP email
        await sendmail(req, email, otp);

        res.status(200).json({ message: 'Reset email sent' });
    } catch (error) {
        console.error('Forget password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};


const verifyEmail = async (req, res) => {
    const { token } = req.params;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(400).json({ message: 'Invalid token' });
        }

        user.isVerified = true;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(400).json({ message: 'Invalid or expired token' });
    }
};

// Get Profile
const getProfile = async (req, res) => {
    const userId = req.user.id;

    try {
        const user = await User.findById(userId).select('-password');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(user);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Reset Password

const resetpassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        // Check if the email is present
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'Email not found' });
        }

        // Check if the OTP is valid and not expired
        if (user.resetPasswordToken !== otp || user.resetPasswordExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        // Reset the password
        user.password = newPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};



module.exports = {
    signup,
    login,
    logout,
    refreshToken,
    forgetpassword,
    getProfile,
    resetpassword,
    verifyEmail
};
