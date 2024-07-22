const express = require('express');
const router = express.Router();

const { signup, login,logout, refreshToken, forgetpassword, getProfile, resetpassword, verifyEmail } = require('../controllers/user');
const verifyToken = require('../middleware/auth');


router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);
router.post('/refresh-token', refreshToken);
router.post('/forgetpassword', forgetpassword);
router.get('/profile', verifyToken, getProfile);
router.put('/resetpassword', resetpassword);
router.get('/verify-email/:token', verifyEmail); 
module.exports = router;
