// Import necessary libraries
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const moment = require('moment-timezone');
const csv = require('csv-parser');
const fs = require('fs');



// Initialize Express app
const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/contact_manager', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
});
const User = mongoose.model('User', userSchema);

// Contact Schema
const contactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    timezone: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    isDeleted: { type: Boolean, default: false },
});
const Contact = mongoose.model('Contact', contactSchema);

// Email Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your_email@gmail.com',
        pass: 'your_email_password',
    },
});

// Rate Limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
});

// Validation Schema
const userSchemaValidation = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

const contactSchemaValidation = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    phone: Joi.string().required(),
    address: Joi.string().required(),
    timezone: Joi.string().required(),
});

// Middleware for checking JWT
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(403);
    
    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// User Registration
app.post('/register', async (req, res) => {
    const { error } = userSchemaValidation.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    const verificationToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '1h' });
    const verificationLink = ('http://localhost:5000/verify/${verificationToken}');

    await transporter.sendMail({
        to: email,
        subject: 'Verify your email',
        text: ('Click this link to verify: ${verificationLink}'),
    });

    res.status(201).json({ message: 'User registered! Check your email for verification.' });
});

// Email Verification
app.get('/verify/:token', async (req, res) => {
    const { token } = req.params;
    const { email } = jwt.verify(token, 'your_jwt_secret');
    await User.updateOne({ email }, { isVerified: true });
    res.send('Email verified!');
});

// User Login
app.post('/login', loginLimiter, async (req, res) => {
    const { error } = userSchemaValidation.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// Password Reset Request
app.post('/reset-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const resetToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '15m' });
    await transporter.sendMail({
        to: email,
        subject: 'Reset your password',
        text: ('Reset link: http://localhost:5000/reset/${resetToken}'),
    });

    res.send('Password reset link sent!');
});

// Reset Password
app.post('/reset/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;
    const { email } = jwt.verify(token, 'your_jwt_secret');

    const user = await User.findOne({ email });
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.send('Password reset successfully!');
});

// Add a new contact
app.post('/contacts', authenticateJWT, async (req, res) => {
    const { error } = contactSchemaValidation.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const contact = new Contact(req.body);
    await contact.save();
    res.status(201).json({ message: 'Contact added!' });
});

// Retrieve contacts
app.get('/contacts', authenticateJWT, async (req, res) => {
    const { filter, sort } = req.query;
    const query = { isDeleted: false };

    if (filter) {
        query.$or = [
            { name: new RegExp(filter, 'i') },
            { email: new RegExp(filter, 'i') },
            { timezone: new RegExp(filter, 'i') },
        ];
    }

    const contacts = await Contact.find(query).sort(sort);
    res.json(contacts);
});

// Update contact details
app.put('/contacts/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    await Contact.findByIdAndUpdate(id, req.body);
    res.send('Contact updated!');
});

// Soft delete contact
app.delete('/contacts/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    await Contact.findByIdAndUpdate(id, { isDeleted: true });
    res.send('Contact deleted (soft delete)!');
});

// Batch processing for contacts
app.post('/contacts/batch', authenticateJWT, async (req, res) => {
    const contacts = req.body;
    await Contact.insertMany(contacts);
    res.send('Batch processing completed!');
});

// File handling for bulk upload
const upload = multer({ dest: 'uploads/' });
app.post('/upload', authenticateJWT, upload.single('file'), (req, res) => {
    const results = [];
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', async (data) => {
            results.push(data);
        })
        .on('end', async () => {
            await Contact.insertMany(results);
            res.send('Contacts added from file!');
        });
});

// Download contacts as CSV
app.get('/download', authenticateJWT, async (req, res) => {
    const contacts = await Contact.find();
    const csvData = contacts.map(contact => ({
        name: contact.name,
        email: contact.email,
        phone: contact.phone,
        address: contact.address,
        timezone: contact.timezone,
        createdAt: contact.createdAt.toISOString(),
    }));

    res.header('Content-Type', 'text/csv');
    res.attachment('contacts.csv');
    res.send(csvData);
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log('Server is running on http://localhost:${PORT}')
});