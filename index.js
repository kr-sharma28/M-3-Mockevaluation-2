require('dotenv').config();
let express = require('express');
let mongoose = require('mongoose');
let morgan = require('morgan');
let cors = require('cors');
let authRoutes = require('./routes/authRoutes');
let taskRoutes = require('./routes/taskRoutes');
let { connectDB } = require('./config/database');

let app = express();
let PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(morgan('combined'));

// Database Connection
connectDB();

// Routes
app.use('/user', authRoutes);
app.use('/tasks', taskRoutes);

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// models/User.js
let mongoose = require('mongoose');
let bcrypt = require('bcryptjs');

let UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

module.exports = mongoose.model('User', UserSchema);
