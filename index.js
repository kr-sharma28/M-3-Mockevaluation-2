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

// models/Task.js
let mongoose = require('mongoose');

let TaskSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    priority: { type: String, required: true, enum: ['Low', 'Medium', 'High'] },
    deadline: { type: Date, required: true },
    status: { type: String, required: true, enum: ['Pending', 'In Progress', 'Completed'], default: 'Pending' },
    isPublic: { type: Boolean, default: false },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    collaborator: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Task', TaskSchema);

// middlewares/authMiddleware.js
let jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    let token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid Token' });
    }
};

// config/database.js
let mongoose = require('mongoose');

exports.connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log('Database Connected');
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
};
