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

// routes/authRoutes.js
let express = require('express');
let User = require('../models/User');
let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');

let router = express.Router();

router.post('/signup', async (req, res) => {
    try {
        let { name, email, password } = req.body;
        let user = new User({ name, email, password });
        await user.save();
        res.status(201).json({ message: 'User registered' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        let { email, password } = req.body;
        let user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        let token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30m' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;

// routes/taskRoutes.js
let express = require('express');
let Task = require('../models/Task');
let authMiddleware = require('../middlewares/authMiddleware');

let router = express.Router();

router.post('/add', authMiddleware, async (req, res) => {
    try {
        let { title, description, priority, deadline, isPublic, collaborator } = req.body;
        let task = new Task({ title, description, priority, deadline, isPublic, owner: req.userId, collaborator });
        await task.save();
        res.status(201).json({ message: 'Task created' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get('/get', authMiddleware, async (req, res) => {
    try {
        let tasks = await Task.find({ owner: req.userId });
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get('/public/get', async (req, res) => {
    try {
        let tasks = await Task.find({ isPublic: true });
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;
