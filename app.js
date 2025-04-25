require('dotenv').config(); // Load environment variables

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');

const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB Atlas"))
    .catch(err => console.error("Could not connect to MongoDB Atlas", err));

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

app.use((req, res, next) => {
    res.locals.session = req.session; // Make session available in all views
    next();
});

app.use(async (req, res, next) => {
    if (req.session.userId) {
        const user = await User.findById(req.session.userId);
        res.locals.user = user; // Make user object available in all views
    } else {
        res.locals.user = null;
    }
    next();
});

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' } // Add role field
});

const User = mongoose.model('User', userSchema);

// Define Notice Schema and Model
const noticeSchema = new mongoose.Schema({
    title: String,
    content: String,
    department: String,
    priority: String
});

const Notice = mongoose.model('Notice', noticeSchema);

// Middleware to Check Authentication
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

function checkRole(role) {
    return async (req, res, next) => {
        if (req.session.userId) {
            try {
                const user = await User.findById(req.session.userId); // Use async/await
                if (!user || user.role !== role) {
                    return res.status(403).send('Access Denied');
                }
                next();
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        } else {
            res.redirect('/login');
        }
    };
}

// Routes
app.get('/', async (req, res) => {
    const { department, priority } = req.query; // Get filter values from query parameters
    let query = {};

    // Add filters to the query object if they are provided
    if (department) query.department = department;
    if (priority) query.priority = priority;

    try {
        const notices = await Notice.find(query); // Fetch notices based on the query
        res.render('index', { notices, user: res.locals.user }); // Pass notices and user to the view
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body; // Accept role from the form
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, role: role || 'user' }); // Default to 'user'
    await user.save();
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user._id;
        res.redirect('/');
    } else {
        res.send('Invalid username or password');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.get('/add', checkRole('admin'), (req, res) => {
    res.render('add');
});

app.post('/add', checkRole('admin'), async (req, res) => {
    const { title, content, department, priority } = req.body;
    const notice = new Notice({ title, content, department, priority });
    await notice.save();
    res.redirect('/');
});

app.get('/edit/:id', checkRole('admin'), async (req, res) => {
    const notice = await Notice.findById(req.params.id);
    res.render('edit', { notice });
});

app.post('/edit/:id', checkRole('admin'), async (req, res) => {
    const { title, content, department, priority } = req.body;
    await Notice.findByIdAndUpdate(req.params.id, { title, content, department, priority });
    res.redirect('/');
});

app.post('/delete/:id', checkRole('admin'), async (req, res) => {
    await Notice.findByIdAndDelete(req.params.id);
    res.redirect('/');
});

app.listen(4000, () => console.log("Server running on port 4000"));