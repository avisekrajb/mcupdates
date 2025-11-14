const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'photographer_app_secret_key_2024';

// Environment variables for production
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/photographer_app';
const EMAIL_USER = process.env.EMAIL_USER || 'abhishekrajbanshi999@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'krfotyhksoxsoynf';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// MongoDB Connection with better error handling
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('Connected to MongoDB Atlas');
})
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    address: { type: String, required: true },
    phone: { type: String, required: true },
    profilePhoto: { type: String }, // Store base64 or URL
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const bookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    services: [{ type: String, required: true }],
    date: { type: Date, required: true },
    time: { type: String, required: true },
    location: { type: String, required: true },
    specialRequests: { type: String },
    amount: { type: Number, required: true },
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const contactSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    message: { type: String, required: true },
    adminReply: { type: String },
    status: { type: String, default: 'pending' },
    date: { type: Date, default: Date.now }
});

const carouselSchema = new mongoose.Schema({
    image: { type: String, required: true }, // Store base64 image data
    title: { type: String, required: true },
    description: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const serviceSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    image: { type: String }, // Store base64 image data
    isNew: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const visitSchema = new mongoose.Schema({
    count: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
});

// MongoDB Models
const User = mongoose.model('User', userSchema);
const Booking = mongoose.model('Booking', bookingSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Carousel = mongoose.model('Carousel', carouselSchema);
const Service = mongoose.model('Service', serviceSchema);
const Visit = mongoose.model('Visit', visitSchema);

// File upload configuration with base64 conversion
const storage = multer.memoryStorage(); // Store files in memory as buffers

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit for base64 conversion
    }
});

// Convert buffer to base64
function bufferToBase64(buffer, mimetype) {
    return `data:${mimetype};base64,${buffer.toString('base64')}`;
}

// Email transporter configuration
// Email transporter configuration
let transporter;
try {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS
        }
    });
    
    // Verify transporter configuration
    transporter.verify(function(error, success) {
        if (error) {
            console.warn('Email transporter configuration failed:', error);
        } else {
            console.log('Email transporter is ready to send messages');
        }
    });
} catch (emailError) {
    console.warn('Email transporter initialization failed. Emails will not be sent.');
    transporter = null;
}
// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// User middleware (prevent admin from accessing user features)
const requireUser = (req, res, next) => {
    if (req.user.role === 'admin') {
        return res.status(403).json({ error: 'Admin cannot access user features' });
    }
    next();
};

// Visit counter middleware (FIXED: Only count unique visits)
const countVisit = async (req, res, next) => {
    try {
        // Skip API routes for visit counting
        if (req.path.startsWith('/api/')) {
            return next();
        }

        let visit = await Visit.findOne();
        if (!visit) {
            visit = await Visit.create({ count: 1 });
        } else {
            // Only count if last visit was more than 30 minutes ago (session-based)
            const lastVisitTime = new Date(visit.lastUpdated).getTime();
            const currentTime = new Date().getTime();
            const thirtyMinutes = 30 * 60 * 1000;
            
            if (currentTime - lastVisitTime > thirtyMinutes) {
                visit.count += 1;
                visit.lastUpdated = new Date();
                await visit.save();
            }
        }
        next();
    } catch (error) {
        console.error('Visit count error:', error);
        next();
    }
};

// Initialize admin user and default services
const initializeData = async () => {
    try {
        // Create admin user
        const adminExists = await User.findOne({ email: 'a@gmail.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('12345', 10);
            await User.create({
                fullName: 'Admin User',
                email: 'a@gmail.com',
                password: hashedPassword,
                address: 'Admin Address',
                phone: '0000000000',
                role: 'admin'
            });
            console.log('Admin user created: a@gmail.com / 12345');
        }

        // Create default services with base64 images
        const defaultServices = [
            {
                name: 'Wedding Photography',
                description: 'Full day coverage with 2 photographers',
                price: 500,
                isNew: false
            },
            {
                name: 'Photo Sessions',
                description: '2-hour professional photo session',
                price: 200,
                isNew: false
            },
            {
                name: 'Portrait Photography',
                description: 'Professional portrait sessions',
                price: 150,
                isNew: false
            },
            {
                name: 'Event Photography',
                description: 'Event coverage up to 4 hours',
                price: 300,
                isNew: false
            },
            {
                name: 'Commercial Photography',
                description: 'Product and commercial photography',
                price: 400,
                isNew: false
            }
        ];

        for (const serviceData of defaultServices) {
            const serviceExists = await Service.findOne({ name: serviceData.name });
            if (!serviceExists) {
                await Service.create(serviceData);
            }
        }

        // Create default carousel images with URLs (will be converted to base64 if needed)
        const defaultCarousel = [
            {
                image: 'https://images.unsplash.com/photo-1542038784456-1ea8e935640e?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80',
                title: 'Wedding Photography',
                description: 'Capture your special day with our professional wedding photography services'
            },
            {
                image: 'https://images.unsplash.com/photo-1511895426328-dc8714191300?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80',
                title: 'Portrait Sessions',
                description: 'Professional portrait photography for individuals and families'
            },
            {
                image: 'https://images.unsplash.com/photo-1521334884684-d80222895322?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80',
                title: 'Event Photography',
                description: 'Document your corporate events, parties, and special occasions'
            },
            {
                image: 'https://images.unsplash.com/photo-1516035069371-29a1b244cc32?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80',
                title: 'Commercial Photography',
                description: 'High-quality product and commercial photography for businesses'
            }
        ];

        const carouselCount = await Carousel.countDocuments();
        if (carouselCount === 0) {
            await Carousel.insertMany(defaultCarousel);
            console.log('Default carousel images created');
        }

        // Initialize visit counter
        const visitExists = await Visit.findOne();
        if (!visitExists) {
            await Visit.create({ count: 0 });
        }

        console.log('Default data initialized successfully');
    } catch (error) {
        console.error('Error initializing data:', error);
    }
};

// Routes

// Serve main application with visit counting
app.get('/', countVisit, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API Routes

// Get visit count
app.get('/api/visits', async (req, res) => {
    try {
        const visit = await Visit.findOne();
        res.json({ count: visit ? visit.count : 0 });
    } catch (error) {
        console.error('Visit count error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Count website visit (FIXED: Better session-based counting)
app.post('/api/visits', async (req, res) => {
    try {
        let visit = await Visit.findOne();
        if (!visit) {
            visit = await Visit.create({ count: 1 });
        } else {
            visit.count += 1;
            visit.lastUpdated = new Date();
            await visit.save();
        }
        res.json({ 
            message: 'Visit counted successfully',
            count: visit.count 
        });
    } catch (error) {
        console.error('Visit count error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Registration with Email (FIXED: Better error handling)
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password, address, phone } = req.body;

        // Validate required fields
        if (!fullName || !email || !password || !address || !phone) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const newUser = await User.create({
            fullName,
            email,
            password: hashedPassword,
            address,
            phone
        });

        // Send welcome email (with error handling)
        if (transporter) {
            try {
                await transporter.sendMail({
                    from: EMAIL_USER,
                    to: email,
                    subject: 'Welcome to Capture Moments Photography',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                            <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                                <h1 style="color: white; margin: 0;">Capture Moments</h1>
                            </div>
                            <div style="padding: 20px;">
                                <h2 style="color: #FF6B6B;">Welcome, ${fullName}!</h2>
                                <p>Thank you for registering with Capture Moments Photography. We're excited to have you on board!</p>
                                <p>Your account has been successfully created with the following details:</p>
                                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                    <p><strong>Email:</strong> ${email}</p>
                                    <p><strong>Phone:</strong> ${phone}</p>
                                    <p><strong>Address:</strong> ${address}</p>
                                </div>
                                <p>You can now login to your account and start booking our photography services.</p>
                                <p>If you have any questions, feel free to contact us.</p>
                                <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                            </div>
                            <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                                <p style="color: #666; font-size: 12px; margin: 0;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </div>
                    `
                });
                console.log('Welcome email sent to:', email);
            } catch (emailError) {
                console.error('Failed to send welcome email:', emailError);
            }
        }

        // Generate token for auto-login
        const token = jwt.sign(
            { 
                id: newUser._id, 
                email: newUser.email, 
                role: newUser.role 
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' } // 30 days for persistent login
        );

        res.status(201).json({ 
            message: 'User registered successfully',
            token,
            user: {
                id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                role: newUser.role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 11000) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: 'Internal server error during registration' });
    }
});

// User Login (FIXED: Better error handling)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Generate token with longer expiration
        const token = jwt.sign(
            { 
                id: user._id, 
                email: user.email, 
                role: user.role 
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' } // 30 days for persistent login
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                profilePhoto: user.profilePhoto,
                address: user.address,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error during login' });
    }
});

// Get user profile (FIXED: Better error handling)
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile with base64 image storage
app.put('/api/profile', authenticateToken, requireUser, upload.single('profilePhoto'), async (req, res) => {
    try {
        const { fullName, address, phone } = req.body;
        const updateData = { fullName, address, phone };
        
        if (req.file) {
            // Convert uploaded image to base64 and store in database
            const base64Image = bufferToBase64(req.file.buffer, req.file.mimetype);
            updateData.profilePhoto = base64Image;
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            updateData,
            { new: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ 
            message: 'Profile updated successfully',
            user: updatedUser
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Contact form submission (FIXED: Better validation)
app.post('/api/contact', authenticateToken, requireUser, async (req, res) => {
    try {
        const { name, email, phone, message } = req.body;

        // Validate required fields
        if (!name || !email || !phone || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const newContact = await Contact.create({
            userId: req.user.id,
            name,
            email,
            phone,
            message
        });

        // Send confirmation email to user
        if (transporter) {
            try {
                await transporter.sendMail({
                    from: EMAIL_USER,
                    to: email,
                    subject: 'Message Received - Capture Moments',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                            <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                                <h1 style="color: white; margin: 0;">Capture Moments</h1>
                            </div>
                            <div style="padding: 20px;">
                                <h2 style="color: #FF6B6B;">Message Received</h2>
                                <p>Dear ${name},</p>
                                <p>Thank you for contacting Capture Moments Photography. We have received your message and will get back to you shortly.</p>
                                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                    <p><strong>Your Message:</strong></p>
                                    <p style="background: white; padding: 10px; border-radius: 5px;">${message}</p>
                                </div>
                                <p>We typically respond within 24 hours. If you have any urgent inquiries, please call us at +1 (555) 123-4567.</p>
                                <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                            </div>
                            <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                                <p style="color: #666; font-size: 12px; margin: 0;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </div>
                    `
                });
                console.log('Contact confirmation email sent to:', email);
            } catch (emailError) {
                console.error('Failed to send contact confirmation email:', emailError);
            }
        }

        res.json({ 
            message: 'Message sent successfully',
            contact: newContact
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create booking (FIXED: Better validation and error handling)
app.post('/api/bookings', authenticateToken, requireUser, async (req, res) => {
    try {
        const { services, date, time, location, specialRequests, amount } = req.body;

        // Validate required fields
        if (!services || !Array.isArray(services) || services.length === 0) {
            return res.status(400).json({ error: 'At least one service is required' });
        }
        if (!date || !time || !location || !amount) {
            return res.status(400).json({ error: 'Date, time, location, and amount are required' });
        }

        // Check if booking date is in the future
        const bookingDate = new Date(date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        if (bookingDate < today) {
            return res.status(400).json({ error: 'Booking date cannot be in the past' });
        }

        const newBooking = await Booking.create({
            userId: req.user.id,
            services,
            date: bookingDate,
            time,
            location,
            specialRequests: specialRequests || '',
            amount: parseFloat(amount)
        });

        // Get user details for email
        const user = await User.findById(req.user.id);
        
        // Send booking confirmation email
        if (transporter) {
            try {
                await transporter.sendMail({
                    from: EMAIL_USER,
                    to: user.email,
                    subject: 'Booking Confirmation - Capture Moments',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                            <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                                <h1 style="color: white; margin: 0;">Capture Moments</h1>
                            </div>
                            <div style="padding: 20px;">
                                <h2 style="color: #FF6B6B;">Booking Confirmed!</h2>
                                <p>Dear ${user.fullName},</p>
                                <p>Your photography booking has been successfully created. Here are the details:</p>
                                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                    <p><strong>Services:</strong> ${services.join(', ')}</p>
                                    <p><strong>Date:</strong> ${new Date(date).toLocaleDateString()}</p>
                                    <p><strong>Time:</strong> ${time}</p>
                                    <p><strong>Location:</strong> ${location}</p>
                                    <p><strong>Amount:</strong> $${amount}</p>
                                    ${specialRequests ? `<p><strong>Special Requests:</strong> ${specialRequests}</p>` : ''}
                                    <p><strong>Status:</strong> <span style="color: #FFD166; font-weight: bold;">PENDING</span></p>
                                </div>
                                <p>We will review your booking and confirm it shortly. You can check the status in your account.</p>
                                <p>If you have any questions, please don't hesitate to contact us.</p>
                                <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                            </div>
                            <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                                <p style="color: #666; font-size: 12px; margin: 0;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </div>
                    `
                });
                console.log('Booking confirmation email sent to:', user.email);
            } catch (emailError) {
                console.error('Failed to send booking confirmation email:', emailError);
            }
        }

        res.status(201).json({ 
            message: 'Booking created successfully',
            booking: newBooking
        });
    } catch (error) {
        console.error('Booking creation error:', error);
        res.status(500).json({ error: 'Internal server error during booking creation' });
    }
});

// Get user bookings
app.get('/api/my-bookings', authenticateToken, requireUser, async (req, res) => {
    try {
        const bookings = await Booking.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        console.error('Bookings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user messages
app.get('/api/my-messages', authenticateToken, requireUser, async (req, res) => {
    try {
        const messages = await Contact.find({ userId: req.user.id }).sort({ date: -1 });
        res.json(messages);
    } catch (error) {
        console.error('Messages error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete user message
app.delete('/api/my-messages/:id', authenticateToken, requireUser, async (req, res) => {
    try {
        const message = await Contact.findOne({ _id: req.params.id, userId: req.user.id });
        
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        await Contact.findByIdAndDelete(req.params.id);
        res.json({ message: 'Message deleted successfully' });
    } catch (error) {
        console.error('Message delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete booking
app.delete('/api/bookings/:id', authenticateToken, requireUser, async (req, res) => {
    try {
        const booking = await Booking.findOne({ _id: req.params.id, userId: req.user.id });
        
        if (!booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        if (booking.status !== 'pending') {
            return res.status(400).json({ error: 'Only pending bookings can be deleted' });
        }

        await Booking.findByIdAndDelete(req.params.id);
        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        console.error('Booking delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all services
app.get('/api/services', async (req, res) => {
    try {
        // Mark services as not new after 15 days
        await Service.updateMany(
            { 
                isNew: true, 
                createdAt: { $lt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000) }
            },
            { $set: { isNew: false } }
        );

        const services = await Service.find().sort({ isNew: -1, createdAt: -1 });
        res.json(services);
    } catch (error) {
        console.error('Services error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get carousel images
app.get('/api/carousel', async (req, res) => {
    try {
        const images = await Carousel.find().sort({ createdAt: -1 }).limit(4);
        res.json(images);
    } catch (error) {
        console.error('Carousel error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Routes

// Get all bookings (admin only)
app.get('/api/admin/bookings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .populate('userId', 'fullName email phone')
            .sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        console.error('Admin bookings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update booking status (admin only) with Email
app.put('/api/admin/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;

        const booking = await Booking.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'fullName email');

        if (!booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        // Send status update email
        if (transporter) {
            try {
                await transporter.sendMail({
                    from: EMAIL_USER,
                    to: booking.userId.email,
                    subject: `Booking Status Update - ${booking.userId.fullName}`,
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                            <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                                <h1 style="color: white; margin: 0;">Capture Moments</h1>
                            </div>
                            <div style="padding: 20px;">
                                <h2 style="color: #FF6B6B;">Booking Status Update</h2>
                                <p>Dear ${booking.userId.fullName},</p>
                                <p>Your booking status has been updated:</p>
                                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                    <p><strong>Services:</strong> ${booking.services.join(', ')}</p>
                                    <p><strong>Date:</strong> ${new Date(booking.date).toLocaleDateString()}</p>
                                    <p><strong>Time:</strong> ${booking.time}</p>
                                    <p><strong>Location:</strong> ${booking.location}</p>
                                    <p><strong>New Status:</strong> 
                                        <span style="color: ${
                                            status === 'confirmed' ? '#06D6A0' : 
                                            status === 'completed' ? '#4ECDC4' : 
                                            status === 'rejected' ? '#EF476F' : '#FFD166'
                                        }; font-weight: bold;">
                                            ${status.toUpperCase()}
                                        </span>
                                    </p>
                                </div>
                                ${status === 'completed' ? 
                                    '<p>Your photography session has been completed successfully. Thank you for choosing Capture Moments!</p>' : 
                                    status === 'confirmed' ?
                                    '<p>Your booking has been confirmed! We look forward to capturing your special moments.</p>' :
                                    status === 'rejected' ?
                                    '<p>Unfortunately, we cannot accommodate your booking at this time. Please contact us for alternative options.</p>' :
                                    ''
                                }
                                <p>If you have any questions, please don't hesitate to contact us.</p>
                                <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                            </div>
                            <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                                <p style="color: #666; font-size: 12px; margin: 0;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </div>
                    `
                });
                console.log('Booking status update email sent to:', booking.userId.email);
            } catch (emailError) {
                console.error('Failed to send status update email:', emailError);
            }
        }

        res.json({ 
            message: 'Booking status updated successfully',
            booking
        });
    } catch (error) {
        console.error('Booking update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete booking (admin only)
app.delete('/api/admin/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const booking = await Booking.findByIdAndDelete(req.params.id);
        if (!booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        console.error('Booking delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).select('-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user email (admin only)
app.put('/api/admin/users/:id/email', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { email } = req.body;

        // Check if email already exists
        const existingUser = await User.findOne({ email, _id: { $ne: req.params.id } });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { email },
            { new: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ 
            message: 'User email updated successfully',
            user: updatedUser
        });
    } catch (error) {
        console.error('User update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Also delete user's bookings and messages
        await Booking.deleteMany({ userId: req.params.id });
        await Contact.deleteMany({ userId: req.params.id });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('User delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all contact messages (admin only)
app.get('/api/admin/messages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const messages = await Contact.find().populate('userId', 'fullName email').sort({ date: -1 });
        res.json(messages);
    } catch (error) {
        console.error('Admin messages error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update message status and reply (admin only) with Email
app.put('/api/admin/messages/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, adminReply } = req.body;

        const message = await Contact.findByIdAndUpdate(
            req.params.id,
            { status, adminReply },
            { new: true }
        ).populate('userId', 'fullName email');

        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        // Send reply email if admin replied
        if (adminReply && transporter) {
            try {
                await transporter.sendMail({
                    from: EMAIL_USER,
                    to: message.email,
                    subject: `Reply to your message - Capture Moments`,
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                            <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                                <h1 style="color: white; margin: 0;">Capture Moments</h1>
                            </div>
                            <div style="padding: 20px;">
                                <h2 style="color: #FF6B6B;">Response to Your Message</h2>
                                <p>Dear ${message.name},</p>
                                <p>Thank you for contacting us. Here is our response to your message:</p>
                                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                    <p><strong>Your Original Message:</strong></p>
                                    <p style="background: white; padding: 10px; border-left: 4px solid #FF6B6B;">${message.message}</p>
                                    <p><strong>Our Response:</strong></p>
                                    <p style="background: white; padding: 10px; border-left: 4px solid #4ECDC4;">${adminReply}</p>
                                </div>
                                <p>If you have any further questions, please don't hesitate to contact us.</p>
                                <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                            </div>
                            <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                                <p style="color: #666; font-size: 12px; margin: 0;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </div>
                    `
                });
                console.log('Reply email sent to:', message.email);
            } catch (emailError) {
                console.error('Failed to send reply email:', emailError);
            }
        }

        res.json({ 
            message: 'Message updated successfully',
            contact: message
        });
    } catch (error) {
        console.error('Message update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add carousel image (admin only) - MAX 4 IMAGES with base64 storage
app.post('/api/admin/carousel', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const count = await Carousel.countDocuments();
        if (count >= 4) {
            return res.status(400).json({ error: 'Maximum 4 carousel images allowed. Please delete an existing image first.' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Image file is required' });
        }

        const { title, description } = req.body;

        // Convert uploaded image to base64 and store in database
        const base64Image = bufferToBase64(req.file.buffer, req.file.mimetype);

        const newImage = await Carousel.create({
            image: base64Image, // Store base64 in database
            title: title || 'New Carousel Image',
            description: description || 'Carousel image description'
        });

        res.status(201).json({ 
            message: 'Carousel image added successfully',
            image: newImage
        });
    } catch (error) {
        console.error('Carousel image upload error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete carousel image (admin only)
app.delete('/api/admin/carousel/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const image = await Carousel.findByIdAndDelete(req.params.id);
        if (!image) {
            return res.status(404).json({ error: 'Image not found' });
        }

        res.json({ message: 'Carousel image deleted successfully' });
    } catch (error) {
        console.error('Carousel delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add new service (admin only) with base64 image storage
app.post('/api/admin/services', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, description, price } = req.body;

        if (!name || !description || !price) {
            return res.status(400).json({ error: 'Name, description and price are required' });
        }

        // Check if service already exists
        const existingService = await Service.findOne({ name });
        if (existingService) {
            return res.status(400).json({ error: 'Service with this name already exists' });
        }

        const serviceData = {
            name,
            description,
            price: parseFloat(price),
            isNew: true
        };

        if (req.file) {
            // Convert uploaded image to base64 and store in database
            const base64Image = bufferToBase64(req.file.buffer, req.file.mimetype);
            serviceData.image = base64Image;
        }

        const newService = await Service.create(serviceData);

        res.status(201).json({ 
            message: 'Service added successfully',
            service: newService
        });
    } catch (error) {
        console.error('Service creation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete service (admin only)
app.delete('/api/admin/services/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const service = await Service.findByIdAndDelete(req.params.id);
        if (!service) {
            return res.status(404).json({ error: 'Service not found' });
        }

        res.json({ message: 'Service deleted successfully' });
    } catch (error) {
        console.error('Service delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        email: transporter ? 'Configured' : 'Not Configured'
    });
});

// Serve uploaded images (for backward compatibility)
app.get('/uploads/:filename', (req, res) => {
    res.status(404).json({ error: 'Image not found. Images are now stored in database.' });
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
        }
    }
    
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Initialize server
const startServer = async () => {
    await initializeData();
    
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server is running on port ${PORT}`);
        console.log(`Admin credentials: a@gmail.com / 12345`);
        console.log('Environment:', process.env.NODE_ENV || 'development');
        console.log('MongoDB URI:', MONGODB_URI ? 'Connected to MongoDB Atlas' : 'Using local MongoDB');
        console.log('Email Service:', transporter ? 'Configured' : 'Not Configured - check EMAIL_USER and EMAIL_PASS');
        console.log('Image Storage: Database (Base64)');
    });
};

startServer();

module.exports = app;
