#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🚀 UZOQTAXI MVP структураси яратилмоқда...\n');

// Проект кор директорияси
const projectRoot = process.cwd();
const projectName = 'uzoqtaxi-mvp';

// Структура папок
const structure = {
  'backend/src/config/database.js': `const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(\`MongoDB connected: \${conn.connection.host}\`);
  } catch (error) {
    console.error(\`Error: \${error.message}\`);
    process.exit(1);
  }
};

module.exports = connectDB;`,

  'backend/src/middleware/auth.js': `const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      req.user = await User.findById(decoded.id).select('-password');
      
      if (!req.user) {
        return res.status(401).json({ message: 'Фойдаланувчи топилмади' });
      }
      
      next();
    } catch (error) {
      console.error(error);
      return res.status(401).json({ message: 'Токен нотўғри' });
    }
  }

  if (!token) {
    return res.status(401).json({ message: 'Токен йўқ, авторизациядан ўтинг' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: \`Рол \${req.user.role} учун рухсат берилмаган\` 
      });
    }
    next();
  };
};

module.exports = { protect, authorize };`,

  'backend/src/middleware/validation.js': `const { check, validationResult } = require('express-validator');

const validateRegister = [
  check('phone')
    .notEmpty().withMessage('Телефон рақам киритинг')
    .matches(/^998[0-9]{9}$/).withMessage('Телефон рақам нотўғри форматда'),
  
  check('password')
    .isLength({ min: 6 }).withMessage('Парол камида 6 та белгидан иборат бўлиши керак'),
  
  check('fullName')
    .notEmpty().withMessage('Исмингизни киритинг')
    .isLength({ min: 2 }).withMessage('Исм камида 2 та белгидан иборат бўлиши керак'),
  
  check('role')
    .optional()
    .isIn(['driver', 'passenger']).withMessage('Нотўғри рол')
];

const validateLogin = [
  check('phone')
    .notEmpty().withMessage('Телефон рақам киритинг'),
  
  check('password')
    .notEmpty().withMessage('Парол киритинг')
];

const validateCreateRide = [
  check('fromRegion')
    .notEmpty().withMessage('Қаердан (вилоят) киритинг'),
  
  check('fromDistrict')
    .notEmpty().withMessage('Қаердан (туман) киритинг'),
  
  check('toRegion')
    .notEmpty().withMessage('Қаерга (вилоят) киритинг'),
  
  check('departureTime')
    .notEmpty().withMessage('Йўлга чиқиш вақтини киритинг')
    .isISO8601().withMessage('Нотўғри вақт формати'),
  
  check('availableSeats')
    .isInt({ min: 1, max: 6 }).withMessage('Ўринлар сони 1-6 орасида бўлиши керак'),
  
  check('pricePerSeat')
    .isInt({ min: 1000 }).withMessage('Нарх камида 1000 сўм бўлиши керак'),
  
  check('paymentMethods.cash')
    .optional()
    .isBoolean().withMessage('Нақд пул қабул қилиш ҳақида маълумот нотўғри'),
  
  check('paymentMethods.click')
    .optional()
    .isBoolean().withMessage('Click қабул қилиш ҳақида маълумот нотўғри'),
  
  check('linePrice')
    .isInt({ min: 0 }).withMessage('Линия нархи нотўғри')
];

const validateSearchRide = [
  check('fromRegion')
    .notEmpty().withMessage('Қаердан (вилоят) киритинг'),
  
  check('toRegion')
    .notEmpty().withMessage('Қаерга (вилоят) киритинг'),
  
  check('departureDate')
    .notEmpty().withMessage('Сафарингиз кунини киритинг')
];

const validateBooking = [
  check('seats')
    .isInt({ min: 1 }).withMessage('Камида 1 та ўрин танланг'),
  
  check('specialRequests.luggageCount')
    .optional()
    .isInt({ min: 0 }).withMessage('Сумкалар сони нотўғри'),
  
  check('paymentMethod')
    .isIn(['cash', 'click']).withMessage('Нотўғри тўлов усули')
];

const validateResult = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      message: 'Валидация хатоси', 
      errors: errors.array() 
    });
  }
  next();
};

module.exports = {
  validateRegister,
  validateLogin,
  validateCreateRide,
  validateSearchRide,
  validateBooking,
  validateResult
};`,

  'backend/src/models/User.js': `const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  phone: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    enum: ['driver', 'passenger', 'admin'],
    default: 'passenger'
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  avatar: {
    type: String,
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);`,

  'backend/src/models/Driver.js': `const mongoose = require('mongoose');

const driverSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  carModel: {
    type: String,
    required: true,
    trim: true
  },
  carColor: {
    type: String,
    required: true
  },
  carNumber: {
    type: String,
    required: true,
    unique: true,
    uppercase: true
  },
  licenseNumber: {
    type: String,
    required: true,
    unique: true
  },
  rating: {
    type: Number,
    default: 5,
    min: 1,
    max: 5
  },
  totalRides: {
    type: Number,
    default: 0
  },
  paymentMethods: {
    cash: { type: Boolean, default: true },
    click: { type: Boolean, default: false }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  documents: {
    licensePhoto: String,
    techPassportPhoto: String,
    carPhoto: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Driver', driverSchema);`,

  'backend/src/models/Passenger.js': `const mongoose = require('mongoose');

const passengerSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  rating: {
    type: Number,
    default: 5,
    min: 1,
    max: 5
  },
  totalRides: {
    type: Number,
    default: 0
  },
  preferences: {
    language: { type: String, default: 'uz' },
    notifications: { type: Boolean, default: true }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Passenger', passengerSchema);`,

  'backend/src/models/Ride.js': `const mongoose = require('mongoose');

const rideSchema = new mongoose.Schema({
  driver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Driver',
    required: true
  },
  fromRegion: {
    type: String,
    required: true,
    trim: true
  },
  fromDistrict: {
    type: String,
    required: true,
    trim: true
  },
  toRegion: {
    type: String,
    required: true,
    trim: true
  },
  toDistrict: {
    type: String,
    trim: true
  },
  departureTime: {
    type: Date,
    required: true
  },
  availableSeats: {
    type: Number,
    required: true,
    min: 1,
    max: 6
  },
  pricePerSeat: {
    type: Number,
    required: true,
    min: 1000
  },
  paymentMethods: {
    cash: Boolean,
    click: Boolean
  },
  conditions: {
    maxLuggage: { type: Number, default: 1 },
    noSmoking: { type: Boolean, default: false },
    noMusic: { type: Boolean, default: false },
    petsAllowed: { type: Boolean, default: false },
    childrenAllowed: { type: Boolean, default: true }
  },
  linePrice: {
    type: Number,
    required: true,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  bookedSeats: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    enum: ['active', 'in_progress', 'completed', 'cancelled'],
    default: 'active'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Ride', rideSchema);`,

  'backend/src/models/Booking.js': `const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  passenger: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Passenger',
    required: true
  },
  ride: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Ride',
    required: true
  },
  seats: {
    type: Number,
    required: true,
    min: 1
  },
  totalPrice: {
    type: Number,
    required: true
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'click'],
    required: true
  },
  specialRequests: {
    luggageCount: { type: Number, default: 0 },
    hasChildren: { type: Boolean, default: false },
    notes: String
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'cancelled', 'completed'],
    default: 'pending'
  },
  driverConfirmed: {
    type: Boolean,
    default: false
  },
  passengerPhone: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Booking', bookingSchema);`,

  'backend/src/models/Payment.js': `const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
  booking: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Booking',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  type: {
    type: String,
    enum: ['line_price', 'ride_price'],
    required: true
  },
  method: {
    type: String,
    enum: ['cash', 'click', 'payme'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'refunded'],
    default: 'pending'
  },
  transactionId: {
    type: String,
    unique: true
  },
  driverEarnings: {
    type: Number,
    default: 0
  },
  adminCommission: {
    type: Number,
    default: 0
  },
  completedAt: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Payment', paymentSchema);`,

  'backend/src/controllers/authController.js': `const User = require('../models/User');
const Driver = require('../models/Driver');
const Passenger = require('../models/Passenger');
const jwt = require('jsonwebtoken');

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
};

const register = async (req, res) => {
  try {
    const { phone, password, fullName, role, ...additionalData } = req.body;

    const userExists = await User.findOne({ phone });
    if (userExists) {
      return res.status(400).json({ message: 'Бу телефон рақам аллакачон рўйхатдан ўтган' });
    }

    const user = await User.create({
      phone,
      password,
      fullName,
      role: role || 'passenger'
    });

    if (role === 'driver') {
      await Driver.create({
        user: user._id,
        carModel: additionalData.carModel || '',
        carColor: additionalData.carColor || '',
        carNumber: additionalData.carNumber || '',
        licenseNumber: additionalData.licenseNumber || '',
        paymentMethods: {
          cash: additionalData.paymentMethods?.cash !== undefined ? additionalData.paymentMethods.cash : true,
          click: additionalData.paymentMethods?.click !== undefined ? additionalData.paymentMethods.click : false
        }
      });
    } else {
      await Passenger.create({
        user: user._id
      });
    }

    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        phone: user.phone,
        fullName: user.fullName,
        role: user.role,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Серверда хатолик юз берди', 
      error: error.message 
    });
  }
};

const login = async (req, res) => {
  try {
    const { phone, password } = req.body;

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({ message: 'Телефон рақам ёки парол нотўғри' });
    }

    const isPasswordMatch = await user.comparePassword(password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Телефон рақам ёки парол нотўғри' });
    }

    const token = generateToken(user._id);

    let additionalInfo = {};
    if (user.role === 'driver') {
      const driver = await Driver.findOne({ user: user._id });
      additionalInfo.driver = driver;
    } else if (user.role === 'passenger') {
      const passenger = await Passenger.findOne({ user: user._id });
      additionalInfo.passenger = passenger;
    }

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        phone: user.phone,
        fullName: user.fullName,
        role: user.role,
        isVerified: user.isVerified,
        ...additionalInfo
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Серверда хатолик юз берди', 
      error: error.message 
    });
  }
};

const getMe = async (req, res) => {
  try {
    const user = req.user;
    
    let additionalInfo = {};
    if (user.role === 'driver') {
      const driver = await Driver.findOne({ user: user._id });
      additionalInfo.driver = driver;
    } else if (user.role === 'passenger') {
      const passenger = await Passenger.findOne({ user: user._id });
      additionalInfo.passenger = passenger;
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        phone: user.phone,
        fullName: user.fullName,
        role: user.role,
        isVerified: user.isVerified,
        ...additionalInfo
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Серверда хатолик юз берди', 
      error: error.message 
    });
  }
};

module.exports = {
  register,
  login,
  getMe
};`,

  'backend/src/controllers/rideController.js': `const Ride = require('../models/Ride');
const Driver = require('../models/Driver');

const createRide = async (req, res) => {
  try {
    const driver = await Driver.findOne({ user: req.user._id });
    if (!driver) {
      return res.status(404).json({ message: 'Хайдовчи топилмади' });
    }

    const {
      fromRegion,
      fromDistrict,
      toRegion,
      toDistrict,
      departureTime,
      availableSeats,
      pricePerSeat,
      paymentMethods,
      conditions,
      linePrice
    } = req.body;

    const calculatedLinePrice = calculateLinePrice(fromRegion, toRegion, availableSeats);

    const ride = await Ride.create({
      driver: driver._id,
      fromRegion,
      fromDistrict,
      toRegion,
      toDistrict: toDistrict || '',
      departureTime: new Date(departureTime),
      availableSeats,
      pricePerSeat,
      paymentMethods: {
        cash: paymentMethods?.cash !== undefined ? paymentMethods.cash : true,
        click: paymentMethods?.click !== undefined ? paymentMethods.click : false
      },
      conditions: conditions || {
        maxLuggage: 1,
        noSmoking: false,
        noMusic: false,
        petsAllowed: false,
        childrenAllowed: true
      },
      linePrice: calculatedLinePrice,
      isActive: true,
      bookedSeats: 0,
      status: 'active'
    });

    res.status(201).json({
      success: true,
      ride,
      message: 'Йўналиш муваффақиятли яратилди'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Йўналиш яратишда хатолик', 
      error: error.message 
    });
  }
};

const searchRides = async (req, res) => {
  try {
    const {
      fromRegion,
      fromDistrict,
      toRegion,
      departureDate,
      seats = 1,
      paymentMethod,
      maxPrice
    } = req.query;

    const query = {
      fromRegion,
      toRegion,
      isActive: true,
      status: 'active',
      departureTime: {
        $gte: new Date(\`\${departureDate}T00:00:00\`),
        $lt: new Date(\`\${departureDate}T23:59:59\`)
      },
      availableSeats: { $gte: parseInt(seats) }
    };

    if (fromDistrict && fromDistrict !== 'all') {
      query.fromDistrict = fromDistrict;
    }

    if (paymentMethod === 'cash') {
      query['paymentMethods.cash'] = true;
    } else if (paymentMethod === 'click') {
      query['paymentMethods.click'] = true;
    }

    if (maxPrice) {
      query.pricePerSeat = { $lte: parseInt(maxPrice) };
    }

    const rides = await Ride.find(query)
      .populate({
        path: 'driver',
        populate: {
          path: 'user',
          select: 'fullName phone'
        }
      })
      .sort({ departureTime: 1 });

    res.json({
      success: true,
      count: rides.length,
      rides: rides.map(ride => ({
        id: ride._id,
        driver: {
          id: ride.driver._id,
          name: ride.driver.user.fullName,
          phone: ride.driver.user.phone,
          carModel: ride.driver.carModel,
          carColor: ride.driver.carColor,
          rating: ride.driver.rating
        },
        fromRegion: ride.fromRegion,
        fromDistrict: ride.fromDistrict,
        toRegion: ride.toRegion,
        toDistrict: ride.toDistrict,
        departureTime: ride.departureTime,
        availableSeats: ride.availableSeats,
        pricePerSeat: ride.pricePerSeat,
        paymentMethods: ride.paymentMethods,
        conditions: ride.conditions,
        bookedSeats: ride.bookedSeats
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Йўналишларни излашда хатолик', 
      error: error.message 
    });
  }
};

const getDriverRides = async (req, res) => {
  try {
    const driver = await Driver.findOne({ user: req.user._id });
    if (!driver) {
      return res.status(404).json({ message: 'Хайдовчи топилмади' });
    }

    const rides = await Ride.find({ driver: driver._id })
      .sort({ departureTime: -1 });

    res.json({
      success: true,
      rides
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Йўналишларни олишда хатолик', 
      error: error.message 
    });
  }
};

const updateRide = async (req, res) => {
  try {
    const { id } = req.params;
    const driver = await Driver.findOne({ user: req.user._id });
    
    const ride = await Ride.findOne({ _id: id, driver: driver._id });
    if (!ride) {
      return res.status(404).json({ message: 'Йўналиш топилмади' });
    }

    if (ride.status !== 'active') {
      return res.status(400).json({ message: 'Фақат актив йўналишни янгилаш мумкин' });
    }

    const updatedRide = await Ride.findByIdAndUpdate(
      id,
      { ...req.body, updatedAt: Date.now() },
      { new: true, runValidators: true }
    );

    res.json({
      success: true,
      ride: updatedRide,
      message: 'Йўналиш муваффақиятли янгиланди'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Йўналишни янгилашда хатолик', 
      error: error.message 
    });
  }
};

const cancelRide = async (req, res) => {
  try {
    const { id } = req.params;
    const driver = await Driver.findOne({ user: req.user._id });
    
    const ride = await Ride.findOne({ _id: id, driver: driver._id });
    if (!ride) {
      return res.status(404).json({ message: 'Йўналиш топилмади' });
    }

    if (ride.status !== 'active') {
      return res.status(400).json({ message: 'Фақат актив йўналишни бекор қилиш мумкин' });
    }

    ride.status = 'cancelled';
    ride.isActive = false;
    await ride.save();

    res.json({
      success: true,
      message: 'Йўналиш бекор қилинди'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Йўналишни бекор қилишда хатолик', 
      error: error.message 
    });
  }
};

const calculateLinePrice = (fromRegion, toRegion, seats) => {
  const basePrice = 20000;
  const seatMultiplier = Math.min(seats, 4);
  return basePrice * seatMultiplier;
};

module.exports = {
  createRide,
  searchRides,
  getDriverRides,
  updateRide,
  cancelRide
};`,

  'backend/src/controllers/bookingController.js': `const Booking = require('../models/Booking');
const Ride = require('../models/Ride');
const Passenger = require('../models/Passenger');
const Driver = require('../models/Driver');

const createBooking = async (req, res) => {
  try {
    const passenger = await Passenger.findOne({ user: req.user._id });
    if (!passenger) {
      return res.status(404).json({ message: 'Йўловчи топилмади' });
    }

    const { rideId, seats, paymentMethod, specialRequests } = req.body;

    const ride = await Ride.findById(rideId);
    if (!ride) {
      return res.status(404).json({ message: 'Йўналиш топилмади' });
    }

    if (!ride.isActive || ride.status !== 'active') {
      return res.status(400).json({ message: 'Бу йўналишга брон қилиб бўлмайди' });
    }

    if (seats > ride.availableSeats - ride.bookedSeats) {
      return res.status(400).json({ 
        message: \`Фақат \${ride.availableSeats - ride.bookedSeats} та бўш ўрин бор\` 
      });
    }

    if (paymentMethod === 'cash' && !ride.paymentMethods.cash) {
      return res.status(400).json({ message: 'Хайдовчи нақд пул қабул қилмайди' });
    }
    
    if (paymentMethod === 'click' && !ride.paymentMethods.click) {
      return res.status(400).json({ message: 'Хайдовчи Click қабул қилмайди' });
    }

    if (specialRequests?.luggageCount > ride.conditions.maxLuggage) {
      return res.status(400).json({ 
        message: \`Максимум \${ride.conditions.maxLuggage} та сумка олиш мумкин\` 
      });
    }

    if (specialRequests?.hasChildren && !ride.conditions.childrenAllowed) {
      return res.status(400).json({ message: 'Хайдовчи болаларни олишни рад қилади' });
    }

    const totalPrice = seats * ride.pricePerSeat;

    const booking = await Booking.create({
      passenger: passenger._id,
      ride: ride._id,
      seats,
      totalPrice,
      paymentMethod,
      specialRequests: specialRequests || {},
      passengerPhone: req.user.phone
    });

    ride.bookedSeats += seats;
    if (ride.bookedSeats === ride.availableSeats) {
      ride.isActive = false;
    }
    await ride.save();

    res.status(201).json({
      success: true,
      booking: {
        id: booking._id,
        rideId: booking.ride,
        seats: booking.seats,
        totalPrice: booking.totalPrice,
        paymentMethod: booking.paymentMethod,
        status: booking.status,
        createdAt: booking.createdAt
      },
      message: 'Брон муваффақиятли амалга оширилди'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Брон қилишда хатолик', 
      error: error.message 
    });
  }
};

const getDriverBookings = async (req, res) => {
  try {
    const driver = await Driver.findOne({ user: req.user._id });
    if (!driver) {
      return res.status(404).json({ message: 'Хайдовчи топилмади' });
    }

    const rides = await Ride.find({ driver: driver._id });
    const rideIds = rides.map(ride => ride._id);

    const bookings = await Booking.find({ ride: { $in: rideIds } })
      .populate({
        path: 'passenger',
        populate: {
          path: 'user',
          select: 'fullName phone'
        }
      })
      .populate('ride')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      bookings: bookings.map(booking => ({
        id: booking._id,
        passenger: {
          name: booking.passenger.user.fullName,
          phone: booking.passenger.user.phone,
          rating: booking.passenger.rating
        },
        ride: {
          fromRegion: booking.ride.fromRegion,
          fromDistrict: booking.ride.fromDistrict,
          toRegion: booking.ride.toRegion,
          departureTime: booking.ride.departureTime
        },
        seats: booking.seats,
        totalPrice: booking.totalPrice,
        paymentMethod: booking.paymentMethod,
        status: booking.status,
        driverConfirmed: booking.driverConfirmed,
        specialRequests: booking.specialRequests,
        createdAt: booking.createdAt
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Бронларни олишда хатолик', 
      error: error.message 
    });
  }
};

const getPassengerBookings = async (req, res) => {
  try {
    const passenger = await Passenger.findOne({ user: req.user._id });
    if (!passenger) {
      return res.status(404).json({ message: 'Йўловчи топилмади' });
    }

    const bookings = await Booking.find({ passenger: passenger._id })
      .populate({
        path: 'ride',
        populate: {
          path: 'driver',
          populate: {
            path: 'user',
            select: 'fullName phone'
          }
        }
      })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      bookings: bookings.map(booking => ({
        id: booking._id,
        driver: {
          name: booking.ride.driver.user.fullName,
          phone: booking.ride.driver.user.phone,
          carModel: booking.ride.driver.carModel,
          carColor: booking.ride.driver.carColor,
          rating: booking.ride.driver.rating
        },
        ride: {
          fromRegion: booking.ride.fromRegion,
          fromDistrict: booking.ride.fromDistrict,
          toRegion: booking.ride.toRegion,
          toDistrict: booking.ride.toDistrict,
          departureTime: booking.ride.departureTime,
          pricePerSeat: booking.ride.pricePerSeat
        },
        seats: booking.seats,
        totalPrice: booking.totalPrice,
        paymentMethod: booking.paymentMethod,
        status: booking.status,
        driverConfirmed: booking.driverConfirmed,
        specialRequests: booking.specialRequests,
        createdAt: booking.createdAt
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Бронларни олишда хатолик', 
      error: error.message 
    });
  }
};

const confirmBooking = async (req, res) => {
  try {
    const { bookingId } = req.params;
    const driver = await Driver.findOne({ user: req.user._id });
    
    const booking = await Booking.findById(bookingId)
      .populate('ride');
    
    if (!booking) {
      return res.status(404).json({ message: 'Брон топилмади' });
    }

    if (booking.ride.driver.toString() !== driver._id.toString()) {
      return res.status(403).json({ message: 'Бу брон сизнинг йўналишингизга эмас' });
    }

    if (booking.status !== 'pending') {
      return res.status(400).json({ message: 'Бу брон аллакачон тасдиқланган ёки бекор қилинган' });
    }

    booking.status = 'confirmed';
    booking.driverConfirmed = true;
    await booking.save();

    res.json({
      success: true,
      message: 'Брон муваффақиятли тасдиқланди'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Бронни тасдиқлашда хатолик', 
      error: error.message 
    });
  }
};

const cancelBooking = async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { reason } = req.body;

    const passenger = await Passenger.findOne({ user: req.user._id });
    
    const booking = await Booking.findById(bookingId)
      .populate('ride');
    
    if (!booking) {
      return res.status(404).json({ message: 'Брон топилмади' });
    }

    if (booking.passenger.toString() !== passenger._id.toString()) {
      return res.status(403).json({ message: 'Фақат ўз бронларингизни бекор қилишингиз мумкин' });
    }

    if (!['pending', 'confirmed'].includes(booking.status)) {
      return res.status(400).json({ message: 'Бу бронни бекор қилиб бўлмайди' });
    }

    const ride = await Ride.findById(booking.ride);
    if (ride) {
      ride.bookedSeats -= booking.seats;
      if (!ride.isActive && ride.bookedSeats < ride.availableSeats) {
        ride.isActive = true;
      }
      await ride.save();
    }

    booking.status = 'cancelled';
    booking.cancellationReason = reason || 'Йўловчи томонидан бекор қилинди';
    await booking.save();

    res.json({
      success: true,
      message: 'Брон муваффақиятли бекор қилинди'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Бронни бекор қилишда хатолик', 
      error: error.message 
    });
  }
};

module.exports = {
  createBooking,
  getDriverBookings,
  getPassengerBookings,
  confirmBooking,
  cancelBooking
};`,

  'backend/src/controllers/adminController.js': `const User = require('../models/User');
const Driver = require('../models/Driver');
const Ride = require('../models/Ride');
const Booking = require('../models/Booking');
const Payment = require('../models/Payment');

const getStats = async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const totalUsers = await User.countDocuments();
    const totalDrivers = await Driver.countDocuments();
    const totalRides = await Ride.countDocuments();
    const totalBookings = await Booking.countDocuments();
    const totalRevenue = await Payment.aggregate([
      { $match: { status: 'completed', type: 'line_price' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    const todayRides = await Ride.countDocuments({
      createdAt: { $gte: today, $lt: tomorrow }
    });
    
    const todayBookings = await Booking.countDocuments({
      createdAt: { $gte: today, $lt: tomorrow }
    });
    
    const todayRevenue = await Payment.aggregate([
      { 
        $match: { 
          status: 'completed', 
          type: 'line_price',
          createdAt: { $gte: today, $lt: tomorrow }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.json({
      success: true,
      stats: {
        total: {
          users: totalUsers,
          drivers: totalDrivers,
          rides: totalRides,
          bookings: totalBookings,
          revenue: totalRevenue[0]?.total || 0
        },
        today: {
          rides: todayRides,
          bookings: todayBookings,
          revenue: todayRevenue[0]?.total || 0
        }
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Статистикани олишда хатолик', 
      error: error.message 
    });
  }
};

const getAllUsers = async (req, res) => {
  try {
    const { role, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (role) {
      query.role = role;
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Фойдаланувчиларни олишда хатолик', 
      error: error.message 
    });
  }
};

const getAllDrivers = async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    }

    const drivers = await Driver.find(query)
      .populate({
        path: 'user',
        select: 'phone fullName createdAt'
      })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Driver.countDocuments(query);

    res.json({
      success: true,
      drivers: drivers.map(driver => ({
        id: driver._id,
        user: driver.user,
        carModel: driver.carModel,
        carColor: driver.carColor,
        carNumber: driver.carNumber,
        rating: driver.rating,
        totalRides: driver.totalRides,
        paymentMethods: driver.paymentMethods,
        isActive: driver.isActive,
        createdAt: driver.createdAt
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Хайдовчиларни олишда хатолик', 
      error: error.message 
    });
  }
};

const getAllRides = async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status) {
      query.status = status;
    }

    const rides = await Ride.find(query)
      .populate({
        path: 'driver',
        populate: {
          path: 'user',
          select: 'fullName phone'
        }
      })
      .sort({ departureTime: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Ride.countDocuments(query);

    res.json({
      success: true,
      rides: rides.map(ride => ({
        id: ride._id,
        driver: {
          name: ride.driver.user.fullName,
          phone: ride.driver.user.phone,
          carModel: ride.driver.carModel
        },
        fromRegion: ride.fromRegion,
        fromDistrict: ride.fromDistrict,
        toRegion: ride.toRegion,
        toDistrict: ride.toDistrict,
        departureTime: ride.departureTime,
        availableSeats: ride.availableSeats,
        bookedSeats: ride.bookedSeats,
        pricePerSeat: ride.pricePerSeat,
        linePrice: ride.linePrice,
        status: ride.status,
        isActive: ride.isActive,
        createdAt: ride.createdAt
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Йўналишларни олишда хатолик', 
      error: error.message 
    });
  }
};

const getAllBookings = async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status) {
      query.status = status;
    }

    const bookings = await Booking.find(query)
      .populate({
        path: 'passenger',
        populate: {
          path: 'user',
          select: 'fullName phone'
        }
      })
      .populate({
        path: 'ride',
        populate: {
          path: 'driver',
          populate: {
            path: 'user',
            select: 'fullName phone'
          }
        }
      })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Booking.countDocuments(query);

    res.json({
      success: true,
      bookings: bookings.map(booking => ({
        id: booking._id,
        passenger: {
          name: booking.passenger.user.fullName,
          phone: booking.passenger.user.phone
        },
        driver: {
          name: booking.ride.driver.user.fullName,
          phone: booking.ride.driver.user.phone
        },
        ride: {
          fromRegion: booking.ride.fromRegion,
          toRegion: booking.ride.toRegion,
          departureTime: booking.ride.departureTime
        },
        seats: booking.seats,
        totalPrice: booking.totalPrice,
        paymentMethod: booking.paymentMethod,
        status: booking.status,
        driverConfirmed: booking.driverConfirmed,
        createdAt: booking.createdAt
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Бронларни олишда хатолик', 
      error: error.message 
    });
  }
};

const toggleUserBlock = async (req, res) => {
  try {
    const { userId } = req.params;
    const { isBlocked, reason } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Фойдаланувчи топилмади' });
    }

    if (user.role === 'admin') {
      return res.status(403).json({ message: 'Админни блоклаш мумкин эмас' });
    }

    user.isBlocked = isBlocked !== undefined ? isBlocked : !user.isBlocked;
    user.blockReason = reason || '';
    await user.save();

    res.json({
      success: true,
      message: \`Фойдаланувчи \${user.isBlocked ? 'блокланди' : 'блокдан чиқарилди'}\`,
      user: {
        id: user._id,
        phone: user.phone,
        fullName: user.fullName,
        role: user.role,
        isBlocked: user.isBlocked,
        blockReason: user.blockReason
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Фойдаланувчини блоклашда хатолик', 
      error: error.message 
    });
  }
};

const verifyDriver = async (req, res) => {
  try {
    const { driverId } = req.params;
    const { isVerified } = req.body;

    const driver = await Driver.findById(driverId)
      .populate('user');
    
    if (!driver) {
      return res.status(404).json({ message: 'Хайдовчи топилмади' });
    }

    driver.isVerified = isVerified !== undefined ? isVerified : true;
    await driver.save();

    res.json({
      success: true,
      message: \`Хайдовчи \${driver.isVerified ? 'тасдиқланди' : 'тасдиқдан чиқарилди'}\`,
      driver: {
        id: driver._id,
        user: driver.user,
        carModel: driver.carModel,
        carNumber: driver.carNumber,
        isVerified: driver.isVerified
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ 
      message: 'Хайдовчини тасдиқлашда хатолик', 
      error: error.message 
    });
  }
};

module.exports = {
  getStats,
  getAllUsers,
  getAllDrivers,
  getAllRides,
  getAllBookings,
  toggleUserBlock,
  verifyDriver
};`,

  'backend/src/routes/auth.js': `const express = require('express');
const router = express.Router();
const { 
  register, 
  login, 
  getMe 
} = require('../controllers/authController');
const { protect } = require('../middleware/auth');
const { 
  validateRegister, 
  validateLogin, 
  validateResult 
} = require('../middleware/validation');

router.post('/register', validateRegister, validateResult, register);
router.post('/login', validateLogin, validateResult, login);
router.get('/me', protect, getMe);

module.exports = router;`,

  'backend/src/routes/ride.js': `const express = require('express');
const router = express.Router();
const { 
  createRide, 
  searchRides, 
  getDriverRides,
  updateRide,
  cancelRide 
} = require('../controllers/rideController');
const { protect, authorize } = require('../middleware/auth');
const { 
  validateCreateRide, 
  validateSearchRide,
  validateResult 
} = require('../middleware/validation');

router.post(
  '/', 
  protect, 
  authorize('driver'), 
  validateCreateRide, 
  validateResult, 
  createRide
);

router.get(
  '/search', 
  validateSearchRide, 
  validateResult, 
  searchRides
);

router.get(
  '/driver', 
  protect, 
  authorize('driver'), 
  getDriverRides
);

router.put(
  '/:id', 
  protect, 
  authorize('driver'), 
  updateRide
);

router.delete(
  '/:id', 
  protect, 
  authorize('driver'), 
  cancelRide
);

module.exports = router;`,

  'backend/src/routes/booking.js': `const express = require('express');
const router = express.Router();
const { 
  createBooking, 
  getDriverBookings, 
  getPassengerBookings,
  confirmBooking,
  cancelBooking 
} = require('../controllers/bookingController');
const { protect, authorize } = require('../middleware/auth');
const { 
  validateBooking, 
  validateResult 
} = require('../middleware/validation');

router.post(
  '/', 
  protect, 
  authorize('passenger'), 
  validateBooking, 
  validateResult, 
  createBooking
);

router.get(
  '/driver', 
  protect, 
  authorize('driver'), 
  getDriverBookings
);

router.get(
  '/passenger', 
  protect, 
  authorize('passenger'), 
  getPassengerBookings
);

router.put(
  '/:bookingId/confirm', 
  protect, 
  authorize('driver'), 
  confirmBooking
);

router.delete(
  '/:bookingId', 
  protect, 
  authorize('passenger'), 
  cancelBooking
);

module.exports = router;`,

  'backend/src/routes/admin.js': `const express = require('express');
const router = express.Router();
const { 
  getStats,
  getAllUsers,
  getAllDrivers,
  getAllRides,
  getAllBookings,
  toggleUserBlock,
  verifyDriver
} = require('../controllers/adminController');
const { protect, authorize } = require('../middleware/auth');

router.use(protect);
router.use(authorize('admin'));

router.get('/stats', getStats);
router.get('/users', getAllUsers);
router.get('/drivers', getAllDrivers);
router.get('/rides', getAllRides);
router.get('/bookings', getAllBookings);
router.put('/users/:userId/block', toggleUserBlock);
router.put('/drivers/:driverId/verify', verifyDriver);

module.exports = router;`,

  'backend/src/utils/constants.js': `const REGIONS = [
  'Тошкент шаҳри',
  'Тошкент вилояти',
  'Самарқанд вилояти',
  'Фарғона вилояти',
  'Андижон вилояти',
  'Наманган вилояти',
  'Бухоро вилояти',
  'Хоразм вилояти',
  'Қашқадарё вилояти',
  'Сурхондарё вилояти',
  'Жиззах вилояти',
  'Сирдарё вилояти',
  'Навоий вилояти'
];

const DISTRICTS_BY_REGION = {
  'Тошкент шаҳри': [
    'Олмазор тумани',
    'Бектемир тумани',
    'Мирзо Улуғбек тумани',
    'Миробод тумани',
    'Сергели тумани',
    'Чилонзор тумани',
    'Шайхонтоҳур тумани',
    'Юнусобод тумани',
    'Яккасарой тумани',
    'Яшнобод тумани'
  ],
  'Тошкент вилояти': [
    'Олмалиқ',
    'Ангрен',
    'Бекобод',
    'Бўка',
    'Бўстонлиқ',
    'Зангиота',
    'Қибрай',
    'Қуйичирчиқ',
    'Оққўрғон',
    'Оҳангарон',
    'Паркент',
    'Пискент',
    'Қуйичирчиқ',
    'Тошкент тумани',
    'Уртачирчиқ',
    'Чиноз',
    'Янгийўл',
    'Янгиобод'
  ],
  'Самарқанд вилояти': [
    'Самарқанд',
    'Булунғур',
    'Иштихон',
    'Жомбой',
    'Каттақўрғон',
    'Қўшработ',
    'Нарпай',
    'Нурабо',
    'Пайариқ',
    'Пастдарғом',
    'Пахтачи',
    'Тайлоқ',
    'Тойлоқ',
    'Ургут'
  ],
  'Фарғона вилояти': [
    'Фарғона',
    'Бешариқ',
    'Бўғдибозор',
    'Данғара',
    'Ёзёвон',
    'Қува',
    'Қувасой',
    'Олтиариқ',
    'Риштон',
    'Сўх',
    'Тошлоқ',
    'Учкўприк',
    'Ўзбекистон'
  ],
  'Андижон вилояти': [
    'Андижон',
    'Асака',
    'Балиқчи',
    'Бўз',
    'Булоқбоши',
    'Избоскан',
    'Жалақудуқ',
    'Қўрғонтепа',
    'Марҳамат',
    'Олтинкўл',
    'Пахтаобод',
    'Улуғнор',
    'Хўжаобод',
    'Шахрихон'
  ],
  'Наманган вилояти': [
    'Наманган',
    'Косонсой',
    'Мингбулоқ',
    'Норин',
    'Поп',
    'Тўрақўрғон',
    'Уйчи',
    'Учқўрғон',
    'Чортоқ',
    'Чуст',
    'Янгиқўрғон'
  ],
  'Бухоро вилояти': [
    'Бухоро',
    'Вобкент',
    'Жондор',
    'Ғиждувон',
    'Қоракўл',
    'Қоровулбозор',
    'Олот',
    'Пешку',
    'Ромитан',
    'Шофиркон'
  ],
  'Хоразм вилояти': [
    'Урганч',
    'Боғот',
    'Ғурлен',
    'Қўшкўпир',
    'Шовот',
    'Янгиариқ',
    'Янгибозор',
    'Хива',
    'Хонка',
    'Ҳазорасп'
  ],
  'Қашқадарё вилояти': [
    'Қарши',
    'Гузор',
    'Деҳқонобод',
    'Қамаши',
    'Қарши тумани',
    'Косон',
    'Китоб',
    'Миришкор',
    'Муборак',
    'Нишон',
    'Чироқчи',
    'Шахрисабз',
    'Яккабоғ'
  ],
  'Сурхондарё вилояти': [
    'Термиз',
    'Ангор',
    'Бандихон',
    'Бойсун',
    'Денов',
    'Жарқўрғон',
    'Қизириқ',
    'Қумқўрғон',
    'Музработ',
    'Олтинсой',
    'Сариосиё',
    'Термиз тумани',
    'Узун',
    'Шеробод',
    'Шўрчи',
    'Қизилтепа'
  ],
  'Жиззах вилояти': [
    'Жиззах',
    'Арнасой',
    'Бахмал',
    'Галлаорол',
    'Дўстлик',
    'Зомин',
    'Зафаробод',
    'Мирзачўл',
    'Пахтакор',
    'Фориш',
    'Янгиобод'
  ],
  'Сирдарё вилояти': [
    'Гулистон',
    'Боёвут',
    'Гулистон тумани',
    'Мирзаобод',
    'Оқолтин',
    'Сардоба',
    'Сайхунобод',
    'Сирдарё',
    'Ховос'
  ],
  'Навоий вилояти': [
    'Навоий',
    'Зарафшон',
    'Кармана',
    'Қизилтепа',
    'Конимех',
    'Навбаҳор',
    'Нурота',
    'Томди',
    'Учқудуқ'
  ]
};

const LINE_PRICES = {
  SHORT: 15000,
  MEDIUM: 25000,
  LONG: 35000,
  VERY_LONG: 45000,
  EXTREME: 55000
};

const RIDE_STATUS = {
  ACTIVE: 'active',
  IN_PROGRESS: 'in_progress',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled'
};

const BOOKING_STATUS = {
  PENDING: 'pending',
  CONFIRMED: 'confirmed',
  CANCELLED: 'cancelled',
  COMPLETED: 'completed'
};

const PAYMENT_STATUS = {
  PENDING: 'pending',
  COMPLETED: 'completed',
  FAILED: 'failed',
  REFUNDED: 'refunded'
};

const PAYMENT_METHODS = {
  CASH: 'cash',
  CLICK: 'click',
  PAYME: 'payme'
};

module.exports = {
  REGIONS,
  DISTRICTS_BY_REGION,
  LINE_PRICES,
  RIDE_STATUS,
  BOOKING_STATUS,
  PAYMENT_STATUS,
  PAYMENT_METHODS
};`,

  'backend/src/utils/helpers.js': `const { DISTRICTS_BY_REGION } = require('./constants');

const formatPhoneNumber = (phone) => {
  if (!phone) return '';
  const cleaned = phone.replace(/\\D/g, '');
  if (cleaned.length === 12 && cleaned.startsWith('998')) {
    return \`+\${cleaned}\`;
  } else if (cleaned.length === 9) {
    return \`+998\${cleaned}\`;
  }
  return phone;
};

const formatDate = (date, format = 'dd.MM.yyyy HH:mm') => {
  const d = new Date(date);
  
  const day = d.getDate().toString().padStart(2, '0');
  const month = (d.getMonth() + 1).toString().padStart(2, '0');
  const year = d.getFullYear();
  const hours = d.getHours().toString().padStart(2, '0');
  const minutes = d.getMinutes().toString().padStart(2, '0');
  
  return format
    .replace('dd', day)
    .replace('MM', month)
    .replace('yyyy', year)
    .replace('HH', hours)
    .replace('mm', minutes);
};

const calculateDistance = (fromRegion, toRegion) => {
  const regionDistances = {
    'Тошкент шаҳри': {
      'Самарқанд вилояти': 300,
      'Фарғона вилояти': 350,
      'Бухоро вилояти': 600,
      'Қашқадарё вилояти': 700,
      'Сурхондарё вилояти': 900
    },
    'Самарқанд вилояти': {
      'Тошкент шаҳри': 300,
      'Бухоро вилояти': 280,
      'Қашқадарё вилояти': 400,
      'Сурхондарё вилояти': 600
    },
    'Фарғона вилояти': {
      'Тошкент шаҳри': 350,
      'Андижон вилояти': 50,
      'Наманган вилояти': 70
    },
    'Бухоро вилояти': {
      'Тошкент шаҳри': 600,
      'Самарқанд вилояти': 280,
      'Хоразм вилояти': 450
    }
  };
  
  return regionDistances[fromRegion]?.[toRegion] || 200;
};

const calculateLinePrice = (fromRegion, toRegion, seats) => {
  const distance = calculateDistance(fromRegion, toRegion);
  let basePrice;
  
  if (distance <= 100) basePrice = 15000;
  else if (distance <= 200) basePrice = 25000;
  else if (distance <= 300) basePrice = 35000;
  else if (distance <= 400) basePrice = 45000;
  else basePrice = 55000;
  
  const seatMultiplier = Math.min(seats, 4);
  
  return basePrice * seatMultiplier;
};

const getMonthNameUz = (monthIndex) => {
  const months = [
    'Январ', 'Феврал', 'Март', 'Апрел',
    'Май', 'Июн', 'Июл', 'Август',
    'Сентябр', 'Октябр', 'Ноябр', 'Декабр'
  ];
  return months[monthIndex];
};

const getDayNameUz = (dayIndex) => {
  const days = [
    'Якшанба', 'Душанба', 'Сешанба', 'Чоршанба',
    'Пайшанба', 'Жума', 'Шанба'
  ];
  return days[dayIndex];
};

const formatPrice = (price) => {
  return new Intl.NumberFormat('uz-UZ', {
    style: 'decimal',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  }).format(price) + ' сўм';
};

const getDistrictsByRegion = (region) => {
  return DISTRICTS_BY_REGION[region] || [];
};

const generateRandomId = (length = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

module.exports = {
  formatPhoneNumber,
  formatDate,
  calculateDistance,
  calculateLinePrice,
  getMonthNameUz,
  getDayNameUz,
  formatPrice,
  getDistrictsByRegion,
  generateRandomId
};`,

  'backend/src/app.js': `const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const rideRoutes = require('./routes/ride');
const bookingRoutes = require('./routes/booking');
const adminRoutes = require('./routes/admin');

const app = express();

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());
app.use('/uploads', express.static('uploads'));

app.use('/api/auth', authRoutes);
app.use('/api/rides', rideRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/admin', adminRoutes);

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'UZOQTAXI API'
  });
});

app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Бундай API йўли мавжуд эмас'
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Ички сервер хатолиги';
  
  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

module.exports = app;`,

  'backend/server.js': `require('dotenv').config();
const app = require('./src/app');
const connectDB = require('./src/config/database');

const PORT = process.env.PORT || 5000;

connectDB();

const createAdminUser = async () => {
  const User = require('./src/models/User');
  
  const adminExists = await User.findOne({ 
    phone: process.env.ADMIN_PHONE || '998901234567',
    role: 'admin' 
  });
  
  if (!adminExists) {
    await User.create({
      phone: process.env.ADMIN_PHONE || '998901234567',
      password: process.env.ADMIN_PASSWORD || 'admin123',
      fullName: 'Администратор',
      role: 'admin',
      isVerified: true
    });
    console.log('Администратор аккаунти яратилди');
  }
};

const server = app.listen(PORT, async () => {
  console.log(\`🚀 Сервер \${PORT} портда ишга тушибди\`);
  console.log(\`📍 Режим: \${process.env.NODE_ENV}\`);
  
  await createAdminUser();
});

process.on('SIGTERM', () => {
  console.log('SIGTERM сигнали олинди. Серверни тўхтатиш...');
  server.close(() => {
    console.log('Сервер тўхтатилди');
    process.exit(0);
  });
});

process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Сервер тўхтатилди');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});`,

  'backend/package.json': `{
  "name": "uzoqtaxi-backend",
  "version": "1.0.0",
  "description": "UZOQTAXI - Вилоятлар аро такси хизмати",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "prod": "NODE_ENV=production node server.js",
    "test": "jest",
    "lint": "eslint .",
    "seed": "node src/seeds/seed.js"
  },
  "keywords": ["taxi", "uzbekistan", "intercity", "ride-sharing"],
  "author": "UZOQTAXI Team",
  "license": "MIT",
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "express-rate-limit": "^6.7.0",
    "express-validator": "^6.14.3",
    "helmet": "^6.1.5",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^6.9.1",
    "morgan": "^1.10.0"
  },
  "devDependencies": {
    "eslint": "^8.36.0",
    "jest": "^29.5.0",
    "nodemon": "^2.0.21",
    "supertest": "^6.3.3"
  }
}`,

  'frontend/public/index.html': `<!DOCTYPE html>
<html lang="uz">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>UZOQTAXI - Вилоятлар аро такси хизмати</title>
  <meta name="description" content="Вилоятлар аро такси катнови учун ишончли платформа">
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.jsx"></script>
</body>
</html>`,

  'frontend/src/components/common/Header.jsx': `import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="bg-white shadow-md">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Link to="/" className="text-2xl font-bold text-blue-600">
              UZOQTAXI
            </Link>
            <nav className="hidden md:flex space-x-4">
              <Link to="/" className="text-gray-700 hover:text-blue-600">
                Бош саҳифа
              </Link>
              <Link to="/search" className="text-gray-700 hover:text-blue-600">
                Такси излаш
              </Link>
              {user && (
                <>
                  <Link 
                    to={user.role === 'driver' ? '/driver/dashboard' : '/passenger/dashboard'} 
                    className="text-gray-700 hover:text-blue-600"
                  >
                    Дашборд
                  </Link>
                  {user.role === 'admin' && (
                    <Link to="/admin" className="text-gray-700 hover:text-blue-600">
                      Админ
                    </Link>
                  )}
                </>
              )}
            </nav>
          </div>

          <div className="flex items-center space-x-4">
            {user ? (
              <div className="flex items-center space-x-4">
                <span className="text-gray-700">
                  {user.fullName} ({user.role})
                </span>
                <button
                  onClick={logout}
                  className="btn btn-secondary"
                >
                  Чиқиш
                </button>
              </div>
            ) : (
              <div className="flex space-x-2">
                <Link to="/login" className="btn btn-secondary">
                  Кириш
                </Link>
                <Link to="/register" className="btn btn-primary">
                  Рўйхатдан ўтиш
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;`,

  'frontend/src/components/common/Footer.jsx': `const Footer = () => {
  return (
    <footer className="bg-gray-800 text-white mt-12">
      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h3 className="text-xl font-bold mb-4">UZOQTAXI</h3>
            <p className="text-gray-300">
              Вилоятлар аро такси катнови учун ишончли ва қулай платформа.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-4">Қўлланма</h4>
            <ul className="space-y-2">
              <li><a href="#" className="text-gray-300 hover:text-white">Фойдаланиш қоидалари</a></li>
              <li><a href="#" className="text-gray-300 hover:text-white">Хавфсизлик</a></li>
              <li><a href="#" className="text-gray-300 hover:text-white">Ёрдам</a></li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-4">Боғланиш</h4>
            <ul className="space-y-2">
              <li className="text-gray-300">Телефон: +998 90 123 45 67</li>
              <li className="text-gray-300">Email: info@uzoqtaxi.uz</li>
              <li className="text-gray-300">Телеграм: @uzoqtaxi_support</li>
            </ul>
          </div>
        </div>
        
        <div className="border-t border-gray-700 mt-8 pt-8 text-center text-gray-400">
          <p>© 2024 UZOQTAXI. Барча ҳуқуқлар ҳимояланган.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;`,

  'frontend/src/components/auth/Login.jsx': `import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const Login = () => {
  const [formData, setFormData] = useState({
    phone: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const result = await login(formData.phone, formData.password);
    
    if (result.success) {
      toast.success('Муваффақиятли кирилди!');
      navigate(result.user.role === 'driver' ? '/driver/dashboard' : '/passenger/dashboard');
    } else {
      toast.error(result.message || 'Хатолик юз берди');
    }
    
    setLoading(false);
  };

  return (
    <div className="max-w-md mx-auto">
      <div className="card">
        <h2 className="text-2xl font-bold mb-6 text-center">Кириш</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Телефон рақам
            </label>
            <input
              type="tel"
              name="phone"
              value={formData.phone}
              onChange={handleChange}
              placeholder="998901234567"
              className="input"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Парол
            </label>
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Паролни киритинг"
              className="input"
              required
            />
          </div>
          
          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary w-full"
          >
            {loading ? 'Кирилмоқда...' : 'Кириш'}
          </button>
        </form>
        
        <div className="mt-6 text-center">
          <p className="text-gray-600">
            Акаунтингиз йўқми?{' '}
            <Link to="/register" className="text-blue-600 hover:underline">
              Рўйхатдан ўтинг
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;`,

  'frontend/src/components/auth/Register.jsx': `import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const Register = () => {
  const [formData, setFormData] = useState({
    phone: '',
    password: '',
    fullName: '',
    role: 'passenger',
    carModel: '',
    carColor: '',
    carNumber: '',
    licenseNumber: '',
    paymentMethods: {
      cash: true,
      click: false
    }
  });
  
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    if (name.startsWith('paymentMethods.')) {
      const method = name.split('.')[1];
      setFormData(prev => ({
        ...prev,
        paymentMethods: {
          ...prev.paymentMethods,
          [method]: checked
        }
      }));
    } else if (type === 'checkbox') {
      setFormData(prev => ({
        ...prev,
        [name]: checked
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: value
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const result = await register(formData);
    
    if (result.success) {
      toast.success('Муваффақиятли рўйхатдан ўтилди!');
      navigate(result.user.role === 'driver' ? '/driver/dashboard' : '/passenger/dashboard');
    } else {
      toast.error(result.message || 'Хатолик юз берди');
    }
    
    setLoading(false);
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="card">
        <h2 className="text-2xl font-bold mb-6 text-center">Рўйхатдан ўтиш</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Телефон рақам *
              </label>
              <input
                type="tel"
                name="phone"
                value={formData.phone}
                onChange={handleChange}
                placeholder="998901234567"
                className="input"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Исмингиз *
              </label>
              <input
                type="text"
                name="fullName"
                value={formData.fullName}
                onChange={handleChange}
                placeholder="Алишер Алишеров"
                className="input"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Парол *
              </label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="Камида 6 та белги"
                className="input"
                required
                minLength="6"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Сиз кимсиз? *
              </label>
              <select
                name="role"
                value={formData.role}
                onChange={handleChange}
                className="input"
              >
                <option value="passenger">Йўловчи</option>
                <option value="driver">Хайдовчи</option>
              </select>
            </div>
          </div>

          {formData.role === 'driver' && (
            <>
              <div className="border-t pt-4 mt-4">
                <h3 className="text-lg font-semibold mb-4">Хайдовчи маълумотлари</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Автомобил модели *
                    </label>
                    <input
                      type="text"
                      name="carModel"
                      value={formData.carModel}
                      onChange={handleChange}
                      placeholder="Nexia 3, Gentra..."
                      className="input"
                      required
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Автомобил ранг *
                    </label>
                    <input
                      type="text"
                      name="carColor"
                      value={formData.carColor}
                      onChange={handleChange}
                      placeholder="Оқ, кара, кўк..."
                      className="input"
                      required
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Автомобил рақами *
                    </label>
                    <input
                      type="text"
                      name="carNumber"
                      value={formData.carNumber}
                      onChange={handleChange}
                      placeholder="01A123AA"
                      className="input uppercase"
                      required
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Гувоҳнома рақами *
                    </label>
                    <input
                      type="text"
                      name="licenseNumber"
                      value={formData.licenseNumber}
                      onChange={handleChange}
                      placeholder="AB1234567"
                      className="input"
                      required
                    />
                  </div>
                </div>
                
                <div className="mt-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Тўлов усуллари
                  </label>
                  <div className="flex space-x-4">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        name="paymentMethods.cash"
                        checked={formData.paymentMethods.cash}
                        onChange={handleChange}
                        className="mr-2"
                      />
                      <span>Нақд пул</span>
                    </label>
                    
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        name="paymentMethods.click"
                        checked={formData.paymentMethods.click}
                        onChange={handleChange}
                        className="mr-2"
                      />
                      <span>Click/Payme</span>
                    </label>
                  </div>
                </div>
              </div>
            </>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary w-full mt-6"
          >
            {loading ? 'Рўйхатдан ўтилмоқда...' : 'Рўйхатдан ўтиш'}
          </button>
        </form>
        
        <div className="mt-6 text-center">
          <p className="text-gray-600">
            Аллакачон акаунтингиз борми?{' '}
            <Link to="/login" className="text-blue-600 hover:underline">
              Кириш
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;`,

  'frontend/src/components/driver/CreateRide.jsx': `import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const CreateRide = () => {
  const { api } = useAuth();
  const navigate = useNavigate();
  
  const [formData, setFormData] = useState({
    fromRegion: '',
    fromDistrict: '',
    toRegion: '',
    toDistrict: '',
    departureTime: '',
    availableSeats: 4,
    pricePerSeat: '',
    paymentMethods: {
      cash: true,
      click: false
    },
    conditions: {
      maxLuggage: 1,
      noSmoking: false,
      noMusic: false,
      petsAllowed: false,
      childrenAllowed: true
    }
  });
  
  const [loading, setLoading] = useState(false);

  // Вилоятлар рўйхати
  const regions = [
    'Тошкент шаҳри',
    'Тошкент вилояти',
    'Самарқанд вилояти',
    'Фарғона вилояти',
    'Андижон вилояти',
    'Наманган вилояти',
    'Бухоро вилояти',
    'Хоразм вилояти',
    'Қашқадарё вилояти',
    'Сурхондарё вилояти',
    'Жиззах вилояти',
    'Сирдарё вилояти',
    'Навоий вилояти'
  ];

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    if (name.startsWith('paymentMethods.')) {
      const method = name.split('.')[1];
      setFormData(prev => ({
        ...prev,
        paymentMethods: {
          ...prev.paymentMethods,
          [method]: checked
        }
      }));
    } else if (name.startsWith('conditions.')) {
      const condition = name.split('.')[1];
      setFormData(prev => ({
        ...prev,
        conditions: {
          ...prev.conditions,
          [condition]: type === 'checkbox' ? checked : value
        }
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      // Линия нархини ҳисоблаш
      const linePriceResponse = await api.post('/rides/calculate-line-price', {
        fromRegion: formData.fromRegion,
        toRegion: formData.toRegion,
        seats: formData.availableSeats
      });

      const rideData = {
        ...formData,
        linePrice: linePriceResponse.data.linePrice
      };

      const response = await api.post('/rides', rideData);
      
      if (response.data.success) {
        toast.success('Йўналиш муваффақиятли яратилди!');
        navigate('/driver/dashboard');
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Хатолик юз берди');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="card">
        <h2 className="text-2xl font-bold mb-6">Янги йўналиш яратиш</h2>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Йўналиш маълумотлари */}
          <div className="border-b pb-6">
            <h3 className="text-lg font-semibold mb-4">Йўналиш маълумотлари</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Қаердан (Вилоят) *
                </label>
                <select
                  name="fromRegion"
                  value={formData.fromRegion}
                  onChange={handleChange}
                  className="input"
                  required
                >
                  <option value="">Вилоятни танланг</option>
                  {regions.map(region => (
                    <option key={region} value={region}>{region}</option>
                  ))}
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Қаердан (Туман) *
                </label>
                <input
                  type="text"
                  name="fromDistrict"
                  value={formData.fromDistrict}
                  onChange={handleChange}
                  placeholder="Туман номи"
                  className="input"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Қаерга (Вилоят) *
                </label>
                <select
                  name="toRegion"
                  value={formData.toRegion}
                  onChange={handleChange}
                  className="input"
                  required
                >
                  <option value="">Вилоятни танланг</option>
                  {regions.map(region => (
                    <option key={region} value={region}>{region}</option>
                  ))}
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Қаерга (Туман)
                </label>
                <input
                  type="text"
                  name="toDistrict"
                  value={formData.toDistrict}
                  onChange={handleChange}
                  placeholder="Туман номи (ихтиёрий)"
                  className="input"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Йўлга чиқиш вақти *
                </label>
                <input
                  type="datetime-local"
                  name="departureTime"
                  value={formData.departureTime}
                  onChange={handleChange}
                  className="input"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Бўш ўринлар сони *
                </label>
                <select
                  name="availableSeats"
                  value={formData.availableSeats}
                  onChange={handleChange}
                  className="input"
                  required
                >
                  {[1, 2, 3, 4, 5, 6].map(num => (
                    <option key={num} value={num}>{num} та ўрин</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Нарх ва тўлов */}
          <div className="border-b pb-6">
            <h3 className="text-lg font-semibold mb-4">Нарх ва тўлов</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Йўл ҳакки (1 ўрин учун) *
                </label>
                <input
                  type="number"
                  name="pricePerSeat"
                  value={formData.pricePerSeat}
                  onChange={handleChange}
                  placeholder="Мисол: 25000"
                  className="input"
                  required
                  min="1000"
                />
                <p className="text-sm text-gray-500 mt-1">1 киши учун нарх сўмда</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Тўлов усуллари
                </label>
                <div className="space-y-2">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      name="paymentMethods.cash"
                      checked={formData.paymentMethods.cash}
                      onChange={handleChange}
                      className="mr-2"
                    />
                    <span>Нақд пул</span>
                  </label>
                  
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      name="paymentMethods.click"
                      checked={formData.paymentMethods.click}
                      onChange={handleChange}
                      className="mr-2"
                    />
                    <span>Click/Payme</span>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Шартлар */}
          <div className="border-b pb-6">
            <h3 className="text-lg font-semibold mb-4">Шахсий шартлар</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Максимум сумкалар сони
                </label>
                <select
                  name="conditions.maxLuggage"
                  value={formData.conditions.maxLuggage}
                  onChange={handleChange}
                  className="input"
                >
                  {[1, 2, 3, 4].map(num => (
                    <option key={num} value={num}>{num} та сумка</option>
                  ))}
                </select>
              </div>
              
              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="conditions.childrenAllowed"
                    checked={formData.conditions.childrenAllowed}
                    onChange={handleChange}
                    className="mr-2"
                  />
                  <span>Болаларни олиш</span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="conditions.noSmoking"
                    checked={formData.conditions.noSmoking}
                    onChange={handleChange}
                    className="mr-2"
                  />
                  <span>Чилим чекмаслик</span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="conditions.noMusic"
                    checked={formData.conditions.noMusic}
                    onChange={handleChange}
                    className="mr-2"
                  />
                  <span>Мусиқа йўқ</span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="conditions.petsAllowed"
                    checked={formData.conditions.petsAllowed}
                    onChange={handleChange}
                    className="mr-2"
                  />
                  <span>Ҳайвонларни олиш</span>
                </label>
              </div>
            </div>
          </div>

          {/* Линия нархи */}
          <div className="bg-blue-50 p-4 rounded-lg">
            <h3 className="text-lg font-semibold mb-2">Линия нархи</h3>
            <p className="text-gray-600">
              Йўналишнинг линия нархи автомат ҳисобланади ва хайдовчи томонидан тўланади.
              Линияга чиқиш пули йўналишнинг масофаси ва ўринлар сонига қараб белгиланади.
            </p>
            <div className="mt-2 p-3 bg-white rounded border">
              <div className="flex justify-between items-center">
                <span className="font-medium">Тақрибий линия нархи:</span>
                <span className="text-xl font-bold text-blue-600">
                  {(() => {
                    // Содда ҳисоблаш
                    const basePrice = 20000;
                    const seatMultiplier = Math.min(formData.availableSeats, 4);
                    return (basePrice * seatMultiplier).toLocaleString('uz-UZ') + ' сўм';
                  })()}
                </span>
              </div>
            </div>
          </div>

          <div className="flex space-x-4">
            <button
              type="button"
              onClick={() => navigate('/driver/dashboard')}
              className="btn btn-secondary"
            >
              Бекор қилиш
            </button>
            
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary flex-1"
            >
              {loading ? 'Яратилмоқда...' : 'Йўналишни яратиш'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateRide;`,

  'frontend/src/components/passenger/SearchRide.jsx': `import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const SearchRide = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const { api } = useAuth();
  const navigate = useNavigate();
  
  const [searchData, setSearchData] = useState({
    fromRegion: searchParams.get('fromRegion') || '',
    fromDistrict: searchParams.get('fromDistrict') || '',
    toRegion: searchParams.get('toRegion') || '',
    departureDate: searchParams.get('departureDate') || '',
    seats: parseInt(searchParams.get('seats')) || 1,
    paymentMethod: searchParams.get('paymentMethod') || '',
    maxPrice: searchParams.get('maxPrice') || ''
  });
  
  const [rides, setRides] = useState([]);
  const [loading, setLoading] = useState(false);
  const [districts, setDistricts] = useState([]);

  const regions = [
    'Тошкент шаҳри',
    'Тошкент вилояти',
    'Самарқанд вилояти',
    'Фарғона вилояти',
    'Андижон вилояти',
    'Наманган вилояти',
    'Бухоро вилояти',
    'Хоразм вилояти',
    'Қашқадарё вилояти',
    'Сурхондарё вилояти',
    'Жиззах вилояти',
    'Сирдарё вилояти',
    'Навоий вилояти'
  ];

  const handleSearch = async (e) => {
    e?.preventDefault();
    setLoading(true);
    
    // URL параметрларини янгилаш
    const params = {};
    if (searchData.fromRegion) params.fromRegion = searchData.fromRegion;
    if (searchData.fromDistrict) params.fromDistrict = searchData.fromDistrict;
    if (searchData.toRegion) params.toRegion = searchData.toRegion;
    if (searchData.departureDate) params.departureDate = searchData.departureDate;
    if (searchData.seats) params.seats = searchData.seats;
    if (searchData.paymentMethod) params.paymentMethod = searchData.paymentMethod;
    if (searchData.maxPrice) params.maxPrice = searchData.maxPrice;
    
    setSearchParams(params);

    try {
      const response = await api.get('/rides/search', { params: searchData });
      
      if (response.data.success) {
        setRides(response.data.rides);
        if (response.data.rides.length === 0) {
          toast.info('Излаш натикалари топилмади');
        }
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Излашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  // Вилоят танланганда туманларни юклаш
  useEffect(() => {
    if (searchData.fromRegion) {
      // Туманларни API орқали олиш керак, лекин айни пайтда симуляция
      const mockDistricts = [
        'Марказий туман',
        'Шимолий туман',
        'Жанубий туман',
        'Шарқий туман',
        'Ғарбий туман'
      ];
      setDistricts(mockDistricts);
    }
  }, [searchData.fromRegion]);

  // Автомат излаш URL параметрлари бор бўлса
  useEffect(() => {
    const hasSearchParams = 
      searchParams.get('fromRegion') || 
      searchParams.get('toRegion') || 
      searchParams.get('departureDate');
    
    if (hasSearchParams) {
      handleSearch();
    }
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setSearchData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('uz-UZ', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleBookNow = (rideId) => {
    navigate('/booking/' + rideId, { 
      state: { 
        rideId,
        seats: searchData.seats 
      } 
    });
  };

  return (
    <div className="max-w-7xl mx-auto">
      {/* Излаш формаси */}
      <div className="card mb-8">
        <h2 className="text-2xl font-bold mb-6">Такси излаш</h2>
        
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Қаердан (Вилоят) *
              </label>
              <select
                name="fromRegion"
                value={searchData.fromRegion}
                onChange={handleChange}
                className="input"
                required
              >
                <option value="">Вилоятни танланг</option>
                {regions.map(region => (
                  <option key={region} value={region}>{region}</option>
                ))}
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Қаердан (Туман)
              </label>
              <select
                name="fromDistrict"
                value={searchData.fromDistrict}
                onChange={handleChange}
                className="input"
              >
                <option value="">Барча туманлар</option>
                {districts.map(district => (
                  <option key={district} value={district}>{district}</option>
                ))}
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Қаерга (Вилоят) *
              </label>
              <select
                name="toRegion"
                value={searchData.toRegion}
                onChange={handleChange}
                className="input"
                required
              >
                <option value="">Вилоятни танланг</option>
                {regions.map(region => (
                  <option key={region} value={region}>{region}</option>
                ))}
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Сана *
              </label>
              <input
                type="date"
                name="departureDate"
                value={searchData.departureDate}
                onChange={handleChange}
                className="input"
                required
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Ўринлар сони
              </label>
              <select
                name="seats"
                value={searchData.seats}
                onChange={handleChange}
                className="input"
              >
                {[1, 2, 3, 4, 5, 6].map(num => (
                  <option key={num} value={num}>{num} та ўрин</option>
                ))}
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Тўлов усули
              </label>
              <select
                name="paymentMethod"
                value={searchData.paymentMethod}
                onChange={handleChange}
                className="input"
              >
                <option value="">Барчаси</option>
                <option value="cash">Нақд пул</option>
                <option value="click">Click/Payme</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Максимум нарх (ўрин учун)
              </label>
              <input
                type="number"
                name="maxPrice"
                value={searchData.maxPrice}
                onChange={handleChange}
                placeholder="Мисол: 50000"
                className="input"
              />
            </div>
          </div>
          
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
            >
              {loading ? 'Изланмоқда...' : 'Излаш'}
            </button>
          </div>
        </form>
      </div>

      {/* Натижалар */}
      <div>
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold">
            Топилган таксилар ({rides.length})
          </h2>
          
          {rides.length > 0 && (
            <div className="text-gray-600">
              <span className="font-medium">Фильтр:</span>{' '}
              {searchData.fromRegion} → {searchData.toRegion}
            </div>
          )}
        </div>
        
        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Таксилар изланмоқда...</p>
          </div>
        ) : rides.length === 0 ? (
          <div className="card text-center py-12">
            <div className="text-4xl mb-4">🚗</div>
            <h3 className="text-xl font-semibold mb-2">Такси топилмади</h3>
            <p className="text-gray-600">
              Сўровингизга мос келадиган таксилар мавжуд эмас.
              Илтимос, параметрларни ўзгартириб қайта уриниб кўринг.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {rides.map(ride => (
              <div key={ride.id} className="card hover:shadow-lg transition-shadow">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-semibold">
                      {ride.driver.name}
                      <span className="ml-2 text-yellow-500">
                        {'★'.repeat(Math.floor(ride.driver.rating))}
                      </span>
                    </h3>
                    <p className="text-gray-600">{ride.driver.carModel} • {ride.driver.carColor}</p>
                  </div>
                  
                  <div className="text-right">
                    <div className="text-2xl font-bold text-blue-600">
                      {ride.pricePerSeat.toLocaleString('uz-UZ')} сўм
                    </div>
                    <div className="text-sm text-gray-500">1 ўрин учун</div>
                  </div>
                </div>
                
                <div className="space-y-3 mb-4">
                  <div className="flex items-center text-gray-700">
                    <span className="w-24 font-medium">Йўналиш:</span>
                    <span>{ride.fromDistrict}, {ride.fromRegion} → {ride.toRegion}</span>
                  </div>
                  
                  <div className="flex items-center text-gray-700">
                    <span className="w-24 font-medium">Вақт:</span>
                    <span>{formatDate(ride.departureTime)}</span>
                  </div>
                  
                  <div className="flex items-center text-gray-700">
                    <span className="w-24 font-medium">Бўш ўрин:</span>
                    <span>{ride.availableSeats - ride.bookedSeats} / {ride.availableSeats}</span>
                  </div>
                  
                  <div className="flex items-center text-gray-700">
                    <span className="w-24 font-medium">Тўлов:</span>
                    <div className="flex space-x-2">
                      {ride.paymentMethods.cash && (
                        <span className="badge badge-success">💵 Нақд</span>
                      )}
                      {ride.paymentMethods.click && (
                        <span className="badge badge-info">💳 Click</span>
                      )}
                    </div>
                  </div>
                  
                  {ride.conditions && (
                    <div className="flex items-center text-gray-700">
                      <span className="w-24 font-medium">Шартлар:</span>
                      <div className="flex flex-wrap gap-1">
                        {ride.conditions.maxLuggage && (
                          <span className="badge badge-secondary">
                            {ride.conditions.maxLuggage} сумка
                          </span>
                        )}
                        {ride.conditions.noSmoking && (
                          <span className="badge badge-secondary">🚭</span>
                        )}
                        {ride.conditions.noMusic && (
                          <span className="badge badge-secondary">🎵</span>
                        )}
                        {ride.conditions.childrenAllowed && (
                          <span className="badge badge-secondary">👶</span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
                
                <div className="flex justify-between items-center">
                  <div className="text-sm text-gray-500">
                    Хайдовчи: {ride.driver.phone}
                  </div>
                  
                  <button
                    onClick={() => handleBookNow(ride.id)}
                    className="btn btn-primary"
                  >
                    Брон қилиш
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default SearchRide;`,

  'frontend/src/components/driver/DriverDashboard.jsx': `import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const DriverDashboard = () => {
  const { api } = useAuth();
  const [rides, setRides] = useState([]);
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('rides');

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      // Йўналишларни олиш
      const ridesResponse = await api.get('/rides/driver');
      if (ridesResponse.data.success) {
        setRides(ridesResponse.data.rides);
      }

      // Бронларни олиш
      const bookingsResponse = await api.get('/bookings/driver');
      if (bookingsResponse.data.success) {
        setBookings(bookingsResponse.data.bookings);
      }
    } catch (error) {
      toast.error('Маълумотларни юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmBooking = async (bookingId) => {
    try {
      const response = await api.put('/bookings/' + bookingId + '/confirm');
      if (response.data.success) {
        toast.success('Брон тасдиқланди');
        fetchDashboardData();
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Хатолик');
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('uz-UZ', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active': return <span className="badge badge-success">Фаол</span>;
      case 'in_progress': return <span className="badge badge-info">Жараёнда</span>;
      case 'completed': return <span className="badge badge-secondary">Тугаган</span>;
      case 'cancelled': return <span className="badge badge-danger">Бекор</span>;
      default: return <span className="badge badge-warning">{status}</span>;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">Хайдовчи дашборди</h1>
        <Link to="/driver/create-ride" className="btn btn-primary">
          Янги йўналиш
        </Link>
      </div>

      {/* Статистика */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Фаол йўналишлар</h3>
          <div className="text-3xl font-bold text-blue-600">
            {rides.filter(r => r.status === 'active').length}
          </div>
        </div>
        
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Янги бронлар</h3>
          <div className="text-3xl font-bold text-green-600">
            {bookings.filter(b => b.status === 'pending').length}
          </div>
        </div>
        
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Умумий даромад</h3>
          <div className="text-3xl font-bold text-purple-600">
            {bookings
              .filter(b => b.status === 'completed')
              .reduce((sum, b) => sum + b.totalPrice, 0)
              .toLocaleString('uz-UZ')} сўм
          </div>
        </div>
      </div>

      {/* Таблар */}
      <div className="mb-6">
        <div className="border-b">
          <nav className="flex space-x-8">
            <button
              onClick={() => setActiveTab('rides')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'rides'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Менинг йўналишларим ({rides.length})
            </button>
            <button
              onClick={() => setActiveTab('bookings')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'bookings'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Бронлар ({bookings.length})
            </button>
          </nav>
        </div>
      </div>

      {/* Контент */}
      <div>
        {activeTab === 'rides' && (
          <div className="space-y-4">
            {rides.length === 0 ? (
              <div className="card text-center py-12">
                <div className="text-4xl mb-4">🚗</div>
                <h3 className="text-xl font-semibold mb-2">Йўналишлар йўқ</h3>
                <p className="text-gray-600 mb-4">
                  Ҳали биронта йўналиш яратмадингиз
                </p>
                <Link to="/driver/create-ride" className="btn btn-primary">
                  Биринчи йўналишни яратиш
                </Link>
              </div>
            ) : (
              rides.map(ride => (
                <div key={ride._id} className="card">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-lg font-semibold">
                        {ride.fromRegion} → {ride.toRegion}
                      </h3>
                      <div className="flex items-center space-x-4 mt-2">
                        <span className="text-gray-600">
                          {formatDate(ride.departureTime)}
                        </span>
                        <span className="text-gray-600">
                          {ride.availableSeats} ўрин • {ride.pricePerSeat.toLocaleString('uz-UZ')} сўм
                        </span>
                        {getStatusBadge(ride.status)}
                      </div>
                    </div>
                    
                    <div className="text-right">
                      <div className="text-sm text-gray-500">Бронланган</div>
                      <div className="text-xl font-bold">
                        {ride.bookedSeats} / {ride.availableSeats}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex justify-between items-center mt-4 pt-4 border-t">
                    <div className="text-sm text-gray-500">
                      Линия нархи: {ride.linePrice?.toLocaleString('uz-UZ') || '0'} сўм
                    </div>
                    
                    <div className="flex space-x-2">
                      <Link
                        to={\`/ride/\${ride._id}/edit\`}
                        className="btn btn-secondary text-sm"
                      >
                        Таҳрирлаш
                      </Link>
                      
                      {ride.status === 'active' && (
                        <button
                          onClick={() => {
                            // Бекор қилиш функцияси
                          }}
                          className="btn btn-danger text-sm"
                        >
                          Бекор қилиш
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'bookings' && (
          <div className="space-y-4">
            {bookings.length === 0 ? (
              <div className="card text-center py-12">
                <div className="text-4xl mb-4">📋</div>
                <h3 className="text-xl font-semibold mb-2">Бронлар йўқ</h3>
                <p className="text-gray-600">
                  Ҳали сизга брон қилинмаган
                </p>
              </div>
            ) : (
              bookings.map(booking => (
                <div key={booking.id} className="card">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-lg font-semibold">
                        {booking.passenger.name}
                        <span className="ml-2 text-sm text-gray-500">
                          {booking.passenger.phone}
                        </span>
                      </h3>
                      
                      <div className="mt-2 space-y-1">
                        <div className="text-gray-600">
                          {booking.ride.fromRegion} → {booking.ride.toRegion}
                        </div>
                        <div className="text-gray-600">
                          {formatDate(booking.ride.departureTime)}
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-gray-600">
                            {booking.seats} та ўрин • {booking.totalPrice.toLocaleString('uz-UZ')} сўм
                          </span>
                          <span className={\`badge \${
                            booking.status === 'pending' ? 'badge-warning' :
                            booking.status === 'confirmed' ? 'badge-success' :
                            'badge-secondary'
                          }\`}>
                            {booking.status === 'pending' ? 'Кутилмоқда' :
                             booking.status === 'confirmed' ? 'Тасдиқланган' :
                             booking.status}
                          </span>
                        </div>
                        
                        {booking.specialRequests && (
                          <div className="mt-2 text-sm text-gray-500">
                            Илова талаблар:
                            {booking.specialRequests.luggageCount > 0 && (
                              <span className="ml-2">🎒 {booking.specialRequests.luggageCount} сумка</span>
                            )}
                            {booking.specialRequests.hasChildren && (
                              <span className="ml-2">👶 Бола бор</span>
                            )}
                            {booking.specialRequests.notes && (
                              <span className="ml-2">📝 {booking.specialRequests.notes}</span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="text-right">
                      <div className="text-sm text-gray-500 mb-2">
                        Тўлов: {booking.paymentMethod === 'cash' ? '💵 Нақд' : '💳 Click'}
                      </div>
                      
                      {booking.status === 'pending' && (
                        <button
                          onClick={() => handleConfirmBooking(booking.id)}
                          className="btn btn-success"
                        >
                          Тасдиқлаш
                        </button>
                      )}
                      
                      {booking.driverConfirmed && (
                        <span className="badge badge-success">Тасдиқланган</span>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default DriverDashboard;`,

  'frontend/src/components/passenger/PassengerDashboard.jsx': `import { useState, useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const PassengerDashboard = () => {
  const { api } = useAuth();
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('upcoming');

  useEffect(() => {
    fetchBookings();
  }, []);

  const fetchBookings = async () => {
    setLoading(true);
    try {
      const response = await api.get('/bookings/passenger');
      if (response.data.success) {
        setBookings(response.data.bookings);
      }
    } catch (error) {
      toast.error('Бронларни юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const handleCancelBooking = async (bookingId) => {
    if (!window.confirm('Ҳақиқатан хам бронни бекор қилмоқчимисиз?')) return;

    try {
      const response = await api.delete('/bookings/' + bookingId, {
        data: { reason: 'Йўловчи томонидан бекор қилинди' }
      });
      
      if (response.data.success) {
        toast.success('Брон бекор қилинди');
        fetchBookings();
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Хатолик');
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('uz-UZ', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'pending': return <span className="badge badge-warning">Кутилмоқда</span>;
      case 'confirmed': return <span className="badge badge-success">Тасдиқланган</span>;
      case 'cancelled': return <span className="badge badge-danger">Бекор</span>;
      case 'completed': return <span className="badge badge-info">Тугаган</span>;
      default: return <span className="badge badge-secondary">{status}</span>;
    }
  };

  // Бронларни категориялаш
  const upcomingBookings = bookings.filter(b => 
    ['pending', 'confirmed'].includes(b.status) && 
    new Date(b.ride.departureTime) > new Date()
  );

  const pastBookings = bookings.filter(b => 
    b.status === 'completed' || 
    new Date(b.ride.departureTime) <= new Date()
  );

  const cancelledBookings = bookings.filter(b => b.status === 'cancelled');

  const displayBookings = activeTab === 'upcoming' ? upcomingBookings :
                         activeTab === 'past' ? pastBookings : cancelledBookings;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">Йўловчи дашборди</h1>

      {/* Статистика */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Жами бронлар</h3>
          <div className="text-3xl font-bold text-blue-600">
            {bookings.length}
          </div>
        </div>
        
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Кутилаётган</h3>
          <div className="text-3xl font-bold text-yellow-600">
            {upcomingBookings.length}
          </div>
        </div>
        
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Тугаган</h3>
          <div className="text-3xl font-bold text-green-600">
            {pastBookings.length}
          </div>
        </div>
        
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Бекор қилинган</h3>
          <div className="text-3xl font-bold text-red-600">
            {cancelledBookings.length}
          </div>
        </div>
      </div>

      {/* Таблар */}
      <div className="mb-6">
        <div className="border-b">
          <nav className="flex space-x-8">
            <button
              onClick={() => setActiveTab('upcoming')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'upcoming'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Кутилаётган ({upcomingBookings.length})
            </button>
            <button
              onClick={() => setActiveTab('past')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'past'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Тугаган ({pastBookings.length})
            </button>
            <button
              onClick={() => setActiveTab('cancelled')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'cancelled'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Бекор қилинган ({cancelledBookings.length})
            </button>
          </nav>
        </div>
      </div>

      {/* Контент */}
      <div className="space-y-4">
        {displayBookings.length === 0 ? (
          <div className="card text-center py-12">
            <div className="text-4xl mb-4">
              {activeTab === 'upcoming' ? '📅' : 
               activeTab === 'past' ? '✅' : '❌'}
            </div>
            <h3 className="text-xl font-semibold mb-2">
              {activeTab === 'upcoming' ? 'Кутилаётган бронлар йўқ' :
               activeTab === 'past' ? 'Тугаган бронлар йўқ' :
               'Бекор қилинган бронлар йўқ'}
            </h3>
            <p className="text-gray-600 mb-4">
              {activeTab === 'upcoming' && 'Ҳали биронта сафарга брон қилмадингиз'}
              {activeTab === 'past' && 'Ҳали биронта сафарингиз тугамаган'}
              {activeTab === 'cancelled' && 'Ҳали биронта бронни бекор қилмадингиз'}
            </p>
            {activeTab === 'upcoming' && (
              <a href="/search" className="btn btn-primary">
                Такси излаш
              </a>
            )}
          </div>
        ) : (
          displayBookings.map(booking => (
            <div key={booking.id} className="card">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-lg font-semibold">
                        {booking.driver.name}
                        <span className="ml-2 text-sm text-gray-500">
                          {booking.driver.phone}
                        </span>
                      </h3>
                      <div className="mt-1 text-gray-600">
                        {booking.driver.carModel} • {booking.driver.carColor}
                        <span className="ml-2 text-yellow-500">
                          {'★'.repeat(Math.floor(booking.driver.rating))}
                        </span>
                      </div>
                    </div>
                    
                    <div className="text-right">
                      <div className="text-2xl font-bold text-blue-600">
                        {booking.totalPrice.toLocaleString('uz-UZ')} сўм
                      </div>
                      <div className="text-sm text-gray-500">
                        {booking.seats} ўрин
                      </div>
                    </div>
                  </div>
                  
                  <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <div className="text-sm text-gray-500">Йўналиш</div>
                      <div className="font-medium">
                        {booking.ride.fromRegion} → {booking.ride.toRegion}
                        {booking.ride.toDistrict && \` (\${booking.ride.toDistrict})\`}
                      </div>
                    </div>
                    
                    <div>
                      <div className="text-sm text-gray-500">Йўлга чиқиш вақти</div>
                      <div className="font-medium">
                        {formatDate(booking.ride.departureTime)}
                      </div>
                    </div>
                    
                    <div>
                      <div className="text-sm text-gray-500">Тўлов усули</div>
                      <div className="font-medium">
                        {booking.paymentMethod === 'cash' ? '💵 Нақд пул' : '💳 Click/Payme'}
                      </div>
                    </div>
                    
                    <div>
                      <div className="text-sm text-gray-500">Статус</div>
                      <div className="font-medium">
                        {getStatusBadge(booking.status)}
                        {booking.driverConfirmed && (
                          <span className="ml-2 badge badge-success">Хайдовчи тасдиқлади</span>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {booking.specialRequests && (
                    <div className="mt-4 p-3 bg-gray-50 rounded">
                      <div className="text-sm font-medium text-gray-700 mb-1">
                        Илова талаблар:
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {booking.specialRequests.luggageCount > 0 && (
                          <span className="badge badge-secondary">
                            🎒 {booking.specialRequests.luggageCount} сумка
                          </span>
                        )}
                        {booking.specialRequests.hasChildren && (
                          <span className="badge badge-secondary">👶 Бола бор</span>
                        )}
                        {booking.specialRequests.notes && (
                          <span className="text-sm text-gray-600">
                            📝 {booking.specialRequests.notes}
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="flex justify-between items-center mt-6 pt-6 border-t">
                <div className="text-sm text-gray-500">
                  Брон рақами: {booking.id.slice(-8).toUpperCase()}
                </div>
                
                <div className="flex space-x-2">
                  {activeTab === 'upcoming' && booking.status !== 'cancelled' && (
                    <button
                      onClick={() => handleCancelBooking(booking.id)}
                      className="btn btn-danger"
                    >
                      Бронни бекор қилиш
                    </button>
                  )}
                  
                  <button
                    onClick={() => {
                      // Хайдовчи билан боғланиш
                      window.open('tel:' + booking.driver.phone, '_blank');
                    }}
                    className="btn btn-secondary"
                  >
                    Хайдовчига қўнғироқ қилиш
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default PassengerDashboard;`,

  'frontend/src/components/admin/AdminPanel.jsx': `import { useState, useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';
import toast from 'react-hot-toast';

const AdminPanel = () => {
  const { api } = useAuth();
  const [activeTab, setActiveTab] = useState('stats');
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [drivers, setDrivers] = useState([]);
  const [rides, setRides] = useState([]);
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (activeTab === 'stats') {
      fetchStats();
    } else if (activeTab === 'users') {
      fetchUsers();
    } else if (activeTab === 'drivers') {
      fetchDrivers();
    } else if (activeTab === 'rides') {
      fetchRides();
    } else if (activeTab === 'bookings') {
      fetchBookings();
    }
  }, [activeTab]);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const response = await api.get('/admin/stats');
      if (response.data.success) {
        setStats(response.data.stats);
      }
    } catch (error) {
      toast.error('Статистикани юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const response = await api.get('/admin/users');
      if (response.data.success) {
        setUsers(response.data.users);
      }
    } catch (error) {
      toast.error('Фойдаланувчиларни юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const fetchDrivers = async () => {
    setLoading(true);
    try {
      const response = await api.get('/admin/drivers');
      if (response.data.success) {
        setDrivers(response.data.drivers);
      }
    } catch (error) {
      toast.error('Хайдовчиларни юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const fetchRides = async () => {
    setLoading(true);
    try {
      const response = await api.get('/admin/rides');
      if (response.data.success) {
        setRides(response.data.rides);
      }
    } catch (error) {
      toast.error('Йўналишларни юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const fetchBookings = async () => {
    setLoading(true);
    try {
      const response = await api.get('/admin/bookings');
      if (response.data.success) {
        setBookings(response.data.bookings);
      }
    } catch (error) {
      toast.error('Бронларни юклашда хатолик');
    } finally {
      setLoading(false);
    }
  };

  const handleBlockUser = async (userId, isBlocked) => {
    if (!window.confirm(isBlocked ? 
      'Фойдаланувчини блокдан чиқармоқчимисиз?' : 
      'Фойдаланувчини блокламоқчимисиз?')) return;

    try {
      const response = await api.put('/admin/users/' + userId + '/block', {
        isBlocked: !isBlocked
      });
      
      if (response.data.success) {
        toast.success(response.data.message);
        fetchUsers();
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Хатолик');
    }
  };

  const handleVerifyDriver = async (driverId, isVerified) => {
    try {
      const response = await api.put('/admin/drivers/' + driverId + '/verify', {
        isVerified: !isVerified
      });
      
      if (response.data.success) {
        toast.success(response.data.message);
        fetchDrivers();
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Хатолик');
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('uz-UZ', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">Администратор панели</h1>

      {/* Таблар */}
      <div className="mb-6">
        <div className="border-b">
          <nav className="flex flex-wrap space-x-8">
            <button
              onClick={() => setActiveTab('stats')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'stats'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Статистика
            </button>
            <button
              onClick={() => setActiveTab('users')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'users'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Фойдаланувчилар ({users.length})
            </button>
            <button
              onClick={() => setActiveTab('drivers')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'drivers'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Хайдовчилар ({drivers.length})
            </button>
            <button
              onClick={() => setActiveTab('rides')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'rides'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Йўналишлар ({rides.length})
            </button>
            <button
              onClick={() => setActiveTab('bookings')}
              className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                activeTab === 'bookings'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }\`}
            >
              Бронлар ({bookings.length})
            </button>
          </nav>
        </div>
      </div>

      {/* Контент */}
      <div>
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        ) : (
          <>
            {/* Статистика */}
            {activeTab === 'stats' && stats && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-2">Умумий фойдаланувчилар</h3>
                    <div className="text-3xl font-bold text-blue-600">
                      {stats.total.users}
                    </div>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-2">Хайдовчилар</h3>
                    <div className="text-3xl font-bold text-green-600">
                      {stats.total.drivers}
                    </div>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-2">Йўналишлар</h3>
                    <div className="text-3xl font-bold text-purple-600">
                      {stats.total.rides}
                    </div>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-2">Бронлар</h3>
                    <div className="text-3xl font-bold text-yellow-600">
                      {stats.total.bookings}
                    </div>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-4">Кунлик статистика</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span>Йўналишлар:</span>
                        <span className="font-bold">{stats.today.rides}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>Бронлар:</span>
                        <span className="font-bold">{stats.today.bookings}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>Даромад:</span>
                        <span className="font-bold text-green-600">
                          {stats.today.revenue.toLocaleString('uz-UZ')} сўм
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-4">Умумий даромад</h3>
                    <div className="text-center py-8">
                      <div className="text-4xl font-bold text-green-600">
                        {stats.total.revenue.toLocaleString('uz-UZ')}
                      </div>
                      <div className="text-gray-500 mt-2">сўм</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Фойдаланувчилар */}
            {activeTab === 'users' && (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Исм
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Телефон
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Рол
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Статус
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Ҳаракатлар
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {users.map(user => (
                      <tr key={user._id}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="font-medium text-gray-900">{user.fullName}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                          {user.phone}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={\`badge \${
                            user.role === 'admin' ? 'badge-danger' :
                            user.role === 'driver' ? 'badge-info' :
                            'badge-success'
                          }\`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {user.isBlocked ? (
                            <span className="badge badge-danger">Блокланган</span>
                          ) : (
                            <span className="badge badge-success">Фаол</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          {user.role !== 'admin' && (
                            <button
                              onClick={() => handleBlockUser(user._id, user.isBlocked)}
                              className={\`btn \${
                                user.isBlocked ? 'btn-success' : 'btn-danger'
                              } btn-sm\`}
                            >
                              {user.isBlocked ? 'Блокдан чиқариш' : 'Блоклаш'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Хайдовчилар */}
            {activeTab === 'drivers' && (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Хайдовчи
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Автомобил
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Рейтинг
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Статус
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Ҳаракатлар
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {drivers.map(driver => (
                      <tr key={driver.id}>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium text-gray-900">{driver.user?.fullName}</div>
                            <div className="text-sm text-gray-500">{driver.user?.phone}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium">{driver.carModel}</div>
                            <div className="text-sm text-gray-500">{driver.carNumber}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="text-yellow-500">
                            {'★'.repeat(Math.floor(driver.rating))}
                          </span>
                          <span className="text-gray-400 ml-1">
                            ({driver.totalRides} сафар)
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {driver.isActive ? (
                            <span className="badge badge-success">Фаол</span>
                          ) : (
                            <span className="badge badge-danger">Нофаол</span>
                          )}
                          {driver.isVerified && (
                            <span className="ml-2 badge badge-info">Тасдиқланган</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => handleVerifyDriver(driver.id, driver.isVerified)}
                            className={\`btn \${
                              driver.isVerified ? 'btn-warning' : 'btn-success'
                            } btn-sm\`}
                          >
                            {driver.isVerified ? 'Тасдиқдан чиқариш' : 'Тасдиқлаш'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Йўналишлар */}
            {activeTab === 'rides' && (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Йўналиш
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Хайдовчи
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Вақт
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Нарх
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Статус
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {rides.map(ride => (
                      <tr key={ride.id}>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium">
                              {ride.fromRegion} → {ride.toRegion}
                            </div>
                            <div className="text-sm text-gray-500">
                              {ride.fromDistrict} → {ride.toDistrict || '—'}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium">{ride.driver.name}</div>
                            <div className="text-sm text-gray-500">{ride.driver.phone}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {formatDate(ride.departureTime)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div>{ride.pricePerSeat.toLocaleString('uz-UZ')} сўм/ўрин</div>
                            <div className="text-sm text-gray-500">
                              {ride.bookedSeats}/{ride.availableSeats} ўрин
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {ride.isActive ? (
                            <span className="badge badge-success">Фаол</span>
                          ) : (
                            <span className="badge badge-danger">Нофаол</span>
                          )}
                          <div className="text-sm text-gray-500 mt-1">
                            Линия: {ride.linePrice.toLocaleString('uz-UZ')} сўм
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Бронлар */}
            {activeTab === 'bookings' && (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Йўловчи
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Хайдовчи
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Йўналиш
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Нарх
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Статус
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {bookings.map(booking => (
                      <tr key={booking.id}>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium">{booking.passenger.name}</div>
                            <div className="text-sm text-gray-500">{booking.passenger.phone}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium">{booking.driver.name}</div>
                            <div className="text-sm text-gray-500">{booking.driver.phone}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div>
                            <div className="font-medium">
                              {booking.ride.fromRegion} → {booking.ride.toRegion}
                            </div>
                            <div className="text-sm text-gray-500">
                              {formatDate(booking.ride.departureTime)}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div>{booking.totalPrice.toLocaleString('uz-UZ')} сўм</div>
                            <div className="text-sm text-gray-500">
                              {booking.seats} ўрин • {booking.paymentMethod}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {booking.status === 'pending' && (
                            <span className="badge badge-warning">Кутилмоқда</span>
                          )}
                          {booking.status === 'confirmed' && (
                            <span className="badge badge-success">Тасдиқланган</span>
                          )}
                          {booking.status === 'cancelled' && (
                            <span className="badge badge-danger">Бекор</span>
                          )}
                          {booking.status === 'completed' && (
                            <span className="badge badge-info">Тугаган</span>
                          )}
                          {booking.driverConfirmed && (
                            <div className="text-sm text-green-600 mt-1">Хайдовчи тасдиқлади</div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default AdminPanel;`,

  'frontend/src/pages/HomePage.jsx': `const HomePage = () => {
  return (
    <div>
      {/* Hero section */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-2xl p-8 md:p-12 mb-12">
        <div className="max-w-3xl">
          <h1 className="text-4xl md:text-5xl font-bold mb-6">
            Вилоятлар аро такси хизмати
          </h1>
          <p className="text-xl mb-8">
            Ўзбекистон бўйлаб қулай ва ишончли сафар. 
            Хайдовчи ёки йўловчи сифатида рўйхатдан ўтинг.
          </p>
          <div className="flex flex-wrap gap-4">
            <a
              href="/search"
              className="bg-white text-blue-600 hover:bg-gray-100 px-6 py-3 rounded-lg font-semibold text-lg"
            >
              Такси излаш
            </a>
            <a
              href="/register"
              className="bg-transparent border-2 border-white hover:bg-white/10 px-6 py-3 rounded-lg font-semibold text-lg"
            >
              Рўйхатдан ўтиш
            </a>
          </div>
        </div>
      </div>

      {/* Features */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
        <div className="card text-center">
          <div className="text-4xl mb-4">🚗</div>
          <h3 className="text-xl font-semibold mb-3">Хайдовчи бўлинг</h3>
          <p className="text-gray-600">
            Автомобилингиз билан пул ишланг. Ўзингизнинг нарх ва шартларингизни белгиланг.
          </p>
        </div>
        
        <div className="card text-center">
          <div className="text-4xl mb-4">👥</div>
          <h3 className="text-xl font-semibold mb-3">Йўловчи бўлинг</h3>
          <p className="text-gray-600">
            Ўзингизга мос таксини топинг. Нарх ва хизмат сифатини солиштиринг.
          </p>
        </div>
        
        <div className="card text-center">
          <div className="text-4xl mb-4">💳</div>
          <h3 className="text-xl font-semibold mb-3">Тўлов имкониятлари</h3>
          <p className="text-gray-600">
            Нақд пул ёки Click/Payme орқали тўланг. Тўлов ўзаро келишув асосида.
          </p>
        </div>
      </div>

      {/* How it works */}
      <div className="mb-12">
        <h2 className="text-3xl font-bold mb-8 text-center">Бу қандай ишлайди?</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="text-center">
            <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">
              1
            </div>
            <h4 className="font-semibold mb-2">Рўйхатдан ўтинг</h4>
            <p className="text-gray-600 text-sm">
              Йўловчи ёки хайдовчи сифатида рўйхатдан ўтинг
            </p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">
              2
            </div>
            <h4 className="font-semibold mb-2">Йўналиш яратинг</h4>
            <p className="text-gray-600 text-sm">
              Хайдовчи йўналиш яратади, йўловчи излайди
            </p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">
              3
            </div>
            <h4 className="font-semibold mb-2">Брон қилинг</h4>
            <p className="text-gray-600 text-sm">
              Йўловчи таксини танлайди ва брон қилади
            </p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">
              4
            </div>
            <h4 className="font-semibold mb-2">Сафар қилинг</h4>
            <p className="text-gray-600 text-sm">
              Сафарни амалга оширинг ва тўловни амалга оширинг
            </p>
          </div>
        </div>
      </div>

      {/* Popular routes */}
      <div>
        <h2 className="text-3xl font-bold mb-8 text-center">Оммабоп йўналишлар</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            { from: 'Тошкент', to: 'Самарқанд', price: '40,000' },
            { from: 'Тошкент', to: 'Бухоро', price: '70,000' },
            { from: 'Фарғона', to: 'Андижон', price: '18,000' },
            { from: 'Қарши', to: 'Бухоро', price: '35,000' },
            { from: 'Самарқанд', to: 'Бухоро', price: '30,000' },
            { from: 'Тошкент', to: 'Фарғона', price: '45,000' }
          ].map((route, index) => (
            <div key={index} className="card">
              <div className="flex justify-between items-center mb-4">
                <div>
                  <h4 className="font-semibold">{route.from} → {route.to}</h4>
                  <p className="text-sm text-gray-500">1 ўрин учун</p>
                </div>
                <div className="text-xl font-bold text-blue-600">{route.price} сўм</div>
              </div>
              <a
                href={\`/search?fromRegion=\${route.from}&toRegion=\${route.to}\`}
                className="btn btn-primary w-full"
              >
                Такси излаш
              </a>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default HomePage;`,

  'frontend/src/App.jsx': `import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { AuthProvider, useAuth } from './hooks/useAuth'

// Components
import Header from './components/common/Header'
import Footer from './components/common/Footer'
import Login from './components/auth/Login'
import Register from './components/auth/Register'
import DriverDashboard from './components/driver/DriverDashboard'
import PassengerDashboard from './components/passenger/PassengerDashboard'
import SearchRide from './components/passenger/SearchRide'
import CreateRide from './components/driver/CreateRide'
import AdminPanel from './components/admin/AdminPanel'

// Pages
import HomePage from './pages/HomePage'

// Protected Route Component
const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth()
  
  if (loading) {
    return <div className="flex items-center justify-center h-screen">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
    </div>
  }
  
  if (!user) {
    return <Navigate to="/login" />
  }
  
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" />
  }
  
  return children
}

function AppContent() {
  return (
    <Router>
      <div className="min-h-screen flex flex-col bg-gray-50">
        <Header />
        <main className="flex-grow container mx-auto px-4 py-8">
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/search" element={<SearchRide />} />
            
            {/* Protected Routes - Passenger */}
            <Route path="/passenger/dashboard" element={
              <ProtectedRoute allowedRoles={['passenger']}>
                <PassengerDashboard />
              </ProtectedRoute>
            } />
            
            {/* Protected Routes - Driver */}
            <Route path="/driver/dashboard" element={
              <ProtectedRoute allowedRoles={['driver']}>
                <DriverDashboard />
              </ProtectedRoute>
            } />
            <Route path="/driver/create-ride" element={
              <ProtectedRoute allowedRoles={['driver']}>
                <CreateRide />
              </ProtectedRoute>
            } />
            
            {/* Protected Routes - Admin */}
            <Route path="/admin" element={
              <ProtectedRoute allowedRoles={['admin']}>
                <AdminPanel />
              </ProtectedRoute>
            } />
            
            {/* 404 */}
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </main>
        <Footer />
        <Toaster position="top-right" />
      </div>
    </Router>
  )
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}

export default App`,

  'frontend/src/hooks/useAuth.js': `import { useState, useEffect, createContext, useContext } from 'react'
import axios from 'axios'

const AuthContext = createContext({})

export const useAuth = () => useContext(AuthContext)

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [token, setToken] = useState(localStorage.getItem('token'))

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

  const api = axios.create({
    baseURL: API_URL,
    headers: {
      'Content-Type': 'application/json'
    }
  })

  api.interceptors.request.use(
    config => {
      const token = localStorage.getItem('token')
      if (token) {
        config.headers.Authorization = \`Bearer \${token}\`
      }
      return config
    },
    error => Promise.reject(error)
  )

  const login = async (phone, password) => {
    try {
      const response = await api.post('/auth/login', { phone, password })
      const { token, user } = response.data
      
      localStorage.setItem('token', token)
      setToken(token)
      setUser(user)
      
      return { success: true, user }
    } catch (error) {
      return { 
        success: false, 
        message: error.response?.data?.message || 'Логинда хатолик юз берди' 
      }
    }
  }

  const register = async (userData) => {
    try {
      const response = await api.post('/auth/register', userData)
      const { token, user } = response.data
      
      localStorage.setItem('token', token)
      setToken(token)
      setUser(user)
      
      return { success: true, user }
    } catch (error) {
      return { 
        success: false, 
        message: error.response?.data?.message || 'Рўйхатда хатолик юз берди' 
      }
    }
  }

  const logout = () => {
    localStorage.removeItem('token')
    setToken(null)
    setUser(null)
  }

  const getCurrentUser = async () => {
    try {
      const response = await api.get('/auth/me')
      setUser(response.data.user)
    } catch (error) {
      localStorage.removeItem('token')
      setToken(null)
      setUser(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (token) {
      getCurrentUser()
    } else {
      setLoading(false)
    }
  }, [token])

  const value = {
    user,
    loading,
    token,
    login,
    register,
    logout,
    api
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}`,

  'frontend/src/styles.css': `@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  body {
    @apply text-gray-800;
  }
  
  h1 {
    @apply text-3xl font-bold mb-4;
  }
  
  h2 {
    @apply text-2xl font-semibold mb-3;
  }
  
  h3 {
    @apply text-xl font-medium mb-2;
  }
}

@layer components {
  .btn {
    @apply px-4 py-2 rounded-lg font-medium transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2;
  }
  
  .btn-primary {
    @apply bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500;
  }
  
  .btn-secondary {
    @apply bg-gray-200 text-gray-800 hover:bg-gray-300 focus:ring-gray-400;
  }
  
  .btn-success {
    @apply bg-green-600 text-white hover:bg-green-700 focus:ring-green-500;
  }
  
  .btn-danger {
    @apply bg-red-600 text-white hover:bg-red-700 focus:ring-red-500;
  }
  
  .input {
    @apply w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent;
  }
  
  .card {
    @apply bg-white rounded-lg shadow-md p-6;
  }
  
  .badge {
    @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
  }
  
  .badge-success {
    @apply bg-green-100 text-green-800;
  }
  
  .badge-warning {
    @apply bg-yellow-100 text-yellow-800;
  }
  
  .badge-danger {
    @apply bg-red-100 text-red-800;
  }
  
  .badge-info {
    @apply bg-blue-100 text-blue-800;
  }
}

::-webkit-scrollbar {
  width: 8px;
}

::-webkit-scrollbar-track {
  @apply bg-gray-100;
}

::-webkit-scrollbar-thumb {
  @apply bg-gray-400 rounded-full;
}

::-webkit-scrollbar-thumb:hover {
  @apply bg-gray-500;
}`,

  'frontend/vite.config.js': `import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
})`,

  'frontend/package.json': `{
  "name": "uzoqtaxi-frontend",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext js,jsx --report-unused-disable-directives --max-warnings 0"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.1",
    "axios": "^1.3.4",
    "date-fns": "^2.29.3",
    "react-hot-toast": "^2.4.0",
    "react-icons": "^4.8.0",
    "tailwindcss": "^3.2.7"
  },
  "devDependencies": {
    "@types/react": "^18.0.28",
    "@types/react-dom": "^18.0.11",
    "@vitejs/plugin-react": "^3.1.0",
    "autoprefixer": "^10.4.14",
    "eslint": "^8.36.0",
    "eslint-plugin-react": "^7.32.2",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.3.4",
    "postcss": "^8.4.21",
    "vite": "^4.2.0"
  }
}`,

  '.env.example': `# Backend Environment Variables
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb://localhost:27017/uzoqtaxi
JWT_SECRET=your_jwt_secret_key_here_change_this
JWT_EXPIRE=7d
ADMIN_PHONE=998901234567
ADMIN_PASSWORD=admin123

# Frontend Environment Variables
VITE_API_URL=http://localhost:5000/api`,

  '.gitignore': `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.production

# Build outputs
dist/
build/
.out/
.next/

# Runtime data
*.pid
*.seed
*.pid.lock

# Coverage
coverage/
.nyc_output/

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Testing
.nyc_output/

# MongoDB
data/
mongod.log

# Temporary files
tmp/
temp/`,

  'README.md': `# UZOQTAXI - Вилоятлар аро такси хизмати

## Тавсиф

UZOQTAXI - вилоятлар аро такси катнови учун веб-платформа. Хайдовчи ва йўловчилар учун ишончли ва қулай интерфейс.

## Асосий функциялар

### Хайдовчилар учун:
- Йўналиш яратиш
- Нарх ва шартлар белгилаш
- Тўлов усулларини танлаш (нақд/Click)
- Бронларни бошқариш
- Линияга чиқиш пули тўлаш

### Йўловчилар учун:
- Такси излаш ва солиштириш
- Брон қилиш
- Ўз талабларини белгилаш
- Хайдовчиларни баҳолаш

### Админ учун:
- Барча фойдаланувчиларни назорат
- Статистика ва ҳисоботлар
- Тўловлар мониторинги
- Блоклаш ва тасдиқлаш

## Технологиялар

### Бекенд:
- Node.js + Express.js
- MongoDB + Mongoose
- JWT аутентификация
- Express Validator

### Фронтенд:
- React.js
- Tailwind CSS
- React Router
- Axios

## Ишга тушириш

### 1. Репозиторийни клонилаш
\`\`\`bash
git clone https://github.com/yourusername/uzoqtaxi-mvp.git
cd uzoqtaxi-mvp
\`\`\`

### 2. Бекендни ўрнатиш
\`\`\`bash
cd backend
npm install
cp .env.example .env
# .env файлни тўлдиринг
npm run dev
\`\`\`

### 3. Фронтендни ўрнатиш
\`\`\`bash
cd frontend
npm install
npm run dev
\`\`\`

### 4. MongoDB ни ишга тушириш
\`\`\`bash
# Ubuntu/Debian
sudo systemctl start mongod

# Mac
brew services start mongodb-community

# Windows
# MongoDB Compass ёки команд строка орқали
\`\`\`

## Тест учун маълумотлар

### Администратор:
- Телефон: 998901234567
- Парол: admin123

### Йўловчи:
- Телефон: 998901234568
- Парол: passenger123

### Хайдовчи:
- Телефон: 998901234569
- Парол: driver123

## API эндпоинтлар

### Аутентификация:
- \`POST /api/auth/register\` - Рўйхатдан ўтиш
- \`POST /api/auth/login\` - Кириш
- \`GET /api/auth/me\` - Жорий фойдаланувчи

### Йўналишлар:
- \`POST /api/rides\` - Йўналиш яратиш
- \`GET /api/rides/search\` - Йўналишларни излаш
- \`GET /api/rides/driver\` - Хайдовчи йўналишлари

### Бронлар:
- \`POST /api/bookings\` - Брон қилиш
- \`GET /api/bookings/driver\` - Хайдовчи бронлари
- \`GET /api/bookings/passenger\` - Йўловчи бронлари

### Админ:
- \`GET /api/admin/stats\` - Статистика
- \`GET /api/admin/users\` - Фойдаланувчилар
- \`GET /api/admin/drivers\` - Хайдовчилар
- \`GET /api/admin/rides\` - Йўналишлар
- \`GET /api/admin/bookings\` - Бронлар

## Лицензия
MIT Лицензияси

## Алоқа
- Телефон: +998 90 123 45 67
- Email: info@uzoqtaxi.uz
- Телеграм: @uzoqtaxi_support`
};

// Create directories and files
function createStructure() {
  console.log('📁 Папкалар ва файллар яратилмоқда...\n');
  
  let filesCreated = 0;
  let dirsCreated = 0;

  for (const [filePath, content] of Object.entries(structure)) {
    const fullPath = path.join(projectRoot, projectName, filePath);
    const dirPath = path.dirname(fullPath);

    // Create directory if it doesn't exist
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      dirsCreated++;
    }

    // Create file
fs.writeFileSync(fullPath, content, 'utf8');
filesCreated++;

console.log(`✅ ${filePath}`);
}

console.log(`\n🎉 Умумий ${dirsCreated} та папка ва ${filesCreated} та файл яратилди!`);
console.log(`📂 Лойиха манзили: ${path.join(projectRoot, projectName)}`);

return { filesCreated, dirsCreated };
}

// Create setup script
function createSetupScript() {
const setupScript = `#!/bin/bash

echo "🚀 UZOQTAMVP лойихаси ўрнатилмоқда..."

# Create project directory
mkdir -p uzoqtaxi-mvp
cd uzoqtaxi-mvp

echo "📁 Лойиха структураси яратилмоқда..."

# Create backend structure
mkdir -p backend/src/{config,controllers,middleware,models,routes,utils}
mkdir -p frontend/src/{components,components/{common,auth,driver,passenger,admin},pages,services,utils}

echo "✅ Структура яратилди"

# Copy files from template
echo "📋 Файллар нусхалаш учун скриптни ишга туширинг:"
echo "node create-uzoqtaxi.js"

echo ""
echo "📚 Кейинги қадамлар:"
echo "1. cd uzoqtaxi-mvp"
echo "2. node create-uzoqtaxi.js (ёки create-uzoqtaxi.js файлини ишга туширинг)"
echo "3. cd backend && npm install"
echo "4. cd ../frontend && npm install"
echo "5. MongoDB ни ишга туширинг"
echo "6. backend/.env файлни тўлдиринг"
echo "7. Иккала серверни ишга туширинг:"
echo "   - Бекенд: cd backend && npm run dev"
echo "   - Фронтенд: cd frontend && npm run dev"
echo ""
echo "🌐 Браузерда oching: http://localhost:3000"
`;

const scriptPath = path.join(projectRoot, 'setup-uzoqtaxi.sh');
fs.writeFileSync(scriptPath, setupScript, 'utf8');
fs.chmodSync(scriptPath, '755');

console.log(`\n📜 setup-uzoqtaxi.sh скрипти яратилди!`);
console.log(`🔧 Ишга тушириш: bash setup-uzoqtaxi.sh`);
}

// Create Windows batch script
function createWindowsScript() {
const batchScript = `@echo off
echo 🚀 UZOQTAXI MVP лойихаси ўрнатилмоқда...

REM Create project directory
mkdir uzoqtaxi-mvp
cd uzoqtaxi-mvp

echo 📁 Лойиха структураси яратилмоқда...

REM Create backend structure
mkdir backend\\src\\config
mkdir backend\\src\\controllers
mkdir backend\\src\\middleware
mkdir backend\\src\\models
mkdir backend\\src\\routes
mkdir backend\\src\\utils
mkdir frontend\\src\\components\\common
mkdir frontend\\src\\components\\auth
mkdir frontend\\src\\components\\driver
mkdir frontend\\src\\components\\passenger
mkdir frontend\\src\\components\\admin
mkdir frontend\\src\\pages
mkdir frontend\\src\\services
mkdir frontend\\src\\utils

echo ✅ Структура яратилди

echo.
echo 📚 Кейинги қадамлар:
echo 1. cd uzoqtaxi-mvp
echo 2. node create-uzoqtaxi.js
echo 3. cd backend && npm install
echo 4. cd ../frontend && npm install
echo 5. MongoDB ни ишга туширинг
echo 6. backend\\.env файлни тўлдиринг
echo 7. Иккала серверни ишга тушириш:
echo    - Бекенд: cd backend && npm run dev
echo    - Фронтенд: cd frontend && npm run dev
echo.
echo 🌐 Браузерда oching: http://localhost:3000
pause`;

const scriptPath = path.join(projectRoot, 'setup-uzoqtaxi.bat');
fs.writeFileSync(scriptPath, batchScript, 'utf8');

console.log(`📜 setup-uzoqtaxi.bat скрипти яратилди!`);
console.log(`🔧 Ишга тушириш: setup-uzoqtaxi.bat`);
}

// Main execution
try {
// Check if project already exists
const projectPath = path.join(projectRoot, projectName);
if (fs.existsSync(projectPath)) {
  console.log(`⚠️  '${projectName}' номли лойиха аллакачон мавжуд!`);
  const overwrite = process.argv.includes('--overwrite');
  if (!overwrite) {
    console.log('Илтимос, бошқа ном ёки --overwrite флагidan фойдаланинг');
    process.exit(1);
  }
  console.log('Қайта ёзилмоқда...');
}

// Create structure
const result = createStructure();

// Create setup scripts
createSetupScript();
createWindowsScript();

console.log('\n✨ UZOQTAXI MVP лойихаси муваффақиятли яратилди!');
console.log('\n📋 Кейинги қадамлар:');
console.log('1. 📂 Лойиха папкасига ўтиш:');
console.log(`   cd ${projectName}`);
console.log('\n2. ⚙️  Бекендни ўрнатиш:');
console.log('   cd backend');
console.log('   npm install');
console.log('   cp .env.example .env');
console.log('   # .env файлни тўлдиринг');
console.log('\n3. 🎨 Фронтендни ўрнатиш:');
console.log('   cd ../frontend');
console.log('   npm install');
console.log('\n4. 🗄️  MongoDB ни ишга тушириш');
console.log('\n5. 🚀 Серверларни ишга тушириш:');
console.log('   # Янаги терминалда:');
console.log('   cd backend && npm run dev');
console.log('   # Бошқа терминалда:');
console.log('   cd frontend && npm run dev');
console.log('\n6. 🌐 Браузерда oching: http://localhost:3000');
console.log('\n🔑 Тест учун маълумотлар:');
console.log('   Админ: 998901234567 / admin123');
console.log('   Йўловчи: 998901234568 / passenger123');
console.log('   Хайдовчи: 998901234569 / driver123');
console.log(`\n🎉 Умумда ${result.filesCreated} та файл яратилди!`);

} catch (error) {
console.error('❌ Хатолик юз берди:', error.message);
process.exit(1);
}