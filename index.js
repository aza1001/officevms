const express = require('express')
const mongodb = require('mongodb')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const swaggerJsdoc = require('swagger-jsdoc')
const swaggerUi = require('swagger-ui-express')

const app = express()
const port = process.env.PORT || 3000;
const secretKey = 'officeapt';

app.use(express.json())

// MongoDB connection URL
const mongoURL =
  'mongodb+srv://aza:mongoaza@officevms.tilw1nt.mongodb.net/?retryWrites=true&w=majority';

const dbName = 'office appointment';
const staffCollection = 'staff';
const securityCollection = 'security';
const appointmentCollection = 'appointments';

let staffDB, securityDB, appointmentDB;

// MongoDB connection
mongodb.MongoClient.connect(mongoURL, { useUnifiedTopology: true })
  .then((client) => {
    const db = client.db(dbName);
    staffDB = db.collection(staffCollection);
    securityDB = db.collection(securityCollection);
    appointmentDB = db.collection(appointmentCollection);
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });

// Middleware for authentication and authorization
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Missing token');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid or expired token');
    }
    req.user = user;
    next();
  });
};

// HELLO WORLD
/**
 * @swagger
 * /:
 *   get:
 *     summary: Returns a simple "Hello World!" message.
 *     responses:
 *       200:
 *         description: Successful response with the message.
 */

app.get('/', (req, res) => {
   res.send('Hello World!')
})

/**
 * @swagger
 * /register-staff:
 *   post:
 *     summary: Register a new staff member
 *     requestBody:
 *       description: Staff registration details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *     responses:
 *       201:
 *         description: Successfully registered a new staff member
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       400:
 *         description: Bad request, username already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       500:
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *     parameters: []  # Add an empty parameters array to indicate no path/query parameters
 */

app.post('/register-staff', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the username already exists
    const existingStaff = await staffDB.findOne({ username });
    if (existingStaff) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new staff member
    const result = await staffDB.insertOne({
      username,
      password: hashedPassword,
    });

    // Generate JWT token
    const token = jwt.sign({ username, role: 'staff' }, secretKey);

    // Update the staff member with the token
    await staffDB.updateOne({ username }, { $set: { token } });

    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Register security
app.post('/register-security', async (req, res) => {
  const { username, password } = req.body;

  const existingSecurity = await securityDB.findOne({ username });

  if (existingSecurity) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const security = {
    username,
    password: hashedPassword,
  };

  securityDB
    .insertOne(security)
    .then(() => {
      res.status(200).send('Security registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering security');
    });
});

// Staff login
app.post('/login-staff', async (req, res) => {
  const { username, password } = req.body;

  const staff = await staffDB.findOne({ username });

  if (!staff) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, staff.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username, role: 'staff' }, secretKey);
  staffDB
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

// Security login
app.post('/login-security', async (req, res) => {
  const { username, password } = req.body;

  const security = await securityDB.findOne({ username });

  if (!security) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, security.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = security.token || jwt.sign({ username, role: 'security' }, secretKey);
  securityDB
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

// Create appointment
app.post('/appointments', async (req, res) => {
  const {
    name,
    company,
    purpose,
    phoneNo,
    date,
    time,
    verification,
    staff: { username },
  } = req.body;

  const appointment = {
    name,
    company,
    purpose,
    phoneNo,
    date,
    time,
    verification,
    staff: { username },
  };

  appointmentDB
    .insertOne(appointment)
    .then(() => {
      res.status(200).send('Appointment created successfully');
    })
    .catch((error) => {
      res.status(500).send('Error creating appointment');
    });
});

// Get staff's appointments
app.get('/staff-appointments/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  const { role, username: authenticatedUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  if (username !== authenticatedUsername) {
    return res.status(403).send('Invalid or unauthorized token');
  }

  appointmentDB
    .find({ 'staff.username': username })
    .toArray()
    .then((appointments) => {
      res.json(appointments);
    })
    .catch((error) => {
      res.status(500).send('Error retrieving appointments');
    });
});

// Update appointment verification by visitor name
app.put('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { verification } = req.body;
  const { role, username: authenticatedUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  // Find the appointment by name and staff username
  const appointment = await appointmentDB.findOne({ name, 'staff.username': authenticatedUsername });

  if (!appointment) {
    return res.status(404).send('Appointment not found');
  }

  // Update the verification only if the staff member matches the creator
  appointmentDB
    .updateOne({ name, 'staff.username': authenticatedUsername }, { $set: { verification } })
    .then(() => {
      res.status(200).send('Appointment verification updated successfully');
    })
    .catch((error) => {
      res.status(500).send('Error updating appointment verification');
    });
});

// Delete appointment
app.delete('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { role } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  appointmentDB
    .deleteOne({ name })
    .then(() => {
      res.status(200).send('Appointment deleted successfully');
    })
    .catch((error) => {
      res.status(500).send('Error deleting appointment');
    });
});

// Get all appointments (for security)
app.get('/appointments', authenticateToken, async (req, res) => {
  const { name } = req.query;
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  const filter = name ? { name: { $regex: name, $options: 'i' } } : {};

  appointmentDB
    .find(filter)
    .toArray()
    .then((appointments) => {
      res.json(appointments);
    })
    .catch((error) => {
      res.status(500).send('Error retrieving appointments');
    });
});

// Logout
app.post('/logout', authenticateToken, async (req, res) => {
  const { role } = req.user;

  // Depending on the role (staff or security), update the corresponding collection (staffDB or securityDB)
  if (role === 'staff') {
    staffDB
      .updateOne({ username: req.user.username }, { $unset: { token: 1 } })
      .then(() => {
        res.status(200).send('Logged out successfully');
      })
      .catch(() => {
        res.status(500).send('Error logging out');
      });
  } else if (role === 'security') {
    securityDB
      .updateOne({ username: req.user.username }, { $unset: { token: 1 } })
      .then(() => {
        res.status(200).send('Logged out successfully');
      })
      .catch(() => {
        res.status(500).send('Error logging out');
      });
  } else {
    res.status(500).send('Invalid role');
  }
});

// Swagger setup
const options = {
  swaggerDefinition: {
    info: {
      title: 'Office Appointment Management',
      version: '1.0.0',
      description: 'API documentation for my application',
    },
  },
  apis: ['index.js'], 
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})
