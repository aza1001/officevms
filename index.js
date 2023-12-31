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

const dbName = 'officevms';
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

app.get('/', (req, res) => {
   res.send('Hello World!')
})

/**
 * @swagger
 * /register-staff:
 *   post:
 *     summary: Register a new staff member (Security Authorization Required).
 *     parameters:
 *       - in: header
 *         name: authorization
 *         type: string
 *         required: true
 *         description: The security token for authorization.
 *       - in: body
 *         name: body
 *         description: Staff registration details.
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *               description: The username for the new staff member.
 *             password:
 *               type: string
 *               description: The password for the new staff member.
 *           required:
 *             - username
 *             - password
 *     responses:
 *       201:
 *         description: Successfully registered a new staff member.
 *         schema:
 *           type: object
 *           properties:
 *             token:
 *               type: string
 *       400:
 *         description: Bad request, username already exists.
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *       401:
 *         description: Unauthorized, invalid security token.
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               example: Invalid security token
 *       403:
 *         description: Forbidden, only security can register new staff.
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               example: Permission denied
 *       500:
 *         description: Internal Server Error.
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               example: Internal Server Error
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

    // Log the result
    console.log('MongoDB Insert Result:', result);

    // Generate JWT token
    const token = jwt.sign({ username, role: 'staff' }, secretKey);

    // Update the staff member with the token
    await staffDB.updateOne({ username }, { $set: { token } });

    res.status(201).json({ token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
});

/**
 * @swagger
 * /register-security:
 *   post:
 *     summary: Register a new security member
 *     parameters:
 *       - in: body
 *         name: body
 *         description: Security registration details
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *             password:
 *               type: string
 *           required:
 *             - username
 *             - password
 *     responses:
 *       200:
 *         description: Successfully registered a new security member
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Security registered successfully
 *       409:
 *         description: Conflict, username already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Username already exists
 *       500:
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error registering security
 */


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

/**
 * @swagger
 * /login-staff:
 *   post:
 *     summary: Authenticate and login a staff member.
 *     parameters:
 *       - in: body
 *         name: body
 *         description: Staff login details.
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *               description: The username of the staff member.
 *             password:
 *               type: string
 *               description: The password of the staff member.
 *           required:
 *             - username
 *             - password
 *     responses:
 *       200:
 *         description: Successfully logged in. Returns a JWT token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid credentials.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid credentials
 *       500:
 *         description: Internal Server Error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error storing token
 */


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

/**
 * @swagger
 * /login-security:
 *   post:
 *     summary: Authenticate and login a security member.
 *     parameters:
 *       - in: body
 *         name: body
 *         description: Security login details.
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *               description: The username of the security member.
 *             password:
 *               type: string
 *               description: The password of the security member.
 *           required:
 *             - username
 *             - password
 *     responses:
 *       200:
 *         description: Successfully logged in. Returns a JWT token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid credentials.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid credentials
 *       500:
 *         description: Internal Server Error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error storing token
 */


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

/**
 * @swagger
 * /appointments:
 *   post:
 *     summary: Create a new appointment.
 *     parameters:
 *       - in: body
 *         name: body
 *         description: Appointment details.
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *               description: Name of the person making the appointment.
 *             company:
 *               type: string
 *               description: Company of the person making the appointment.
 *             purpose:
 *               type: string
 *               description: Purpose of the appointment.
 *             phoneNo:
 *               type: string
 *               description: Phone number of the person making the appointment.
 *             date:
 *               type: string
 *               format: date
 *               description: Date of the appointment (YYYY-MM-DD).
 *             time:
 *               type: string
 *               format: time
 *               description: Time of the appointment (HH:MM).
 *             verification:
 *               type: string
 *               description: Verification status (N/A for non-editable).
 *             staff:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *                   description: Username of the staff member handling the appointment.
 *           required:
 *             - name
 *             - company
 *             - purpose
 *             - phoneNo
 *             - date
 *             - time
 *             - verification
 *             - staff
 *     responses:
 *       200:
 *         description: Appointment created successfully.
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Appointment created successfully
 *       500:
 *         description: Internal Server Error.
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               example: Error creating appointment
 */


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

/**
 * @swagger
 * /staff-appointments/{username}:
 *   get:
 *     summary: Get appointments for a staff member.
 *     parameters:
 *       - in: header
 *         name: authorization
 *         type: string
 *         required: true
 *         description: The security token for authorization.
 *       - in: path
 *         name: username
 *         description: The username of the staff member.
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Successfully retrieved staff appointments.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                   company:
 *                     type: string
 *                   purpose:
 *                     type: string
 *                   phoneNo:
 *                     type: string
 *                   date:
 *                     type: string
 *                     format: date
 *                   time:
 *                     type: string
 *                     format: time
 *                   verification:
 *                     type: boolean
 *                   staff:
 *                     type: object
 *                     properties:
 *                       username:
 *                         type: string
 *               example:
 *                 - name: John Doe
 *                   company: ABC Inc.
 *                   purpose: Meeting
 *                   phoneNo: +1234567890
 *                   date: '2023-01-01'
 *                   time: '09:00:00'
 *                   verification: true
 *                   staff:
 *                     username: staffuser
 *       403:
 *         description: Invalid or unauthorized token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid or unauthorized token
 *       500:
 *         description: Internal Server Error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error retrieving appointments
 */

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
