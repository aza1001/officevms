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
    return res.status(401).send('Invalid or unauthorized token');
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
 *     summary: Register a new staff member
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         type: string
 *         required: true
 *         description: The security token for authorization.
 *       - in: body
 *         name: body
 *         description: Staff registration details
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
 *         description: Successfully registered a new staff member
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Staff registered successfully
 *       403:
 *         description: Invalid or unauthorized token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid or unauthorized token
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
 *                   example: Error registering staff
 */


app.post('/register-staff', authenticateToken, async (req, res) => {
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  const { username, password } = req.body;

  const existingStaff = await staffDB.findOne({ username });

  if (existingStaff) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const staff = {
    username,
    password: hashedPassword,
  };

  staffDB
    .insertOne(staff)
    .then(() => {
      res.status(200).send('Staff registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering staff');
    });
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
 *      - in: header
 *        name: authorization
 *        type: string
 *        required: true
 *        description: The staff token for authorization.
 *      - in: path
 *        name: username
 *        description: The username of the staff member.
 *        required: true
 *        schema:
 *          type: string
 *     responses:
 *       200:
 *         description: List of appointments for the staff member.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                     description: The name for the appointment.
 *                   company:
 *                     type: string
 *                     description: The company associated with the appointment.
 *                   purpose:
 *                     type: string
 *                     description: The purpose of the appointment.
 *                   phoneNo:
 *                     type: string
 *                     description: The phone number associated with the appointment.
 *                   date:
 *                     type: string
 *                     format: date
 *                     description: The date of the appointment.
 *                   time:
 *                     type: string
 *                     format: time
 *                     description: The time of the appointment.
 *                   verification:
 *                     type: boolean
 *                     description: The verification status of the appointment.
 *                 required:
 *                   - name
 *                   - company
 *                   - purpose
 *                   - phoneNo
 *                   - date
 *                   - time
 *                   - verification
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

/**
 * @swagger
 * /appointments/{name}:
 *   put:
 *     summary: Update appointment verification status by visitor name.
 *     parameters:
 *       - in: path
 *         name: name
 *         description: The name of the visitor associated with the appointment.
 *         required: true
 *         schema:
 *           type: string
 *       - in: body
 *         name: body
 *         description: Appointment verification details.
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             verification:
 *               type: boolean
 *           required:
 *             - verification
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Appointment verification status updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Appointment verification updated successfully
 *       403:
 *         description: Invalid or unauthorized token or appointment not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid or unauthorized token or appointment not found
 *       500:
 *         description: Internal Server Error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error updating appointment verification
 */


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

/**
 * @swagger
 * /appointments/{name}:
 *   delete:
 *     summary: Delete appointment by visitor name.
 *     parameters:
 *       - in: path
 *         name: name
 *         description: The name of the visitor associated with the appointment.
 *         required: true
 *         schema:
 *           type: string
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Appointment deleted successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Appointment deleted successfully
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
 *                   example: Error deleting appointment
 */


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

/**
 * @swagger
 * /appointments:
 *   get:
 *     summary: Get all appointments (for security).
 *     parameters:
 *       - in: header 
 *         name: Authorization
 *         type: string
 *         required: true
 *         description: The security token for authorization.
 *       - in: query
 *         name: name
 *         description: Filter appointments by visitor name (case-insensitive).
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of appointments.
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
 *                   verification:
 *                     type: boolean
 *                   staff:
 *                     type: object
 *                     properties:
 *                       username:
 *                         type: string
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

// Get all appointments (for security)
app.get('/appointments', authenticateToken, async (req, res) => {
  const { name } = req.query;
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  const filter = name ? { name: name } : {};

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

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: Logout (invalidate token).
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully logged out.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Logged out successfully
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
 *                   example: Error logging out
 */


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
