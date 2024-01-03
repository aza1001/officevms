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

