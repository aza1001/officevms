const express = require('express')
const mongodb = require('mongodb')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

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

// MongoDB connection
mongodb.MongoClient.connect(mongoURL, { useUnifiedTopology: true })
  .then((client) => {
    const db = client.db(dbName);
    const staffDB = db.collection(staffCollection);
    const securityDB = db.collection(securityCollection);
    const appointmentDB = db.collection(appointmentCollection);
  })

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



app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})
