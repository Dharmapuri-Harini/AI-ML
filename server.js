const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = 5000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join( __dirname, 'views')));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'QRcode'
});

db.connect((err) => {
    if (err) throw err;
    console.log('connected to database');
});
require('./route')(app,db,bcrypt);

app.listen(port, ()=>{
    console.log(`Server running on port ${port}`);
});