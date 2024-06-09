const express = require('express');
const app = express();
const port = 3000;
const initializeDataBase = require('./database/database.js');
const routes = require('./routes'); //Rutas del back
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database("database/db.sqlite");
const cors = require('cors');

app.use(express.json());
app.use(cors());

// Usa las rutas definidas en routes.js
app.use('/api', routes);

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
  initializeDataBase(db);
});
