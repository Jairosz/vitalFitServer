function initializeDataBase(db) {
    // Crear la tabla de usuarios
    db.run(`CREATE TABLE IF NOT EXISTS USUARIOS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        pfp TEXT,
        role TEXT NOT NULL DEFAULT 'user'
    )`, err => {
        if (err) {
            console.error('Error al crear la tabla de usuarios', err);
        } else {
            console.log('Tabla de usuarios creada o ya existente');
        }
    });

    // Crear la tabla de ejercicios
    db.run(`CREATE TABLE IF NOT EXISTS EJERCICIOS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date DATE NOT NULL,
        type TEXT NOT NULL,
        weight INTEGER NOT NULL,
        repetitions INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES USUARIOS(id)
    )`, err => {
        if (err) {
            console.error('Error al crear la tabla de EJERCICIOS', err);
        } else {
            console.log('Tabla de EJERCICIOS creada o ya existente');
        }
    });

    // Crear la tabla de dietas
    db.run(`CREATE TABLE IF NOT EXISTS DIETAS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        description TEXT,
        FOREIGN KEY(user_id) REFERENCES USUARIOS(id)

     );`, err => {
        if (err) {
            console.error('Error al crear la tabla de DIETAS', err);
        } else {
            console.log('Tabla de DIETAS creada o ya existente');
        }
    });

    db.run(`CREATE TABLE IF NOT EXISTS COMIDAS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT,
        description TEXT,
        long_description TEXT,
        kcal INTEGER,
        proteins INTEGER,
        carbohydrates INTEGER,
        fats INTEGER,
        fiber INTEGER,
        vitamins TEXT,
        minerals TEXT,
        image TEXT,
        shared BOOLEAN,
        FOREIGN KEY(user_id) REFERENCES users(id)
     );`, err => {
        if (err) {
            console.error('Error al crear la tabla de COMIDAS', err);
        } else {
            console.log('Tabla de COMIDAS modificada o ya existente');
        }
     });

    // Crear la tabla intermedia diet_meals
    db.run(`CREATE TABLE IF NOT EXISTS DIETA_COMIDAS (
        dieta_id INTEGER,
        slotComida1_id INTEGER,
        slotComida2_id INTEGER,
        slotComida3_id INTEGER,
        slotComida4_id INTEGER, 
        slotComida5_id INTEGER,
        slotComida6_id INTEGER,
        slotComida7_id INTEGER,
        day_of_week INTEGER,
        FOREIGN KEY (dieta_id) REFERENCES DIETAS(id),
        FOREIGN KEY (slotComida1_id) REFERENCES COMIDAS(id)
        FOREIGN KEY (slotComida2_id) REFERENCES COMIDAS(id)
        FOREIGN KEY (slotComida3_id) REFERENCES COMIDAS(id)
        FOREIGN KEY (slotComida4_id) REFERENCES COMIDAS(id)
        FOREIGN KEY (slotComida5_id) REFERENCES COMIDAS(id)
        FOREIGN KEY (slotComida6_id) REFERENCES COMIDAS(id)
        FOREIGN KEY (slotComida7_id) REFERENCES COMIDAS(id)
     );`, err => {
        if (err) {
            console.error('Error al crear la tabla intermedia DIETA_COMIDAS', err);
        } else {
            console.log('Tabla intermedia diet_meals creada o ya existente');
        }
    });
}

module.exports = initializeDataBase;
