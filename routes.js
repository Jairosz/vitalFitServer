const express = require('express'); // IMPORT DE EXPRESS
const router = express.Router(); // ROUTER
const sqlite3 = require('sqlite3').verbose();  // SQLITE IMPORT
const db = new sqlite3.Database("database/db.sqlite"); // RUTA DE LA DB
const bcrypt = require('bcrypt'); // ENCRIPTAR PWD
const jwt = require('jsonwebtoken');  // TOKEN PARA AUTH

const SECRET_KEY = 'BYPASS'; // Clave secreta segura 

// Middleware de autenticación
function authenticateToken(req, res, next) {
    if (!req.header('authorization')) {
        return res.status(401).json({ error: 'Acceso denegado. No se proporcionó ningún token.' });
    }
    const token = req.header('authorization').split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Acceso denegado. No se proporcionó ningún token.' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido.' });
        }

        req.user = user;
        next();
    });
}

// Middleware para verificar si el usuario es administrador
function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'No tienes permisos para realizar esta acción' });
    }
}

// Ruta para registrar un usuario
router.post('/signup', async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        // Verificar si el email ya está registrado
        db.get('SELECT email FROM USUARIOS WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (row) {
                // El email ya está registrado
                return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
            }

            // Hashear la contraseña y registrar el nuevo usuario
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(`INSERT INTO USUARIOS (name, email, password, role) VALUES (?, ?, ?, ?)`, [name, email, hashedPassword, role || 'user'], function (err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ id: this.lastID });
            });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Ruta para hacer login

router.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM USUARIOS WHERE email = ?`, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }
        try {
            if (await bcrypt.compare(password, user.password)) {
                const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '24h' });

                const response = {
                    token: token,
                    message: `Bienvenido, ${user.name}!`,
                    expiresIn: '24h',
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role,
                        profilePicture: user.pfp 
                    }
                };

                res.json(response);
            } else {
                res.status(401).json({ error: 'Contraseña incorrecta' });
            }
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
});

// Ruta para crear un usuario de forma MANUAL (ADMIN) - token y verificar si es admin
router.post('/users', authenticateToken, isAdmin, (req, res) => {
    const { name, email, password, role } = req.body;
    db.run(`INSERT INTO USUARIOS (name, email, password, role) VALUES (?, ?, ?, ?)`, [name, email, password, role || 'user'], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID });
    });
});

// Ruta para crear un ejercicio -  token
router.post('/exercises', authenticateToken, (req, res) => {
    const { user_id, date, type, weight, repetitions } = req.body;
    const { id } = req.user;

    db.run(`INSERT INTO EJERCICIOS (user_id, date, type, weight, repetitions) VALUES (?, ?, ?, ?, ?)`, [id, date, type, weight, repetitions], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID });
    });
});

// Ruta para crear una dieta - token
router.post('/diets', authenticateToken, (req, res) => {
    const { name } = req.body;
    const { id } = req.user;

    db.run(`INSERT INTO DIETAS (user_id, name) VALUES (?, ?)`, [id, name], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID });
    });
});

// Ruta para crear una comida -token
router.post('/meals', authenticateToken, (req, res) => {
    const { name, description, long_description, kcal, proteins, carbohydrates, fats, fiber, vitamins, minerals, image, shared } = req.body;
    const { id } = req.user;
    db.run(`INSERT INTO COMIDAS (user_id, name, description, long_description, kcal, proteins, carbohydrates, fats, fiber, vitamins, minerals, image, shared) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, name, description, long_description, kcal, proteins, carbohydrates, fats, fiber, vitamins, minerals, image, shared || false], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID });
        });
});
router.post('/diet-meals', authenticateToken, (req, res) => {
    const { dieta_id, slotComida1_id, slotComida2_id, slotComida3_id, slotComida4_id, slotComida5_id, slotComida6_id, slotComida7_id, day_of_week, meal_type } = req.body;
    db.run(`INSERT INTO DIETA_COMIDAS (dieta_id, slotComida1_id, slotComida2_id, slotComida3_id, slotComida4_id, slotComida5_id, slotComida6_id, slotComida7_id, day_of_week, meal_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [dieta_id, slotComida1_id, slotComida2_id, slotComida3_id, slotComida4_id, slotComida5_id, slotComida6_id, slotComida7_id, day_of_week, meal_type], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: "Comida añadida a la dieta exitosamente!" });
        });
});

// Ruta protegida de ejemplo - token
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Este es un recurso protegido', user: req.user });
});

// Ruta para eliminar un usuario -token y verificar si es admin
router.delete('/users/:id', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM USUARIOS WHERE id = ?`, [id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Usuario eliminado' });
    });
});

// Ruta para actualizar un usuario -  token y verificar si es admin
router.put('/users/:id', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    const { name, email, password, role } = req.body;
    db.run(`UPDATE USUARIOS SET name = ?, email = ?, password = ?, role = ? WHERE id = ?`, [name, email, password, role, id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Usuario actualizado' });
    });
});
//  GET para obtener información de un usuario
router.get('/users/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.get(`SELECT id, name, email, role, pfp FROM USUARIOS WHERE id = ?`, [id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json(user);
    });
});
//  update información de un usuario

router.put('/users/update/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, pfp } = req.body;
    db.run(`UPDATE USUARIOS SET name = ?, pfp = ? WHERE id = ?`, [name,pfp, id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Usuario actualizado' });
    });
});
// Ruta para obtener comidas compartidas con el nombre del usuario que las creó
router.get('/shared_meals', authenticateToken, (req, res) => {
    const query = `
        SELECT C.*, U.name as username
        FROM COMIDAS C
        JOIN USUARIOS U ON C.user_id =
 U.id
        WHERE C.shared = 1
    `;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
 });
// Ruta para obtener comidas  del usuario 
router.get('/user_meals', authenticateToken, (req, res) => {
    const userId = req.user.id; 

    db.all(`SELECT  * FROM COMIDAS WHERE user_id = ?`, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Ruta para eliminar un usuario - token y verificar si es admin
router.delete('/users/:id', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM USUARIOS WHERE id = ?`, [id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Usuario eliminado' });
    });
});
// Ruta para actualizar un usuario -  token y verificar si es admin
router.put('/users/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`UPDATE USUARIOS SET name = ?, email = ?, password = ?, role = ? WHERE id = ?`, [name, email, hashedPassword, role, id], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Usuario actualizado' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// Ruta para eliminar una comida -  token y verificar si es admin
router.delete('/meals/:id', authenticateToken,(req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM COMIDAS WHERE id = ?`, [id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Comida eliminada' });
    });
});
// Ruta para actualizar una comida - token 
router.put('/meals/:id', authenticateToken,(req, res) => {
    const { id } = req.params;
    const { name, description, long_description, kcal, proteins, carbohydrates, fats, fiber, vitamins, minerals, image, shared } = req.body;
    db.run(`UPDATE COMIDAS SET name = ?, description = ?, long_description = ?, kcal = ?, proteins = ?, carbohydrates = ?, fats = ?, fiber = ?, vitamins = ?, minerals = ?, image = ?, shared = ? WHERE id = ?`,
        [name, description, long_description, kcal, proteins, carbohydrates, fats, fiber, vitamins, minerals, image, shared, id], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Comida actualizada' });
        });
});
// Ruta para obtener todos los ejercicios - 
router.get('/exercises', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM EJERCICIOS`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});
// Ruta para obtener ejercicios por nombre - 
router.get('/exercises/search', authenticateToken, (req, res) => {
    const { name } = req.query;
    db.all(`SELECT * FROM EJERCICIOS WHERE type LIKE ?`, [`%${name}%`], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

module.exports = router;

