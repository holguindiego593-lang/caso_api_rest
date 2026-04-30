import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

const users = [];

const SECRET_KEY = process.env.SECRET_KEY || "secreto123";

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validar datos
        if (!username || !password) {
            return res.status(400).json({ message: 'Datos incompletos' });
        }

        const userExists = users.find(u => u.username === username);
        if (userExists) {
            return res.status(400).json({ message: 'El usuario ya existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        users.push({
            username,
            password: hashedPassword
        });

        res.status(201).json({ message: 'Usuario registrado correctamente' });

    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Buscar usuario
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(401).json({ message: 'Usuario no encontrado' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        const token = jwt.sign(
            { username: user.username },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Autenticación exitosa',
            token
        });

    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(403).json({ message: 'Token requerido' });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        req.user = user;
        next();
    });
}

app.get('/protected', verifyToken, (req, res) => {
    res.json({
        message: 'Acceso permitido',
        user: req.user
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
