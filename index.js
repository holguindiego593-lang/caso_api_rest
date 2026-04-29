import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());


const users = [];
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';


app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    
    res.status(201).json({ message: 'Usuario registrado' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === useername);

    if (user && await bcrypt.compare(password, user.password)) {
        
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: 'Credenciales inválidas' });
    }
});

app.get('/dashboard', authenticateToken, (req, res) => {
    res.json({ message: `Bienvenido ${req.user.username}, esta es una ruta protegida` });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Token requerido' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
}

const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
