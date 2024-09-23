const express = require('express');
const { MongoClient } = require('mongodb');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const uri = process.env.MONGODB_URI || "mongodb+srv://admin:123senac@conecta.rqjpi.mongodb.net/?retryWrites=true&w=majority&appName=Conecta";

let db;
MongoClient.connect(uri)
    .then(client => {
        db = client.db('conectaDB');
        console.log('Conectado ao MongoDB Atlas');
    })
    .catch(error => console.error(error));

function generateToken(user) {
    return jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
    const token = req.cookies.authToken;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Acesso negado. Token não fornecido.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Token inválido.' });
        }

        req.user = user;
        next();
    });
}

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
});

app.post('/register', (req, res) => {
    if (!db) {
        return res.json({ success: false, message: 'Erro ao conectar ao banco de dados.' });
    }

    const { username, password } = req.body;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.json({ success: false, message: 'Erro ao processar a senha.' });
        }

        const collection = db.collection('users');
        collection.insertOne({ username, password: hashedPassword })
            .then(result => {
                res.json({ success: true, message: 'Usuário cadastrado com sucesso!' });
            })
            .catch(error => {
                res.json({ success: false, message: 'Erro ao cadastrar o usuário.' });
                console.error(error);
            });
    });
});

app.post('/login', (req, res) => {
    if (!db) {
        return res.json({ success: false, message: 'Erro ao conectar ao banco de dados.' });
    }

    const { username, password } = req.body;

    const collection = db.collection('users');
    collection.findOne({ username })
        .then(user => {
            if (!user) {
                return res.redirect('/login-error');
            }

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return res.json({ success: false, message: 'Erro ao comparar a senha.' });
                }

                if (result) {
                    const token = generateToken(user);

                    res.cookie('authToken', token, { httpOnly: true, secure: false, maxAge: 3600000 }); // 1 hora
                    res.redirect('/logado');
                } else {
                    res.redirect('/login-error');
                }
            });
        })
        .catch(error => {
            res.json({ success: false, message: 'Erro ao realizar login.' });
            console.error(error);
        });
});


// Rota protegida para pacote1.html
app.get('/pacote1', authenticateToken, (req, res) => {
    res.sendFile(__dirname + '/public/pacote1.html');
});

app.get('/login-error', (req, res) => {
    res.sendFile(__dirname + '/public/error.html');
});

app.get('/logado', authenticateToken, (req, res) => {
    res.sendFile(__dirname + '/public/logado.html');
});
 
app.get('/home', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});
 
// rota do usuário
app.get('/get-username', authenticateToken, (req, res) => {
    res.json({ username: req.user.username });
});
 
 
// Rota protegida para pacotes com parâmetros dinâmicos
app.get('/:setor', authenticateToken, (req, res) => {
    const setor = req.params.setor;
 
    // Mapeia o setor para o arquivo HTML correspondente
    const pacotes = {
        'imobiliario': '/public/pacote1.html',
        'automotivo': '/pacotes/pacote2.html',
        'agro': '/pacotes/pacote3.html',
        'beleza-cosmeticos': '/pacotes/pacote4.html',
        'construcao': '/pacotes/pacote5.html',
        'tecnologia': '/pacotes/pacote6.html',
        'turismo-hotelaria': '/pacotes/pacote7.html',
        'petshop': '/pacotes/pacote8.html',
        'fitness': '/pacotes/pacote9.html'
    };
 
    const filePath = pacotes[setor];
 
    if (filePath) {
        res.sendFile(__dirname + filePath);
    } else {
        res.sendFile(__dirname + '/public/error.html'); // isso é bug
    }
});
 
// Rota protegida para cobrar com parâmetros dinâmicos
app.get('/cobrar/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
 
    // Mapeia o id para o arquivo HTML correspondente
    const cobrarPaginas = {
        '100': '/public/100.html',
        '110': '/public/110.html',
        '120': '/public/120.html',
        '130': '/public/130.html'
    };
 
    const filePath = cobrarPaginas[id];
 
    if (filePath) {
        res.sendFile(__dirname + filePath);
    } else {
        res.redirect('/home');
    }
});
 
 
app.get('/login-error', (req, res) => {
    res.sendFile(__dirname + '/public/error.html');
});
 
app.get('/logout', (req, res) => {
    res.clearCookie('authToken'); // Limpa o cookie ao fazer logout
    res.redirect('/login');
});
 
 
app.get('/check-token', (req, res) => {
    const token = req.cookies.authToken; // Obter o token do cookie
 
    if (token) {
        res.json({ success: true, message: 'Token encontrado!', token: token });
    } else {
        res.json({ success: false, message: 'Nenhum token encontrado.' });
    }
});

app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
