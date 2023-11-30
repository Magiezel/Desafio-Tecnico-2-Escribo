const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

// Mock database for user persistence
const users = [];

app.use(bodyParser.json());

// Middleware para verificar o token de autenticação
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ mensagem: 'Não autorizado' });
  }

  jwt.verify(token.replace('Bearer ', ''), 'secret_key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ mensagem: 'Sessão inválida' });
    }
    req.user = decoded;
    next();
  });
};

// Endpoint para cadastro (Sign Up)
app.post('/signup', (req, res) => {
  const { nome, email, senha, telefones } = req.body;

  // Verifica se o e-mail já está cadastrado
  if (users.some(user => user.email === email)) {
    return res.status(400).json({ mensagem: 'E-mail já existente' });
  }

  const id = generateId();
  const data_criacao = new Date();
  const data_atualizacao = data_criacao;
  const ultimo_login = data_criacao;
  const token = generateToken(id);

  const newUser = {
    id,
    nome,
    email,
    senha: hashPassword(senha),
    telefones,
    data_criacao,
    data_atualizacao,
    ultimo_login,
    token,
  };

  users.push(newUser);

  res.status(201).json({
    id: newUser.id,
    data_criacao: newUser.data_criacao,
    data_atualizacao: newUser.data_atualizacao,
    ultimo_login: newUser.ultimo_login,
    token: newUser.token,
  });
});

// Endpoint para autenticação (Sign In)
app.post('/signin', (req, res) => {
  const { email, senha } = req.body;

  const user = users.find(user => user.email === email);

  if (!user || !bcrypt.compareSync(senha, user.senha)) {
    return res.status(401).json({ mensagem: 'Usuário e/ou senha inválidos' });
  }

  user.ultimo_login = new Date();
  user.token = generateToken(user.id);

  res.json({
    id: user.id,
    data_criacao: user.data_criacao,
    data_atualizacao: user.data_atualizacao,
    ultimo_login: user.ultimo_login,
    token: user.token,
  });
});

// Endpoint para buscar usuário autenticado
app.get('/me', verifyToken, (req, res) => {
  const user = users.find(user => user.id === req.user.id);

  res.json({
    id: user.id,
    nome: user.nome,
    email: user.email,
    telefones: user.telefones,
    data_criacao: user.data_criacao,
    data_atualizacao: user.data_atualizacao,
    ultimo_login: user.ultimo_login,
  });
});

// Função para gerar ID único
function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

// Função para gerar token JWT
function generateToken(id) {
  return jwt.sign({ id }, 'secret_key', { expiresIn: '30m' });
}

// Função para gerar hash da senha
function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
