const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const fs = require('fs');
const crypto = require('crypto');
const cron = require('node-cron');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json'); // Importa o arquivo de especificação
const os = require('os');
const app = express();
const port = 80;

// Configura o diretório de views
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public')); // Serve arquivos estáticos do diretório public

// Configuração de sessão
app.use(session({
    secret: 'segredo',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Caminho dos arquivos JSON
const usersFilePath = path.join(__dirname, 'data', 'users.json');
const campeonatosFilePath = path.join(__dirname, 'data', 'campeonatos.json');
const tokensFilePath = path.join(__dirname, 'data', 'tokens.json');
const agendamentosFilePath = path.join(__dirname, 'data', 'agendamentos.json');

// Função para ler dados de um arquivo JSON
function readJSONFile(filePath) {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, '[]');
    }
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data);
}

// Função para escrever dados em um arquivo JSON
function writeJSONFile(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// Dados do superusuário
const superuser = {
    username: 'admin',
    password: 'admin123'
};

// Carregar dados dos usuários, campeonatos e tokens
let users = readJSONFile(usersFilePath);
let campeonatos = readJSONFile(campeonatosFilePath);
let tokens = readJSONFile(tokensFilePath);
let agendamentos = readJSONFile(agendamentosFilePath);

// Função para gerar um token único
function generateToken() {
    return crypto.randomBytes(16).toString('hex');
}

// Função para calcular saldo de gols e pontos
function calcularClassificacao(times) {
    return times.map(time => {
        time.saldoGols = time.golsMarcados - time.golsSofridos;
        time.pontos = (time.vitorias * 3) + (time.empates * 1);
        return time;
    }).sort((a, b) => b.pontos - a.pontos || b.saldoGols - a.saldoGols);
}

// Middleware para verificar autenticação
const isAuthenticated = (req, res, next) => {
    const username = req.session.username;
    if (username) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Middleware para verificar se é superusuário
const isSuperuser = (req, res, next) => {
    const username = req.session.username;
    if (username === superuser.username) {
        next();
    } else {
        res.status(403).json({ error: 'Acesso negado: apenas o superusuário pode realizar esta ação.' });
    }
};

// Middleware para verificar token de acesso
const checkToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (token && tokens.includes(token)) {
        next();
    } else {
        res.status(401).json({ error: 'Acesso negado: token inválido ou ausente.' });
    }
};

// Função para remover um agendamento e seu índice do usuário
function removerAgendamento(agendaId) {
    // Remove o agendamento do arquivo agendamentos.json
    const agendamentos = readJSONFile(agendamentosFilePath);
    const agendamentosAtualizados = agendamentos.filter((_, index) => index !== agendaId);
    writeJSONFile(agendamentosFilePath, agendamentosAtualizados);

    // Remove o índice do agendamento do array agendas no users.json
    const users = readJSONFile(usersFilePath);
    const usersAtualizados = users.map(user => {
        if (user.agendas && user.agendas.includes(agendaId)) {
            user.agendas = user.agendas.filter(id => id !== agendaId); // Remove o índice
        }
        return user;
    });
    writeJSONFile(usersFilePath, usersAtualizados);

    console.log(`Agendamento ${agendaId} removido com sucesso.`);
}

// Função para excluir agendas passadas
function excluirAgendasPassadas() {
    const hoje = new Date();
    const agendamentos = readJSONFile(agendamentosFilePath);
    const agendamentosAtualizados = agendamentos.filter(agendamento => {
        const dataAgendamento = new Date(`${agendamento.data}T${agendamento.hora}`);
        return dataAgendamento >= hoje;
    });
    writeJSONFile(agendamentosFilePath, agendamentosAtualizados);
}

// Agendar a tarefa para ser executada todos os dias à meia-noite
cron.schedule('0 0 * * *', () => {
    excluirAgendasPassadas();
    console.log('Agendas passadas foram excluídas.');
});

// Rota para a documentação Swagger
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Rotas da aplicação web
app.get('/', (req, res) => {
    res.render('index', { 
        campeonatos: campeonatos,
        calcularClassificacao: calcularClassificacao
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Verifica se é o superusuário
    if (username === superuser.username && password === superuser.password) {
        req.session.username = username;
        return res.redirect('/admin'); // Redireciona para a página de admin
    }

    // Verifica se é um usuário comum
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ error: 'Usuário não encontrado.' }); // Usuário não existe
    }

    if (user.password !== password) {
        return res.status(401).json({ error: 'Senha incorreta.' }); // Senha incorreta
    }

    // Se o login for bem-sucedido (usuário comum)
    req.session.username = username;
    const userCampeonatoIds = user.campeonatos || [];
    req.session.userCampeonatoIds = userCampeonatoIds;
    return res.redirect('/user'); // Redireciona para a página do usuário
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/admin', isAuthenticated, isSuperuser, (req, res) => {
    res.render('admin', { campeonatos, users, tokens });
});

app.post('/admin/users/create', isAuthenticated, isSuperuser, (req, res) => {
    const { username, password } = req.body;
    users.push({ username, password });
    writeJSONFile(usersFilePath, users);
    res.redirect('/admin');
});

app.post('/admin/campeonatos/add', isAuthenticated, isSuperuser, (req, res) => {
    const { nome, responsavel } = req.body;
    const novoCampeonato = { nome, responsavel, times: [] };
    campeonatos.push(novoCampeonato);
    const campeonatoId = campeonatos.length - 1;

    const userIndex = users.findIndex(u => u.username === responsavel);
    if (userIndex !== -1) {
        if (!users[userIndex].campeonatos) {
            users[userIndex].campeonatos = [];
        }
        users[userIndex].campeonatos.push(campeonatoId);
        writeJSONFile(usersFilePath, users);
    }

    writeJSONFile(campeonatosFilePath, campeonatos);
    res.redirect('/admin');
});

app.post('/admin/campeonatos/delete/:id', isAuthenticated, isSuperuser, (req, res) => {
    const { id } = req.params;
    if (campeonatos[id]) {
        campeonatos.splice(id, 1);

        users.forEach(user => {
            if (user.campeonatos) {
                user.campeonatos = user.campeonatos.filter(campeonatoId => campeonatoId !== parseInt(id));
                user.campeonatos = user.campeonatos.map(campeonatoId => {
                    if (campeonatoId > id) {
                        return campeonatoId - 1;
                    }
                    return campeonatoId;
                });
            }
        });

        writeJSONFile(campeonatosFilePath, campeonatos);
        writeJSONFile(usersFilePath, users);
        res.redirect('/admin');
    } else {
        res.status(404).send('Campeonato não encontrado.');
    }
});

app.get('/user', isAuthenticated, (req, res) => {
    const username = req.session.username;
    const userCampeonatoIds = req.session.userCampeonatoIds || [];
    const userCampeonatos = userCampeonatoIds
        .map(id => campeonatos[id])
        .filter(campeonato => campeonato !== undefined);

    const success = req.session.success || null;
    const error = req.session.error || null;
    req.session.success = null;
    req.session.error = null;

    res.render('user', { 
        campeonatos: userCampeonatos, 
        userCampeonatoIds,
        username,
        success,
        error
    });
});

app.post('/user/campeonatos/:id/add-time', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;

    if (campeonatos[id] && campeonatos[id].responsavel.trim().toLowerCase() === username.trim().toLowerCase()) {
        if (!nome || isNaN(vitorias) || isNaN(jogos) || isNaN(empates) || isNaN(derrotas) || isNaN(golsMarcados) || isNaN(golsSofridos)) {
            req.session.error = 'Dados do time inválidos. Preencha todos os campos corretamente.';
        } else {
            campeonatos[id].times.push({
                nome,
                vitorias: parseInt(vitorias),
                jogos: parseInt(jogos),
                empates: parseInt(empates),
                derrotas: parseInt(derrotas),
                golsMarcados: parseInt(golsMarcados),
                golsSofridos: parseInt(golsSofridos)
            });
            writeJSONFile(campeonatosFilePath, campeonatos);
            req.session.success = 'Time adicionado com sucesso!';
        }
    } else {
        req.session.error = 'Acesso negado: você não é o responsável por este campeonato.';
    }

    res.redirect('/user');
});

app.post('/admin/api-keys/create', isAuthenticated, isSuperuser, (req, res) => {
    const token = generateToken();
    tokens.push(token);
    writeJSONFile(tokensFilePath, tokens);
    res.redirect('/admin');
});

app.post('/admin/api-keys/revoke', isAuthenticated, isSuperuser, (req, res) => {
    const { token } = req.body;
    const index = tokens.indexOf(token);
    if (index !== -1) {
        tokens.splice(index, 1);
        writeJSONFile(tokensFilePath, tokens);
    }
    res.redirect('/admin');
});

app.get('/user/campeonatos/:id/edit-time/:timeIndex', isAuthenticated, (req, res) => {
    const { id, timeIndex } = req.params;
    const username = req.session.username;
    if (campeonatos[id].responsavel === username) {
        const time = campeonatos[id].times[timeIndex];
        res.render('edit-time', { campeonatoId: id, timeIndex, time });
    } else {
        res.status(403).send('Acesso negado.');
    }
});

app.post('/user/campeonatos/:id/update-time/:timeIndex', isAuthenticated, (req, res) => {
    const { id, timeIndex } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;
    if (campeonatos[id].responsavel === username) {
        campeonatos[id].times[timeIndex] = { nome, vitorias: parseInt(vitorias), jogos: parseInt(jogos), empates: parseInt(empates), derrotas: parseInt(derrotas), golsMarcados: parseInt(golsMarcados), golsSofridos: parseInt(golsSofridos) };
        writeJSONFile(campeonatosFilePath, campeonatos);
    }
    res.redirect('/user');
});

app.post('/user/campeonatos/:id/delete-time/:timeIndex', isAuthenticated, (req, res) => {
    const { id, timeIndex } = req.params;
    const username = req.session.username;
    if (campeonatos[id].responsavel === username) {
        campeonatos[id].times.splice(timeIndex, 1);
        writeJSONFile(campeonatosFilePath, campeonatos);
    }
    res.redirect('/user');
});

// Rota para exibir a agenda de jogos do usuário
app.get('/user/agenda', isAuthenticated, (req, res) => {
    const username = req.session.username;

    // Busca as agendas do usuário
    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username);

    let userAgendas = [];
    if (user && user.agendas) {
        const agendamentos = readJSONFile(agendamentosFilePath);
        userAgendas = user.agendas.map(id => {
            const agenda = agendamentos[id];
            if (agenda) {
                agenda.id = id; // Adiciona o ID real da agenda ao objeto
            }
            return agenda;
        }).filter(a => a !== undefined);
    }

    // Passa as variáveis success e error para o template
    const success = req.session.success || null;
    const error = req.session.error || null;
    req.session.success = null;
    req.session.error = null;

    res.render('user-agenda', { 
        agendamentos: userAgendas,
        success,
        error
    });
});

// Rota para adicionar um jogo à agenda do usuário
app.post('/user/agendar-jogo', isAuthenticated, (req, res) => {
    const { logo1, time1, logo2, time2, data, hora, local } = req.body;
    const username = req.session.username;

    if (!logo1 || !time1 || !logo2 || !time2 || !data || !hora || !local) {
        req.session.error = 'Preencha todos os campos corretamente.';
    } else {
        const novoJogo = { 
            logo1, 
            time1, 
            logo2, 
            time2, 
            data, 
            hora, 
            local, 
            responsavel: username // Define o responsável como o usuário logado
        };

        // Adiciona o novo jogo ao arquivo de agendamentos
        const agendamentos = readJSONFile(agendamentosFilePath);
        agendamentos.push(novoJogo);
        const agendaId = agendamentos.length - 1; // ID da nova agenda
        writeJSONFile(agendamentosFilePath, agendamentos);

        // Adiciona o ID da agenda ao usuário responsável
        const users = readJSONFile(usersFilePath);
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex !== -1) {
            if (!users[userIndex].agendas) {
                users[userIndex].agendas = []; // Inicializa o campo agendas se não existir
            }
            users[userIndex].agendas.push(agendaId); // Adiciona o ID da agenda
            writeJSONFile(usersFilePath, users);
        }

        // Agendar a remoção do jogo no horário especificado
        const dataHoraJogo = new Date(`${data}T${hora}`);
        const cronExpression = `${dataHoraJogo.getMinutes()} ${dataHoraJogo.getHours()} ${dataHoraJogo.getDate()} ${dataHoraJogo.getMonth() + 1} *`;

        cron.schedule(cronExpression, () => {
            removerAgendamento(agendaId); // Remove o agendamento e o índice do usuário
            console.log(`Jogo removido: ${time1} vs ${time2} em ${data} ${hora}`);
        });

        req.session.success = 'Jogo agendado com sucesso!';
    }

    res.redirect('/user/agenda');
});

// Rota para exibir a página de edição de um agendamento
app.get('/user/agenda/editar/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const username = req.session.username;

    // Verifica se o usuário tem permissão para editar a agenda
    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username);

    if (user && user.agendas && user.agendas.includes(Number(id))) {
        const agendamentos = readJSONFile(agendamentosFilePath);
        const agendamento = agendamentos[id];

        if (agendamento) {
            res.render('editar-agenda', { agendamento, id });
        } else {
            res.status(404).send('Agendamento não encontrado.');
        }
    } else {
        res.status(403).send('Acesso negado: você não tem permissão para editar este agendamento.');
    }
});

// Rota para atualizar um agendamento
app.post('/user/agenda/editar/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { logo1, time1, logo2, time2, data, hora, local } = req.body;
    const username = req.session.username;

    // Verifica se o usuário tem permissão para editar a agenda
    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username);

    if (user && user.agendas && user.agendas.includes(Number(id))) {
        const agendamentos = readJSONFile(agendamentosFilePath);
        const agendamento = agendamentos[id];

        if (agendamento) {
            // Atualiza os dados do agendamento
            agendamentos[id] = { 
                logo1, 
                time1, 
                logo2, 
                time2, 
                data, 
                hora, 
                local, 
                responsavel: username // Mantém o responsável como o usuário logado
            };
            writeJSONFile(agendamentosFilePath, agendamentos);
            req.session.success = 'Agendamento atualizado com sucesso!';
            res.redirect('/user/agenda');
        } else {
            res.status(404).send('Agendamento não encontrado.');
        }
    } else {
        res.status(403).send('Acesso negado: você não tem permissão para editar este agendamento.');
    }
});

app.get('/agenda', (req, res) => {
    const agenda = readJSONFile(agendamentosFilePath); // Lê os agendamentos do arquivo JSON
    res.render('agenda', { agenda }); // Passa os agendamentos para o template
});

// API Routes
app.get('/api/campeonatos', checkToken, (req, res) => {
    res.json(campeonatos);
});

app.get('/api/campeonatos/:id', checkToken, (req, res) => {
    const { id } = req.params;
    const campeonato = campeonatos[id];
    if (campeonato) {
        res.json(campeonato);
    } else {
        res.status(404).json({ error: 'Campeonato não encontrado.' });
    }
});

app.get('/api/agendamentos', checkToken, (req, res) => {
    res.json(agendamentos);
});

app.get('/api/agendamentos/:id', checkToken, (req, res) => {
    const { id } = req.params;
    const agendamento = agendamentos[id];
    if (agendamento) {
        res.json(agendamento);
    } else {
        res.status(404).json({ error: 'Agendamento não encontrado.' });
    }
});

app.put('/api/campeonatos/:id', checkToken, (req, res) => {
    const { id } = req.params;
    const { nome, responsavel } = req.body;
  
    if (!nome || !responsavel) {
      return res.status(400).json({ error: 'Nome e responsável são obrigatórios.' });
    }
  
    const campeonatos = readJSONFile(campeonatosFilePath);
  
    if (id >= campeonatos.length || id < 0) {
      return res.status(404).json({ error: 'Campeonato não encontrado.' });
    }
  
    campeonatos[id] = { nome, responsavel, times: campeonatos[id].times || [] };
    writeJSONFile(campeonatosFilePath, campeonatos);
  
    res.json({ message: 'Campeonato atualizado com sucesso!', campeonato: campeonatos[id] });
});

app.put('/api/campeonatos/:id/times/:timeId', checkToken, (req, res) => {
    const { id, timeId } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
  
    if (!nome || isNaN(vitorias) || isNaN(jogos) || isNaN(empates) || isNaN(derrotas) || isNaN(golsMarcados) || isNaN(golsSofridos)) {
      return res.status(400).json({ error: 'Todos os campos do time são obrigatórios.' });
    }
  
    const campeonatos = readJSONFile(campeonatosFilePath);
  
    if (id >= campeonatos.length || id < 0) {
      return res.status(404).json({ error: 'Campeonato não encontrado.' });
    }
  
    const times = campeonatos[id].times || [];
  
    if (timeId >= times.length || timeId < 0) {
      return res.status(404).json({ error: 'Time não encontrado.' });
    }
  
    times[timeId] = { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos };
    campeonatos[id].times = times;
    writeJSONFile(campeonatosFilePath, campeonatos);
  
    res.json({ message: 'Time atualizado com sucesso!', time: times[timeId] });
});

app.put('/api/agendamentos/:id', checkToken, (req, res) => {
    const { id } = req.params;
    const { logo1, time1, logo2, time2, data, hora, local } = req.body;
  
    if (!logo1 || !time1 || !logo2 || !time2 || !data || !hora || !local) {
      return res.status(400).json({ error: 'Todos os campos do agendamento são obrigatórios.' });
    }
  
    const agendamentos = readJSONFile(agendamentosFilePath);
  
    if (id >= agendamentos.length || id < 0) {
      return res.status(404).json({ error: 'Agendamento não encontrado.' });
    }
  
    agendamentos[id] = { logo1, time1, logo2, time2, data, hora, local, responsavel: agendamentos[id].responsavel };
    writeJSONFile(agendamentosFilePath, agendamentos);
  
    res.json({ message: 'Agendamento atualizado com sucesso!', agendamento: agendamentos[id] });
});

app.post('/api/agendamentos', checkToken, (req, res) => {
    const { logo1, time1, logo2, time2, data, hora, local, responsavel } = req.body;
  
    if (!logo1 || !time1 || !logo2 || !time2 || !data || !hora || !local || !responsavel) {
      return res.status(400).json({ error: 'Todos os campos do agendamento são obrigatórios.' });
    }
  
    const agendamentos = readJSONFile(agendamentosFilePath);
    const novoAgendamento = { logo1, time1, logo2, time2, data, hora, local, responsavel };
    agendamentos.push(novoAgendamento);
    writeJSONFile(agendamentosFilePath, agendamentos);
  
    res.status(201).json({ message: 'Agendamento criado com sucesso!', agendamento: novoAgendamento });
});

app.post('/api/campeonatos/:id/times', checkToken, (req, res) => {
    const { id } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
  
    if (!nome || isNaN(vitorias) || isNaN(jogos) || isNaN(empates) || isNaN(derrotas) || isNaN(golsMarcados) || isNaN(golsSofridos)) {
      return res.status(400).json({ error: 'Todos os campos do time são obrigatórios.' });
    }
  
    const campeonatos = readJSONFile(campeonatosFilePath);
  
    if (id >= campeonatos.length || id < 0) {
      return res.status(404).json({ error: 'Campeonato não encontrado.' });
    }
  
    const novoTime = {
      nome,
      vitorias: parseInt(vitorias),
      jogos: parseInt(jogos),
      empates: parseInt(empates),
      derrotas: parseInt(derrotas),
      golsMarcados: parseInt(golsMarcados),
      golsSofridos: parseInt(golsSofridos)
    };
  
    if (!campeonatos[id].times) {
      campeonatos[id].times = [];
    }
  
    campeonatos[id].times.push(novoTime);
    writeJSONFile(campeonatosFilePath, campeonatos);
  
    res.status(201).json({ message: 'Time adicionado com sucesso!', time: novoTime });
});

app.post('/api/campeonatos', checkToken, (req, res) => {
    const { nome, responsavel } = req.body;
  
    if (!nome || !responsavel) {
      return res.status(400).json({ error: 'Nome e responsável são obrigatórios.' });
    }
  
    const campeonatos = readJSONFile(campeonatosFilePath);
    const novoCampeonato = { nome, responsavel, times: [] };
    campeonatos.push(novoCampeonato);
    writeJSONFile(campeonatosFilePath, campeonatos);
  
    res.status(201).json({ message: 'Campeonato criado com sucesso!', campeonato: novoCampeonato });
});

// Rota de login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
  
    // Verifica se é o superusuário
    if (username === superuser.username && password === superuser.password) {
      const token = generateToken();
      const tokens = readJSONFile(tokensFilePath);
      tokens.push(token);
      writeJSONFile(tokensFilePath, tokens);
  
      return res.json({ message: 'Login bem-sucedido!', token });
    }
  
    // Verifica se é um usuário comum
    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username && u.password === password);
  
    if (user) {
      const token = generateToken();
      const tokens = readJSONFile(tokensFilePath);
      tokens.push(token);
      writeJSONFile(tokensFilePath, tokens);
  
      return res.json({ message: 'Login bem-sucedido!', token });
    }
  
    // Se não encontrou o usuário
    res.status(401).json({ error: 'Usuário ou senha incorretos.' });
});

function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const interface of interfaces[name]) {
            const { address, family, internal } = interface;
            if (family === 'IPv4' && !internal) {
                return address;
            }
        }
    }
}

const localIP = getLocalIP();
if (localIP) {
    console.log(`Endereço IP local: ${localIP}`);
} else {
    console.log('Não foi possível encontrar um endereço IP local.');
}

app.listen(port, () => {
    console.log(`Servidor rodando em http://${localIP}:${port}`);
});