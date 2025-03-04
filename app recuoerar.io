const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const fs = require('fs');
const crypto = require('crypto');
const cron = require('node-cron');
const swaggerUi = require('swagger-ui-express');
const flash = require('connect-flash');
const swaggerDocument = require('./swagger.json'); // Importa o arquivo de especificação
const os = require('os');
const app = express();
const port = 8000;

const cronJobs = {}; // Objeto para armazenar tarefas agendadas

app.use(session({
    secret: 'seu-segredo-aqui', // Defina um segredo para a sessão
    resave: false,
    saveUninitialized: true
}));

app.use(flash()); // Habilita o uso do flash


app.set('view cache', false);  // Desabilita o cache de views
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); // Não armazena no cache
    next();
});


// Configura o diretório de views
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public')); // Serve arquivos estáticos do diretório public

// Configuração de sessão
app.use(session({
    secret: 'segredo', // Chave secreta para assinar o cookie da sessão
    resave: false, // Evita regravar a sessão se nada mudar
    saveUninitialized: true, // Salva sessões não inicializadas
    cookie: {
        secure: false, // Defina como true apenas se estiver usando HTTPS
        maxAge: 1000 * 60 * 60 * 24, // Tempo de vida do cookie (1 dia)
        httpOnly: true // Impede que o cookie seja acessado via JavaScript no navegador
    }
}));

// Caminho dos arquivos JSON
const usersFilePath = path.join(__dirname, 'data', 'users.json');
const campeonatosFilePath = path.join(__dirname, 'data', 'campeonatos.json');
const tokensFilePath = path.join(__dirname, 'data', 'tokens.json');
const agendamentosFilePath = path.join(__dirname, 'data', 'agendamentos.json');
const accessDataFilePath = path.join(__dirname, 'data', 'accessData.json'); // Adicionado


// Função para ler dados de um arquivo JSON
function readJSONFile(filePath) {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, '[]');
    }
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data);
}
// Função para escrever dados em um arquivo JSON
function readJSONFile(filePath) {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data); // Retorna os dados no formato JSON
    } catch (error) {
        console.error(`Erro ao ler o arquivo ${filePath}:`, error);
        return [];
    }
}


// Função para escrever dados em um arquivo JSON
function writeJSONFile(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// Função para ler os dados de acesso
function readAccessData() {
    if (!fs.existsSync(accessDataFilePath)) {
        fs.writeFileSync(accessDataFilePath, JSON.stringify({ home: 0, agenda: 0 }));
    }
    return JSON.parse(fs.readFileSync(accessDataFilePath, 'utf-8'));
}
// Função para atualizar os dados de acesso
function updateAccessData(route) {
    const accessData = readAccessData();
    accessData[route]++;
    fs.writeFileSync(accessDataFilePath, JSON.stringify(accessData, null, 2));
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

// Middleware para contar acessos à rota "/"
app.get('/', (req, res, next) => {
    // Atualiza os dados de acesso sem interferir na sessão
    const accessData = readAccessData();
    accessData.home++;
    writeJSONFile(accessDataFilePath, accessData);
    next();
});

// Middleware para contar acessos à rota "/agenda"
app.get('/agenda', (req, res, next) => {
    // Atualiza os dados de acesso sem interferir na sessão
    const accessData = readAccessData();
    accessData.agenda++;
    writeJSONFile(accessDataFilePath, accessData);
    next();
});

// Reinicia a contagem diariamente à meia-noite
cron.schedule('0 0 * * *', () => {
    fs.writeFileSync(accessDataFilePath, JSON.stringify({ home: 0, agenda: 0 }));
    console.log('Contagem de acessos reiniciada.');
});

// Middleware para verificar autenticação
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
    // Caminho para o arquivo JSON
    const caminhoArquivo = path.join(__dirname, 'data', 'campeonatos.json');

    // Lê o arquivo JSON
    fs.readFile(caminhoArquivo, 'utf8', (err, data) => {
        if (err) {
            console.error('Erro ao ler o arquivo JSON:', err);
            return res.status(500).send('Erro ao carregar os dados');
        }

        // Converte o JSON para um objeto JavaScript
        const campeonatos = JSON.parse(data);

        // Renderiza a página com os dados atualizados
        res.render('index', {
            campeonatos: campeonatos,
            calcularClassificacao: calcularClassificacao
        });
    });
});

app.get('/login', (req, res) => {
    // Verifica se o usuário já está logado
    if (req.session.username) {
        // Redireciona para a página correta com base no tipo de usuário
        if (req.session.username === superuser.username) {
            return res.redirect('/admin/master'); // Redireciona para a página de admin
        } else {
            return res.redirect('/user'); // Redireciona para a página do usuário comum
        }
    }

    // Se o usuário não estiver logado, renderiza a página de login
    res.render('login');
});



app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Carregar os usuários do arquivo sempre que houver um login
    let users = readJSONFile(usersFilePath);

    // Verifica se é o superusuário
    if (username === superuser.username && password === superuser.password) {
        req.session.username = username;
        return res.redirect('/admin/master');
    }

    // Verifica se é um usuário comum
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ error: 'Usuário não encontrado.' });
    }

    if (user.password !== password) {
        return res.status(401).json({ error: 'Senha incorreta.' });
    }

    // Se o login for bem-sucedido
    req.session.username = username;
    req.session.userCampeonatoIds = Array.isArray(user.campeonatos) ? user.campeonatos : []; // Garante que seja sempre um array

    return res.redirect('/user');
});



app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});



app.post('/admin/campeonatos/add', isAuthenticated, isSuperuser, (req, res) => {
    const { nome, responsavel } = req.body;

    // Lê os arquivos JSON novamente
    let users = readJSONFile(usersFilePath);
    let campeonatos = readJSONFile(campeonatosFilePath);

    // Cria o novo campeonato com um campo 'id' explícito
    const campeonatoId = campeonatos.length; // O ID será o tamanho do array, garantindo unicidade
    const novoCampeonato = { id: campeonatoId, nome, responsavel, times: [] };

    // Adiciona o campeonato à lista de campeonatos
    campeonatos.push(novoCampeonato);

    // Associa o campeonato ao usuário responsável
    const userIndex = users.findIndex(u => u.username === responsavel);
    if (userIndex !== -1) {
        if (!users[userIndex].campeonatos) {
            users[userIndex].campeonatos = [];
        }
        users[userIndex].campeonatos.push(campeonatoId);
    }

    // Salva as alterações nos arquivos JSON
    writeJSONFile(usersFilePath, users);
    writeJSONFile(campeonatosFilePath, campeonatos);

    // Redireciona para a lista de campeonatos
    res.redirect('/admin/campeonatos');
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
        res.redirect('/admin/campeonatos');
    } else {
        res.status(404).send('Campeonato não encontrado.');
    }
});

app.get('/user', isAuthenticated, (req, res) => {
    const username = req.session.username;
    const userCampeonatoIds = req.session.userCampeonatoIds || [];

    // Carrega os campeonatos do arquivo a cada acesso
    let campeonatos = readJSONFile(campeonatosFilePath);

    // Filtra os campeonatos do usuário
    const userCampeonatos = userCampeonatoIds
        .map(id => campeonatos[id])
        .filter(campeonato => campeonato !== undefined);

    res.render('user', { 
        campeonatos: userCampeonatos, 
        userCampeonatoIds, // Passa os IDs dos campeonatos do usuário
        username
    });
});


app.post('/user/campeonatos/:id/add-time', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;

    // Lê os campeonatos do JSON sempre antes da verificação
    let campeonatos = readJSONFile(campeonatosFilePath);

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

            // Atualiza o arquivo JSON
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
    res.redirect('/admin/tokens');
});

app.post('/admin/api-keys/revoke', isAuthenticated, isSuperuser, (req, res) => {
    const { token } = req.body;
    const index = tokens.indexOf(token);
    if (index !== -1) {
        tokens.splice(index, 1);
        writeJSONFile(tokensFilePath, tokens);
    }
    res.redirect('/admin/tokens');
});

app.get('/user/campeonatos/:id/edit-time/:timeIndex', isAuthenticated, (req, res) => {
    const id = parseInt(req.params.id); // Garante que o ID seja um número
    const timeIndex = parseInt(req.params.timeIndex); // Converte o índice do time para número
    const username = req.session.username;

    // Recarrega os campeonatos do JSON antes de buscar o time
    let campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o campeonato existe
    if (!campeonatos[id]) {
        return res.status(404).send('Campeonato não encontrado.');
    }

    // Verifica se o usuário é o responsável pelo campeonato
    if (campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).send('Acesso negado.');
    }

    // Verifica se o índice do time é válido
    if (!campeonatos[id].times || !campeonatos[id].times[timeIndex]) {
        return res.status(404).send('Time não encontrado.');
    }

    // Obtém o time correto
    const time = campeonatos[id].times[timeIndex];

    // Renderiza a página de edição com os dados do time
    res.render('edit-time', { campeonatoId: id, timeIndex, time });
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


 // Caminho dos arquivos JSON
    const campeonatosFilePath = './data/campeonatos.json';  // Caminho do arquivo de campeonatos
    const agendamentosFilePath = './data/agendamentos.json';  // Caminho do arquivo de agendamentos
    

    // Lê o arquivo campeonatos.json
    let campeonatos = readJSONFile(campeonatosFilePath);

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

    

 // Busca os campeonatos do usuário
 const userCampeonatoIds = user.campeonatos || [];  // IDs de campeonatos do usuário
 const userCampeonatos = userCampeonatoIds
     .map(id => campeonatos.find(campeonato => campeonato.id === id)) // Busca pelo id do campeonato
     .filter(campeonato => campeonato !== undefined);  // Filtra campeonatos que não existirem

        
    // Passa as variáveis success e error para o template
    const success = req.session.success || null;
    const error = req.session.error || null;
    req.session.success = null;
    req.session.error = null;

    res.render('user-agenda', { 
        agendamentos: userAgendas,
        campeonatos: userCampeonatos, // Passa os campeonatos do usuário
        success,
        error
    });
});


// Rota para adicionar um jogo à agenda do usuário
app.post('/user/agendar-jogo', isAuthenticated, (req, res) => {
    const { logo1, time1, logo2, time2, camp, data, hora, local } = req.body;
    const username = req.session.username;

    if (!logo1 || !time1 || !logo2 || !time2 || !camp || !data || !hora || !local) {
        req.session.error = 'Preencha todos os campos corretamente.';
    } else {
        const agendamentos = readJSONFile(agendamentosFilePath);
        const novoJogo = { 
            id: agendamentos.length, // O ID é o índice atual do array, iniciando de 0
            logo1, 
            time1, 
            logo2, 
            time2,
            camp, 
            data, 
            hora, 
            local, 
            responsavel: username // Define o responsável como o usuário logado
        };

        // Adiciona o novo jogo ao arquivo de agendamentos
        agendamentos.push(novoJogo);
        writeJSONFile(agendamentosFilePath, agendamentos);

        // Adiciona o ID da agenda ao usuário responsável
        const users = readJSONFile(usersFilePath);
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex !== -1) {
            if (!users[userIndex].agendas) {
                users[userIndex].agendas = []; // Inicializa o campo agendas se não existir
            }
            users[userIndex].agendas.push(novoJogo.id); // Adiciona o ID da agenda
            writeJSONFile(usersFilePath, users);
        }

        // Agendar a remoção do jogo no horário especificado
        const dataHoraJogo = new Date(`${data}T${hora}`);
        const cronExpression = `${dataHoraJogo.getMinutes()} ${dataHoraJogo.getHours()} ${dataHoraJogo.getDate()} ${dataHoraJogo.getMonth() + 1} *`;

        cron.schedule(cronExpression, () => {
            removerAgendamento(novoJogo.id); // Remove o agendamento com o ID
            console.log(`Jogo removido: ${time1} vs ${time2} em ${data} ${hora}`);
        });

        req.session.success = 'Jogo agendado com sucesso!';
    }

    res.redirect('/user/agenda');
});




// Rota para editar agendamento
app.get('/user/agenda/editar/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const username = req.session.username;

    console.log(`Tentativa de editar agendamento com ID: ${id}`);

    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username);

    if (user && user.agendas && user.agendas.includes(Number(id))) {
        const agendamentos = readJSONFile(agendamentosFilePath);
        const agendamento = agendamentos[id];

        if (agendamento) {
            console.log('Agendamento encontrado:', agendamento);

            const campeonatos = readJSONFile(campeonatosFilePath);
            const userCampeonatos = campeonatos.filter(campeonato => user.campeonatos.includes(campeonato.id));

            // Passando o id do agendamento para a view
            res.render('editar-agenda', {
                campeonatos: userCampeonatos,
                agendamento: agendamento,
                id: id,  // Passando o id para a view
                success: req.flash('success'),
                error: req.flash('error')
            });
        } else {
            console.log('Agendamento não encontrado.');
            res.status(404).send('Agendamento não encontrado.');
        }
    } else {
        console.log('Acesso negado: usuário não tem permissão.');
        res.status(403).send('Acesso negado: você não tem permissão para editar este agendamento.');
    }
});







// Rota para atualizar um agendamento
app.post('/user/agenda/editar/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { logo1, time1, logo2, time2, camp, data, hora, local } = req.body;
    const username = req.session.username;

    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username);

    if (user && user.agendas && user.agendas.includes(Number(id))) {
        const agendamentos = readJSONFile(agendamentosFilePath);
        const agendamento = agendamentos[id];

        if (agendamento) {
            // Cancela o cron job antigo, se existir
            if (cronJobs[id]) {
                cronJobs[id].stop();
                console.log(`Tarefa agendada anterior para o agendamento ${id} foi cancelada.`);
            }

            // Atualiza os dados do agendamento
            agendamentos[id] = {
                logo1,
                time1,
                logo2,
                time2,
                camp,
                data,
                hora,
                local,
                responsavel: username
            };

            // Salva as alterações no JSON
            writeJSONFile(agendamentosFilePath, agendamentos);

            // Agenda a nova remoção com base na nova data e hora
            const dataHoraJogo = new Date(`${data}T${hora}`);
            const cronExpression = `${dataHoraJogo.getMinutes()} ${dataHoraJogo.getHours()} ${dataHoraJogo.getDate()} ${dataHoraJogo.getMonth() + 1} *`;

            cronJobs[id] = cron.schedule(cronExpression, () => {
                removerAgendamento(Number(id));
                console.log(`Jogo removido: ${time1} vs ${time2} em ${data} ${hora}`);
                delete cronJobs[id]; // Remove a referência após execução
            });

            req.session.success = 'Agendamento atualizado com sucesso!';
            return res.redirect('/user/agenda');
        } else {
            return res.status(404).send('Agendamento não encontrado.');
        }
    } else {
        return res.status(403).send('Acesso negado: você não tem permissão para editar este agendamento.');
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
app.get('/admin', isAuthenticated, isSuperuser, (req, res) => {
    try {
        const page = req.query.page || 'master'; // Pega o parâmetro 'page' da URL ou define 'master' como padrão

        // Lê os dados reais dos arquivos JSON
        const users = readJSONFile(usersFilePath); // Lê os usuários
        const tokens = readJSONFile(tokensFilePath); // Lê os tokens
        const campeonatos = readJSONFile(campeonatosFilePath); // Lê os campeonatos
        const accessData = readAccessData(); // Lê os dados de acesso

        // Renderiza o template admin.ejs com os dados reais
        res.render('admin', {
            page, // Passa a página atual para o template
            users, // Passa a lista de usuários
            tokens, // Passa a lista de tokens
            campeonatos, // Passa a lista de campeonatos
            accessData // Passa os dados de acesso
        });
    } catch (error) {
        console.error('Erro ao carregar a página de admin:', error);
        res.status(500).send('Erro interno ao carregar a página de administração.');
    }
});

// Rota para a página Master
app.get('/admin/master', isAuthenticated, isSuperuser, (req, res) => {
    const accessData = readAccessData(); // Lê os dados de acesso
    console.log('Dados de acesso:', accessData); // Adicione este log para depuração

    res.render('admin', {
        page: 'master',
        users,
        tokens,
        campeonatos,
        accessData // Passa os dados de acesso para o template
    });
});

// Rota para a página Adicionar Campeonato
app.get('/admin/adicionar-campeonato', isAuthenticated, isSuperuser, (req, res) => {
    // Lê o arquivo users.json novamente
    const users = readJSONFile(usersFilePath);

    // Log para depuração
    console.log('Usuários carregados do arquivo:', users);

    res.render('admin', {
        page: 'adicionar-campeonato', // Define a página atual
        users, // Passa os usuários atualizados para o template
        tokens: readJSONFile(tokensFilePath), // Carrega os tokens
        campeonatos: readJSONFile(campeonatosFilePath) // Carrega os campeonatos
    });
});

// Rota para a página Tokens
app.get('/admin/tokens', isAuthenticated, isSuperuser, (req, res) => {
    res.render('admin', {
        page: 'tokens', // Define a página atual
        users,
        tokens,
        campeonatos
    });
});

// Rota para a página Campeonatos
app.get('/admin/campeonatos', isAuthenticated, isSuperuser, (req, res) => {
    res.render('admin', {
        page: 'campeonatos', // Define a página atual
       users, // Passa os usuários para o template
        tokens: readJSONFile(tokensFilePath), // Carrega os tokens
        campeonatos: readJSONFile(campeonatosFilePath) // Carrega os campeonatos
    });
});

// Rota para a página Usuários
app.get('/admin/usuarios', isAuthenticated, isSuperuser, (req, res) => {
    // Lê o arquivo users.json novamente
    const users = readJSONFile(usersFilePath);

    res.render('admin', {
        page: 'usuarios', // Define a página atual
        users, // Passa os usuários para o template
        tokens: readJSONFile(tokensFilePath), // Carrega os tokens
        campeonatos: readJSONFile(campeonatosFilePath) // Carrega os campeonatos
    });
});

app.get('/admin/master',  (req, res) => {
    // Caminho para o arquivo JSON
    const dataPath = path.join(__dirname, 'data', 'acessData.json');

    // Lê o arquivo JSON
    fs.readFile(dataPath, 'utf8', (err, data) => {
        if (err) {
            console.error('Erro ao ler o arquivo JSON:', err);
            return res.status(500).send('Erro ao carregar os dados de acesso.');
        }

        // Converte o JSON para um objeto JavaScript
        const accessData = JSON.parse(data);

        // Renderiza o template admin.ejs com os dados
        res.render('admin', {
            page: 'master', // Define a página como 'master'
            accessData: accessData // Passa os dados de acesso para o template
        });
    });
});



// Rota para renderizar a página de edição do usuário
app.get('/admin/users/edit/:id', isAuthenticated, isSuperuser, (req, res) => {
    const userId = req.params.id; // Pega o ID do usuário da URL
    console.log('ID do usuário:', userId); // Log para depuração

    // Busca o usuário no arquivo JSON
    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.id === parseInt(userId));

    if (!user) {
        console.log('Usuário não encontrado no arquivo JSON.'); // Log para depuração
        return res.status(404).send('Usuário não encontrado');
    }

    console.log('Usuário encontrado:', user); // Log para depuração

    // Renderiza a página de edição com os dados do usuário
    res.render('edit-user', { user });
});

// Rota para atualizar o usuário
app.post('/admin/users/update/:id', isAuthenticated, isSuperuser, (req, res) => {
    const userId = req.params.id; // Pega o ID do usuário da URL
    const { username, password } = req.body; // Pega os dados do formulário

    // Busca o usuário no arquivo JSON
    const users = readJSONFile(usersFilePath);
    const userIndex = users.findIndex(u => u.id === parseInt(userId));

    if (userIndex === -1) {
        return res.status(404).send('Usuário não encontrado');
    }

    // Atualiza os dados do usuário
    users[userIndex].username = username;
    if (password) {
        users[userIndex].password = password; // Atualiza a senha apenas se for fornecida
    }

    // Salva as alterações no arquivo JSON
    writeJSONFile(usersFilePath, users);

    // Redireciona para a lista de usuários
    res.redirect('/admin/usuarios');
});

// Rota para criar um novo usuário
app.post('/admin/users/create', isAuthenticated, isSuperuser, (req, res) => {
    const { username, password } = req.body;

    // Lê o arquivo users.json novamente
    let users = readJSONFile(usersFilePath);

    // Gera um ID único para o novo usuário
    const newUserId = users.length > 0 ? users[users.length - 1].id + 1 : 1;

    // Adiciona o novo usuário com um ID único
    users.push({ id: newUserId, username, password });

    // Salva as alterações no arquivo JSON
    writeJSONFile(usersFilePath, users);

    // Recarrega os usuários após a criação
    users = readJSONFile(usersFilePath);

    // Log para depuração
    console.log('Novo usuário adicionado:', users[users.length - 1]);

    // Redireciona para a lista de usuários
    res.redirect('/admin/usuarios');
});

// Rota para deletar um usuário
app.post('/admin/users/delete/:id', isAuthenticated, isSuperuser, (req, res) => {
    const userId = parseInt(req.params.id); // Converte o ID para número

    // Lê o arquivo users.json novamente
    const users = readJSONFile(usersFilePath);

    // Busca o índice do usuário no array
    const userIndex = users.findIndex(u => u.id === userId);

    if (userIndex === -1) {
        return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }

    // Remove o usuário do array
    users.splice(userIndex, 1);

    // Salva as alterações no arquivo JSON
    writeJSONFile(usersFilePath, users);

    // Retorna uma resposta JSON
    res.json({ success: true });
});

app.get('/admin/usuarios/data', isAuthenticated, isSuperuser, (req, res) => {
    const users = readJSONFile(usersFilePath);
    res.json(users);
});

app.get('/campeonato/:nome', (req, res) => {
    const nomeCampeonato = req.params.nome;
    const caminhoArquivo = path.join(__dirname, 'data', 'campeonatos.json');

    fs.readFile(caminhoArquivo, 'utf8', (err, data) => {
        if (err) {
            console.error('Erro ao ler o arquivo JSON:', err);
            return res.status(500).send('Erro ao carregar os dados');
        }

        const campeonatos = JSON.parse(data);
        const campeonato = campeonatos.find(c => c.nome === nomeCampeonato);

        if (!campeonato) {
            return res.status(404).send('Campeonato não encontrado');
        }

        res.render('campeonato', {
            campeonato: campeonato,
            calcularClassificacao: calcularClassificacao
        });
    });
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