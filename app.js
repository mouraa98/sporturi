const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const cron = require('node-cron');
const swaggerUi = require('swagger-ui-express');
const flash = require('connect-flash');
const axios = require('axios');
const swaggerDocument = require('./swagger.json'); // Importa o arquivo de especificação
const os = require('os');
const app = express();
const port = 8000;


// Configuração do Multer para upload de arquivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir); // Salva os arquivos na pasta public/uploads
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limite de 5MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Apenas imagens são permitidas!'), false);
        }
    }
});




// Rota para buscar a imagem
app.get('/proxy-image', async (req, res) => {
    const imageUrl = req.query.url; // URL da imagem externa

    try {
        const response = await axios.get(imageUrl, { responseType: 'arraybuffer' });
        res.set('Content-Type', response.headers['content-type']);
        res.send(response.data);
    } catch (err) {
        console.error('Erro ao buscar a imagem:', err);
        res.status(500).send('Erro ao buscar a imagem');
    }
});

app.use(express.json()); // Necessário para interpretar JSON no body

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
const linksTokensFilePath = path.join(__dirname, 'data', 'linkstokens.json');

// Função para escrever em um arquivo JSON
function writeJSONFile(filePath, data) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2)); // Salva os dados formatados
    } catch (err) {
        console.error('Erro ao salvar o arquivo JSON:', err);
        throw err;
    }
}

// Função para ler o arquivo linkstokens.json
function readLinksTokensFile() {
    try {
        const data = fs.readFileSync(linksTokensFilePath, 'utf-8');
        const tokens = JSON.parse(data);
        return removeExpiredTokens(tokens); // Remove tokens expirados ao ler o arquivo
    } catch (err) {
        if (err.code === 'ENOENT') {
            return [];
        }
        throw err;
    }
}

// Função para remover tokens expirados
function removeExpiredTokens(tokens) {
    const now = new Date(); // Obtém a data e hora atual
    const validTokens = tokens.filter(token => new Date(token.expires) > now); // Filtra tokens válidos
    writeLinksTokensFile(validTokens); // Salva a lista atualizada
    return validTokens; // Retorna a lista de tokens válidos (opcional)
}

// Função para ler o arquivo linkstokens.json
function readLinksTokensFile() {
    try {
        const data = fs.readFileSync(linksTokensFilePath, 'utf-8');
        const tokens = JSON.parse(data);

        if (tokens.length === 0) {
            console.log('Nenhum token encontrado no arquivo linkstokens.json.');
            return [];
        }

        return removeExpiredTokens(tokens); // Remove tokens expirados ao ler o arquivo
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.log('Arquivo linkstokens.json não encontrado. Criando um novo...');
            return [];
        }
        throw err;
    }
}

// Função para adicionar um token
function addToken(username) {
    try {
        const tokens = readLinksTokensFile();
        const token = generateToken(); // Gera um token único
        const newToken = {
            token,
            username,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // Expira em 7 dias
        };
        tokens.push(newToken);
        writeLinksTokensFile(tokens);
        return token;
    } catch (err) {
        console.error('Erro ao adicionar token:', err);
        throw err;
    }
}

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
function writeLinksTokensFile(data) {
    try {
        fs.writeFileSync(linksTokensFilePath, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error('Erro ao escrever no arquivo linkstokens.json:', err);
        throw err;
    }
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

// Rota para adicionar campeonato
app.post('/admin/campeonatos/add', isAuthenticated, isSuperuser, upload.single('logoCamp'), (req, res) => {
    const { nome, responsavel, tipoTabela, grupos } = req.body;
    const logoCamp = req.file ? '/uploads/' + req.file.filename : null; // Caminho da logo

    if (!nome || !responsavel || !tipoTabela) {
        return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    let campeonatos = readJSONFile(campeonatosFilePath);
    let users = readJSONFile(usersFilePath);

    const campeonatoId = campeonatos.length;
    const novoCampeonato = {
        id: campeonatoId,
        nome,
        responsavel,
        tipoTabela,
        logoCamp: logoCamp ? '/uploads/' + logoCamp : null, // Adiciona o caminho da logo
        times: tipoTabela === 'pontosCorridos' ? [] : null,
        grupos: (tipoTabela === 'grupos' && grupos) ? JSON.parse(grupos) : null
    };

    campeonatos.push(novoCampeonato);

    const userIndex = users.findIndex(u => u.username === responsavel);
    if (userIndex !== -1) {
        if (!users[userIndex].campeonatos) {
            users[userIndex].campeonatos = [];
        }
        users[userIndex].campeonatos.push(campeonatoId);
    }

    writeJSONFile(usersFilePath, users);
    writeJSONFile(campeonatosFilePath, campeonatos);

    res.redirect('/admin/campeonatos');
});


app.post('/admin/campeonatos/update/:id', isAuthenticated, isSuperuser, (req, res) => {
    const { id } = req.params;
    const { nome, responsavel, tipoTabela, grupos } = req.body;

    // Lê os arquivos JSON novamente
    let campeonatos = readJSONFile(campeonatosFilePath);

    if (campeonatos[id]) {
        campeonatos[id].nome = nome;
        campeonatos[id].responsavel = responsavel;
        campeonatos[id].tipoTabela = tipoTabela;
        if (tipoTabela === 'pontosCorridos') {
            campeonatos[id].times = campeonatos[id].times || [];
            campeonatos[id].grupos = null;
        } else if (tipoTabela === 'grupos') {
            campeonatos[id].grupos = JSON.parse(grupos);
            campeonatos[id].times = null;
        }

        // Salva as alterações no arquivo JSON
        writeJSONFile(campeonatosFilePath, campeonatos);

        res.redirect('/admin/campeonatos');
    } else {
        res.status(404).send('Campeonato não encontrado.');
    }
});

app.post('/admin/campeonatos/delete/:id', isAuthenticated, isSuperuser, (req, res) => {
    const campeonatoId = parseInt(req.params.id); // Converte o ID para número inteiro

    let campeonatos = readJSONFile(campeonatosFilePath);
    let users = readJSONFile(usersFilePath);

    const campeonatoIndex = campeonatos.findIndex(c => c.id === campeonatoId); // Busca pelo ID

    if (campeonatoIndex !== -1) {
        campeonatos.splice(campeonatoIndex, 1); // Remove pelo índice encontrado

        users.forEach(user => {
            if (user.campeonatos) {
                user.campeonatos = user.campeonatos.filter(campeonatoId => campeonatoId !== campeonatoId);
                user.campeonatos = user.campeonatos.map(campeonatoId => {
                    if (campeonatoId > campeonatoId) {
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

app.post('/user/campeonatos/:id/add-time/:grupoIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).json({ success: false, error: 'Acesso negado.' });
    }

    if (!campeonatos[id].grupos || !campeonatos[id].grupos[grupoIndex]) {
        return res.status(404).json({ success: false, error: 'Grupo não encontrado.' });
    }

    if (!nome || isNaN(vitorias) || isNaN(jogos) || isNaN(empates) || isNaN(derrotas) || isNaN(golsMarcados) || isNaN(golsSofridos)) {
        return res.status(400).json({ success: false, error: 'Todos os campos do time são obrigatórios.' });
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

    campeonatos[id].grupos[grupoIndex].times.push(novoTime);
    writeJSONFile(campeonatosFilePath, campeonatos);
   
    res.redirect('/user');
    
});

app.post('/user/campeonatos/:id/delete-time/:grupoIndex/:timeIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex, timeIndex } = req.params;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o campeonato e o grupo existem
    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).json({ success: false, error: 'Acesso negado.' });
    }

    if (!campeonatos[id].grupos || !campeonatos[id].grupos[grupoIndex]) {
        return res.status(404).json({ success: false, error: 'Grupo não encontrado.' });
    }

    if (!campeonatos[id].grupos[grupoIndex].times || !campeonatos[id].grupos[grupoIndex].times[timeIndex]) {
        return res.status(404).json({ success: false, error: 'Time não encontrado.' });
    }

    // Remove o time do grupo
    campeonatos[id].grupos[grupoIndex].times.splice(timeIndex, 1);
    writeJSONFile(campeonatosFilePath, campeonatos);

    res.redirect('/user');
});

// Rota para editar times de grupos
app.get('/user/campeonatos/:id/edit-time/grupos/:grupoIndex/:timeIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex, timeIndex } = req.params;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o campeonato, grupo e time existem
    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).send('Acesso negado.');
    }

    if (!campeonatos[id].grupos || !campeonatos[id].grupos[grupoIndex]) {
        return res.status(404).send('Grupo não encontrado.');
    }

    if (!campeonatos[id].grupos[grupoIndex].times || !campeonatos[id].grupos[grupoIndex].times[timeIndex]) {
        return res.status(404).send('Time não encontrado.');
    }

    // Obtém os dados do time para edição
    const time = campeonatos[id].grupos[grupoIndex].times[timeIndex];

    res.render('edit-time', { campeonatoId: id, grupoIndex, timeIndex, time });
});


// Rota para editar times de pontos corridos
app.get('/user/campeonatos/:id/edit-time/pontos-corridos/:timeIndex', isAuthenticated, (req, res) => {
    const { id, timeIndex } = req.params;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o campeonato e o time existem
    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).send('Acesso negado.');
    }

    if (!campeonatos[id].times || !campeonatos[id].times[timeIndex]) {
        return res.status(404).send('Time não encontrado.');
    }

    // Obtém os dados do time para edição
    const time = campeonatos[id].times[timeIndex];

    res.render('edit-time', { campeonatoId: id, timeIndex, time });
});

// Rota para atualizar times de grupos
app.post('/user/campeonatos/:id/update-time/grupos/:grupoIndex/:timeIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex, timeIndex } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o campeonato, grupo e time existem
    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).send('Acesso negado.');
    }

    if (!campeonatos[id].grupos || !campeonatos[id].grupos[grupoIndex]) {
        return res.status(404).send('Grupo não encontrado.');
    }

    if (!campeonatos[id].grupos[grupoIndex].times || !campeonatos[id].grupos[grupoIndex].times[timeIndex]) {
        return res.status(404).send('Time não encontrado.');
    }

    // Atualiza os dados do time
    campeonatos[id].grupos[grupoIndex].times[timeIndex].nome = nome;
    campeonatos[id].grupos[grupoIndex].times[timeIndex].vitorias = parseInt(vitorias);
    campeonatos[id].grupos[grupoIndex].times[timeIndex].jogos = parseInt(jogos);
    campeonatos[id].grupos[grupoIndex].times[timeIndex].empates = parseInt(empates);
    campeonatos[id].grupos[grupoIndex].times[timeIndex].derrotas = parseInt(derrotas);
    campeonatos[id].grupos[grupoIndex].times[timeIndex].golsMarcados = parseInt(golsMarcados);
    campeonatos[id].grupos[grupoIndex].times[timeIndex].golsSofridos = parseInt(golsSofridos);

    writeJSONFile(campeonatosFilePath, campeonatos);
    res.redirect('/user');
});

// Rota para atualizar times de pontos corridos
app.post('/user/campeonatos/:id/update-time/pontos-corridos/:timeIndex', isAuthenticated, (req, res) => {
    const { id, timeIndex } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o campeonato e o time existem
    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).send('Acesso negado.');
    }

    if (!campeonatos[id].times || !campeonatos[id].times[timeIndex]) {
        return res.status(404).send('Time não encontrado.');
    }

    // Atualiza os dados do time
    campeonatos[id].times[timeIndex].nome = nome;
    campeonatos[id].times[timeIndex].vitorias = parseInt(vitorias);
    campeonatos[id].times[timeIndex].jogos = parseInt(jogos);
    campeonatos[id].times[timeIndex].empates = parseInt(empates);
    campeonatos[id].times[timeIndex].derrotas = parseInt(derrotas);
    campeonatos[id].times[timeIndex].golsMarcados = parseInt(golsMarcados);
    campeonatos[id].times[timeIndex].golsSofridos = parseInt(golsSofridos);

    writeJSONFile(campeonatosFilePath, campeonatos);
    res.redirect('/user');
});

app.post('/user/campeonatos/:id/delete-grupo/:grupoIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex } = req.params;
    const username = req.session.username;

    // Lê os campeonatos do JSON
    let campeonatos = readJSONFile(campeonatosFilePath);

    if (campeonatos[id] && campeonatos[id].responsavel === username) {
        if (campeonatos[id].grupos && campeonatos[id].grupos[grupoIndex]) {
            // Remove o grupo
            campeonatos[id].grupos.splice(grupoIndex, 1);

            // Salva as alterações no arquivo JSON
            writeJSONFile(campeonatosFilePath, campeonatos);
            req.session.success = 'Grupo excluído com sucesso!';
        } else {
            req.session.error = 'Grupo não encontrado.';
        }
    } else {
        req.session.error = 'Acesso negado: você não é o responsável por este campeonato.';
    }

    res.redirect('/user');
});

app.post('/user/campeonatos/:id/update-time/:grupoIndex/:timeIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex, timeIndex } = req.params;
    const { nome, vitorias, jogos, empates, derrotas, golsMarcados, golsSofridos } = req.body;
    const username = req.session.username;

    let campeonatos = readJSONFile(campeonatosFilePath);

    if (!campeonatos[id] || campeonatos[id].responsavel.trim().toLowerCase() !== username.trim().toLowerCase()) {
        return res.status(403).send('Acesso negado.');
    }

    if (!campeonatos[id].grupos || !campeonatos[id].grupos[grupoIndex]) {
        return res.status(404).send('Grupo não encontrado.');
    }

    if (!campeonatos[id].grupos[grupoIndex].times || !campeonatos[id].grupos[grupoIndex].times[timeIndex]) {
        return res.status(404).send('Time não encontrado.');
    }

    // Atualiza os dados do time
    campeonatos[id].grupos[grupoIndex].times[timeIndex] = {
        nome,
        vitorias: parseInt(vitorias),
        jogos: parseInt(jogos),
        empates: parseInt(empates),
        derrotas: parseInt(derrotas),
        golsMarcados: parseInt(golsMarcados),
        golsSofridos: parseInt(golsSofridos)
    };

    writeJSONFile(campeonatosFilePath, campeonatos);

    res.redirect('/user'); // Redireciona para a lista de campeonatos
});



app.post('/user/campeonatos/:id/add-grupo', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { nomeGrupo } = req.body;
    const username = req.session.username;

    // Lê os campeonatos do JSON sempre antes da verificação
    let campeonatos = readJSONFile(campeonatosFilePath);

    if (campeonatos[id] && campeonatos[id].responsavel.trim().toLowerCase() === username.trim().toLowerCase()) {
        if (!nomeGrupo) {
            req.session.error = 'Nome do grupo é obrigatório.';
        } else {
            if (!campeonatos[id].grupos) {
                campeonatos[id].grupos = [];
            }
            campeonatos[id].grupos.push({
                nome: nomeGrupo,
                times: []
            });

            // Atualiza o arquivo JSON
            writeJSONFile(campeonatosFilePath, campeonatos);
            req.session.success = 'Grupo adicionado com sucesso!';
        }
    } else {
        req.session.error = 'Acesso negado: você não é o responsável por este campeonato.';
    }

    res.redirect('/user');
});

app.post('/user/campeonatos/:id/delete-grupo/:grupoIndex', isAuthenticated, (req, res) => {
    const { id, grupoIndex } = req.params;
    const username = req.session.username;

    // Lê os campeonatos do JSON sempre antes da verificação
    let campeonatos = readJSONFile(campeonatosFilePath);

    if (campeonatos[id] && campeonatos[id].responsavel.trim().toLowerCase() === username.trim().toLowerCase()) {
        if (campeonatos[id].grupos && campeonatos[id].grupos[grupoIndex]) {
            campeonatos[id].grupos.splice(grupoIndex, 1);

            // Atualiza o arquivo JSON
            writeJSONFile(campeonatosFilePath, campeonatos);
            req.session.success = 'Grupo excluído com sucesso!';
        } else {
            req.session.error = 'Grupo não encontrado.';
        }
    } else {
        req.session.error = 'Acesso negado: você não é o responsável por este campeonato.';
    }

    res.redirect('/user');
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





// Rota para agendar jogos
app.post('/user/agendar-jogo', isAuthenticated, upload.fields([{ name: 'logo1_file', maxCount: 1 }, { name: 'logo2_file', maxCount: 1 }]), (req, res) => {
    const { 
        logo1_url, 
        logo2_url, 
        time1, 
        time2, 
        camp, 
        data, 
        hora, 
        local, 
        status, 
        placarAtivo, 
        golsTime1, 
        golsTime2, 
        rodada, 
        fase 
    } = req.body;

    const username = req.session.username;

    // Verifica se os campos obrigatórios estão preenchidos
    if (!time1 || !time2 || !camp || !data || !hora || !local) {
        req.session.error = 'Preencha todos os campos corretamente.';
        return res.redirect('/user/agenda');
    }

    // Define as URLs das logos
    const logo1 = req.files['logo1_file'] ? `/uploads/${req.files['logo1_file'][0].filename}` : logo1_url;
    const logo2 = req.files['logo2_file'] ? `/uploads/${req.files['logo2_file'][0].filename}` : logo2_url;

    // Verifica se as logos foram fornecidas
    if (!logo1 || !logo2) {
        req.session.error = 'Forneça uma URL ou envie uma imagem para as logos dos times.';
        return res.redirect('/user/agenda');
    }

    // Lê os agendamentos existentes
    const agendamentos = readJSONFile(agendamentosFilePath);

    // Cria o novo jogo com os novos campos
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
        status: status || 'agendado', // Define o status padrão como "agendado"
        placarAtivo: placarAtivo === 'on', // Converte para booleano
        golsTime1: placarAtivo === 'on' ? parseInt(golsTime1) || 0 : null, // Define os gols se o placar estiver ativo
        golsTime2: placarAtivo === 'on' ? parseInt(golsTime2) || 0 : null,
        rodada,
        fase,
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

    req.session.success = 'Jogo agendado com sucesso!';
    res.redirect('/user/agenda');
});



// Rota para deletar um jogo agendado
app.get('/user/agenda/deletar/:id', (req, res) => {
    const jogoId = parseInt(req.params.id);

    // Lógica para ler os dados dos agendamentos do arquivo JSON
    const caminhoArquivoAgendamentos = path.join(__dirname, 'data', 'agendamentos.json');
    fs.readFile(caminhoArquivoAgendamentos, 'utf8', (err, dataAgendamentos) => {
        if (err) {
            console.error('Erro ao ler o arquivo JSON de agendamentos:', err);
            return res.status(500).send('Erro ao carregar os dados');
        }

        let agendamentos = JSON.parse(dataAgendamentos);

        // Encontrar o índice do jogo a ser deletado
        const jogoIndex = agendamentos.findIndex(jogo => jogo.id === jogoId);

        if (jogoIndex === -1) {
            return res.status(404).send('Jogo não encontrado');
        }

        agendamentos.splice(jogoIndex, 1); // Remove o jogo do array

        // Escrever os dados atualizados de volta para o arquivo JSON de agendamentos
        fs.writeFile(caminhoArquivoAgendamentos, JSON.stringify(agendamentos, null, 2), (err) => {
            if (err) {
                console.error('Erro ao escrever no arquivo JSON de agendamentos:', err);
                return res.status(500).send('Erro ao salvar os dados');
            }

            // Lógica para ler os dados dos usuários do arquivo JSON
            const caminhoArquivoUsuarios = path.join(__dirname, 'data', 'users.json');
            fs.readFile(caminhoArquivoUsuarios, 'utf8', (err, dataUsuarios) => {
                if (err) {
                    console.error('Erro ao ler o arquivo JSON de usuários:', err);
                    return res.status(500).send('Erro ao carregar os dados');
                }

                let usuarios = JSON.parse(dataUsuarios);

                // Iterar sobre os usuários e remover o jogo agendado
                usuarios.forEach(usuario => {
                    if (usuario.agendas) {
                        usuario.agendas = usuario.agendas.filter(idJogo => idJogo !== jogoId);
                    }
                });

                // Escrever os dados atualizados dos usuários de volta para o arquivo JSON
                fs.writeFile(caminhoArquivoUsuarios, JSON.stringify(usuarios, null, 2), (err) => {
                    if (err) {
                        console.error('Erro ao escrever no arquivo JSON de usuários:', err);
                        return res.status(500).send('Erro ao salvar os dados');
                    }

                    // Redirecionar de volta para a página da agenda
                    res.redirect('/user/agenda');
                });
            });
        });
    });
});

// Rota para editar agendamento (GET)
app.get('/user/agenda/editar/:id', isAuthenticated, (req, res) => {
    const jogoId = parseInt(req.params.id); // Obtém o ID do agendamento da URL
    const username = req.session.username; // Obtém o usuário logado

    // Lê os arquivos JSON
    const users = readJSONFile(usersFilePath);
    const agendamentos = readJSONFile(agendamentosFilePath);
    const campeonatos = readJSONFile(campeonatosFilePath);

    // Verifica se o usuário tem permissão para editar o agendamento
    const user = users.find(u => u.username === username);
    if (user && user.agendas && user.agendas.includes(jogoId)) {
        const agendamento = agendamentos.find(jogo => jogo.id === jogoId); // Encontra o agendamento pelo ID

        if (agendamento) {
            // Filtra os campeonatos do usuário
            const userCampeonatos = campeonatos.filter(campeonato => 
                user.campeonatos.includes(campeonato.id)
            );

            // Renderiza a página de edição com os dados do agendamento
            res.render('editar-agenda', {
                campeonatos: userCampeonatos,
                agendamento: agendamento,
                id: jogoId, // Passa o ID para o template
                success: req.session.success,
                error: req.session.error
            });
        } else {
            // Agendamento não encontrado
            res.status(404).send('Agendamento não encontrado.');
        }
    } else {
        // Usuário não tem permissão
        res.status(403).send('Acesso negado: você não tem permissão para editar este agendamento.');
    }
});

// Rota para editar agendamento (POST)
app.post('/user/agenda/editar/:id', isAuthenticated, (req, res) => {
    const jogoId = parseInt(req.params.id);
    const { 
        logo1, 
        time1, 
        logo2, 
        time2, 
        camp, 
        data, 
        hora, 
        local, 
        status, 
        placarAtivo, 
        golsTime1, 
        golsTime2, 
        rodada, 
        fase 
    } = req.body;

    const username = req.session.username;

    const users = readJSONFile(usersFilePath);
    const user = users.find(u => u.username === username);

    if (user && user.agendas && user.agendas.includes(jogoId)) {
        const agendamentos = readJSONFile(agendamentosFilePath);
        const agendamentoIndex = agendamentos.findIndex(jogo => jogo.id === jogoId);

        if (agendamentoIndex !== -1) {
            // Atualiza os dados do agendamento
            agendamentos[agendamentoIndex] = {
                ...agendamentos[agendamentoIndex],
                logo1,
                time1,
                logo2,
                time2,
                camp,
                data,
                hora,
                local,
                status: status || 'agendado',
                placarAtivo: placarAtivo === 'on',
                golsTime1: placarAtivo === 'on' ? parseInt(golsTime1) || 0 : null,
                golsTime2: placarAtivo === 'on' ? parseInt(golsTime2) || 0 : null,
                rodada,
                fase,
                responsavel: username,
                updatedAt: new Date().toISOString() // Atualiza o campo updatedAt
            };

            // Salva as alterações no arquivo JSON
            writeJSONFile(agendamentosFilePath, agendamentos);

            // Redireciona para a página de agenda
            res.redirect('/user/agenda');
        } else {
            res.status(404).send('Agendamento não encontrado.');
        }
    } else {
        res.status(403).send('Acesso negado: você não tem permissão para editar este agendamento.');
    }
});




app.get('/agenda', (req, res) => {
         const agendamentos = readJSONFile(agendamentosFilePath);
        const campeonatos = readJSONFile(campeonatosFilePath);
    
        const agenda = agendamentos.map(jogo => {
            const campeonato = campeonatos.find(camp => camp.nome === jogo.camp);
            return {
                ...jogo,
                logoCamp: campeonato ? campeonato.logoCamp : null
            };
        });

    // Ordena os agendamentos por campeonato e horário
    agenda.sort((a, b) => {
        if (a.camp < b.camp) return -1;
        if (a.camp > b.camp) return 1;

        // Ordena por horário se os campeonatos forem iguais
        let horaA = parseInt(a.hora.replace('h', ''));
        let horaB = parseInt(b.hora.replace('h', ''));
        return horaA - horaB;
    });

    res.render('agenda', { agenda });
});

app.get('/agenda/campeonato/:id', (req, res) => {
    const campeonatoId = req.params.id;
    const agendamentos = readJSONFile(agendamentosFilePath);
    const campeonatos = readJSONFile(campeonatosFilePath);

    let agenda = agendamentos.map(jogo => { // Usando let aqui
        const campeonato = campeonatos.find(camp => camp.nome === jogo.camp);
        return {
            ...jogo,
            logoCamp: campeonato ? campeonato.logoCamp : null
        };
    });

    // Ordena os agendamentos por campeonato e horário
    agenda.sort((a, b) => {
        if (a.camp < b.camp) return -1;
        if (a.camp > b.camp) return 1;

        // Ordena por horário se os campeonatos forem iguais
        let horaA = parseInt(a.hora.replace('h', ''));
        let horaB = parseInt(b.hora.replace('h', ''));
        return horaA - horaB;
    });

    agenda = agenda.filter(jogo => {
        return String(jogo.camp) === campeonatoId; // Converte ambos para string
    });

    res.render('agenda', { agenda });
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
// Rota para exibir a página de cadastro
app.get('/cadastro', (req, res) => {
    const token = req.query.token; // Obtém o token da URL
    console.log('Token recebido:', token); // Log para depuração

    if (!token) {
        return res.status(400).send('Token não fornecido');
    }

    // Valida o token
    const tokens = readLinksTokensFile();
    const validToken = tokens.find(t => t.token === token && new Date(t.expires) > new Date());

    if (validToken) {
        // Token válido, renderiza a página de cadastro com o token
        console.log('Token válido:', validToken); // Log para depuração
        res.render('cadastro', { token });
    } else {
        // Token inválido ou expirado
        console.log('Token inválido ou expirado'); // Log para depuração
        res.status(400).send('Token inválido ou expirado');
    }
});
// Rota para processar o cadastro

app.post('/cadastro', (req, res) => {
    console.log('Dados recebidos:', req.body); // Log para depuração

    const { username, password, token } = req.body;

    if (!username || !password || !token) {
        console.log('Dados ausentes:', { username, password, token }); // Log para depuração
        return res.status(400).json({ error: 'Dados ausentes' });
    }

    // Valida o token
    const tokens = readLinksTokensFile();
    const validToken = tokens.find(t => t.token === token && new Date(t.expires) > new Date());

    if (!validToken) {
        console.log('Token inválido ou expirado:', token); // Log para depuração
        return res.status(400).json({ error: 'Token inválido ou expirado' });
    }

    // Verifica se o nome de usuário já existe
    const users = readJSONFile(usersFilePath);
    const userExists = users.some(u => u.username === username);
    if (userExists) {
        console.log('Nome de usuário já existe:', username); // Log para depuração
        return res.status(400).json({ error: 'Nome de usuário já existe' });
    }

    // Cria o novo usuário
    const newUserId = users.length > 0 ? users[users.length - 1].id + 1 : 1;
    users.push({ id: newUserId, username, password });

    // Salva as alterações
    writeJSONFile(usersFilePath, users);

    // Remove o token usado
    const updatedTokens = tokens.filter(t => t.token !== token);
    writeLinksTokensFile(updatedTokens);

    // Redireciona para a página de login
    res.redirect('/login');
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
    res.redirect('/admin/usuarios');
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

        console.log('Campeonato encontrado:', campeonato); // Log para depuração

        // Verificação e correção de campeonato.grupos
        if (campeonato.tipoTabela === 'grupos' && !Array.isArray(campeonato.grupos)) {
            console.error(`Campeonato ${nomeCampeonato} tem tipoTabela 'grupos', mas grupos não é um array.`);
            campeonato.grupos = []; // Define grupos como um array vazio para evitar o erro
            console.log('Grupos corrigidos:', campeonato.grupos); // Log para depuração
        } else if (campeonato.tipoTabela === 'grupos') {
            console.log('Grupos do campeonato:', campeonato.grupos); // Log para depuração
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
app.get('/gerar-link-convite', (req, res) => {
    try {
        const username = req.query.username; // Nome de usuário associado ao token (opcional)
        const token = addToken(username); // Gera e armazena o token
        const link = `http://${localIP}:${port}/cadastro?token=${token}`; // Link com o token
        res.json({ link }); // Resposta em JSON
    } catch (err) {
        console.error('Erro ao gerar link de convite:', err);
        res.status(500).json({ error: 'Erro ao gerar link de convite' }); // Erro em JSON
    }
});

const localIP = getLocalIP();
if (localIP) {
    console.log(`Endereço IP local: ${localIP}`);
} else {
    console.log('Não foi possível encontrar um endereço IP local.');
}

app.listen(port, () => {
    console.log(`Servidor rodando em http://${localIP}:${port}`);
});