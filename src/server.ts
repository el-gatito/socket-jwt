import { Server, Socket } from 'socket.io';
import dotenv from 'dotenv';
import express, { Express, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import path from 'path';
import http, { Server as HttpServer } from 'http';

dotenv.config();

const app: Express = express();
const server: HttpServer = http.createServer(app);

const port: string | number = process.env.PORT || 3000;
const jwtsecret: string = process.env.JWT_SECRET || 'token-secreta-padrao';

const io: Server = new Server(server, {
    path: '/socket.io/',
    serveClient: false,
});

const authMiddleware = (
    socket: Socket,
    next: (err?: Error | undefined) => void
) => {
    /*  Este é o middleware que será executado antes de qualquer evento
        ser disparado. Aqui, checamos se o usuário está autenticado, e 
        se ele estiver, passamos para o próximo middleware, até chegar
        no evento que queremos disparar.

        Caso o usuário não esteja autenticado, retornamos um erro, e o
        evento não é disparado. */

    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error('Authentication error'));
    }

    try {
        const decoded = jwt.verify(token, jwtsecret) as Record<string, unknown>;
        /*  Se a token for válida, armazenamos as informações do usuário
            na propriedade "data" do socket, para que possamos acessar
            em qualquer evento.
        */
        socket.data.user = decoded;
    } catch (err: any) {
        return next(new Error('Authentication error'));
    }

    next();
};

io.use(authMiddleware);

io.on('connection', (socket: Socket) => {
    console.log(`[socket]: user connected: ${socket.data.user.username}`);

    /*  Note que agora, podemos acessar as informações do usuário através
        da propriedade "data" do socket, e o usuário só consegue se conectar
        se estiver autenticado. 
        
        Para notificar uma room por exemplo, não precisamos mais esperar que o 
        cliente envie seu username, pois já temos essa informação de maneira
        segura, já que o usuário não será capaz de alterar o valor da propriedade. */

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

app.use(express.json());

app.post('/auth', async (req: Request, res: Response) => {
    const { username } = req.body;

    /*  Todo o código de autenticação vem aqui, query na database e checar
        a hash de senha. Aqui, estamos apenas assumindo que o usuário já 
        está autenticado. */

    const token = jwt.sign({ username }, jwtsecret, { expiresIn: '30d' });

    /*  Com a token gerada, retornamos as informações relevantes para o
        front-end, que irá armazenar a token (para qualquer requisição) 
        outras informações do usuário. */

    res.json({ token, username });
});

app.get('/', (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

server.listen(port, () => {
    console.log(`[server]: running at http://localhost:${port}`);
});

/*
    DESCRIÇÃO GERAL DO CÓDIGO
    
    1.  Definimos uma função de middleware `authMiddleware` que é 
        usada para autenticar conexões de socket.

    2.  Nesta função de middleware, recuperamos o token JWT de 
        `socket.handshake.auth.token`, passado pelo cliente.

    3.  Se nenhum token for fornecido, ele chama a próxima função 
        com erro, que rejeitará a conexão.

    4.  Se um token for fornecido, ele tentará verificar e 
        decodificar o token usando `jwt.verify`. Se o token for 
        inválido (por exemplo, se expirou ou se não foi assinado 
        com o segredo correto), `jwt.verify` gerará um erro e a 
        função de middleware chamará `next` com um erro.

    5.  Se o token for válido, ele armazena os dados do token 
        decodificado em `socket.data.user` e chama `next` sem 
        nenhum argumento, o que permitirá a conexão.

    6.  No manipulador de eventos de conexão `io.on('connection'`,
        recuperamos as informações do usuário autenticado com 
        `socket.data.user.username`.
*/
