import express, { Express } from 'express';
import compression from 'compression';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import expressSession from 'express-session';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import bodyParser from 'body-parser';

import dotenv from 'dotenv';
dotenv.config();

const init = (): Express => {
    const app: Express = express();
    app.use(
        cors({
            origin: process.env.CLIENT_URL, // Must provide origin to include credentials like cookies, sessions
            credentials: true, // Allows cookies to be included
        }),
    );
    app.use(cookieParser());
    app.use(morgan('dev'));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, '../public')));
    app.use(bodyParser.urlencoded({ extended: false }));
    app.use(compression());
    app.use(helmet());
    app.use(
        expressSession({
            secret: process.env.SECRET_KEY as string,
            resave: false,
            saveUninitialized: true,
            // In a development environment, secure can be set to false, but it should be true in production when using HTTPS.
            cookie: { secure: false, maxAge: 5 * 60000, sameSite: 'lax' },
        }),
    );
    return app;
};

export { init };
