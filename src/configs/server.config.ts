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
    app.use(cors());
    app.use(morgan('dev'));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, '../public')));
    app.use(bodyParser.urlencoded({ extended: false }));
    app.use(compression());
    app.use(helmet());
    app.use(cookieParser());
    app.use(
        expressSession({
            secret: process.env.SECRET_KEY as string,
            resave: false,
            saveUninitialized: true,
            // secure: false allow https and http to requuest while secure: true just allows https
            cookie: { secure: false, maxAge: 5*60000 },
        }),
    );
    return app;
};

export { init };
