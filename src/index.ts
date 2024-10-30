import { NextFunction, Request, Response, Express } from 'express';
import createHttpError, { HttpError } from 'http-errors';

import router from './routes';
import * as server from './configs/server.config';
import * as database from './configs/database.config';
import * as EnvConfig from './configs/env.config';
import dotenv from 'dotenv';
dotenv.config();
declare module 'express-session' {
    interface SessionData {
        accessToken?: string;
    }
}
const app: Express = server.init();
database.connect();

// validate env variable
EnvConfig.getSanitzedConfig(EnvConfig.getConfig());

app.get('/', (req: Request, res: Response): any => {
    return res.status(200).json({
        msg: 'Server Initialized',
    });
});

app.use('/api/v1', router);

app.use((req: Request, res: Response, next: NextFunction) => {
    const error = createHttpError(404, 'Page Not Found');
    next(error);
});

app.use((err: HttpError, req: Request, res: Response, next: NextFunction): any => {
    return res.status(err.statusCode || 500).json({
        status: err.status || 500,
        msg: err.message || 'Internal Server Error',
        stack: err.stack || undefined,
    });
});

app.listen(process.env.PORT, () => {
    console.log(`Server running on http://localhost:${process.env.PORT}`);
});
