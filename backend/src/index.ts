import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Routes
import authRoutes from './routes/auth.routes';

const app = express();

// Basic middlewares
app.use(cors({
	origin: process.env.CORS_ORIGIN?.split(',').map(o => o.trim()) || true,
	credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Mount routes
app.use('/api/auth', authRoutes);

// Simple liveness endpoint (POST-only)
app.post('/healthz', (_req, res) => res.status(200).json({ status: 'ok' }));

// 404 handler
app.use((req, res) => {
	res.status(404).json({ message: 'Not Found', path: req.path });
});

// Error handler
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
	console.error('Unhandled error:', err);
	res.status(err?.status || 500).json({ message: err?.message || 'Internal server error' });
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => {
	console.log(`Auth service listening on http://localhost:${PORT}`);
});

export default app;
