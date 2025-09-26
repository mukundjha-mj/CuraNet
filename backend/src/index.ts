import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Routes
import authRoutes from './routes/auth.routes';
import recordRoutes from './routes/records.routes';
import adminRoutes from './routes/admin.routes';

const app = express();

// Basic middlewares
const allowedOrigins = process.env.CORS_ORIGIN
	? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
	: [
		'http://localhost:3000',
		'http://127.0.0.1:3000',
		'http://localhost:3001',
		'http://127.0.0.1:3001',
	];

const corsOptions: cors.CorsOptions = {
	origin: allowedOrigins,
	credentials: true,
	methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
	allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
	optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
// Handle CORS preflight (OPTIONS) across-the-board using a regex (Express 5 compatible)
app.options(/.*/, cors(corsOptions));
// Handle CORS preflight (OPTIONS) for all API routes (Express 5 doesn't support '*')
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api/records', recordRoutes);
app.use('/api/admin', adminRoutes);

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

const PORT = Number(process.env.PORT ?? 3001);
app.listen(PORT, () => {
	console.log(`Auth service listening on http://localhost:${PORT}`);
});

export default app;
