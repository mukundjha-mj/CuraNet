"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const dotenv_1 = __importDefault(require("dotenv"));
// Load environment variables
dotenv_1.default.config();
// Routes
const auth_routes_1 = __importDefault(require("./routes/auth.routes"));
const app = (0, express_1.default)();
// Basic middlewares
app.use((0, cors_1.default)({
    origin: ((_a = process.env.CORS_ORIGIN) === null || _a === void 0 ? void 0 : _a.split(',').map(o => o.trim())) || true,
    credentials: true
}));
app.use(express_1.default.json({ limit: '1mb' }));
app.use(express_1.default.urlencoded({ extended: true }));
app.use((0, cookie_parser_1.default)());
// Mount routes
app.use('/api/auth', auth_routes_1.default);
// Simple liveness endpoint (POST-only)
app.post('/healthz', (_req, res) => res.status(200).json({ status: 'ok' }));
// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Not Found', path: req.path });
});
// Error handler
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status((err === null || err === void 0 ? void 0 : err.status) || 500).json({ message: (err === null || err === void 0 ? void 0 : err.message) || 'Internal server error' });
});
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => {
    console.log(`Auth service listening on http://localhost:${PORT}`);
});
exports.default = app;
