# Frontend

React SPA served by the FastAPI backend in production, or standalone on port 3000 in development.

---

## Running

### Development (hot reload)

```bash
npm install   # first time only
npm start     # http://localhost:3000
```

Proxies API calls to http://localhost:8000. The backend must be running separately:

```bash
python main.py --dev
```

### Production build

```bash
npm run build
```

The `build/` output is served as static files by FastAPI at http://localhost:8000.

---

## Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | Model accuracy, recent activity, system uptime |
| Batch Processing | `/batch` | Upload CSV, classify, view results |
| Live Detection | `/live` | Start/stop live capture, real-time threat feed |
| Simulation | `/simulation` | Replay pre-recorded traffic, real-time threat feed |
| Data Management | `/data` | Upload, archive, delete batch CSVs |
| Reports | `/reports` | Browse all past session reports |
| Training Pipeline | `/training` | Run ML training modules, monitor progress |

---

## Structure

```
src/
├── App.js              # Router + layout
├── Common.js           # Shared utilities
├── Header.js           # Top navigation bar
├── Sidebar.js          # Left navigation
├── pages/
│   ├── Dashboard.js
│   ├── BatchProcessing.js
│   ├── LiveClassification.js
│   ├── Simulation.js
│   ├── DataManagement.js
│   ├── Reports.js
│   └── TrainingPipeline.js
└── styles/             # Per-page CSS files
```

---

## API Communication

All pages use polling — there are no WebSockets.

- Live and simulation pages poll `/api/live/events/{id}?from=N` or `/api/simulation/events/{id}?from=N` every 500ms
- The `from` parameter is the last received event index; the server returns only new events since that index
- Sessions are started with POST and stopped with POST to `/stop/{id}`

In development, `package.json` proxies all `/api` requests to http://localhost:8000. In production the frontend and backend share the same origin.
