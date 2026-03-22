import { useState, useEffect, useRef, useCallback } from 'react';
import { Card, Button, Grid, Section } from '../components/Common';
import {
  PieChart, Pie, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import '../styles/Pages.css';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const THREAT_COLORS = {
  Benign:        '#22c55e',
  Botnet:        '#ef4444',
  BruteForce:    '#f97316',
  DDoS:          '#8b5cf6',
  DoS:           '#06b6d4',
  Infilteration: '#ec4899',
  'Brute Force': '#f97316',
};
const DEFAULT_COLOR = '#94a3b8';

// The 4 folder definitions: fixed order for the 2x2 grid
const FOLDER_DEFS = [
  {
    model:       'default',
    folder_type: 'batch',
    cardTitle:   '5 Class — Unlabeled',
    modelLabel:  '5 Class (Default)',
    typeLabel:   'No ground truth',
  },
  {
    model:       'default',
    folder_type: 'batch_labeled',
    cardTitle:   '5 Class — Labeled',
    modelLabel:  '5 Class (Default)',
    typeLabel:   'With ground truth',
  },
  {
    model:       'all',
    folder_type: 'batch',
    cardTitle:   '6 Class — Unlabeled',
    modelLabel:  '6 Class (All)',
    typeLabel:   'No ground truth',
  },
  {
    model:       'all',
    folder_type: 'batch_labeled',
    cardTitle:   '6 Class — Labeled',
    modelLabel:  '6 Class (All)',
    typeLabel:   'With ground truth',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(isoStr) {
  if (!isoStr) return '';
  try {
    return new Date(isoStr).toLocaleDateString();
  } catch {
    return isoStr;
  }
}

function buildPredictedPieData(results) {
  const counts = {};
  (results || []).forEach(row => {
    const label = row.prediction || 'Unknown';
    counts[label] = (counts[label] || 0) + 1;
  });
  return Object.entries(counts).map(([name, value]) => ({
    name,
    value,
    fill: THREAT_COLORS[name] ?? DEFAULT_COLOR,
  }));
}

function buildActualPieData(results) {
  const counts = {};
  (results || []).forEach(row => {
    const label = row.actual_label || 'Unknown';
    counts[label] = (counts[label] || 0) + 1;
  });
  return Object.entries(counts).map(([name, value]) => ({
    name,
    value,
    fill: THREAT_COLORS[name] ?? DEFAULT_COLOR,
  }));
}

function buildPerClassData(confusion_matrix, labels) {
  if (!confusion_matrix || !labels) return [];
  return labels.map((label, i) => {
    const row = confusion_matrix[i] || [];
    const correct = row[i] ?? 0;
    const total = row.reduce((a, b) => a + b, 0);
    return { name: label, correct, wrong: total - correct };
  });
}

function modelLabel(model) {
  return model === 'all' ? '6 Class (All)' : '5 Class (Default)';
}

// ---------------------------------------------------------------------------
// TrashIcon
// ---------------------------------------------------------------------------

function TrashIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6l-1 14H6L5 6" />
      <path d="M10 11v6M14 11v6" />
      <path d="M9 6V4h6v2" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// FolderCard component
// ---------------------------------------------------------------------------

function FolderCard({ def, files, onUpload, onProcess, onDelete }) {
  const { cardTitle, modelLabel: mLabel, typeLabel, model, folder_type } = def;
  const fileInputRef = useRef(null);

  const [expandedFile, setExpandedFile] = useState(null);   // filename | null
  const [deleteTarget, setDeleteTarget] = useState(null);   // filename | null

  const handleUploadClick = () => {
    if (fileInputRef.current) fileInputRef.current.click();
  };

  const handleFileInputChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      onUpload(model, folder_type, file);
      e.target.value = '';
    }
  };

  const handleRowClick = (filename) => {
    setExpandedFile(prev => prev === filename ? null : filename);
  };

  const handleProcess = (filename) => {
    onProcess(model, folder_type, filename);
  };

  const handleTrashClick = (e, filename) => {
    e.stopPropagation();
    setDeleteTarget(filename);
  };

  const handleDeleteConfirm = () => {
    if (deleteTarget) {
      onDelete(model, folder_type, deleteTarget);
      if (expandedFile === deleteTarget) setExpandedFile(null);
      setDeleteTarget(null);
    }
  };

  return (
    <div className="batch-folder-card">
      {/* Header row: title/labels on left, + button on right */}
      <div className="batch-folder-header">
        <div>
          <div className="batch-folder-title">{cardTitle}</div>
          <div className="batch-folder-model-label">{mLabel}</div>
          <div className="batch-folder-type-label">{typeLabel}</div>
        </div>
        <button className="batch-upload-plus" onClick={handleUploadClick} title="Upload CSV file">
          +
        </button>
      </div>

      {/* File list — accordion */}
      <div className="batch-folder-files">
        {files.length === 0 ? (
          <div className="batch-folder-empty">No files. Click + to upload a CSV.</div>
        ) : (
          files.map(f => {
            const isExpanded = expandedFile === f.filename;
            return (
              <div key={f.filename} className={`batch-file-row${isExpanded ? ' batch-file-row-expanded' : ''}`}>
                {/* Filename row with always-visible Process button */}
                <div className="batch-file-name-row" onClick={() => handleRowClick(f.filename)}>
                  <span className="batch-file-chevron">{isExpanded ? '▾' : '▸'}</span>
                  <span className="batch-file-name">{f.filename}</span>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={e => { e.stopPropagation(); handleProcess(f.filename); }}
                  >
                    Process
                  </Button>
                </div>

                {/* Expanded detail: metadata + trash only */}
                {isExpanded && (
                  <div className="batch-file-detail">
                    <span className="batch-file-meta">
                      {formatBytes(f.size)} &middot; {formatDate(f.modified)}
                      {f.rows != null && ` \u00b7 ${f.rows.toLocaleString()} rows`}
                      {f.cols != null && ` \u00b7 ${f.cols} cols`}
                    </span>
                    <div className="batch-file-actions">
                      <button
                        className="batch-trash-btn"
                        onClick={e => handleTrashClick(e, f.filename)}
                        title={`Delete ${f.filename}`}
                      >
                        <TrashIcon />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".csv"
        style={{ display: 'none' }}
        onChange={handleFileInputChange}
      />

      {/* Delete confirmation modal */}
      {deleteTarget && (
        <div className="batch-modal-overlay" onClick={() => setDeleteTarget(null)}>
          <div className="batch-modal" onClick={e => e.stopPropagation()}>
            <div className="batch-modal-title">Delete file?</div>
            <div className="batch-modal-body">
              <strong>{deleteTarget}</strong> will be permanently removed.
            </div>
            <div className="batch-modal-actions">
              <Button variant="danger" size="sm" onClick={handleDeleteConfirm}>Delete</Button>
              <Button variant="secondary" size="sm" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// LabeledChartsSection component
// ---------------------------------------------------------------------------

function LabeledChartsSection({ accuracy_metrics, results }) {
  if (!accuracy_metrics) return null;

  const { accuracy, precision, recall, f1, confusion_matrix, labels } = accuracy_metrics;

  const predictedPieData = buildPredictedPieData(results);
  const actualPieData = buildActualPieData(results);
  const perClassData = buildPerClassData(confusion_matrix, labels);

  return (
    <div className="labeled-charts-section">
      <h3>Accuracy Analysis</h3>

      {/* 1. Accuracy summary cards */}
      <div className="labeled-accuracy-cards">
        <div className="live-stat-box">
          <div className="live-stat-label">Accuracy</div>
          <div className="live-stat-value" style={{ color: '#22c55e' }}>
            {accuracy != null ? `${(accuracy * 100).toFixed(2)}%` : '—'}
          </div>
        </div>
        <div className="live-stat-box">
          <div className="live-stat-label">Precision</div>
          <div className="live-stat-value">
            {precision != null ? `${(precision * 100).toFixed(2)}%` : '—'}
          </div>
        </div>
        <div className="live-stat-box">
          <div className="live-stat-label">Recall</div>
          <div className="live-stat-value">
            {recall != null ? `${(recall * 100).toFixed(2)}%` : '—'}
          </div>
        </div>
        <div className="live-stat-box">
          <div className="live-stat-label">F1-Score</div>
          <div className="live-stat-value">
            {f1 != null ? `${(f1 * 100).toFixed(2)}%` : '—'}
          </div>
        </div>
      </div>

      {/* 2. Side-by-side pie charts */}
      <div className="labeled-chart-pair">
        <div className="labeled-chart-box">
          <h4>Predicted Distribution</h4>
          {predictedPieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={predictedPieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(1)}%`
                  }
                />
                <Tooltip
                  contentStyle={{
                    background: 'var(--secondary)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>No data</div>
          )}
        </div>

        <div className="labeled-chart-box">
          <h4>Actual Distribution</h4>
          {actualPieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={actualPieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(1)}%`
                  }
                />
                <Tooltip
                  contentStyle={{
                    background: 'var(--secondary)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>No data</div>
          )}
        </div>
      </div>

      {/* 3. Per-class confusion bar chart */}
      {perClassData.length > 0 && (
        <div className="labeled-chart-box" style={{ marginTop: '1.5rem' }}>
          <h4>Per-Class: Correct vs Misclassified</h4>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={perClassData}
              margin={{ top: 8, right: 24, left: 0, bottom: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                dataKey="name"
                tick={{ fill: 'var(--text-secondary)', fontSize: 12 }}
              />
              <YAxis
                tick={{ fill: 'var(--text-secondary)', fontSize: 12 }}
              />
              <Tooltip
                contentStyle={{
                  background: 'var(--secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                }}
              />
              <Legend />
              <Bar dataKey="correct" stackId="a" fill="#22c55e" name="Correct" />
              <Bar dataKey="wrong" stackId="a" fill="#ef4444" name="Misclassified" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ResultsPanel component
// ---------------------------------------------------------------------------

function ResultsPanel({ results, onClose }) {
  const {
    filename, model, folder_type,
    total_flows, threat_count, threat_percentage,
    suspicious_count,
    accuracy_metrics,
  } = results;

  const isLabeled = folder_type === 'batch_labeled';

  const handleDownload = (format) => {
    const rows = results.results || [];
    let content = '';

    if (format === 'csv') {
      if (rows.length > 0) {
        const headers = Object.keys(rows[0]);
        content = headers.join(',') + '\n';
        rows.forEach(row => {
          content += headers.map(h => {
            const v = row[h];
            return v == null ? '' : String(v);
          }).join(',') + '\n';
        });
      }
    } else {
      content = JSON.stringify(rows, null, 2);
    }

    const blob = new Blob(
      [content],
      { type: format === 'csv' ? 'text/csv' : 'application/json' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}_results.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="batch-results-panel">
      {/* Header */}
      <Card
        title={`Results — ${modelLabel(model)} — ${filename}`}
        subtitle={isLabeled ? 'With ground truth evaluation' : 'Unlabeled batch classification'}
      >
        {/* Core stats */}
        <Grid cols={5}>
          <div className="live-stat-box">
            <div className="live-stat-label">Total Flows</div>
            <div className="live-stat-value">{total_flows?.toLocaleString()}</div>
          </div>
          <div className="live-stat-box">
            <div className="live-stat-label">Threats Detected</div>
            <div className="live-stat-value" style={{ color: '#ef4444' }}>
              {threat_count?.toLocaleString()}
            </div>
          </div>
          <div className="live-stat-box">
            <div className="live-stat-label">Threat %</div>
            <div className="live-stat-value" style={{ color: '#f97316' }}>
              {threat_percentage}%
            </div>
          </div>
          <div className="live-stat-box">
            <div className="live-stat-label">Suspicious</div>
            <div className="live-stat-value" style={{ color: '#f97316' }}>
              {suspicious_count != null ? suspicious_count.toLocaleString() : '—'}
            </div>
          </div>
          <div className="live-stat-box">
            <div className="live-stat-label">Model</div>
            <div className="live-stat-value" style={{ fontSize: '1.1rem' }}>
              {modelLabel(model)}
            </div>
          </div>
        </Grid>

        {/* Labeled accuracy charts — placed after stat cards, before table */}
        {isLabeled && accuracy_metrics && (
          <LabeledChartsSection
            accuracy_metrics={accuracy_metrics}
            results={results.results || []}
          />
        )}
      </Card>

      {/* Results table — first 20 rows */}
      <Card title="Sample Results" subtitle="First 20 rows">
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Prediction</th>
                <th>Confidence</th>
                {isLabeled && <th>Actual Label</th>}
                <th>2nd Prediction</th>
                <th>2nd Confidence</th>
              </tr>
            </thead>
            <tbody>
              {(results.results || []).slice(0, 20).map((row, idx) => (
                <tr key={idx}>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {row.timestamp ?? '—'}
                  </td>
                  <td
                    style={{
                      fontWeight: 600,
                      color: row.prediction === 'Benign' ? '#22c55e' : '#ef4444',
                    }}
                  >
                    {row.prediction ?? '—'}
                  </td>
                  <td>
                    {row.confidence != null
                      ? `${(row.confidence * 100).toFixed(1)}%`
                      : '—'}
                  </td>
                  {isLabeled && (
                    <td
                      style={{
                        fontWeight: 600,
                        color: row.actual_label === row.prediction ? '#22c55e' : '#ef4444',
                      }}
                    >
                      {row.actual_label ?? '—'}
                    </td>
                  )}
                  <td>{row.top2_prediction ?? '—'}</td>
                  <td>
                    {row.top2_confidence != null
                      ? `${(row.top2_confidence * 100).toFixed(1)}%`
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Download + reset */}
      <Card>
        <div className="btn-group">
          <Button variant="success" onClick={() => handleDownload('csv')}>
            Download CSV
          </Button>
          <Button variant="success" onClick={() => handleDownload('json')}>
            Download JSON
          </Button>
          <Button variant="secondary" onClick={onClose}>
            Back to Folders
          </Button>
        </div>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// BatchProcessing page
// ---------------------------------------------------------------------------

function BatchProcessing() {
  const [folders, setFolders] = useState({
    default: { batch: [], batch_labeled: [] },
    all:     { batch: [], batch_labeled: [] },
  });
  const [loadError, setLoadError]   = useState(null);
  const [classifyError, setClassifyError] = useState(null);
  const [classifyLoading, setClassifyLoading] = useState(false);
  const [results, setResults]       = useState(null);

  // ---------------------------------------------------------------------------
  // Load folders
  // ---------------------------------------------------------------------------

  const loadFolders = useCallback(async () => {
    try {
      const res = await fetch('/api/batch/folders');
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `Server returned ${res.status}`);
      }
      const data = await res.json();
      setFolders(data);
      setLoadError(null);
    } catch (err) {
      setLoadError(`Failed to load folders: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    loadFolders();
  }, [loadFolders]);

  // ---------------------------------------------------------------------------
  // Upload
  // ---------------------------------------------------------------------------

  const handleUpload = async (model, folder_type, file) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`/api/batch/upload/${model}/${folder_type}`, {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `Upload failed (${res.status})`);
      }
      await loadFolders();
    } catch (err) {
      setClassifyError(`Upload failed: ${err.message}`);
    }
  };

  // ---------------------------------------------------------------------------
  // Delete
  // ---------------------------------------------------------------------------

  const handleDelete = async (model, folder_type, filename) => {
    try {
      const res = await fetch(
        `/api/batch/delete/${model}/${folder_type}/${encodeURIComponent(filename)}`,
        { method: 'DELETE' }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `Delete failed (${res.status})`);
      }
      await loadFolders();
    } catch (err) {
      setClassifyError(`Delete failed: ${err.message}`);
    }
  };

  // ---------------------------------------------------------------------------
  // Classify from folder
  // ---------------------------------------------------------------------------

  const handleClassify = async (model, folder_type, filename) => {
    setClassifyLoading(true);
    setClassifyError(null);
    setResults(null);

    try {
      const res = await fetch('/api/batch/classify-folder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, folder_type, filename }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `Classification failed (${res.status})`);
      }
      const data = await res.json();
      setResults(data);
    } catch (err) {
      const raw = err.message ?? '';
      const lower = raw.toLowerCase();
      let msg;
      if (lower.includes('feature names') || lower.includes('feature name')) {
        const variant = model === 'all' ? '6 Class (All)' : '5 Class (Default)';
        msg = `Column mismatch for ${variant} model. ` +
          'The CSV columns do not match the model\u2019s expected features. ' +
          'Make sure the file was generated by CICFlowMeter with the correct ' +
          `column set for this model (${variant}). Do not rename, add, or remove columns.`;
      } else {
        msg = `Classification failed: ${raw}`;
      }
      setClassifyError(msg);
    } finally {
      setClassifyLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  const getFiles = (model, folder_type) =>
    folders?.[model]?.[folder_type] ?? [];

  return (
    <Section title="Batch Processing">
      {/* Error banners */}
      {loadError && (
        <div className="live-error-msg" style={{ marginBottom: '1rem' }}>
          {loadError}
        </div>
      )}
      {classifyError && (
        <div className="live-error-msg" style={{ marginBottom: '1rem' }}>
          {classifyError}
        </div>
      )}

      {/* Loading overlay */}
      {classifyLoading && (
        <div className="live-stat-box" style={{ marginBottom: '1rem', textAlign: 'center' }}>
          <div className="live-stat-label">Classifying...</div>
        </div>
      )}

      {/* Results panel */}
      {results ? (
        <ResultsPanel
          results={results}
          onClose={() => { setResults(null); setClassifyError(null); }}
        />
      ) : (
        <>
          {/* Section 1: Dataset folders */}
          <Card
            title="Select Dataset"
            subtitle="Choose a folder, upload files, or classify"
          >
            <div className="batch-folders-grid">
              {FOLDER_DEFS.map(def => (
                <FolderCard
                  key={`${def.model}-${def.folder_type}`}
                  def={def}
                  files={getFiles(def.model, def.folder_type)}
                  onUpload={handleUpload}
                  onProcess={handleClassify}
                  onDelete={handleDelete}
                />
              ))}
            </div>
          </Card>
        </>
      )}
    </Section>
  );
}

export default BatchProcessing;
