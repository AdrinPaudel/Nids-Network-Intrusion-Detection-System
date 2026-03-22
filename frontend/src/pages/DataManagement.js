import { useState, useEffect, useCallback, useRef } from 'react';
import { Card, Button, Section } from '../components/Common';
import '../styles/Pages.css';
import '../styles/DataManagement.css';

const API = '/api';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatSize(mb) {
  if (mb < 0.01) return '< 0.01 MB';
  if (mb < 1) return `${(mb * 1024).toFixed(0)} KB`;
  return `${mb.toFixed(2)} MB`;
}

function formatDate(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

// ---------------------------------------------------------------------------
// Storage stats derived from file lists
// ---------------------------------------------------------------------------

function StorageStats({ rawFiles, archivedFiles }) {
  const totalCount = rawFiles.length + archivedFiles.length;
  const totalMb = [...rawFiles, ...archivedFiles].reduce((sum, f) => sum + (f.size_mb || 0), 0);
  return (
    <div className="storage-stats">
      <div className="stat-pill">
        <span className="stat-pill-label">Active</span>
        <span className="stat-pill-value">{rawFiles.length}</span>
      </div>
      <div className="stat-pill">
        <span className="stat-pill-label">Archived</span>
        <span className="stat-pill-value">{archivedFiles.length}</span>
      </div>
      <div className="stat-pill">
        <span className="stat-pill-label">Total files</span>
        <span className="stat-pill-value">{totalCount}</span>
      </div>
      <div className="stat-pill">
        <span className="stat-pill-label">Total size</span>
        <span className="stat-pill-value">{formatSize(totalMb)}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Drag-and-drop upload zone
// ---------------------------------------------------------------------------

function UploadZone({ onUploaded }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const inputRef = useRef(null);

  const uploadFile = useCallback(async (file) => {
    if (!file.name.endsWith('.csv')) {
      setUploadError('Only CSV files are supported.');
      return;
    }
    setUploading(true);
    setUploadError(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await fetch(`${API}/upload-dataset`, { method: 'POST', body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Upload failed');
      onUploaded(data);
    } catch (err) {
      setUploadError(err.message);
    } finally {
      setUploading(false);
    }
  }, [onUploaded]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(file);
  }, [uploadFile]);

  const handleChange = useCallback((e) => {
    const file = e.target.files[0];
    if (file) uploadFile(file);
    e.target.value = '';
  }, [uploadFile]);

  return (
    <div
      className={`upload-zone${dragging ? ' upload-zone--active' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current && inputRef.current.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && inputRef.current && inputRef.current.click()}
      aria-label="Upload CSV file"
    >
      <input
        ref={inputRef}
        type="file"
        accept=".csv"
        style={{ display: 'none' }}
        onChange={handleChange}
      />
      {uploading ? (
        <p className="upload-zone__text">Uploading...</p>
      ) : (
        <>
          <p className="upload-zone__icon">+</p>
          <p className="upload-zone__text">
            Drag and drop a CSV file here, or click to browse
          </p>
        </>
      )}
      {uploadError && (
        <p className="upload-zone__error">{uploadError}</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Preview modal
// ---------------------------------------------------------------------------

function PreviewModal({ filename, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch(`${API}/data/preview/${encodeURIComponent(filename)}`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch((err) => { setError(err.message); setLoading(false); });
  }, [filename]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">Preview: {filename}</span>
          <button className="modal-close" onClick={onClose} aria-label="Close">x</button>
        </div>
        <div className="modal-body">
          {loading && <p>Loading...</p>}
          {error && <p className="error-text">{error}</p>}
          {data && (
            <div className="preview-table-wrap">
              <table className="preview-table">
                <thead>
                  <tr>
                    {data.columns.map((col) => (
                      <th key={col}>{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.rows.map((row, i) => (
                    <tr key={i}>
                      {data.columns.map((col) => (
                        <td key={col}>{row[col] == null ? '' : String(row[col])}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="preview-note">Showing first {data.rows.length} rows</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single file row — active dataset
// ---------------------------------------------------------------------------

function FileRow({ file, onArchive, onDelete, onPreview }) {
  const [busy, setBusy] = useState(false);

  const wrap = useCallback(async (action) => {
    setBusy(true);
    try { await action(); } finally { setBusy(false); }
  }, []);

  return (
    <div className="file-item">
      <div className="file-info">
        <div className="file-name">{file.name}</div>
        <div className="file-meta">
          {formatSize(file.size_mb)} &bull; modified {formatDate(file.modified)}
        </div>
      </div>
      <div className="file-actions">
        <Button variant="secondary" size="sm" onClick={() => onPreview(file.name)} disabled={busy}>
          Preview
        </Button>
        <Button variant="secondary" size="sm" onClick={() => wrap(() => onArchive(file.name))} disabled={busy}>
          Archive
        </Button>
        <Button variant="danger" size="sm" onClick={() => wrap(() => onDelete(file.name))} disabled={busy}>
          Delete
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single file row — archived dataset
// ---------------------------------------------------------------------------

function ArchivedRow({ file, onRestore, onDelete }) {
  const [busy, setBusy] = useState(false);

  const wrap = useCallback(async (action) => {
    setBusy(true);
    try { await action(); } finally { setBusy(false); }
  }, []);

  return (
    <div className="file-item file-item--archived">
      <div className="file-info">
        <div className="file-name">{file.name}</div>
        <div className="file-meta">
          {formatSize(file.size_mb)} &bull; modified {formatDate(file.modified)}
        </div>
      </div>
      <div className="file-actions">
        <Button variant="secondary" size="sm" onClick={() => wrap(() => onRestore(file.name))} disabled={busy}>
          Restore
        </Button>
        <Button variant="danger" size="sm" onClick={() => wrap(() => onDelete(file.name))} disabled={busy}>
          Delete
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

function DataManagement() {
  const [rawFiles, setRawFiles] = useState([]);
  const [archivedFiles, setArchivedFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [previewFile, setPreviewFile] = useState(null);
  const [notification, setNotification] = useState(null);

  const notify = useCallback((msg, type = 'success') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 3500);
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawRes, archRes] = await Promise.all([
        fetch(`${API}/data/list-raw`),
        fetch(`${API}/data/list-archived`),
      ]);
      const [rawData, archData] = await Promise.all([rawRes.json(), archRes.json()]);
      setRawFiles(rawData.files || []);
      setArchivedFiles(archData.files || []);
    } catch (err) {
      setError('Failed to load datasets. Is the backend running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleUploaded = useCallback((result) => {
    notify(`Uploaded ${result.filename} (${formatSize(result.size_mb)})`);
    loadData();
  }, [notify, loadData]);

  const handleArchive = useCallback(async (filename) => {
    const res = await fetch(`${API}/data/archive/${encodeURIComponent(filename)}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Archive failed');
    notify(`Archived ${filename}`);
    loadData();
  }, [notify, loadData]);

  const handleRestore = useCallback(async (filename) => {
    const res = await fetch(`${API}/data/restore/${encodeURIComponent(filename)}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Restore failed');
    notify(`Restored ${filename}`);
    loadData();
  }, [notify, loadData]);

  const handleDelete = useCallback(async (filename) => {
    if (!window.confirm(`Permanently delete "${filename}"? This cannot be undone.`)) return;
    const res = await fetch(`${API}/data/delete/${encodeURIComponent(filename)}?confirm=true`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Delete failed');
    notify(`Deleted ${filename}`);
    loadData();
  }, [notify, loadData]);

  const handleDeleteArchived = useCallback(async (filename) => {
    if (!window.confirm(`Permanently delete archived "${filename}"? This cannot be undone.`)) return;
    const res = await fetch(`${API}/data/delete-archived/${encodeURIComponent(filename)}?confirm=true`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Delete failed');
    notify(`Deleted archived ${filename}`);
    loadData();
  }, [notify, loadData]);

  if (loading) {
    return (
      <Section title="Data Management">
        <p style={{ padding: '2rem', textAlign: 'center' }}>Loading datasets...</p>
      </Section>
    );
  }

  return (
    <Section title="Data Management">
      {notification && (
        <div className={`dm-notification dm-notification--${notification.type}`}>
          {notification.msg}
        </div>
      )}

      {error && (
        <div className="dm-notification dm-notification--error">{error}</div>
      )}

      {/* Storage summary */}
      <StorageStats rawFiles={rawFiles} archivedFiles={archivedFiles} />

      {/* Upload */}
      <Card title="Upload Dataset" subtitle="Add a new CSV to the active dataset pool">
        <UploadZone onUploaded={handleUploaded} />
      </Card>

      {/* Active datasets */}
      <Card title="Active Datasets" subtitle={`${rawFiles.length} file${rawFiles.length !== 1 ? 's' : ''} in data/data_model_use/default/`}>
        {rawFiles.length > 0 ? (
          <div className="file-list">
            {rawFiles.map((file) => (
              <FileRow
                key={file.name}
                file={file}
                onArchive={handleArchive}
                onDelete={handleDelete}
                onPreview={setPreviewFile}
              />
            ))}
          </div>
        ) : (
          <p style={{ color: 'var(--text-secondary)' }}>No datasets uploaded yet. Use the upload zone above.</p>
        )}
      </Card>

      {/* Archived datasets */}
      <Card title="Archived Datasets" subtitle={`${archivedFiles.length} file${archivedFiles.length !== 1 ? 's' : ''} in data/data_model_use/archived/`}>
        {archivedFiles.length > 0 ? (
          <div className="file-list">
            {archivedFiles.map((file) => (
              <ArchivedRow
                key={file.name}
                file={file}
                onRestore={handleRestore}
                onDelete={handleDeleteArchived}
              />
            ))}
          </div>
        ) : (
          <p style={{ color: 'var(--text-secondary)' }}>No archived datasets.</p>
        )}
      </Card>

      {/* Preview modal */}
      {previewFile && (
        <PreviewModal filename={previewFile} onClose={() => setPreviewFile(null)} />
      )}
    </Section>
  );
}

export default DataManagement;
