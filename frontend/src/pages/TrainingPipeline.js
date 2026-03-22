import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, Alert, StatCard, Grid, Section } from '../components/Common';
import '../styles/Pages.css';
import '../styles/TrainingPipeline.css';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PIPELINE_MODULES = [
  { id: 1, name: 'Data Loading',    detail: 'Raw CSVs ingested from CICIDS2018 dataset (10 files, ~11GB)' },
  { id: 2, name: 'Exploration',     detail: 'Class distribution, feature statistics, correlation heatmap' },
  { id: 3, name: 'Preprocessing',   detail: 'Cleaning, SMOTE balancing, feature scaling, RFE selection (40 features)' },
  { id: 4, name: 'Training',        detail: 'RandomForestClassifier, 150 estimators, RandomizedSearchCV (15 iterations)' },
  { id: 5, name: 'Testing',         detail: 'Held-out evaluation, confusion matrix, ROC curves, per-class metrics' },
];

const MODELS = [
  {
    key: 'default',
    label: '5 Class (Default)',
    classes: 'Benign, DDoS, DoS, Brute Force, Botnet',
    accuracy: '99.99%',
    macroF1: '0.9993',
    features: 40,
    estimators: 150,
    samples: '10.2M',
    cvScore: '99.93%',
    tuningTime: '31.7 min',
    trainingDate: '2026-03-04',
    status: 'Production Ready',
    statusColor: '#22c55e',
  },
  {
    key: 'all',
    label: '6 Class (All)',
    classes: 'Benign, DDoS, DoS, Brute Force, Botnet, Infilteration',
    accuracy: '90.88%',
    macroF1: '0.8430',
    features: 40,
    estimators: 150,
    samples: '10.6M',
    cvScore: '88.9%',
    tuningTime: '49.9 min',
    trainingDate: '2026-03-04',
    status: 'Review Needed',
    statusColor: '#f97316',
  },
];

const RAW_FILES = [
  'Wednesday-14-02-2018',
  'Thursday-15-02-2018',
  'Friday-16-02-2018',
  'Wednesday-21-02-2018',
  'Thuesday-20-02-2018',
  'Thursday-22-02-2018',
  'Friday-23-02-2018',
  'Wednesday-28-02-2018',
  'Thursday-01-03-2018',
  'Friday-02-03-2018',
];

// ---------------------------------------------------------------------------
// CompletedModuleRow
// ---------------------------------------------------------------------------

function CompletedModuleRow({ module }) {
  return (
    <div className="module-row module-completed">
      <div className="module-icon">
        <span style={{ color: '#22c55e', fontWeight: '700' }}>✓</span>
      </div>
      <div className="module-name">
        Module {module.id}: {module.name}
      </div>
      <div className="module-status-badge status-completed">completed</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ModelSummaryCard
// ---------------------------------------------------------------------------

function ModelSummaryCard({ model }) {
  return (
    <Card title={model.label} subtitle={model.classes}>
      <div style={{ marginBottom: '0.75rem' }}>
        <span
          className="report-badge-type"
          style={{
            background: model.statusColor + '22',
            color: model.statusColor,
            padding: '0.2rem 0.6rem',
            borderRadius: '6px',
            fontSize: '0.8rem',
            fontWeight: 700,
          }}
        >
          {model.status}
        </span>
      </div>
      <Grid cols={3}>
        <StatCard label="Accuracy"   value={model.accuracy} />
        <StatCard label="Macro F1"   value={model.macroF1} />
        <StatCard label="CV Score"   value={model.cvScore} />
        <StatCard label="Features"   value={model.features} />
        <StatCard label="Estimators" value={model.estimators} />
        <StatCard label="Samples"    value={model.samples} />
        <StatCard label="Tuning"     value={model.tuningTime} />
        <StatCard label="Trained On" value={model.trainingDate} />
      </Grid>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// buildSimSteps — exported pure helper (testable)
// Maps selected step keys → simulation step descriptors
// ---------------------------------------------------------------------------

const SIM_STEP_META = {
  exploration: {
    label: 'Data Exploration',
    workingMsg: 'Exploring dataset — analyzing class distribution, feature statistics, and correlations...',
    doneMsg: 'Data exploration complete ✓',
  },
  preprocessing: {
    label: 'Preprocessing',
    workingMsg: 'Cleaning data, applying SMOTE balancing, scaling features, running RFE selection...',
    doneMsg: 'Preprocessing complete ✓',
  },
  tuning: {
    label: 'Hyperparameter Tuning',
    workingMsg: 'Running cross-validation grid search — evaluating hyperparameter combinations...',
    doneMsg: 'Hyperparameter tuning complete ✓',
  },
  training: {
    label: 'Model Training',
    workingMsg: 'Training Random Forest model on processed dataset — fitting 150 estimators...',
    doneMsg: 'Model training complete ✓',
  },
  testing: {
    label: 'Testing & Evaluation',
    workingMsg: 'Evaluating model on held-out test set — computing confusion matrix and ROC curves...',
    doneMsg: 'Testing & evaluation complete ✓',
  },
};

export function buildSimSteps(keys) {
  return keys.map((key) => SIM_STEP_META[key] ?? {
    label: key,
    workingMsg: `Running ${key}...`,
    doneMsg: `${key} complete ✓`,
  });
}

// Total simulation duration in ms
const SIM_TOTAL_MS = 60000;
// Tick interval in ms
const SIM_TICK_MS = 400;

// ---------------------------------------------------------------------------
// SimulationPanel
// ---------------------------------------------------------------------------

function SimulationPanel({ steps, onReset }) {
  const safeSteps = steps && steps.length > 0 ? steps : null;

  // Each step spends 80% of its slot "working" and 20% showing "done"
  const totalTicks = SIM_TOTAL_MS / SIM_TICK_MS;
  const ticksPerStep = safeSteps ? totalTicks / safeSteps.length : totalTicks;
  const workingTicks = Math.floor(ticksPerStep * 0.8);

  const [tick, setTick] = useState(0);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (!safeSteps) return;
    intervalRef.current = setInterval(() => {
      setTick((t) => t + 1);
    }, SIM_TICK_MS);
    return () => clearInterval(intervalRef.current);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const isDone = tick >= totalTicks;

  useEffect(() => {
    if (isDone) clearInterval(intervalRef.current);
  }, [isDone]);

  if (!safeSteps) {
    return (
      <div className="sim-container" data-testid="sim-panel">
        <p>No pipeline steps selected. Please go back and select at least one step.</p>
        <button className="btn btn-secondary" onClick={onReset}>Go Back</button>
      </div>
    );
  }

  // Which step is active
  const stepIndex = Math.min(Math.floor(tick / ticksPerStep), steps.length - 1);
  // Ticks into the current step
  const tickInStep = tick - stepIndex * ticksPerStep;
  // Is the current step in "done" sub-phase?
  const currentStepDone = tickInStep >= workingTicks;

  // Overall progress 0-100
  const progress = isDone ? 100 : Math.min((tick / totalTicks) * 100, 99);

  if (isDone) {
    return (
      <div className="sim-container" data-testid="sim-panel">
        <div className="sim-complete-banner" data-testid="sim-complete">
          <span className="sim-complete-icon">✓</span>
          Training Pipeline Complete!
        </div>
        <div className="sim-step-list">
          {steps.map((s, i) => (
            <div key={i} className="sim-step-done" data-testid="sim-step-done">
              <span className="sim-step-check">✓</span>
              {s.doneMsg}
            </div>
          ))}
        </div>
        <button className="btn btn-primary btn-md" onClick={onReset}>
          Start New Run
        </button>
      </div>
    );
  }

  return (
    <div className="sim-container" data-testid="sim-panel">
      <div className="sim-header">
        <span className="sim-spinner" />
        Running Training Pipeline
      </div>

      <div className="sim-progress-bar-track">
        <div
          className="sim-progress-bar-fill"
          style={{ width: `${progress.toFixed(1)}%` }}
        />
      </div>
      <div className="sim-progress-label">{Math.round(progress)}%</div>

      <div className="sim-step-list">
        {steps.map((s, i) => {
          if (i < stepIndex) {
            return (
              <div key={i} className="sim-step-done" data-testid="sim-step-done">
                <span className="sim-step-check">✓</span>
                {s.doneMsg}
              </div>
            );
          }
          if (i === stepIndex) {
            return (
              <div key={i} className="sim-step-active">
                <span className="sim-step-spinner" />
                <span data-testid="sim-current-msg">
                  {currentStepDone ? s.doneMsg : s.workingMsg}
                </span>
              </div>
            );
          }
          return (
            <div key={i} className="sim-step-pending">
              <span className="sim-step-dot" />
              {s.label}
            </div>
          );
        })}
      </div>

      <div className="sim-step-counter">
        Step {stepIndex + 1} of {steps.length}: {steps[stepIndex]?.label}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TrainAgainPanel — mock configuration form
// ---------------------------------------------------------------------------

function TrainAgainPanel() {
  const [modelChoice, setModelChoice]         = useState('default');
  const [steps, setSteps]                     = useState({
    exploration: true, preprocessing: true, tuning: true, training: true, testing: true,
  });
  const [dataSource, setDataSource]           = useState('existing');
  const [selectedFiles, setSelectedFiles]     = useState(
    Object.fromEntries(RAW_FILES.map(f => [f, true]))
  );
  const [showAdvanced, setShowAdvanced]       = useState(false);
  const [advancedOpts, setAdvancedOpts]       = useState({
    stratified: true, smote: true, scaling: true, correlation: true, skipTuning: false,
  });
  const [estimators, setEstimators]           = useState(150);
  const [maxDepth, setMaxDepth]               = useState(20);
  const [uploadedFile, setUploadedFile]       = useState(null);
  const [configError, setConfigError]         = useState('');
  const [simRunning, setSimRunning]           = useState(false);
  const fileInputRef                          = useRef(null);

  const toggleStep = (key) =>
    setSteps(prev => ({ ...prev, [key]: !prev[key] }));
  const toggleFile = (name) =>
    setSelectedFiles(prev => ({ ...prev, [name]: !prev[name] }));
  const toggleAdvanced = (key) =>
    setAdvancedOpts(prev => ({ ...prev, [key]: !prev[key] }));

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) setUploadedFile(file.name);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) setUploadedFile(file.name);
  };

  const handleConfigure = () => {
    const anyStep = Object.values(steps).some(Boolean);
    const anyFile = dataSource === 'existing'
      ? Object.values(selectedFiles).some(Boolean)
      : !!uploadedFile;
    if (!anyStep) {
      setConfigError('Select at least one pipeline step.');
      return;
    }
    if (!anyFile) {
      setConfigError(
        dataSource === 'existing'
          ? 'Select at least one data file.'
          : 'Upload a CSV file.'
      );
      return;
    }
    setConfigError('');
    setSimRunning(true);
  };

  const handleReset = useCallback(() => {
    setSimRunning(false);
    setConfigError('');
  }, []);

  const selectedStepKeys = [
    steps.exploration   && 'exploration',
    steps.preprocessing && 'preprocessing',
    steps.tuning        && 'tuning',
    steps.training      && 'training',
    steps.testing       && 'testing',
  ].filter(Boolean);
  const simSteps = buildSimSteps(selectedStepKeys);

  // Show simulation panel when running
  if (simRunning) {
    return <SimulationPanel steps={simSteps} onReset={handleReset} />;
  }

  return (
    <div className="train-again-panel">
      {/* Model Selection */}
      <div className="train-section">
        <div className="train-section-title">Model Variant</div>
        {[
          { value: 'default', label: '5 Class (Default) — Benign, DDoS, DoS, Brute Force, Botnet' },
          { value: 'all',     label: '6 Class (All) — + Infilteration' },
          { value: 'both',    label: 'Both Models' },
        ].map(opt => (
          <label key={opt.value} className="train-radio-label">
            <input
              type="radio"
              name="modelChoice"
              value={opt.value}
              checked={modelChoice === opt.value}
              onChange={() => setModelChoice(opt.value)}
            />
            {opt.label}
          </label>
        ))}
      </div>

      {/* Pipeline Steps */}
      <div className="train-section">
        <div className="train-section-title">Pipeline Steps</div>
        {[
          { key: 'exploration',   label: 'Data Exploration',        detail: '(class distribution, feature stats)' },
          { key: 'preprocessing', label: 'Preprocessing',           detail: '(scaling, SMOTE, feature selection)' },
          { key: 'tuning',        label: 'Hyperparameter Tuning',   detail: '(RandomizedSearchCV, 15 iterations)' },
          { key: 'training',      label: 'Training',                detail: '(RandomForestClassifier)' },
          { key: 'testing',       label: 'Testing',                 detail: '(confusion matrix, ROC curves)' },
        ].map(s => (
          <label key={s.key} className="train-check-label" htmlFor={`step-${s.key}`}>
            <input
              id={`step-${s.key}`}
              type="checkbox"
              checked={steps[s.key]}
              onChange={() => toggleStep(s.key)}
              aria-label={s.label}
            />
            {s.label} <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{s.detail}</span>
          </label>
        ))}
      </div>

      {/* Data Source */}
      <div className="train-section">
        <div className="train-section-title">Data Source</div>
        <label className="train-radio-label">
          <input
            type="radio"
            name="dataSource"
            value="existing"
            checked={dataSource === 'existing'}
            onChange={() => setDataSource('existing')}
          />
          Use existing CICIDS2018 training data
        </label>
        <label className="train-radio-label">
          <input
            type="radio"
            name="dataSource"
            value="upload"
            checked={dataSource === 'upload'}
            onChange={() => setDataSource('upload')}
          />
          Upload new CSV file
        </label>

        {dataSource === 'existing' && (
          <div style={{ marginTop: '0.75rem' }}>
            <div className="train-section-subtitle">Select Raw Data Files (CICIDS2018)</div>
            <div className="train-file-grid">
              {RAW_FILES.map(name => (
                <label key={name} className="train-check-label">
                  <input
                    type="checkbox"
                    checked={selectedFiles[name]}
                    onChange={() => toggleFile(name)}
                  />
                  {name}
                </label>
              ))}
            </div>
            <div style={{ marginTop: '0.5rem' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedFiles(Object.fromEntries(RAW_FILES.map(f => [f, true])))}
                style={{ marginRight: '0.5rem' }}
              >
                Select All
              </button>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedFiles(Object.fromEntries(RAW_FILES.map(f => [f, false])))}
              >
                Deselect All
              </button>
            </div>
          </div>
        )}

        {dataSource === 'upload' && (
          <div
            className="upload-dropzone"
            onDrop={handleDrop}
            onDragOver={e => e.preventDefault()}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              style={{ display: 'none' }}
              onChange={handleFileChange}
            />
            {uploadedFile ? (
              <div className="upload-dropzone-filename">
                <span style={{ color: '#22c55e', marginRight: '0.5rem' }}>✓</span>
                {uploadedFile}
              </div>
            ) : (
              <div className="upload-dropzone-hint">
                Drag &amp; drop a CSV file here, or click to browse
              </div>
            )}
          </div>
        )}
      </div>

      {/* Advanced Options (collapsible) */}
      <div className="train-section">
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => setShowAdvanced(v => !v)}
          style={{ marginBottom: '0.5rem' }}
        >
          {showAdvanced ? '▲ Hide' : '▼ Show'} Advanced Options
        </button>
        {showAdvanced && (
          <div>
            {[
              { key: 'stratified',  label: 'Stratified Train/Test Split (80:20)' },
              { key: 'smote',       label: 'Apply SMOTE Oversampling' },
              { key: 'scaling',     label: 'Feature Scaling (StandardScaler)' },
              { key: 'correlation', label: 'Correlation Feature Elimination (threshold: 0.99)' },
              { key: 'skipTuning',  label: 'Use previous hyperparameters (skip tuning)' },
            ].map(opt => (
              <label key={opt.key} className="train-check-label">
                <input
                  type="checkbox"
                  checked={advancedOpts[opt.key]}
                  onChange={() => toggleAdvanced(opt.key)}
                />
                {opt.label}
              </label>
            ))}
            <div className="train-params-row">
              <div className="form-group" style={{ margin: 0 }}>
                <label>Number of Estimators</label>
                <input
                  type="number"
                  min="10"
                  max="500"
                  value={estimators}
                  onChange={e => setEstimators(Number(e.target.value))}
                  className="train-number-input"
                />
              </div>
              <div className="form-group" style={{ margin: 0 }}>
                <label>Max Depth</label>
                <input
                  type="number"
                  min="5"
                  max="50"
                  value={maxDepth}
                  onChange={e => setMaxDepth(Number(e.target.value))}
                  className="train-number-input"
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {configError && (
        <div className="train-error">{configError}</div>
      )}

      <button
        className="btn btn-primary btn-md"
        onClick={handleConfigure}
      >
        Start Training
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TrainingPipeline page
// ---------------------------------------------------------------------------

function TrainingPipeline() {
  const navigate = useNavigate();
  const [showTrainAgain, setShowTrainAgain] = useState(false);

  return (
    <Section title="Training Pipeline">
      <Alert type="info">
        Models were trained offline on the CICIDS2018 dataset. Results are available in the
        Reports section. Use "Configure New Training Run" below to prepare a new training configuration.
      </Alert>

      {/* Trained model summaries */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        {MODELS.map(model => (
          <ModelSummaryCard key={model.key} model={model} />
        ))}
      </div>

      {/* Pipeline steps */}
      <Card
        title="Pipeline Steps"
        subtitle="5-module pipeline completed for both model variants"
      >
        <div className="module-list">
          {PIPELINE_MODULES.map(mod => (
            <CompletedModuleRow key={mod.id} module={mod} />
          ))}
        </div>
        <div style={{
          marginTop: '1.25rem',
          padding: '0.75rem 1rem',
          background: 'var(--primary)',
          borderRadius: '7px',
          fontSize: '0.85rem',
          color: 'var(--text-secondary)',
          lineHeight: '1.6',
        }}>
          {PIPELINE_MODULES.map(mod => (
            <div key={mod.id} style={{ marginBottom: '0.25rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>{mod.name}:</strong> {mod.detail}
            </div>
          ))}
        </div>
      </Card>

      {/* Configure new training run */}
      <Card
        title="Configure New Training Run"
        subtitle="Set up a new training pipeline run with custom configuration"
      >
        <div style={{ marginBottom: '1rem' }}>
          <button
            className={`btn btn-md ${showTrainAgain ? 'btn-secondary' : 'btn-primary'}`}
            onClick={() => setShowTrainAgain(v => !v)}
          >
            {showTrainAgain ? 'Hide Configuration' : 'Configure Training Run'}
          </button>
        </div>
        {showTrainAgain && <TrainAgainPanel />}
      </Card>

      {/* Link to Reports */}
      <Card>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
            View detailed evaluation metrics, confusion matrices, and classification reports:
          </span>
          <button
            className="btn btn-primary btn-md"
            onClick={() => navigate('/reports')}
          >
            Go to Reports
          </button>
        </div>
      </Card>
    </Section>
  );
}

export default TrainingPipeline;
