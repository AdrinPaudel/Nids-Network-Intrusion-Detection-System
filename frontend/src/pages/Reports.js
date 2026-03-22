import { useState, useEffect, useCallback } from 'react';
import {
  PieChart, Pie, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell,
} from 'recharts';
import { Section } from '../components/Common';
import '../styles/Pages.css';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TYPE_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'simul', label: 'Simulation' },
  { value: 'batch', label: 'Batch' },
  { value: 'live', label: 'Live' },
];

const MODEL_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'default', label: '5 Class (Default)' },
  { value: 'all', label: '6 Class (All)' },
];

const TYPE_LABELS = {
  simul: 'Simulation',
  simulation: 'Simulation',
  batch: 'Batch',
  live: 'Live',
  training: 'Training',
  unknown: 'Unknown',
};

const TYPE_BADGE_COLORS = {
  simul: { background: 'rgba(139,92,246,0.2)', color: '#8b5cf6' },
  simulation: { background: 'rgba(139,92,246,0.2)', color: '#8b5cf6' },
  batch: { background: 'rgba(249,115,22,0.2)', color: '#f97316' },
  live: { background: 'rgba(34,197,94,0.2)', color: '#22c55e' },
  training: { background: 'rgba(59,130,246,0.2)', color: '#3b82f6' },
};

const MODEL_LABELS = {
  default: '5 Class (Default)',
  all: '6 Class (All)',
};

// Pie chart colour palette — one colour per class
const PIE_COLORS = ['#22c55e', '#ef4444', '#f97316', '#8b5cf6', '#3b82f6', '#eab308'];

const THREAT_CLASSES = new Set(['ddos', 'dos', 'botnet', 'brute force', 'web attack', 'infiltration', 'infilteration', 'heartbleed']);

// ---------------------------------------------------------------------------
// Pure helper exports (used by tests)
// ---------------------------------------------------------------------------

/**
 * Build a human-readable title from structured report metadata.
 * @param {{ type: string|null, model: string|null, date_iso: string|null }} report
 * @returns {string}
 */
export function formatReportTitle({ type, model, date_iso }) {
  const typeLabel = TYPE_LABELS[type] ?? (type ? type.charAt(0).toUpperCase() + type.slice(1) : 'Report');
  const modelLabel = MODEL_LABELS[model] ?? (model ? model.charAt(0).toUpperCase() + model.slice(1) : 'Unknown Model');

  let dateLabel = '';
  if (date_iso) {
    const d = new Date(date_iso);
    if (!isNaN(d.getTime())) {
      dateLabel = d.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    }
  }

  const parts = [typeLabel, modelLabel];
  if (dateLabel) parts.push(dateLabel);
  return parts.join(' — ');
}

/**
 * Parse a session_summary.txt string into structured data.
 * Returns defaults for any field that can't be parsed.
 *
 * @param {string|null} content
 * @returns {{
 *   totalFlows: number|null,
 *   threats: number|null,
 *   suspicious: number|null,
 *   clean: number|null,
 *   duration: string|null,
 *   breakdown: Array<{name: string, count: number, pct: number}>
 * }}
 */
export function parseSessionSummary(content) {
  const empty = {
    totalFlows: null, threats: null, suspicious: null, clean: null,
    duration: null, breakdown: [], accuracy: null, accuracyCorrect: null,
  };
  if (!content || typeof content !== 'string') return empty;

  const extract = (pattern) => {
    const m = content.match(pattern);
    return m ? parseInt(m[1].replace(/,/g, ''), 10) : null;
  };

  const totalFlows = extract(/Total Flows Classified[:\s]+(\d[\d,]*)/i);
  let threats = extract(/Threats Detected[:\s]+(\d[\d,]*)/i);
  let suspicious = extract(/Suspicious Flows[:\s]+(\d[\d,]*)/i);
  let clean = extract(/Clean Flows[:\s]+(\d[\d,]*)/i);

  // Fallback for labeled simul/live: sum per-minute Threats:/Suspicious:/Clean: lines
  // (these appear indented in the MINUTE-BY-MINUTE BREAKDOWN section)
  if (threats === null || suspicious === null || clean === null) {
    const sumPattern = (pattern) => {
      const re = new RegExp(pattern, 'gm');
      const matches = [...content.matchAll(re)];
      if (matches.length === 0) return null;
      return matches.reduce((acc, m) => acc + parseInt(m[1], 10), 0);
    };
    if (threats === null)    threats    = sumPattern('^\\s{4,}Threats:\\s+(\\d+)');
    if (suspicious === null) suspicious = sumPattern('^\\s{4,}Suspicious:\\s+(\\d+)');
    if (clean === null)      clean      = sumPattern('^\\s{4,}Clean:\\s+(\\d+)');
  }

  // Accuracy: "86.50% (865/1000)" — labeled sessions
  const accMatch = content.match(/Accuracy:\s+([\d.]+)%\s*\((\d+)\/(\d+)\)/i);
  const accuracy = accMatch ? parseFloat(accMatch[1]) : null;
  const accuracyCorrect = accMatch ? parseInt(accMatch[2], 10) : null;

  const durationMatch = content.match(/Actual Duration[:\s]+(\S+)/i);
  const duration = durationMatch ? durationMatch[1] : null;

  // Parse classification breakdown lines like:
  //   "    Benign              :    490 ( 75.6%)"
  const breakdown = [];
  const breakdownRe = /^\s{2,}(\S[^\n:]+?)\s*:\s*([\d,]+)\s*\(\s*([\d.]+)%\s*\)/gm;
  let bm;
  while ((bm = breakdownRe.exec(content)) !== null) {
    const name = bm[1].trim();
    const count = parseInt(bm[2].replace(/,/g, ''), 10);
    const pct = parseFloat(bm[3]);
    if (name && !isNaN(count)) {
      breakdown.push({ name, count, pct });
    }
  }

  // Fallback: if no Classification Breakdown found (e.g. labeled batch summaries),
  // derive predicted counts from Per-Class Precision lines
  if (breakdown.length === 0) {
    const perClassFallbackRe = /^\s+([^\n:]+?)\s*:\s*[\d.]+%\s*\(\d+\/\d+\)\s*\|\s*Predicted:\s*(\d+)/gm;
    let pm;
    const perClassEntries = [];
    let predictedTotal = 0;
    while ((pm = perClassFallbackRe.exec(content)) !== null) {
      const name = pm[1].trim();
      const count = parseInt(pm[2], 10);
      if (name && !isNaN(count)) {
        perClassEntries.push({ name, count });
        predictedTotal += count;
      }
    }
    if (perClassEntries.length > 0) {
      const denom = totalFlows ?? predictedTotal;
      perClassEntries.forEach(entry => {
        const pct = denom > 0 ? parseFloat(((entry.count / denom) * 100).toFixed(1)) : 0;
        breakdown.push({ name: entry.name, count: entry.count, pct });
      });
    }
  }

  return { totalFlows, threats, suspicious, clean, duration, breakdown, accuracy, accuracyCorrect };
}

/**
 * Parse the "Per-Class Precision" section from labeled summaries.
 * Line format: "  ClassName  :  XX.XX% (correct/predicted) | Predicted:  NNN"
 *
 * @param {string|null} content
 * @returns {Array<{className, correct, predicted, wrong}>}
 */
export function parsePerClassPrecision(content) {
  if (!content || typeof content !== 'string') return [];
  const re = /^\s+([^\n:]+?)\s*:\s*[\d.]+%\s*\((\d+)\/\d+\)\s*\|\s*Predicted:\s*(\d+)/gm;
  const results = [];
  let m;
  while ((m = re.exec(content)) !== null) {
    const className = m[1].trim();
    const correct = parseInt(m[2], 10);
    const predicted = parseInt(m[3], 10);
    if (className && !isNaN(correct) && !isNaN(predicted)) {
      results.push({ className, correct, predicted, wrong: predicted - correct });
    }
  }
  return results;
}

/**
 * Compute binary confusion matrix from per-class precision data.
 * Returns { TP, TN, FP, FN } or null if insufficient data.
 */
function computeBinaryMatrix(perClass, totalFlows, totalCorrect) {
  if (!perClass || perClass.length === 0 || totalFlows == null || totalCorrect == null) return null;
  const benign = perClass.find(p => p.className.toLowerCase() === 'benign');
  if (!benign) return null;
  const TN = benign.correct;
  const FN = benign.predicted - benign.correct;
  const TP = totalCorrect - TN;
  const FP = totalFlows - TN - FN - TP;
  if (TP < 0 || FP < 0) return null;
  return { TP, TN, FP, FN };
}

// ---------------------------------------------------------------------------
// Pipeline results parsers (exploration, preprocessing, training files)
// ---------------------------------------------------------------------------

/**
 * Parse exploration_results.txt into structured metrics.
 * @param {string|null} content
 * @returns {{totalRows, totalColumns, originalClasses, consolidatedClasses, giniCoefficient, imbalanceSeverity, memoryUsage}}
 */
export function parseExplorationResults(content) {
  const empty = {
    totalRows: null, totalColumns: null, originalClasses: null,
    consolidatedClasses: null, giniCoefficient: null, imbalanceSeverity: null, memoryUsage: null,
  };
  if (!content || typeof content !== 'string') return empty;

  const extract = (pattern) => { const m = content.match(pattern); return m ? m[1].trim() : null; };

  const totalRows = extract(/Total Rows:\s+([\d,]+)/i);
  const totalColumnsStr = extract(/Total Columns:\s+(\d+)/i);
  const totalColumns = totalColumnsStr ? parseInt(totalColumnsStr, 10) : null;
  const originalClassesStr = extract(/Total Classes:\s+(\d+)/i);
  const originalClasses = originalClassesStr ? parseInt(originalClassesStr, 10) : null;
  const memoryUsage = extract(/Memory Usage:\s+([\d.]+ \w+)/i);
  const imbalanceSeverity = extract(/Imbalance Severity:\s+(\w+)/i);

  // Gini from the first occurrence (before consolidation)
  const giniStr = extract(/Gini Coefficient:\s+([\d.]+)/i);
  const giniCoefficient = giniStr ? parseFloat(giniStr) : null;

  // Consolidated classes: look for "Classes: N" in the AFTER consolidation section
  let consolidatedClasses = null;
  const afterIdx = content.indexOf('AFTER Consolidation');
  if (afterIdx !== -1) {
    const afterSection = content.slice(afterIdx);
    const cm = afterSection.match(/Classes:\s+(\d+)/);
    if (cm) consolidatedClasses = parseInt(cm[1], 10);
  }

  return { totalRows, totalColumns, originalClasses, consolidatedClasses, giniCoefficient, imbalanceSeverity, memoryUsage };
}

/**
 * Parse preprocessing_results.txt into structured metrics.
 * @param {string|null} content
 * @returns {{initialRows, finalRows, rowsRemoved, dataLossPct, trainingSamples, testSamples, smoteSamples, featuresSelected}}
 */
export function parsePreprocessingResults(content) {
  const empty = {
    initialRows: null, finalRows: null, rowsRemoved: null, dataLossPct: null,
    trainingSamples: null, testSamples: null, smoteSamples: null, featuresSelected: null,
  };
  if (!content || typeof content !== 'string') return empty;

  const extract = (pattern) => { const m = content.match(pattern); return m ? m[1].trim() : null; };

  // Initial rows — from "Initial Dataset:" block
  const initialRows = extract(/Initial Dataset:[\s\S]*?Rows:\s+([\d,]+)/i);

  // Final clean rows — from "Final Clean Dataset:" block
  const finalRows = extract(/Final Clean Dataset:[\s\S]*?Rows:\s+([\d,]+)/i);

  // Rows removed
  const rowsRemovedMatch = content.match(/Total removed:\s+([\d,]+)\s+rows\s*\(([\d.]+)%\)/i);
  const rowsRemoved = rowsRemovedMatch ? rowsRemovedMatch[1] : null;
  const dataLossPct = rowsRemovedMatch ? rowsRemovedMatch[2] : null;

  // Training samples (after SMOTE)
  const trainingSamples = extract(/Samples after:\s+([\d,]+)/i);

  // Test samples
  const testSamples = extract(/Test set:\s+([\d,]+)\s+samples/i);

  // SMOTE synthetic samples
  const smoteSamples = extract(/Synthetic samples:\s+([\d,]+)/i);

  // Features selected
  const featuresStr = extract(/Features selected:\s+(\d+)/i);
  const featuresSelected = featuresStr ? parseInt(featuresStr, 10) : null;

  return { initialRows, finalRows, rowsRemoved, dataLossPct, trainingSamples, testSamples, smoteSamples, featuresSelected };
}

/**
 * Parse training_results.txt into structured metrics.
 * Named 'parseTrainingFileResults' to avoid collision with the existing parseTestingResults.
 * @param {string|null} content
 * @returns {{cvF1Score, tuningTime, trainingTime, totalTime, trees, avgDepth, features, top10Importance, topFeature, topFeatureImportance}}
 */
export function parseTrainingFileResults(content) {
  const empty = {
    cvF1Score: null, tuningTime: null, trainingTime: null, totalTime: null,
    trees: null, avgDepth: null, features: null,
    top10Importance: null, topFeature: null, topFeatureImportance: null,
  };
  if (!content || typeof content !== 'string') return empty;

  const extract = (pattern) => { const m = content.match(pattern); return m ? m[1].trim() : null; };

  const cvF1Score = extract(/Macro F1-Score:\s+([\d.]+)/i);
  const tuningTime = extract(/Hyperparameter Tuning:\s+([\d.]+ minutes?)/i);
  const trainingTime = extract(/Final Model Training:\s+([\d.]+ minutes?)/i);
  const totalTime = extract(/Total Training Time:\s+([\d.]+ minutes?)/i);

  const treesStr = extract(/Number of Trees:\s+(\d+)/i);
  const trees = treesStr ? parseInt(treesStr, 10) : null;

  const avgDepthStr = extract(/Average Tree Depth:\s+([\d.]+)/i);
  const avgDepth = avgDepthStr ? parseFloat(avgDepthStr) : null;

  const featuresStr = extract(/Training Configuration[\s\S]*?Features:\s+(\d+)/i);
  const features = featuresStr ? parseInt(featuresStr, 10) : null;

  const top10Importance = extract(/Top 10 features:\s+([\d.]+%)\s+of total importance/i);

  // Top feature: first rank line "  1  | FeatureName   |  importance  |"
  const topFeatureMatch = content.match(/^\s+1\s+\|\s+(.+?)\s+\|\s+([\d.]+)\s+\|/m);
  const topFeature = topFeatureMatch ? topFeatureMatch[1].trim() : null;
  const topFeatureImportance = topFeatureMatch ? topFeatureMatch[2] : null;

  return { cvF1Score, tuningTime, trainingTime, totalTime, trees, avgDepth, features, top10Importance, topFeature, topFeatureImportance };
}

/**
 * Parse testing_results.txt content into structured metrics.
 *
 * @param {string|null} content
 * @returns {{
 *   accuracy: string|null,
 *   macroF1: string|null,
 *   inferenceSpeed: string|null,
 *   meanConfidence: string|null,
 *   perClass: Array<{className, precision, recall, f1, auc, support}>,
 *   binary: {accuracy, precision, recall, specificity, auc, f1}
 * }}
 */
export function parseTestingResults(content) {
  const emptyBinary = { accuracy: null, precision: null, recall: null, specificity: null, auc: null, f1: null };
  const empty = { accuracy: null, macroF1: null, inferenceSpeed: null, meanConfidence: null, perClass: [], binary: emptyBinary };
  if (!content || typeof content !== 'string') return empty;

  // Extract single-value fields
  const extract = (pattern) => {
    const m = content.match(pattern);
    return m ? m[1].trim() : null;
  };

  const accuracy = extract(/^Accuracy:\s+([\d.]+)/m);
  const macroF1 = extract(/^Macro F1-Score:\s+([\d.]+)/m);
  const inferenceSpeed = extract(/Inference speed:\s+([^\n]+)/i);
  const meanConfidence = extract(/Mean confidence:\s+([\d.]+)/i);

  // Per-class table — lines after the dashes separator that contain tabular data.
  // Header: Class  Precision  Recall  F1-Score  AUC  Support
  // Rows:   Benign 0.9999     1.0000  0.9999    ...
  const perClass = [];
  const perClassSectionMatch = content.match(/Per-Class Performance:([\s\S]*?)(?:\n\n|\n\d+\.)/);
  if (perClassSectionMatch) {
    const section = perClassSectionMatch[1];
    const rowRe = /^([A-Za-z][A-Za-z\s]+?)\s{2,}([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d,]+)\s*$/gm;
    let rm;
    while ((rm = rowRe.exec(section)) !== null) {
      const className = rm[1].trim();
      if (className === 'Class') continue; // skip header row if matched
      perClass.push({
        className,
        precision: rm[2],
        recall: rm[3],
        f1: rm[4],
        auc: rm[5],
        support: rm[6],
      });
    }
  }

  // Parse binary section by finding it after the "4. BINARY" header
  const binarySection = (() => {
    const idx = content.indexOf('4. BINARY');
    return idx === -1 ? '' : content.slice(idx);
  })();

  const extractFromSection = (section, pattern) => {
    const m = section.match(pattern);
    return m ? m[1].trim() : null;
  };

  const binary = {
    accuracy: extractFromSection(binarySection, /^Accuracy:\s+([\d.]+)/m),
    precision: extractFromSection(binarySection, /^Precision:\s+([\d.]+)/m),
    recall: extractFromSection(binarySection, /^Recall \(TPR\):\s+([\d.]+)/m),
    specificity: extractFromSection(binarySection, /^Specificity \(TNR\):\s+([\d.]+)/m),
    auc: extractFromSection(binarySection, /^Binary AUC:\s+([\d.]+)/m),
    f1: extractFromSection(binarySection, /^F1-Score:\s+([\d.]+)/m),
  };

  return { accuracy, macroF1, inferenceSpeed, meanConfidence, perClass, binary };
}

// ---------------------------------------------------------------------------
// Utility: determine if a flow row is a threat or suspicious
// ---------------------------------------------------------------------------

function isThreatenClass(className) {
  if (!className) return false;
  return THREAT_CLASSES.has(className.toLowerCase());
}

function isRowThreat(row) {
  return isThreatenClass(row.class1);
}

function isRowSuspicious(row) {
  if (isRowThreat(row)) return false;
  // suspicious = benign primary but secondary class has >25% confidence
  const conf2 = typeof row.conf2 === 'number' ? row.conf2 : 0;
  return conf2 > 0.25;
}

// ---------------------------------------------------------------------------
// Sub-component: MetricCard
// ---------------------------------------------------------------------------

function MetricCard({ label, value, sub }) {
  return (
    <div className="results-metric-card">
      <div className="results-metric-label">{label}</div>
      <div className="results-metric-value">{value ?? '—'}</div>
      {sub && <div className="results-metric-sub">{sub}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: SessionMetrics
// Renders parsed summary data as stat cards + pie chart
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// BinaryMatrix: 2x2 visual for labeled sessions
// ---------------------------------------------------------------------------

function BinaryMatrix({ matrix }) {
  const { TP, TN, FP, FN } = matrix;
  const total = TP + TN + FP + FN;
  const fmt = (n) => n.toLocaleString();
  const pct = (n) => total > 0 ? ` (${((n / total) * 100).toFixed(1)}%)` : '';
  return (
    <div className="binary-matrix">
      <div className="binary-matrix-header-row">
        <div />
        <div className="binary-matrix-col-label">Pred. Benign</div>
        <div className="binary-matrix-col-label">Pred. Attack</div>
      </div>
      <div className="binary-matrix-row">
        <div className="binary-matrix-row-label">Actual Benign</div>
        <div className="binary-matrix-cell cell-tn">
          <div className="bm-abbr">TN</div>
          <div className="bm-val">{fmt(TN)}</div>
          <div className="bm-pct">{pct(TN)}</div>
        </div>
        <div className="binary-matrix-cell cell-fp">
          <div className="bm-abbr">FP</div>
          <div className="bm-val">{fmt(FP)}</div>
          <div className="bm-pct">{pct(FP)}</div>
        </div>
      </div>
      <div className="binary-matrix-row">
        <div className="binary-matrix-row-label">Actual Attack</div>
        <div className="binary-matrix-cell cell-fn">
          <div className="bm-abbr">FN</div>
          <div className="bm-val">{fmt(FN)}</div>
          <div className="bm-pct">{pct(FN)}</div>
        </div>
        <div className="binary-matrix-cell cell-tp">
          <div className="bm-abbr">TP</div>
          <div className="bm-val">{fmt(TP)}</div>
          <div className="bm-pct">{pct(TP)}</div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SessionMetrics: stats + charts
// ---------------------------------------------------------------------------

function SessionMetrics({ summary, isLabeled }) {
  const parsed = parseSessionSummary(summary);
  const perClass = parsePerClassPrecision(summary);
  const [selectedClass, setSelectedClass] = useState('all');

  const pieData = parsed.breakdown.map((b, i) => ({
    name: b.name,
    value: b.count,
    fill: PIE_COLORS[i % PIE_COLORS.length],
  }));

  // Binary confusion matrix (labeled only)
  const binaryMatrix = (isLabeled && perClass.length > 0 && parsed.totalFlows != null && parsed.accuracyCorrect != null)
    ? computeBinaryMatrix(perClass, parsed.totalFlows, parsed.accuracyCorrect)
    : null;

  // Per-class bar data filtered by dropdown
  const perClassBarData = perClass
    .filter(p => selectedClass === 'all' || p.className === selectedClass)
    .map(p => ({ name: p.className, Correct: p.correct, Wrong: p.wrong }));

  // Threat breakdown data for unlabeled reports — only include non-zero values
  const threatBreakdownData = !isLabeled ? [
    (parsed.threats    != null && parsed.threats    > 0) ? { name: 'Threats',    value: parsed.threats,    fill: '#ef4444' } : null,
    (parsed.suspicious != null && parsed.suspicious > 0) ? { name: 'Suspicious', value: parsed.suspicious, fill: '#f97316' } : null,
    (parsed.clean      != null && parsed.clean      > 0) ? { name: 'Clean',      value: parsed.clean,      fill: '#22c55e' } : null,
  ].filter(Boolean) : [];

  const hasThreeCharts = isLabeled && (binaryMatrix || perClass.length > 0);
  // Two charts when both the class-distribution pie and the threat breakdown have data
  const visibleUnlabeledCharts = (pieData.length > 0 ? 1 : 0) + (threatBreakdownData.length > 0 ? 1 : 0);
  const hasTwoCharts = !isLabeled && visibleUnlabeledCharts >= 2;

  return (
    <div className="session-metrics-section">
      {/* Stats row */}
      <div className="session-metrics-grid">
        <MetricCard label="Total Flows" value={parsed.totalFlows ?? '—'} />
        {isLabeled && (
          <MetricCard
            label="Accuracy"
            value={parsed.accuracy != null ? `${parsed.accuracy.toFixed(2)}%` : '—'}
          />
        )}
        <MetricCard label="Threats"    value={parsed.threats    != null ? parsed.threats    : '—'} />
        <MetricCard label="Suspicious" value={parsed.suspicious != null ? parsed.suspicious : '—'} />
        <MetricCard label="Clean"      value={parsed.clean      != null ? parsed.clean      : '—'} />
        {parsed.duration && <MetricCard label="Duration" value={parsed.duration} />}
      </div>

      {/* Charts row */}
      <div className={`session-charts-row${hasThreeCharts ? ' three-col' : hasTwoCharts ? ' two-col' : ''}`}>
        {/* LEFT: Prediction distribution pie */}
        {pieData.length > 0 && (
          <div className="session-chart-box">
            <div className="session-chart-title">Class Distribution</div>
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={75}
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => value.toLocaleString()} />
                <Legend wrapperStyle={{ fontSize: '0.8rem' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* CENTER: Threat breakdown pie for unlabeled reports */}
        {!isLabeled && threatBreakdownData.length > 0 && (
          <div className="session-chart-box">
            <div className="session-chart-title">Threat Breakdown</div>
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={threatBreakdownData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={75}
                >
                  {threatBreakdownData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => value.toLocaleString()} />
                <Legend wrapperStyle={{ fontSize: '0.8rem' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* CENTER: Binary confusion matrix (labeled only) */}
        {isLabeled && binaryMatrix && (
          <div className="session-chart-box">
            <div className="session-chart-title">Binary Detection</div>
            <div className="binary-matrix-container">
              <BinaryMatrix matrix={binaryMatrix} />
            </div>
          </div>
        )}

        {/* RIGHT: Per-class precision bar chart (labeled only) */}
        {isLabeled && perClass.length > 0 && (
          <div className="session-chart-box">
            <div className="session-chart-title-row">
              <span className="session-chart-title">Per-Class Precision</span>
              <select
                className="session-class-select"
                value={selectedClass}
                onChange={e => setSelectedClass(e.target.value)}
              >
                <option value="all">All Classes</option>
                {perClass.map(p => (
                  <option key={p.className} value={p.className}>{p.className}</option>
                ))}
              </select>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={perClassBarData} margin={{ top: 4, right: 8, bottom: 40, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  angle={-30}
                  textAnchor="end"
                  interval={0}
                />
                <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: 'var(--secondary)', border: '1px solid var(--border)', borderRadius: '8px' }}
                />
                <Legend />
                <Bar dataKey="Correct" fill="#22c55e" radius={[3, 3, 0, 0]} />
                <Bar dataKey="Wrong" fill="#ef4444" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: MinuteTable
// Renders parsed flow rows with colour coding and pagination
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;

function MinuteTable({ rows }) {
  const [page, setPage] = useState(0);

  if (!rows || rows.length === 0) {
    return <div className="minute-table-empty">No flow data in this minute file.</div>;
  }

  const totalPages = Math.ceil(rows.length / PAGE_SIZE);
  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div className="minute-table-wrapper">
      <div className="minute-table-scroll">
        <table className="minute-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Src IP:Port</th>
              <th>Dst IP:Port</th>
              <th>Proto</th>
              <th>Prediction</th>
              <th>Confidence</th>
              <th>#2 Prediction</th>
              <th>#2 Conf</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.map((row, idx) => {
              const threat = isRowThreat(row);
              const suspicious = isRowSuspicious(row);
              const rowClass = threat
                ? 'minute-row-threat'
                : suspicious
                ? 'minute-row-suspicious'
                : '';

              const src = row.src_ip && row.src_port ? `${row.src_ip}:${row.src_port}` : (row.src_ip || '?');
              const dst = row.dst_ip && row.dst_port ? `${row.dst_ip}:${row.dst_port}` : (row.dst_ip || '?');
              const conf1Pct = typeof row.conf1 === 'number' ? `${(row.conf1 * 100).toFixed(1)}%` : '—';
              const conf2Pct = typeof row.conf2 === 'number' ? `${(row.conf2 * 100).toFixed(1)}%` : '—';

              return (
                <tr key={idx} className={rowClass}>
                  <td className="minute-cell-mono">{row.timestamp || '—'}</td>
                  <td className="minute-cell-mono">{src}</td>
                  <td className="minute-cell-mono">{dst}</td>
                  <td>{row.protocol || '—'}</td>
                  <td className="minute-cell-class">{row.class1 || '—'}</td>
                  <td>{conf1Pct}</td>
                  <td className="minute-cell-class">{row.class2 || '—'}</td>
                  <td>{conf2Pct}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="minute-pagination">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            Prev
          </button>
          <span className="minute-page-info">
            Page {page + 1} of {totalPages} ({rows.length} rows)
          </span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            disabled={page === totalPages - 1}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: BatchResultsTable
// Shows all flows from batch_results.txt with pagination
// ---------------------------------------------------------------------------

function BatchResultsTable({ reportName }) {
  const [rows, setRows] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetch(`/api/reports/${encodeURIComponent(reportName)}/batch-results`)
      .then(res => {
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (!cancelled) {
          setRows(data.rows ?? []);
          setLoading(false);
        }
      })
      .catch(err => {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [reportName]);

  if (loading) return <div className="minute-loading">Loading batch results...</div>;
  if (error) return <div className="minute-error">Failed to load: {error}</div>;
  if (!rows || rows.length === 0) return <div className="minute-table-empty">No flow data found in batch_results.txt.</div>;

  const totalPages = Math.ceil(rows.length / PAGE_SIZE);
  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const hasActualLabel = rows.some(r => r.actual_label != null);

  return (
    <div className="minute-table-wrapper">
      <div className="minute-table-scroll">
        <table className="minute-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Src IP:Port</th>
              <th>Dst IP:Port</th>
              <th>Proto</th>
              <th>Prediction</th>
              <th>Confidence</th>
              <th>#2 Prediction</th>
              <th>#2 Conf</th>
              {hasActualLabel && <th>Actual Label</th>}
            </tr>
          </thead>
          <tbody>
            {pageRows.map((row, idx) => {
              const threat = isRowThreat(row);
              const suspicious = isRowSuspicious(row);
              const rowClass = threat ? 'minute-row-threat' : suspicious ? 'minute-row-suspicious' : '';
              const src = row.src_ip && row.src_port ? `${row.src_ip}:${row.src_port}` : (row.src_ip || '?');
              const dst = row.dst_ip && row.dst_port ? `${row.dst_ip}:${row.dst_port}` : (row.dst_ip || '?');
              const conf1Pct = typeof row.conf1 === 'number' ? `${(row.conf1 * 100).toFixed(1)}%` : '—';
              const conf2Pct = typeof row.conf2 === 'number' ? `${(row.conf2 * 100).toFixed(1)}%` : '—';
              const isCorrect = hasActualLabel && row.actual_label != null && row.class1 === row.actual_label;
              const isWrong = hasActualLabel && row.actual_label != null && row.class1 !== row.actual_label;

              return (
                <tr key={idx} className={rowClass}>
                  <td className="minute-cell-mono">{row.timestamp || '—'}</td>
                  <td className="minute-cell-mono">{src}</td>
                  <td className="minute-cell-mono">{dst}</td>
                  <td>{row.protocol || '—'}</td>
                  <td className="minute-cell-class">{row.class1 || '—'}</td>
                  <td>{conf1Pct}</td>
                  <td className="minute-cell-class">{row.class2 || '—'}</td>
                  <td>{conf2Pct}</td>
                  {hasActualLabel && (
                    <td style={{ fontWeight: 600, color: isCorrect ? '#22c55e' : isWrong ? '#ef4444' : undefined }}>
                      {row.actual_label || '—'}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="minute-pagination">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            Prev
          </button>
          <span className="minute-page-info">
            Page {page + 1} of {totalPages} ({rows.length} rows)
          </span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            disabled={page === totalPages - 1}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: MinutesList
// Shows the per-minute files list with click-to-load detail
// ---------------------------------------------------------------------------

function MinutesList({ minutes }) {
  const [selectedMinute, setSelectedMinute] = useState(null);
  const [minuteData, setMinuteData] = useState(null);
  const [minuteLoading, setMinuteLoading] = useState(false);
  const [minuteError, setMinuteError] = useState(null);

  const handleSelectMinute = useCallback(async (minute) => {
    if (selectedMinute === minute.filename) {
      setSelectedMinute(null);
      setMinuteData(null);
      return;
    }

    setSelectedMinute(minute.filename);
    setMinuteLoading(true);
    setMinuteError(null);
    setMinuteData(null);

    try {
      const res = await fetch(minute.url);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setMinuteData(data);
    } catch (err) {
      setMinuteError(err.message);
    } finally {
      setMinuteLoading(false);
    }
  }, [selectedMinute]);

  if (!minutes || minutes.length === 0) {
    return <div className="minute-list-empty">No minutes available.</div>;
  }

  return (
    <div className="minute-list">
      <div className="minute-list-title">Per-Minute Files</div>
      <div className="minute-list-rows">
        {minutes.map((minute) => (
          <div key={minute.filename} className="minute-list-item">
            <button
              className={`minute-file-btn${selectedMinute === minute.filename ? ' active' : ''}`}
              onClick={() => handleSelectMinute(minute)}
            >
              {minute.filename}
            </button>

            {selectedMinute === minute.filename && (
              <div className="minute-detail-panel">
                {minuteLoading && <div className="minute-loading">Loading flows...</div>}
                {minuteError && <div className="minute-error">Failed to load: {minuteError}</div>}
                {!minuteLoading && !minuteError && minuteData && (
                  <MinuteTable rows={minuteData.rows} />
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: ReportCard
// ---------------------------------------------------------------------------

function ReportCard({ report }) {
  const [expanded, setExpanded] = useState(false);
  const [minutes, setMinutes] = useState(null);
  const [minutesLoading, setMinutesLoading] = useState(false);
  const [minutesError, setMinutesError] = useState(null);

  const bStyle = TYPE_BADGE_COLORS[report.type] ?? { background: 'rgba(148,163,184,0.2)', color: '#94a3b8' };
  const typeLabel = TYPE_LABELS[report.type] ?? (report.type || 'Unknown');
  const modelLabel = MODEL_LABELS[report.model] ?? (report.model || 'Unknown');
  const isLabeled = report.is_labeled ?? false;

  const handleViewDetails = useCallback(async () => {
    if (expanded) {
      setExpanded(false);
      return;
    }

    // Batch reports don't have minute files — expand immediately and show BatchResultsTable
    if (report.type === 'batch') {
      setExpanded(true);
      return;
    }

    // If already loaded, just expand
    if (minutes !== null) {
      setExpanded(true);
      return;
    }

    setMinutesLoading(true);
    setMinutesError(null);

    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(report.name)}/minutes`);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setMinutes(data.minutes ?? []);
      setExpanded(true);
    } catch (err) {
      setMinutesError(err.message);
      setExpanded(true);
    } finally {
      setMinutesLoading(false);
    }
  }, [expanded, minutes, report.name, report.type]);

  // Compute threat percentage
  const threatPct = (report.flows && report.threats != null)
    ? ((report.threats / report.flows) * 100).toFixed(1)
    : null;

  // Use suspicious/clean from API response (backend now parses these for all report types)
  const suspiciousCount = report.suspicious ?? null;
  const cleanCount = report.clean ?? null;

  return (
    <div className="session-report-card">
      <div className="report-card-top">
        <div className="report-card-meta">
          <div className="report-badges-row">
            <span className="report-badge-type" style={bStyle}>
              {typeLabel}
            </span>
            <span className="report-badge-model">
              {modelLabel}
            </span>
            {isLabeled ? (
              <span className="report-badge-labeled">Labeled</span>
            ) : (
              <span className="report-badge-unlabeled">Unlabeled</span>
            )}
          </div>
          <div className="report-title">{formatReportTitle(report)}</div>

          <div className="report-metrics-strip">
            <span>Flows: <strong>{report.flows != null ? report.flows.toLocaleString() : '—'}</strong></span>
            <span className="report-metrics-sep">|</span>
            <span>Threats: <strong style={{ color: '#ef4444' }}>{report.threats != null ? report.threats.toLocaleString() : '—'}</strong></span>
            {!isLabeled && suspiciousCount != null && (
              <>
                <span className="report-metrics-sep">|</span>
                <span>Suspicious: <strong style={{ color: '#f97316' }}>{suspiciousCount.toLocaleString()}</strong></span>
              </>
            )}
            {!isLabeled && cleanCount != null && (
              <>
                <span className="report-metrics-sep">|</span>
                <span>Clean: <strong style={{ color: '#22c55e' }}>{cleanCount.toLocaleString()}</strong></span>
              </>
            )}
            <span className="report-metrics-sep">|</span>
            {isLabeled ? (
              <span>Accuracy: <strong>{report.accuracy != null ? `${report.accuracy}%` : '—'}</strong></span>
            ) : (
              <span>Threat %: <strong>{threatPct != null ? `${threatPct}%` : '—'}</strong></span>
            )}
          </div>
        </div>

        <div className="report-card-actions">
          <button
            className="btn btn-secondary btn-sm"
            onClick={handleViewDetails}
            disabled={minutesLoading}
          >
            {minutesLoading ? 'Loading...' : expanded ? 'Hide Details' : 'View Details'}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="report-detail-expanded">
          {minutesError && (
            <div className="report-detail-error">Failed to load details: {minutesError}</div>
          )}

          {/* Session summary metrics + pie chart */}
          {report.summary && <SessionMetrics summary={report.summary} isLabeled={isLabeled} />}

          {/* Batch flow results table */}
          {report.type === 'batch' && (
            <div className="minute-list">
              <div className="minute-list-title">Batch Flow Results</div>
              <BatchResultsTable reportName={report.name} />
            </div>
          )}

          {/* Per-minute file list (live/simul only) */}
          {report.type !== 'batch' && minutes !== null && !minutesError && (
            <MinutesList minutes={minutes} />
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: ImageGallery
// ---------------------------------------------------------------------------

function ImageGallery({ images, subdir }) {
  const [modalSrc, setModalSrc] = useState(null);

  if (!images || images.length === 0) return null;

  return (
    <div className="results-image-section">
      <div className="results-section-title">Model Images</div>
      <div className="results-image-gallery">
        {images.map((filename) => {
          const src = `/results-static/${subdir}/${filename}`;
          return (
            <div key={filename} className="results-image-item">
              <img
                className="results-image-thumb"
                src={src}
                alt={filename}
                title={filename}
                onClick={() => setModalSrc(src)}
                loading="lazy"
              />
              <div className="results-image-name">{filename.replace(/_/g, ' ').replace('.png', '')}</div>
            </div>
          );
        })}
      </div>

      {modalSrc && (
        <div
          className="image-modal-overlay"
          onClick={() => setModalSrc(null)}
          role="dialog"
          aria-label="Image full size"
        >
          <img
            className="image-modal-img"
            src={modalSrc}
            alt="Full size"
            onClick={(e) => e.stopPropagation()}
          />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: PerClassTable
// ---------------------------------------------------------------------------

function PerClassTable({ rows }) {
  if (!rows || rows.length === 0) return null;

  return (
    <div className="per-class-table-wrapper">
      <table className="per-class-table">
        <thead>
          <tr>
            <th>Class</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1</th>
            <th>AUC</th>
            <th>Support</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.className}>
              <td>{row.className}</td>
              <td>{row.precision}</td>
              <td>{row.recall}</td>
              <td>{row.f1}</td>
              <td>{row.auc}</td>
              <td>{row.support}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pipeline section definitions
// ---------------------------------------------------------------------------

const PIPELINE_SECTIONS = [
  { key: 'exploration',    label: '1. Exploration',   description: 'Initial data scouting, class distribution, and imbalance analysis' },
  { key: 'preprocessing', label: '2. Preprocessing',  description: 'Data cleaning, SMOTE balancing, and feature selection' },
  { key: 'training',      label: '3. Training',       description: 'Hyperparameter tuning and final Random Forest training' },
  { key: 'testing',       label: '4. Testing',        description: 'Evaluation on held-out test set — accuracy, F1, and per-class performance' },
];

// ---------------------------------------------------------------------------
// Sub-component: ResultsSectionContent
// Fetches and renders one pipeline section for a given variant.
// ---------------------------------------------------------------------------

function ResultsSectionContent({ sectionKey, variant, structure }) {
  const [content, setContent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showRaw, setShowRaw] = useState(false);

  const FILE_NAME = `${sectionKey}_results.txt`;
  const files = structure?.[sectionKey] ?? [];
  const hasFile = files.includes(FILE_NAME);

  // Static subdir for image URLs (exploration is always shared)
  const staticSubdir =
    sectionKey === 'exploration' ? 'exploration' :
    variant === 'all' ? `${sectionKey}_all` : sectionKey;

  const images = structure?.images?.[sectionKey] ?? [];

  useEffect(() => {
    if (!hasFile) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    const path = `${sectionKey}/${FILE_NAME}`;
    fetch(`/api/results/file?path=${encodeURIComponent(path)}&variant=${variant}`)
      .then((r) => { if (!r.ok) throw new Error(`Server returned ${r.status}`); return r.json(); })
      .then((d) => { if (!cancelled) setContent(d.content ?? ''); })
      .catch((e) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [sectionKey, variant, hasFile, FILE_NAME]);

  if (loading) return <div className="results-state-msg">Loading {sectionKey} results...</div>;
  if (error) return <div className="results-state-msg results-state-error">Failed to load: {error}</div>;
  if (!hasFile && images.length === 0) {
    return <div className="results-state-msg">No results found for this section.</div>;
  }

  return (
    <div>
      {/* Exploration metrics */}
      {content && sectionKey === 'exploration' && (() => {
        const m = parseExplorationResults(content);
        return (
          <>
            <div className="results-section">
              <div className="results-section-title">Dataset Overview</div>
              <div className="results-metrics-grid">
                <MetricCard label="Total Rows" value={m.totalRows} />
                <MetricCard label="Total Columns" value={m.totalColumns} />
                <MetricCard label="Memory Usage" value={m.memoryUsage} />
              </div>
            </div>
            <div className="results-section">
              <div className="results-section-title">Class Analysis</div>
              <div className="results-metrics-grid">
                <MetricCard label="Original Classes" value={m.originalClasses} />
                <MetricCard label="Consolidated Classes" value={m.consolidatedClasses} />
                <MetricCard label="Gini Coefficient" value={m.giniCoefficient != null ? m.giniCoefficient.toFixed(4) : null} />
                <MetricCard label="Imbalance Severity" value={m.imbalanceSeverity} />
              </div>
            </div>
          </>
        );
      })()}

      {/* Preprocessing metrics */}
      {content && sectionKey === 'preprocessing' && (() => {
        const m = parsePreprocessingResults(content);
        return (
          <>
            <div className="results-section">
              <div className="results-section-title">Data Cleaning</div>
              <div className="results-metrics-grid">
                <MetricCard label="Initial Rows" value={m.initialRows} />
                <MetricCard label="Final Rows" value={m.finalRows} />
                <MetricCard label="Rows Removed" value={m.rowsRemoved != null && m.dataLossPct != null ? `${m.rowsRemoved} (${m.dataLossPct}%)` : m.rowsRemoved} />
                <MetricCard label="Features Selected" value={m.featuresSelected} />
              </div>
            </div>
            <div className="results-section">
              <div className="results-section-title">Data Split & SMOTE</div>
              <div className="results-metrics-grid">
                <MetricCard label="Training Samples" value={m.trainingSamples} />
                <MetricCard label="Test Samples" value={m.testSamples} />
                <MetricCard label="SMOTE Synthetic Samples" value={m.smoteSamples} />
              </div>
            </div>
          </>
        );
      })()}

      {/* Training metrics */}
      {content && sectionKey === 'training' && (() => {
        const m = parseTrainingFileResults(content);
        return (
          <>
            <div className="results-section">
              <div className="results-section-title">Model Configuration</div>
              <div className="results-metrics-grid">
                <MetricCard label="CV Macro F1" value={m.cvF1Score} />
                <MetricCard label="Number of Trees" value={m.trees} />
                <MetricCard label="Average Depth" value={m.avgDepth} />
                <MetricCard label="Features Used" value={m.features} />
              </div>
            </div>
            <div className="results-section">
              <div className="results-section-title">Training Time</div>
              <div className="results-metrics-grid">
                <MetricCard label="Hyperparameter Tuning" value={m.tuningTime} />
                <MetricCard label="Final Model Training" value={m.trainingTime} />
                <MetricCard label="Total Training Time" value={m.totalTime} />
              </div>
            </div>
            {m.topFeature && (
              <div className="results-section">
                <div className="results-section-title">Feature Importance</div>
                <div className="results-metrics-grid">
                  <MetricCard label="Top Feature" value={m.topFeature} />
                  <MetricCard label="Top Feature Importance" value={m.topFeatureImportance} />
                  <MetricCard label="Top 10 Features Share" value={m.top10Importance} />
                </div>
              </div>
            )}
          </>
        );
      })()}

      {/* Testing metrics */}
      {content && sectionKey === 'testing' && (() => {
        const m = parseTestingResults(content);
        return (
          <>
            <div className="results-section">
              <div className="results-section-title">Testing Metrics</div>
              <div className="results-metrics-grid">
                <MetricCard label="Accuracy" value={m.accuracy} />
                <MetricCard label="Macro F1" value={m.macroF1} />
                <MetricCard label="Inference Speed" value={m.inferenceSpeed} />
                <MetricCard label="Mean Confidence" value={m.meanConfidence} />
              </div>
            </div>
            {m.perClass.length > 0 && (
              <div className="results-section">
                <div className="results-section-title">Per-Class Performance</div>
                <PerClassTable rows={m.perClass} />
              </div>
            )}
            {m.binary && (
              <div className="results-section">
                <div className="results-section-title">Binary Evaluation (Benign vs Attack)</div>
                <div className="results-metrics-grid">
                  <MetricCard label="Binary Accuracy" value={m.binary.accuracy} />
                  <MetricCard label="Precision" value={m.binary.precision} />
                  <MetricCard label="Recall" value={m.binary.recall} />
                  <MetricCard label="Specificity" value={m.binary.specificity} />
                  <MetricCard label="Binary AUC" value={m.binary.auc} />
                </div>
              </div>
            )}
          </>
        );
      })()}

      {/* Image gallery */}
      <ImageGallery images={images} subdir={staticSubdir} />

      {/* Raw report viewer */}
      {content && (
        <div className="results-section">
          <button
            className="btn-secondary results-raw-toggle"
            onClick={() => setShowRaw((v) => !v)}
          >
            {showRaw ? 'Hide Raw Report' : 'View Raw Report'}
          </button>
          {showRaw && <pre className="results-raw-text">{content}</pre>}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: ResultsVariantPanel
// Shows all 4 pipeline sections for one variant (default or all)
// ---------------------------------------------------------------------------

function ResultsVariantPanel({ variant, structure }) {
  const [activeSection, setActiveSection] = useState('testing');

  return (
    <div className="results-variant-panel">
      <div className="results-pipeline-tabs">
        {PIPELINE_SECTIONS.map((s) => (
          <button
            key={s.key}
            className={`results-pipeline-tab-btn${activeSection === s.key ? ' active' : ''}`}
            onClick={() => setActiveSection(s.key)}
          >
            {s.label}
          </button>
        ))}
      </div>

      {PIPELINE_SECTIONS.filter((s) => s.key === activeSection).map((s) => (
        <div key={s.key} className="results-pipeline-section">
          <p className="results-pipeline-section-desc">{s.description}</p>
          <ResultsSectionContent
            key={`${variant}-${s.key}`}
            sectionKey={s.key}
            variant={variant}
            structure={structure}
          />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: TrainingResultsTab
// ---------------------------------------------------------------------------

function TrainingResultsTab() {
  const [structure, setStructure] = useState(null);
  const [structureLoading, setStructureLoading] = useState(true);
  const [structureError, setStructureError] = useState(null);
  const [activeVariant, setActiveVariant] = useState('default');

  useEffect(() => {
    let cancelled = false;
    setStructureLoading(true);
    setStructureError(null);

    fetch('/api/results/structure')
      .then((res) => {
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        return res.json();
      })
      .then((data) => {
        if (!cancelled) setStructure(data);
      })
      .catch((err) => {
        if (!cancelled) setStructureError(err.message);
      })
      .finally(() => {
        if (!cancelled) setStructureLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  if (structureLoading) {
    return <div className="results-state-msg">Loading results structure...</div>;
  }

  if (structureError) {
    return <div className="results-state-msg results-state-error">Failed to load results: {structureError}</div>;
  }

  const variantStructure = structure?.[activeVariant] ?? {};

  return (
    <div className="training-results-tab">
      {/* Sub-tabs */}
      <div className="results-subtabs">
        <button
          className={`report-tab-btn${activeVariant === 'default' ? ' active' : ''}`}
          onClick={() => setActiveVariant('default')}
        >
          5 Class (Default)
        </button>
        <button
          className={`report-tab-btn${activeVariant === 'all' ? ' active' : ''}`}
          onClick={() => setActiveVariant('all')}
        >
          6 Class (All)
        </button>
      </div>

      <ResultsVariantPanel
        key={activeVariant}
        variant={activeVariant}
        structure={variantStructure}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: SessionReportsTab
// ---------------------------------------------------------------------------

function SessionReportsTab() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [typeFilter, setTypeFilter] = useState('');
  const [modelFilter, setModelFilter] = useState('');

  const fetchReports = useCallback(async (type, model) => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      if (type) params.set('type', type);
      if (model) params.set('model', model);
      const qs = params.toString();
      const res = await fetch(`/api/reports${qs ? `?${qs}` : ''}`);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setReports(data.reports ?? []);
    } catch (err) {
      setError(err.message);
      setReports([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports(typeFilter, modelFilter);
  }, [typeFilter, modelFilter, fetchReports]);

  return (
    <div className="session-reports-tab">
      {/* Filter bar */}
      <div className="reports-filter-bar">
        <div className="form-group" style={{ margin: 0 }}>
          <label htmlFor="type-filter">Type</label>
          <select
            id="type-filter"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            {TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div className="form-group" style={{ margin: 0 }}>
          <label htmlFor="model-filter">Model</label>
          <select
            id="model-filter"
            value={modelFilter}
            onChange={(e) => setModelFilter(e.target.value)}
          >
            {MODEL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Reports list */}
      <div className="reports-list-enhanced">
        {loading && (
          <div className="reports-state-msg">Loading reports...</div>
        )}

        {!loading && error && (
          <div className="reports-state-msg reports-state-error">
            Failed to load reports: {error}
          </div>
        )}

        {!loading && !error && reports.length === 0 && (
          <div className="reports-state-msg">
            No reports found{typeFilter ? ` for type "${typeFilter}"` : ''}.
          </div>
        )}

        {!loading && !error && reports.length > 0 && reports.map((report) => (
          <ReportCard key={report.name} report={report} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root component: Reports
// ---------------------------------------------------------------------------

function Reports() {
  const [activeTab, setActiveTab] = useState('session');

  return (
    <Section title="Reports & Results">
      {/* Top-level tabs */}
      <div className="reports-tabs">
        <button
          className={`report-tab-btn${activeTab === 'session' ? ' active' : ''}`}
          onClick={() => setActiveTab('session')}
        >
          Session Reports
        </button>
        <button
          className={`report-tab-btn${activeTab === 'training' ? ' active' : ''}`}
          onClick={() => setActiveTab('training')}
        >
          Training Results
        </button>
      </div>

      {activeTab === 'session' && <SessionReportsTab />}
      {activeTab === 'training' && <TrainingResultsTab />}
    </Section>
  );
}

export default Reports;
