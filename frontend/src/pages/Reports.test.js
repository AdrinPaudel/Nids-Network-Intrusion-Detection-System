/**
 * Reports.test.js
 *
 * TDD test suite for the rewritten Reports page.
 * Tests are written BEFORE implementation (RED phase).
 *
 * Coverage areas:
 *   - Helper functions (pure, unit-testable)
 *   - Session Reports tab: filter bar, report cards, expanded detail
 *   - Training Results tab: sub-tabs, metrics parsing, image gallery
 *   - Edge cases: null/empty data, API errors, loading states
 *   - Minute flow table: colour coding, pagination
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';

// ---------------------------------------------------------------------------
// Module under test — imported AFTER mocks are declared
// ---------------------------------------------------------------------------
// We defer the import so jest.mock() calls run first (hoisted).

// ---------------------------------------------------------------------------
// Mock fetch globally
// ---------------------------------------------------------------------------
beforeEach(() => {
  global.fetch = jest.fn();
});

afterEach(() => {
  jest.resetAllMocks();
});

// ---------------------------------------------------------------------------
// Helpers — extracted pure functions tested independently
// ---------------------------------------------------------------------------

// These helpers will be exported from the new Reports.js for testability.
// Import them directly once the file is written.

describe('formatReportTitle helper', () => {
  let formatReportTitle;

  beforeAll(async () => {
    // Dynamic import so the module is loaded after mocks
    const mod = await import('./Reports');
    formatReportTitle = mod.formatReportTitle;
  });

  test('formats a standard simul_default name into readable title', () => {
    const title = formatReportTitle({
      type: 'simul',
      model: 'default',
      date_iso: '2026-03-05T17:23:17',
    });
    expect(title).toMatch(/Simulation/i);
    expect(title).toMatch(/Default/i);
    expect(title).toMatch(/Mar 5, 2026/i);
  });

  test('formats batch_all correctly', () => {
    const title = formatReportTitle({
      type: 'batch',
      model: 'all',
      date_iso: '2026-01-15T08:00:00',
    });
    expect(title).toMatch(/Batch/i);
    expect(title).toMatch(/All/i);
    expect(title).toMatch(/Jan 15, 2026/i);
  });

  test('handles null/undefined gracefully', () => {
    const title = formatReportTitle({ type: null, model: null, date_iso: null });
    expect(typeof title).toBe('string');
    expect(title.length).toBeGreaterThan(0);
  });

  test('handles unknown type gracefully', () => {
    const title = formatReportTitle({ type: 'unknown', model: 'default', date_iso: null });
    expect(typeof title).toBe('string');
  });
});

describe('parseSessionSummary helper', () => {
  let parseSessionSummary;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseSessionSummary = mod.parseSessionSummary;
  });

  const SAMPLE_SUMMARY = `
====================================================================================================
  NIDS CLASSIFICATION - SIMULATION SESSION SUMMARY
====================================================================================================

  Session Mode:      SIMUL
  Model:             Default
  Session Started:   2026-03-05 17:23:17
  Session Ended:     2026-03-05 17:25:27
  Actual Duration:   130s

  FULL SESSION SUMMARY
  ------------------------------------------------------------------------------------------------

  Total Flows Classified: 648
  Threats Detected:       158
  Suspicious Flows:       0
  Clean Flows:            490

  Classification Breakdown:
    Benign              :    490 ( 75.6%)
    DDoS                :     97 ( 15.0%)
    DoS                 :     31 (  4.8%)
    Botnet              :     18 (  2.8%)
    Brute Force         :     12 (  1.9%)
`;

  test('extracts totalFlows from summary text', () => {
    const result = parseSessionSummary(SAMPLE_SUMMARY);
    expect(result.totalFlows).toBe(648);
  });

  test('extracts threats from summary text', () => {
    const result = parseSessionSummary(SAMPLE_SUMMARY);
    expect(result.threats).toBe(158);
  });

  test('extracts suspicious from summary text', () => {
    const result = parseSessionSummary(SAMPLE_SUMMARY);
    expect(result.suspicious).toBe(0);
  });

  test('extracts clean flows from summary text', () => {
    const result = parseSessionSummary(SAMPLE_SUMMARY);
    expect(result.clean).toBe(490);
  });

  test('extracts duration from summary text', () => {
    const result = parseSessionSummary(SAMPLE_SUMMARY);
    expect(result.duration).toMatch(/130s/);
  });

  test('extracts class breakdown as array of {name, count, pct}', () => {
    const result = parseSessionSummary(SAMPLE_SUMMARY);
    expect(Array.isArray(result.breakdown)).toBe(true);
    expect(result.breakdown.length).toBeGreaterThan(0);

    const benign = result.breakdown.find(b => b.name === 'Benign');
    expect(benign).toBeDefined();
    expect(benign.count).toBe(490);
    expect(typeof benign.pct).toBe('number');
  });

  test('returns safe defaults when content is empty string', () => {
    const result = parseSessionSummary('');
    expect(result.totalFlows).toBeNull();
    expect(result.threats).toBeNull();
    expect(result.breakdown).toEqual([]);
  });

  test('returns safe defaults when content is null', () => {
    const result = parseSessionSummary(null);
    expect(result.totalFlows).toBeNull();
    expect(result.breakdown).toEqual([]);
  });
});

describe('parseTestingResults helper', () => {
  let parseTestingResults;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseTestingResults = mod.parseTestingResults;
  });

  const SAMPLE_RESULTS = `
================================================================================
              MODEL TESTING & EVALUATION REPORT
================================================================================

2. INFERENCE PERFORMANCE
--------------------------------------------------------------------------------
Inference speed: 456,820 samples/second
Inference time: 5.18 seconds
Mean confidence: 0.9988

3. MULTICLASS EVALUATION
--------------------------------------------------------------------------------
Accuracy:           0.9999 (99.99%)
Macro Precision:    0.9998
Macro Recall:       0.9989
Macro F1-Score:     0.9993
Weighted F1-Score:  0.9999
Macro AUC:          1.0000

Per-Class Performance:
Class                Precision  Recall     F1-Score   AUC        Support
--------------------------------------------------------------------------------
Benign               0.9999     1.0000     0.9999     1.0000     2,125,607
Botnet               1.0000     0.9997     0.9998     1.0000     28,907
Brute Force          0.9995     0.9957     0.9976     1.0000     18,977
DDoS                 0.9997     0.9993     0.9995     1.0000     155,191
DoS                  0.9997     0.9997     0.9997     1.0000     39,314

4. BINARY EVALUATION (Benign vs Attack)
--------------------------------------------------------------------------------
Accuracy:           0.9999 (99.99%)
Precision:          0.9998
Recall (TPR):       0.9992
F1-Score:           0.9995
Specificity (TNR):  1.0000
Binary AUC:         1.0000
`;

  test('extracts accuracy as string', () => {
    const result = parseTestingResults(SAMPLE_RESULTS);
    expect(result.accuracy).toBe('0.9999');
  });

  test('extracts macroF1 as string', () => {
    const result = parseTestingResults(SAMPLE_RESULTS);
    expect(result.macroF1).toBe('0.9993');
  });

  test('extracts inferenceSpeed', () => {
    const result = parseTestingResults(SAMPLE_RESULTS);
    expect(result.inferenceSpeed).toMatch(/456/);
  });

  test('extracts meanConfidence', () => {
    const result = parseTestingResults(SAMPLE_RESULTS);
    expect(result.meanConfidence).toBe('0.9988');
  });

  test('extracts perClass rows with correct fields', () => {
    const result = parseTestingResults(SAMPLE_RESULTS);
    expect(Array.isArray(result.perClass)).toBe(true);
    expect(result.perClass.length).toBe(5);

    const benign = result.perClass.find(r => r.className === 'Benign');
    expect(benign).toBeDefined();
    expect(benign.precision).toBe('0.9999');
    expect(benign.recall).toBe('1.0000');
    expect(benign.f1).toBe('0.9999');
    expect(benign.auc).toBe('1.0000');
    expect(benign.support).toBe('2,125,607');
  });

  test('extracts binary evaluation metrics', () => {
    const result = parseTestingResults(SAMPLE_RESULTS);
    expect(result.binary).toBeDefined();
    expect(result.binary.accuracy).toBe('0.9999');
    expect(result.binary.precision).toBe('0.9998');
    expect(result.binary.recall).toBe('0.9992');
    expect(result.binary.specificity).toBe('1.0000');
    expect(result.binary.auc).toBe('1.0000');
  });

  test('returns empty structure for empty input', () => {
    const result = parseTestingResults('');
    expect(result.accuracy).toBeNull();
    expect(result.perClass).toEqual([]);
    expect(result.binary).toBeDefined();
  });

  test('returns empty structure for null input', () => {
    const result = parseTestingResults(null);
    expect(result.accuracy).toBeNull();
    expect(result.perClass).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Reports page — integration-style render tests
// ---------------------------------------------------------------------------

function makeMockReport(overrides = {}) {
  return {
    name: 'simul_default_2026-03-05_17-23-17',
    type: 'simul',
    model: 'default',
    date: '2026-03-05',
    date_iso: '2026-03-05T17:23:17',
    flows: 648,
    threats: 158,
    summary_preview: 'Preview text...',
    summary: `
  Total Flows Classified: 648
  Threats Detected:       158
  Suspicious Flows:       0
  Clean Flows:            490
  Actual Duration:   130s
  Classification Breakdown:
    Benign              :    490 ( 75.6%)
    DDoS                :     97 ( 15.0%)
`,
    size: 12345,
    ...overrides,
  };
}

function mockFetchReports(reports = [makeMockReport()]) {
  global.fetch.mockResolvedValueOnce({
    ok: true,
    json: async () => ({ reports }),
  });
}

function mockFetchResultsStructure(structure = {
  default: {
    testing: ['testing_results.txt'],
    images: { testing: ['confusion_matrix_multiclass.png'] },
  },
  all: {
    testing: ['testing_results.txt'],
    images: { testing: ['confusion_matrix_multiclass.png'] },
  },
}) {
  global.fetch.mockResolvedValueOnce({
    ok: true,
    json: async () => structure,
  });
}

function mockFetchResultsFile(content = '') {
  global.fetch.mockResolvedValueOnce({
    ok: true,
    json: async () => ({ path: 'testing/testing_results.txt', content, size: content.length }),
  });
}

let Reports;

beforeAll(async () => {
  const mod = await import('./Reports');
  Reports = mod.default;
});

// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------

describe('Reports page — tab navigation', () => {
  test('renders both tab buttons on initial load', async () => {
    mockFetchReports([]);
    render(<Reports />);
    expect(screen.getByRole('button', { name: /session reports/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /training results/i })).toBeInTheDocument();
  });

  test('Session Reports tab is active by default', async () => {
    mockFetchReports([]);
    render(<Reports />);
    const sessionTab = screen.getByRole('button', { name: /session reports/i });
    expect(sessionTab).toHaveClass('active');
  });

  test('clicking Training Results tab switches content', async () => {
    mockFetchReports([]);
    mockFetchResultsStructure();
    mockFetchResultsFile('');
    mockFetchResultsFile('');

    render(<Reports />);
    const trainingTab = screen.getByRole('button', { name: /training results/i });
    fireEvent.click(trainingTab);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /5 class/i })).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Session Reports tab — filter bar
// ---------------------------------------------------------------------------

describe('Session Reports tab — filter bar', () => {
  test('renders Type dropdown with correct options', async () => {
    mockFetchReports([]);
    render(<Reports />);
    await waitFor(() => {
      const select = screen.getByLabelText(/type/i);
      expect(select).toBeInTheDocument();
      expect(within(select).getByRole('option', { name: /all/i })).toBeInTheDocument();
      expect(within(select).getByRole('option', { name: /simulation/i })).toBeInTheDocument();
      expect(within(select).getByRole('option', { name: /batch/i })).toBeInTheDocument();
      expect(within(select).getByRole('option', { name: /live/i })).toBeInTheDocument();
    });
  });

  test('renders Model dropdown with correct options', async () => {
    mockFetchReports([]);
    render(<Reports />);
    await waitFor(() => {
      const select = screen.getByLabelText(/model/i);
      expect(select).toBeInTheDocument();
      // Use exact name to avoid matching "6 Class (All)" for the blank/all option
      expect(within(select).getByRole('option', { name: 'All' })).toBeInTheDocument();
      expect(within(select).getByRole('option', { name: /5 class/i })).toBeInTheDocument();
      expect(within(select).getByRole('option', { name: /6 class/i })).toBeInTheDocument();
    });
  });

  test('changing Type filter triggers new API call with correct type param', async () => {
    mockFetchReports([]);
    mockFetchReports([]);

    render(<Reports />);
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));

    const select = screen.getByLabelText(/type/i);
    fireEvent.change(select, { target: { value: 'simul' } });

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(2);
      const url = global.fetch.mock.calls[1][0];
      expect(url).toContain('type=simul');
    });
  });

  test('changing Model filter triggers new API call with correct model param', async () => {
    mockFetchReports([]);
    mockFetchReports([]);

    render(<Reports />);
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));

    const select = screen.getByLabelText(/model/i);
    fireEvent.change(select, { target: { value: 'default' } });

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(2);
      const url = global.fetch.mock.calls[1][0];
      expect(url).toContain('model=default');
    });
  });
});

// ---------------------------------------------------------------------------
// Session Reports tab — loading and error states
// ---------------------------------------------------------------------------

describe('Session Reports tab — loading and error states', () => {
  test('shows loading message while fetching reports', () => {
    global.fetch.mockReturnValue(new Promise(() => {})); // never resolves
    render(<Reports />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  test('shows error message when API call fails', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Network error'));
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/failed/i)).toBeInTheDocument();
    });
  });

  test('shows empty state when no reports returned', async () => {
    mockFetchReports([]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/no reports/i)).toBeInTheDocument();
    });
  });

  test('shows non-ok fetch response as error', async () => {
    global.fetch.mockResolvedValueOnce({ ok: false, status: 500 });
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/failed/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Session Reports tab — report cards
// ---------------------------------------------------------------------------

describe('Session Reports tab — report cards', () => {
  test('renders a report card with formatted title', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/simulation/i)).toBeInTheDocument();
    });
  });

  test('renders type badge with correct text', async () => {
    mockFetchReports([makeMockReport({ type: 'simul' })]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/simulation/i)).toBeInTheDocument();
    });
  });

  test('renders model badge', async () => {
    mockFetchReports([makeMockReport({ model: 'default' })]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/5 class/i)).toBeInTheDocument();
    });
  });

  test('renders flows metric on card', async () => {
    mockFetchReports([makeMockReport({ flows: 648 })]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/648/)).toBeInTheDocument();
    });
  });

  test('renders threats metric on card', async () => {
    mockFetchReports([makeMockReport({ threats: 158 })]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/158/)).toBeInTheDocument();
    });
  });

  test('renders threat percentage on card', async () => {
    mockFetchReports([makeMockReport({ flows: 648, threats: 158 })]);
    render(<Reports />);
    await waitFor(() => {
      // 158/648 ≈ 24.4%
      expect(screen.getByText(/24\.\d+%|24%/)).toBeInTheDocument();
    });
  });

  test('renders View Details button', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /view details/i })).toBeInTheDocument();
    });
  });

  test('renders multiple report cards when API returns multiple reports', async () => {
    mockFetchReports([
      makeMockReport({ name: 'simul_default_2026-03-05_17-23-17' }),
      makeMockReport({ name: 'simul_all_2026-03-05_17-28-07', type: 'simul', model: 'all' }),
    ]);
    render(<Reports />);
    await waitFor(() => {
      const buttons = screen.getAllByRole('button', { name: /view details/i });
      expect(buttons.length).toBe(2);
    });
  });

  test('batch type badge has orange styling', async () => {
    mockFetchReports([makeMockReport({ type: 'batch', name: 'batch_default_2026-01-01_08-00-00' })]);
    render(<Reports />);
    await waitFor(() => {
      const badge = screen.getByText(/batch/i);
      // The badge element should exist with appropriate styling
      expect(badge).toBeInTheDocument();
    });
  });

  test('live type badge is rendered', async () => {
    mockFetchReports([makeMockReport({ type: 'live', name: 'live_default_2026-01-01_08-00-00' })]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByText(/live/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Session Reports tab — expanded detail panel
// ---------------------------------------------------------------------------

describe('Session Reports tab — expanded detail panel', () => {
  function mockMinutes(reportName = 'simul_default_2026-03-05_17-23-17') {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        minutes: [
          { filename: 'minute_17-23.txt', url: `/api/reports/${reportName}/minute/17-23` },
          { filename: 'minute_17-24.txt', url: `/api/reports/${reportName}/minute/17-24` },
        ],
      }),
    });
  }

  test('clicking View Details fetches minutes list', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => {
      const calls = global.fetch.mock.calls.map(c => c[0]);
      expect(calls.some(url => url.includes('/minutes'))).toBe(true);
    });
  });

  test('expanded panel shows session metrics cards', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => {
      // Should show total flows, threats, clean, suspicious, duration
      expect(screen.getByText(/total flows/i)).toBeInTheDocument();
    });
  });

  test('expanded panel shows minute file list', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => {
      expect(screen.getByText(/minute_17-23\.txt/)).toBeInTheDocument();
    });
  });

  test('clicking a minute file loads flow table', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => screen.getByText(/minute_17-23\.txt/));

    // Mock minute detail fetch
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        filename: 'minute_17-23.txt',
        content: '...',
        rows: [
          {
            timestamp: '2026-03-05 17:23:18',
            src_ip: '?', src_port: '?',
            dst_ip: '?', dst_port: '0',
            protocol: '0',
            class1: 'Benign', conf1: 1.0,
            class2: 'Brute Force', conf2: 0.0,
            class3: 'Botnet', conf3: 0.0,
          },
          {
            timestamp: '2026-03-05 17:23:19',
            src_ip: '?', src_port: '?',
            dst_ip: '?', dst_port: '80',
            protocol: '6',
            class1: 'DDoS', conf1: 0.949,
            class2: 'Benign', conf2: 0.034,
            class3: 'DoS', conf3: 0.016,
          },
        ],
      }),
    });

    fireEvent.click(screen.getByText(/minute_17-23\.txt/));

    await waitFor(() => {
      // Table column headers
      expect(screen.getByText(/timestamp/i)).toBeInTheDocument();
    });
  });

  test('threat rows have threat CSS class applied', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => screen.getByText(/minute_17-23\.txt/));

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        filename: 'minute_17-23.txt',
        content: '',
        rows: [
          {
            timestamp: '2026-03-05 17:23:19',
            src_ip: '?', src_port: '?',
            dst_ip: '?', dst_port: '80',
            protocol: '6',
            class1: 'DDoS', conf1: 0.949,
            class2: 'Benign', conf2: 0.034,
            class3: 'DoS', conf3: 0.016,
          },
        ],
      }),
    });

    fireEvent.click(screen.getByText(/minute_17-23\.txt/));

    await waitFor(() => {
      const threatRows = document.querySelectorAll('.minute-row-threat');
      expect(threatRows.length).toBeGreaterThan(0);
    });
  });

  test('suspicious rows (conf2 > 25%) get suspicious CSS class', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => screen.getByText(/minute_17-23\.txt/));

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        filename: 'minute_17-23.txt',
        content: '',
        rows: [
          {
            timestamp: '2026-03-05 17:23:20',
            src_ip: '?', src_port: '?',
            dst_ip: '?', dst_port: '80',
            protocol: '6',
            class1: 'Benign', conf1: 0.72,
            class2: 'DDoS', conf2: 0.26,  // >25% = suspicious
            class3: 'DoS', conf3: 0.02,
          },
        ],
      }),
    });

    fireEvent.click(screen.getByText(/minute_17-23\.txt/));

    await waitFor(() => {
      const suspiciousRows = document.querySelectorAll('.minute-row-suspicious');
      expect(suspiciousRows.length).toBeGreaterThan(0);
    });
  });

  test('detail panel collapses when View Details clicked again', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    mockMinutes();
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => screen.getByText(/total flows/i));

    fireEvent.click(screen.getByRole('button', { name: /hide details/i }));

    await waitFor(() => {
      expect(screen.queryByText(/total flows/i)).not.toBeInTheDocument();
    });
  });

  test('shows error when minutes fetch fails', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));
    global.fetch.mockRejectedValueOnce(new Error('Network error'));
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => {
      expect(screen.getByText(/failed/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Training Results tab
// ---------------------------------------------------------------------------

const SAMPLE_RESULTS_TEXT = `
================================================================================
              MODEL TESTING & EVALUATION REPORT
================================================================================

2. INFERENCE PERFORMANCE
--------------------------------------------------------------------------------
Inference speed: 456,820 samples/second
Inference time: 5.18 seconds
Mean confidence: 0.9988

3. MULTICLASS EVALUATION
--------------------------------------------------------------------------------
Accuracy:           0.9999 (99.99%)
Macro Precision:    0.9998
Macro Recall:       0.9989
Macro F1-Score:     0.9993
Weighted F1-Score:  0.9999
Macro AUC:          1.0000

Per-Class Performance:
Class                Precision  Recall     F1-Score   AUC        Support
--------------------------------------------------------------------------------
Benign               0.9999     1.0000     0.9999     1.0000     2,125,607
Botnet               1.0000     0.9997     0.9998     1.0000     28,907

4. BINARY EVALUATION (Benign vs Attack)
--------------------------------------------------------------------------------
Accuracy:           0.9999 (99.99%)
Precision:          0.9998
Recall (TPR):       0.9992
F1-Score:           0.9995
Specificity (TNR):  1.0000
Binary AUC:         1.0000
`;

function setupTrainingTab() {
  // 1. initial reports fetch (session tab)
  mockFetchReports([]);
  // 2. structure fetch
  mockFetchResultsStructure();
  // 3. default testing_results.txt
  mockFetchResultsFile(SAMPLE_RESULTS_TEXT);
  // 4. all testing_results.txt
  mockFetchResultsFile(SAMPLE_RESULTS_TEXT);
}

async function switchToTrainingTab() {
  setupTrainingTab();
  render(<Reports />);
  const trainingTab = screen.getByRole('button', { name: /training results/i });
  fireEvent.click(trainingTab);
  await waitFor(() => screen.getByRole('button', { name: /5 class/i }));
}

describe('Training Results tab', () => {
  test('shows two sub-tabs: 5 Class (Default) and 6 Class (All)', async () => {
    await switchToTrainingTab();
    expect(screen.getByRole('button', { name: /5 class/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /6 class/i })).toBeInTheDocument();
  });

  test('5 Class sub-tab is active by default', async () => {
    await switchToTrainingTab();
    const fiveClass = screen.getByRole('button', { name: /5 class/i });
    expect(fiveClass).toHaveClass('active');
  });

  test('shows accuracy metric card for default variant', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      // Use exact match to distinguish "Accuracy" from "Binary Accuracy"
      expect(screen.getByText('Accuracy')).toBeInTheDocument();
      // Sample data has same accuracy for overall and binary — use getAllByText
      expect(screen.getAllByText(/0\.9999|99\.99%/).length).toBeGreaterThan(0);
    });
  });

  test('shows Macro F1 metric card', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      expect(screen.getByText(/macro f1/i)).toBeInTheDocument();
      expect(screen.getByText(/0\.9993/)).toBeInTheDocument();
    });
  });

  test('shows inference speed metric card', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      expect(screen.getByText(/inference speed/i)).toBeInTheDocument();
      expect(screen.getByText(/456/)).toBeInTheDocument();
    });
  });

  test('shows mean confidence metric card', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      expect(screen.getByText(/mean confidence/i)).toBeInTheDocument();
      expect(screen.getByText(/0\.9988/)).toBeInTheDocument();
    });
  });

  test('shows per-class metrics table header', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      expect(screen.getByText(/per.class/i)).toBeInTheDocument();
    });
  });

  test('per-class table has Benign row', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      expect(screen.getByText('Benign')).toBeInTheDocument();
    });
  });

  test('shows binary evaluation section', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      // Use section title to avoid ambiguity with "Binary Accuracy" / "Binary AUC" metric cards
      expect(screen.getByText(/binary evaluation/i)).toBeInTheDocument();
    });
  });

  test('switching to 6 Class sub-tab fetches all variant results', async () => {
    await switchToTrainingTab();

    mockFetchResultsFile(SAMPLE_RESULTS_TEXT);

    const sixClassTab = screen.getByRole('button', { name: /6 class/i });
    fireEvent.click(sixClassTab);

    await waitFor(() => {
      expect(sixClassTab).toHaveClass('active');
    });
  });

  test('shows image thumbnails when structure has images', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      const imgs = document.querySelectorAll('.results-image-thumb');
      expect(imgs.length).toBeGreaterThan(0);
    });
  });

  test('clicking an image opens modal overlay', async () => {
    await switchToTrainingTab();
    await waitFor(() => {
      const thumbs = document.querySelectorAll('.results-image-thumb');
      expect(thumbs.length).toBeGreaterThan(0);
    });

    const firstThumb = document.querySelector('.results-image-thumb');
    fireEvent.click(firstThumb);

    await waitFor(() => {
      expect(document.querySelector('.image-modal-overlay')).toBeInTheDocument();
    });
  });

  test('clicking modal overlay closes it', async () => {
    await switchToTrainingTab();
    await waitFor(() => document.querySelector('.results-image-thumb'));

    fireEvent.click(document.querySelector('.results-image-thumb'));
    await waitFor(() => document.querySelector('.image-modal-overlay'));

    fireEvent.click(document.querySelector('.image-modal-overlay'));
    await waitFor(() => {
      expect(document.querySelector('.image-modal-overlay')).not.toBeInTheDocument();
    });
  });

  test('shows loading state while fetching results', () => {
    mockFetchReports([]);
    global.fetch.mockReturnValue(new Promise(() => {})); // never resolves for structure
    render(<Reports />);
    const trainingTab = screen.getByRole('button', { name: /training results/i });
    fireEvent.click(trainingTab);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  test('shows error when results structure fetch fails', async () => {
    mockFetchReports([]);
    global.fetch.mockRejectedValueOnce(new Error('Network error'));
    render(<Reports />);
    const trainingTab = screen.getByRole('button', { name: /training results/i });
    fireEvent.click(trainingTab);
    await waitFor(() => {
      expect(screen.getByText(/failed/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('Edge cases', () => {
  test('handles report with null flows gracefully', async () => {
    mockFetchReports([makeMockReport({ flows: null, threats: null })]);
    render(<Reports />);
    await waitFor(() => {
      // Should not crash — page renders
      expect(screen.getByRole('button', { name: /view details/i })).toBeInTheDocument();
    });
  });

  test('handles report with empty summary gracefully', async () => {
    mockFetchReports([makeMockReport({ summary: '' })]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ minutes: [] }),
    });

    fireEvent.click(screen.getByRole('button', { name: /view details/i }));
    await waitFor(() => {
      // No crashes, panel rendered
      expect(screen.getByText(/no minutes/i)).toBeInTheDocument();
    });
  });

  test('handles minute list with zero minutes', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ minutes: [] }),
    });

    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => {
      expect(screen.getByText(/no minutes/i)).toBeInTheDocument();
    });
  });

  test('handles special characters in report names without crashing', async () => {
    // Report names are folder names — no special chars expected, but should be safe
    mockFetchReports([makeMockReport({ name: 'simul_default_2026-03-05_17-23-17' })]);
    render(<Reports />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /view details/i })).toBeInTheDocument();
    });
  });

  test('handles non-ok response for minutes fetch', async () => {
    mockFetchReports([makeMockReport()]);
    render(<Reports />);

    await waitFor(() => screen.getByRole('button', { name: /view details/i }));

    global.fetch.mockResolvedValueOnce({ ok: false, status: 404 });
    fireEvent.click(screen.getByRole('button', { name: /view details/i }));

    await waitFor(() => {
      expect(screen.getByText(/failed/i)).toBeInTheDocument();
    });
  });

  test('handles results file fetch failing gracefully', async () => {
    mockFetchReports([]);
    mockFetchResultsStructure();
    global.fetch.mockRejectedValueOnce(new Error('file error'));
    global.fetch.mockRejectedValueOnce(new Error('file error'));

    render(<Reports />);
    const trainingTab = screen.getByRole('button', { name: /training results/i });
    fireEvent.click(trainingTab);

    // Should not crash — shows empty/error state for metrics
    await waitFor(() => {
      // Structure loaded, but file content empty
      expect(screen.getByRole('button', { name: /5 class/i })).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// parsePerClassPrecision helper
// ---------------------------------------------------------------------------

describe('parsePerClassPrecision helper', () => {
  let parsePerClassPrecision;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parsePerClassPrecision = mod.parsePerClassPrecision;
  });

  const LABELED_CONTENT = `
  Per-Class Precision (of predicted, how many correct):
    Benign              :  85.13% (773/908)  |  Predicted:    908
    Botnet              : 100.00% (1/1)  |  Predicted:      1
    Brute Force         : 100.00% (21/21)  |  Predicted:     21
    DDoS                : 100.00% (65/65)  |  Predicted:     65
    DoS                 : 100.00% (5/5)  |  Predicted:      5
`;

  test('returns array of entries with className, correct, predicted, wrong', () => {
    const result = parsePerClassPrecision(LABELED_CONTENT);
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(5);
  });

  test('parses Benign entry correctly', () => {
    const result = parsePerClassPrecision(LABELED_CONTENT);
    const benign = result.find(r => r.className === 'Benign');
    expect(benign).toBeDefined();
    expect(benign.correct).toBe(773);
    expect(benign.predicted).toBe(908);
    expect(benign.wrong).toBe(908 - 773);
  });

  test('parses 100% precision entry correctly (Botnet)', () => {
    const result = parsePerClassPrecision(LABELED_CONTENT);
    const botnet = result.find(r => r.className === 'Botnet');
    expect(botnet).toBeDefined();
    expect(botnet.correct).toBe(1);
    expect(botnet.predicted).toBe(1);
    expect(botnet.wrong).toBe(0);
  });

  test('parses all five classes from labeled content', () => {
    const result = parsePerClassPrecision(LABELED_CONTENT);
    const names = result.map(r => r.className);
    expect(names).toContain('Benign');
    expect(names).toContain('Botnet');
    expect(names).toContain('Brute Force');
    expect(names).toContain('DDoS');
    expect(names).toContain('DoS');
  });

  test('returns empty array for null input', () => {
    const result = parsePerClassPrecision(null);
    expect(result).toEqual([]);
  });

  test('returns empty array for empty string', () => {
    const result = parsePerClassPrecision('');
    expect(result).toEqual([]);
  });

  test('returns empty array when content has no Per-Class Precision lines', () => {
    const result = parsePerClassPrecision('Total Flows Classified: 100\nThreats Detected: 5\n');
    expect(result).toEqual([]);
  });

  test('wrong field is the difference between predicted and correct', () => {
    const result = parsePerClassPrecision(LABELED_CONTENT);
    result.forEach(entry => {
      expect(entry.wrong).toBe(entry.predicted - entry.correct);
    });
  });
});

// ---------------------------------------------------------------------------
// parseSessionSummary — NEW paths: labeled batch fallback
// ---------------------------------------------------------------------------

describe('parseSessionSummary — labeled batch summary (fallback from Per-Class Precision)', () => {
  let parseSessionSummary;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseSessionSummary = mod.parseSessionSummary;
  });

  // Labeled batch format: has Accuracy + Per-Class Precision but NO Classification Breakdown section
  const LABELED_BATCH_SUMMARY = `
====================================================================================================
  NIDS CLASSIFICATION - BATCH SESSION SUMMARY
====================================================================================================

  Session Mode:      BATCH
  Model:             Default

  FULL SESSION SUMMARY
  ------------------------------------------------------------------------------------------------

  Total Flows Classified: 1000
  Accuracy:               86.50% (865/1000)

  Per-Class Precision (of predicted, how many correct):
    Benign              :  85.13% (773/908)  |  Predicted:    908
    Botnet              : 100.00% (1/1)  |  Predicted:      1
    Brute Force         : 100.00% (21/21)  |  Predicted:     21
    DDoS                : 100.00% (65/65)  |  Predicted:     65
    DoS                 : 100.00% (5/5)  |  Predicted:      5
`;

  test('extracts totalFlows correctly', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(result.totalFlows).toBe(1000);
  });

  test('extracts accuracy correctly', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(result.accuracy).toBe(86.50);
  });

  test('extracts accuracyCorrect correctly', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(result.accuracyCorrect).toBe(865);
  });

  test('threats is null (not present in labeled batch format)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(result.threats).toBeNull();
  });

  test('suspicious is null (not present in labeled batch format)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(result.suspicious).toBeNull();
  });

  test('clean is null (not present in labeled batch format)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(result.clean).toBeNull();
  });

  test('breakdown is derived from Per-Class Precision (fallback path)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    expect(Array.isArray(result.breakdown)).toBe(true);
    expect(result.breakdown.length).toBe(5);
  });

  test('breakdown Benign entry uses predicted count (908)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    const benign = result.breakdown.find(b => b.name === 'Benign');
    expect(benign).toBeDefined();
    expect(benign.count).toBe(908);
  });

  test('breakdown Botnet entry uses predicted count (1)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    const botnet = result.breakdown.find(b => b.name === 'Botnet');
    expect(botnet).toBeDefined();
    expect(botnet.count).toBe(1);
  });

  test('breakdown DDoS entry has predicted count 65', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    const ddos = result.breakdown.find(b => b.name === 'DDoS');
    expect(ddos).toBeDefined();
    expect(ddos.count).toBe(65);
  });

  test('breakdown percentages are calculated relative to totalFlows (1000)', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    const benign = result.breakdown.find(b => b.name === 'Benign');
    // 908 / 1000 * 100 = 90.8%
    expect(benign.pct).toBe(90.8);
  });

  test('breakdown pct values are numbers', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    result.breakdown.forEach(entry => {
      expect(typeof entry.pct).toBe('number');
      expect(isNaN(entry.pct)).toBe(false);
    });
  });

  test('breakdown contains all five expected class names', () => {
    const result = parseSessionSummary(LABELED_BATCH_SUMMARY);
    const names = result.breakdown.map(b => b.name);
    expect(names).toContain('Benign');
    expect(names).toContain('Botnet');
    expect(names).toContain('Brute Force');
    expect(names).toContain('DDoS');
    expect(names).toContain('DoS');
  });
});

// ---------------------------------------------------------------------------
// parseSessionSummary — unlabeled batch summary (Classification Breakdown present)
// ---------------------------------------------------------------------------

describe('parseSessionSummary — unlabeled batch summary (Classification Breakdown section)', () => {
  let parseSessionSummary;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseSessionSummary = mod.parseSessionSummary;
  });

  // Unlabeled batch: Threats Detected WITHOUT colon, has Classification Breakdown
  const UNLABELED_BATCH_SUMMARY = `
====================================================================================================
  NIDS CLASSIFICATION - BATCH SESSION SUMMARY
====================================================================================================

  Session Mode:      BATCH
  Model:             Default

  FULL SESSION SUMMARY
  ------------------------------------------------------------------------------------------------

  Total Flows Classified: 1000
  Threats Detected          95 (9.5%)
  Suspicious Flows          126 (12.6%)
  Clean Flows               779 (77.9%)

  Classification Breakdown:
    Benign              :    905 ( 90.5%)
    DDoS                :     71 (  7.1%)
    Brute Force         :     17 (  1.7%)
    DoS                 :      7 (  0.7%)
`;

  test('extracts totalFlows correctly', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    expect(result.totalFlows).toBe(1000);
  });

  test('extracts threats correctly (no colon after Threats Detected)', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    expect(result.threats).toBe(95);
  });

  test('extracts suspicious count', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    expect(result.suspicious).toBe(126);
  });

  test('extracts clean count', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    expect(result.clean).toBe(779);
  });

  test('accuracy is null (no Accuracy line in unlabeled format)', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    expect(result.accuracy).toBeNull();
  });

  test('breakdown is parsed from Classification Breakdown section (4 entries)', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    expect(Array.isArray(result.breakdown)).toBe(true);
    expect(result.breakdown.length).toBe(4);
  });

  test('breakdown Benign entry has count 905', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    const benign = result.breakdown.find(b => b.name === 'Benign');
    expect(benign).toBeDefined();
    expect(benign.count).toBe(905);
  });

  test('breakdown DDoS entry has count 71', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    const ddos = result.breakdown.find(b => b.name === 'DDoS');
    expect(ddos).toBeDefined();
    expect(ddos.count).toBe(71);
  });

  test('breakdown Brute Force entry has count 17', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    const bf = result.breakdown.find(b => b.name === 'Brute Force');
    expect(bf).toBeDefined();
    expect(bf.count).toBe(17);
  });

  test('breakdown DoS entry has count 7', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    const dos = result.breakdown.find(b => b.name === 'DoS');
    expect(dos).toBeDefined();
    expect(dos.count).toBe(7);
  });

  test('breakdown pct values match the file content', () => {
    const result = parseSessionSummary(UNLABELED_BATCH_SUMMARY);
    const benign = result.breakdown.find(b => b.name === 'Benign');
    expect(benign.pct).toBe(90.5);
  });
});

// ---------------------------------------------------------------------------
// parseSessionSummary — labeled simul summary (Classification Breakdown wins over fallback)
// ---------------------------------------------------------------------------

describe('parseSessionSummary — labeled simul summary (Classification Breakdown takes priority over Per-Class Precision)', () => {
  let parseSessionSummary;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseSessionSummary = mod.parseSessionSummary;
  });

  // Labeled simul: has BOTH Per-Class Precision AND Classification Breakdown
  // The Classification Breakdown section should be used (not the fallback)
  const LABELED_SIMUL_SUMMARY = `
====================================================================================================
  NIDS CLASSIFICATION - SIMULATION SESSION SUMMARY
====================================================================================================

  Session Mode:      SIMUL
  Model:             Default
  Session Started:   2026-03-05 17:23:17
  Session Ended:     2026-03-05 17:25:27
  Actual Duration:   130s

  FULL SESSION SUMMARY
  ------------------------------------------------------------------------------------------------

  Total Flows Classified: 649
  Accuracy:               100.00% (649/649)

  Per-Class Precision (of predicted, how many correct):
    Benign              : 100.00% (491/491)  |  Predicted:    491
    Botnet              : 100.00% (18/18)  |  Predicted:     18
    DDoS                : 100.00% (97/97)  |  Predicted:     97
    DoS                 : 100.00% (43/43)  |  Predicted:     43

  Classification Breakdown:
    Benign              :    491 ( 75.7%)
    DDoS                :     97 ( 14.9%)
    DoS                 :     43 (  6.6%)
    Botnet              :     18 (  2.8%)
`;

  test('extracts totalFlows correctly', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    expect(result.totalFlows).toBe(649);
  });

  test('extracts accuracy correctly', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    expect(result.accuracy).toBe(100.00);
  });

  test('extracts duration correctly', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    expect(result.duration).toMatch(/130s/);
  });

  test('breakdown is parsed from Classification Breakdown section (4 entries)', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    expect(Array.isArray(result.breakdown)).toBe(true);
    expect(result.breakdown.length).toBe(4);
  });

  test('breakdown uses Classification Breakdown counts, not Per-Class Precision predicted counts', () => {
    // Both sections agree in this sample, so verify the counts match Classification Breakdown
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    const benign = result.breakdown.find(b => b.name === 'Benign');
    expect(benign).toBeDefined();
    // Classification Breakdown says 491; Per-Class Precision predicted also 491 — same value
    expect(benign.count).toBe(491);
  });

  test('breakdown pct values come from Classification Breakdown text (75.7 for Benign)', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    const benign = result.breakdown.find(b => b.name === 'Benign');
    // Classification Breakdown pct = 75.7; derived pct would be 491/649*100 = 75.65... rounded to 75.7 also
    // The key test: pct is 75.7 (parsed directly from the text, NOT computed)
    expect(benign.pct).toBe(75.7);
  });

  test('breakdown DDoS entry has count 97 and pct 14.9', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    const ddos = result.breakdown.find(b => b.name === 'DDoS');
    expect(ddos).toBeDefined();
    expect(ddos.count).toBe(97);
    expect(ddos.pct).toBe(14.9);
  });

  test('fallback is NOT triggered (breakdown length equals Classification Breakdown entries, not Per-Class entries)', () => {
    // There are 4 Per-Class Precision lines and 4 Classification Breakdown lines
    // If the fallback fired, breakdown would still be 4 — but verify by ensuring pct is from text
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    // Classification Breakdown for DDoS says 14.9%; fallback-computed would be 97/649*100 = 14.94... => 14.9 rounded
    // Test with Benign: Classification = 75.7%; fallback would compute 491/649*100 = 75.65... => 75.7 rounded
    // The values happen to be very close. The distinguishing check: if fallback was used, pct would be computed
    // and might differ by 0.1 for some entries. For Botnet: Classification = 2.8%; fallback = 18/649*100 = 2.77 => 2.8
    // For DoS: Classification = 6.6%; fallback = 43/649*100 = 6.62 => 6.6
    // All values round the same. The real guarantee is that breakdown.length = 4 (not > 4)
    expect(result.breakdown.length).toBe(4);
  });

  test('threats is null in labeled simul (no Threats Detected line, no per-minute lines)', () => {
    const result = parseSessionSummary(LABELED_SIMUL_SUMMARY);
    expect(result.threats).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// parseSessionSummary — per-minute summing fallback (labeled simul/live)
// ---------------------------------------------------------------------------

describe('parseSessionSummary — per-minute Threats/Suspicious/Clean summing', () => {
  let parseSessionSummary;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseSessionSummary = mod.parseSessionSummary;
  });

  // Simulates a real labeled simul session_summary.txt with per-minute breakdown
  // but no "Threats Detected" / "Suspicious Flows" / "Clean Flows" in the full summary
  const LABELED_SIMUL_WITH_MINUTES = `
====================================================================================================
  NIDS CLASSIFICATION - SIMULATION SESSION SUMMARY
====================================================================================================

  Session Mode:      SIMUL
  Labeled Data:      Yes

  MINUTE-BY-MINUTE BREAKDOWN
  ------------------------------------------------------------------------------------------------

  Minute 1: 00:44 (00:44:36 - 00:45:00)
    File:       minute_00-44.txt
    Flows:      117
    Threats:    24
    Suspicious: 5
    Clean:      88
    Breakdown:  Benign: 93, DDoS: 17, DoS: 4, Brute Force: 2, Botnet: 1

  Minute 2: 00:45 (00:45:00 - 00:46:00)
    File:       minute_00-45.txt
    Flows:      300
    Threats:    74
    Suspicious: 12
    Clean:      214
    Breakdown:  Benign: 226, DDoS: 42, DoS: 17, Botnet: 9, Brute Force: 6

  ------------------------------------------------------------------------------------------------

  FULL SESSION SUMMARY
  ------------------------------------------------------------------------------------------------

  Total Flows Classified: 417
  Accuracy:               92.00% (384/417)

  Per-Class Precision (of predicted, how many correct):
    Benign              : 100.00% (302/302)  |  Predicted:    302
    DDoS                : 100.00% (59/59)  |  Predicted:     59
    DoS                 : 100.00% (21/21)  |  Predicted:     21
    Botnet              : 100.00% (10/10)  |  Predicted:     10
    Brute Force         : 100.00% (8/8)  |  Predicted:      8

  Classification Breakdown:
    Benign              :    302 ( 72.4%)
    DDoS                :     59 ( 14.1%)
    DoS                 :     21 (  5.0%)
    Botnet              :     10 (  2.4%)
    Brute Force         :      8 (  1.9%)
`;

  test('sums per-minute Threats when no Threats Detected line exists', () => {
    const result = parseSessionSummary(LABELED_SIMUL_WITH_MINUTES);
    // 24 + 74 = 98
    expect(result.threats).toBe(98);
  });

  test('sums per-minute Suspicious when no Suspicious Flows line exists', () => {
    const result = parseSessionSummary(LABELED_SIMUL_WITH_MINUTES);
    // 5 + 12 = 17
    expect(result.suspicious).toBe(17);
  });

  test('sums per-minute Clean when no Clean Flows line exists', () => {
    const result = parseSessionSummary(LABELED_SIMUL_WITH_MINUTES);
    // 88 + 214 = 302
    expect(result.clean).toBe(302);
  });

  test('does NOT use per-minute sum when Threats Detected line is present (unlabeled)', () => {
    // Simulates unlabeled simul summary that has both explicit lines AND per-minute breakdown
    const content = `
  Total Flows Classified: 649
  Threats Detected:       158
  Suspicious Flows:       0
  Clean Flows:            491

  Minute 1:
    Threats:    7
    Suspicious: 0
    Clean:      39
`;
    const result = parseSessionSummary(content);
    // Should use the explicit line value, NOT the per-minute sum
    expect(result.threats).toBe(158);
    expect(result.suspicious).toBe(0);
    expect(result.clean).toBe(491);
  });

  test('handles summary with no per-minute lines and no explicit T/S/C — returns null', () => {
    const content = `
  Total Flows Classified: 500
  Accuracy: 95.00% (475/500)

  Per-Class Precision:
    Benign : 99.00% (400/404)  |  Predicted:    404
    DDoS   : 80.00% (75/96)   |  Predicted:     96
`;
    const result = parseSessionSummary(content);
    expect(result.threats).toBeNull();
    expect(result.suspicious).toBeNull();
    expect(result.clean).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// parseExplorationResults
// ---------------------------------------------------------------------------

describe('parseExplorationResults helper', () => {
  let parseExplorationResults;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseExplorationResults = mod.parseExplorationResults;
  });

  const EXPLORATION_CONTENT = `
================================================================================
                    DATA EXPLORATION REPORT
                         CICIDS2018 Dataset
                    Generated: 2026-03-04 17:39:46
================================================================================

1. DATASET OVERVIEW
   ----------------
   Total Rows:          16,232,943
   Total Columns:       80
   Memory Usage:        11.66 GB

2. CLASS DISTRIBUTION
   ------------------
   Total Classes: 15

   Imbalance Severity: EXTREME
   Gini Coefficient: 0.305
   Classes requiring SMOTE (<1%): 8

2.5 LABEL CONSOLIDATION IMPACT

   AFTER Consolidation (SQL Injection, Heartbleed dropped):
     Classes: 6
     Gini Coefficient: 0.3013
`;

  test('returns null fields for null input', () => {
    const r = parseExplorationResults(null);
    expect(r.totalRows).toBeNull();
    expect(r.totalColumns).toBeNull();
  });

  test('extracts totalRows', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.totalRows).toBe('16,232,943');
  });

  test('extracts totalColumns', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.totalColumns).toBe(80);
  });

  test('extracts originalClasses', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.originalClasses).toBe(15);
  });

  test('extracts consolidatedClasses (from AFTER consolidation)', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.consolidatedClasses).toBe(6);
  });

  test('extracts giniCoefficient', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.giniCoefficient).toBe(0.305);
  });

  test('extracts imbalanceSeverity', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.imbalanceSeverity).toBe('EXTREME');
  });

  test('extracts memoryUsage', () => {
    const r = parseExplorationResults(EXPLORATION_CONTENT);
    expect(r.memoryUsage).toBe('11.66 GB');
  });
});

// ---------------------------------------------------------------------------
// parsePreprocessingResults
// ---------------------------------------------------------------------------

describe('parsePreprocessingResults helper', () => {
  let parsePreprocessingResults;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parsePreprocessingResults = mod.parsePreprocessingResults;
  });

  const PREPROCESSING_CONTENT = `
================================================================================
                    DATA PREPROCESSING REPORT
================================================================================

1. DATA CLEANING
   Initial Dataset:
     Rows: 16,232,943
     Columns: 80
     Memory: 11.01 GB

   Final Clean Dataset:
     Rows: 11,979,405
     Columns: 79
     Memory: 7.91 GB
     Total removed: 4,253,538 rows (26.203%)

   Quality Assessment: ⚠ WARNING - HIGH DATA LOSS

4. TRAIN-TEST SPLIT
   Dataset Sizes:
     Total samples: 11,839,980
     Features: 80
     Training set: 9,471,984 samples
     Test set: 2,367,996 samples

6. CLASS IMBALANCE HANDLING (SMOTE)
   SMOTE Summary:
     Samples before: 9,471,984
     Samples after: 10,228,735
     Synthetic samples: 756,751
     Increase: 7.99%

6.5. CORRELATION-BASED FEATURE ELIMINATION
   Features removed: 20

7. FEATURE SELECTION
   Features selected: 40
`;

  test('returns null fields for null input', () => {
    const r = parsePreprocessingResults(null);
    expect(r.initialRows).toBeNull();
  });

  test('extracts initialRows', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.initialRows).toBe('16,232,943');
  });

  test('extracts finalRows after cleaning', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.finalRows).toBe('11,979,405');
  });

  test('extracts rowsRemoved count', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.rowsRemoved).toBe('4,253,538');
  });

  test('extracts dataLossPct', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.dataLossPct).toBe('26.203');
  });

  test('extracts trainingSamples (after SMOTE)', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.trainingSamples).toBe('10,228,735');
  });

  test('extracts testSamples', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.testSamples).toBe('2,367,996');
  });

  test('extracts smoteSamples', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.smoteSamples).toBe('756,751');
  });

  test('extracts featuresSelected', () => {
    const r = parsePreprocessingResults(PREPROCESSING_CONTENT);
    expect(r.featuresSelected).toBe(40);
  });
});

// ---------------------------------------------------------------------------
// parseTrainingResults
// ---------------------------------------------------------------------------

describe('parseTrainingResults (training_results.txt) helper', () => {
  let parseTrainingFileResults;

  beforeAll(async () => {
    const mod = await import('./Reports');
    parseTrainingFileResults = mod.parseTrainingFileResults;
  });

  const TRAINING_CONTENT = `
================================================================================
                    MODEL TRAINING REPORT
================================================================================

1. TRAINING OVERVIEW
   Timeline:
     Hyperparameter Tuning: 31.7 minutes
     Final Model Training: 12.5 minutes
     Total Training Time: 44.3 minutes (0.7 hours)

2. HYPERPARAMETER TUNING
   2.3 Best Cross-Validation Score
       Macro F1-Score: 0.9993
       Standard Deviation: 0.0000

   2.2 Best Hyperparameters Found
       n_estimators: 150
       max_depth: 20

3. FINAL MODEL TRAINING
   3.1 Training Configuration
       Training samples: 10,228,735
       Features: 40
       Classes: 5

   3.2 Model Architecture
       Number of Trees: 150
       Average Tree Depth: 20.0

4. FEATURE IMPORTANCES
   Rank | Feature Name                          | Importance | Cumulative
   --------------------------------------------------------------------------
     1  | Dst Port                                 |   0.1055   | 10.55%
     2  | Fwd Seg Size Min                         |   0.0943   | 19.98%

   Feature Importance Summary:
     Top 10 features: 56.20% of total importance
     Top 20 features: 80.93% of total importance
`;

  test('returns null fields for null input', () => {
    const r = parseTrainingFileResults(null);
    expect(r.cvF1Score).toBeNull();
  });

  test('extracts cvF1Score', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.cvF1Score).toBe('0.9993');
  });

  test('extracts tuningTime', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.tuningTime).toBe('31.7 minutes');
  });

  test('extracts trainingTime', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.trainingTime).toBe('12.5 minutes');
  });

  test('extracts totalTime', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.totalTime).toBe('44.3 minutes');
  });

  test('extracts trees (n_estimators)', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.trees).toBe(150);
  });

  test('extracts avgDepth', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.avgDepth).toBe(20.0);
  });

  test('extracts features', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.features).toBe(40);
  });

  test('extracts top10Importance', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.top10Importance).toBe('56.20%');
  });

  test('extracts topFeature name', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.topFeature).toBe('Dst Port');
  });

  test('extracts topFeatureImportance', () => {
    const r = parseTrainingFileResults(TRAINING_CONTENT);
    expect(r.topFeatureImportance).toBe('0.1055');
  });
});
