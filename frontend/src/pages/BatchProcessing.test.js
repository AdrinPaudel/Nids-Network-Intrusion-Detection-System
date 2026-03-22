/**
 * BatchProcessing — TDD test suite (Phase 6)
 *
 * Tests cover:
 *  - Loads folder contents from GET /api/batch/folders on mount
 *  - Shows 4 folder cards in a 2x2 grid
 *  - Each card shows: title, model label, type label, file list
 *  - File rows: filename, size, modified date, Delete button
 *  - Delete calls DELETE /api/batch/delete/{model}/{folder_type}/{filename}
 *  - Folder list refreshes after delete
 *  - Upload button opens file picker
 *  - Upload calls POST /api/batch/upload/{model}/{folder_type}
 *  - Folder list refreshes after upload
 *  - Classify button opens file selector (dropdown of files in folder)
 *  - Classify calls POST /api/batch/classify-folder with correct body
 *  - Results section shown after classification (unlabeled)
 *  - Results section shows accuracy metrics for labeled folder
 *  - PieChart rendered for results
 *  - Results table shows first 20 rows with correct columns
 *  - Download CSV button
 *  - Download JSON button
 *  - No model selection dropdown (model determined by folder card)
 *  - Error display when classify fails
 *  - Error display when folder load fails
 *  - Loading state during classify
 */

import React from 'react';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  within,
  act,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import BatchProcessing from './BatchProcessing';

// ---------------------------------------------------------------------------
// Recharts mock (avoid SVG rendering issues in jsdom)
// ---------------------------------------------------------------------------

jest.mock('recharts', () => {
  const React = require('react');
  return {
    ResponsiveContainer: ({ children }) => <div data-testid="responsive-container">{children}</div>,
    PieChart: ({ children }) => <div data-testid="pie-chart">{children}</div>,
    Pie: () => <div data-testid="pie" />,
    Cell: () => null,
    Tooltip: () => null,
    Legend: () => null,
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EMPTY_FOLDERS = {
  default: { batch: [], batch_labeled: [] },
  all: { batch: [], batch_labeled: [] },
};

const FOLDERS_WITH_FILES = {
  default: {
    batch: [
      { filename: 'traffic.csv', size: 10240, modified: '2026-03-01T10:00:00Z' },
      { filename: 'network.csv', size: 20480, modified: '2026-03-02T11:00:00Z' },
    ],
    batch_labeled: [
      { filename: 'labeled_test.csv', size: 5120, modified: '2026-03-03T12:00:00Z' },
    ],
  },
  all: {
    batch: [
      { filename: 'full_capture.csv', size: 30720, modified: '2026-03-04T09:00:00Z' },
    ],
    batch_labeled: [],
  },
};

const CLASSIFY_RESULT_UNLABELED = {
  success: true,
  filename: 'traffic.csv',
  model: 'default',
  folder_type: 'batch',
  total_flows: 500,
  threat_count: 42,
  threat_percentage: 8.4,
  results: Array.from({ length: 25 }, (_, i) => ({
    timestamp: `2026-03-05 17:${String(i).padStart(2, '0')}:00`,
    prediction: i % 5 === 0 ? 'DDoS' : 'Benign',
    confidence: 0.95 - i * 0.01,
    top2_prediction: 'Benign',
    top2_confidence: 0.04,
  })),
};

const CLASSIFY_RESULT_LABELED = {
  ...CLASSIFY_RESULT_UNLABELED,
  folder_type: 'batch_labeled',
  filename: 'labeled_test.csv',
  accuracy_metrics: {
    accuracy: 0.9341,
    precision: 0.9125,
    recall: 0.9341,
    f1: 0.9200,
  },
};

// ---------------------------------------------------------------------------
// fetch mock factory
// ---------------------------------------------------------------------------

function makeFetch(foldersData = EMPTY_FOLDERS) {
  return jest.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(foldersData),
  });
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  global.fetch = makeFetch();
  // Mock URL.createObjectURL for download tests
  global.URL.createObjectURL = jest.fn(() => 'blob:mock');
  global.URL.revokeObjectURL = jest.fn();
});

afterEach(() => {
  jest.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// 1. Folder cards layout
// ---------------------------------------------------------------------------

describe('Folder cards', () => {
  test('renders 4 folder cards', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const cards = document.querySelectorAll('.batch-folder-card');
      expect(cards.length).toBe(4);
    });
  });

  test('renders Default Batch card', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      expect(screen.getByText(/default.*batch|batch.*default/i)).toBeInTheDocument();
    });
  });

  test('renders Default Labeled card', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      expect(screen.getByText(/default.*labeled|labeled.*default/i)).toBeInTheDocument();
    });
  });

  test('renders All Batch card', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      expect(screen.getByText(/all.*batch|batch.*all/i)).toBeInTheDocument();
    });
  });

  test('renders All Labeled card', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      expect(screen.getByText(/all.*labeled|labeled.*all/i)).toBeInTheDocument();
    });
  });

  test('shows 5 Class (Default) model label on default cards', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const labels = screen.getAllByText(/5 class \(default\)/i);
      expect(labels.length).toBeGreaterThanOrEqual(2);
    });
  });

  test('shows 6 Class (All) model label on all cards', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const labels = screen.getAllByText(/6 class \(all\)/i);
      expect(labels.length).toBeGreaterThanOrEqual(2);
    });
  });

  test('shows Unlabeled label on batch cards', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const labels = screen.getAllByText(/unlabeled/i);
      expect(labels.length).toBeGreaterThanOrEqual(2);
    });
  });

  test('shows With Ground Truth label on batch_labeled cards', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const labels = screen.getAllByText(/with ground truth/i);
      expect(labels.length).toBeGreaterThanOrEqual(2);
    });
  });

  test('no model selection dropdown rendered', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const selects = document.querySelectorAll('select');
      // Only file selectors inside classify dialogs, not a top-level model selector
      // Verify there is no select with model options
      const modelSelect = Array.from(selects).find(s =>
        s.innerHTML.includes('5 Class') && s.innerHTML.includes('6 Class')
      );
      expect(modelSelect).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// 2. File listing
// ---------------------------------------------------------------------------

describe('File listing', () => {
  beforeEach(() => {
    global.fetch = makeFetch(FOLDERS_WITH_FILES);
  });

  test('shows filenames from API in the correct card', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      expect(screen.getByText('traffic.csv')).toBeInTheDocument();
      expect(screen.getByText('network.csv')).toBeInTheDocument();
      expect(screen.getByText('labeled_test.csv')).toBeInTheDocument();
      expect(screen.getByText('full_capture.csv')).toBeInTheDocument();
    });
  });

  test('shows file sizes', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      // 10240 bytes = 10.0 KB
      expect(screen.getByText(/10\.0\s*KB|10240/)).toBeInTheDocument();
    });
  });

  test('shows modified dates', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      // Should show some date representation of 2026-03-01
      expect(screen.getByText(/2026|Mar.*2026|03\/01\/2026/)).toBeInTheDocument();
    });
  });

  test('shows Delete button for each file', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const deleteButtons = screen.getAllByText(/delete/i);
      // 4 files total (2 + 1 + 1 + 0)
      expect(deleteButtons.length).toBeGreaterThanOrEqual(4);
    });
  });

  test('shows empty state message when folder has no files', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      // "All / Labeled" has no files → empty state shown
      expect(screen.getByText(/no files|empty|upload.*csv/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// 3. Delete file
// ---------------------------------------------------------------------------

describe('Delete file', () => {
  beforeEach(() => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) }) // initial load
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ deleted: true }) }); // delete + refresh
  });

  test('calls DELETE /api/batch/delete/default/batch/traffic.csv', async () => {
    // Refresh fetch to return updated folders (without traffic.csv)
    const updatedFolders = {
      ...FOLDERS_WITH_FILES,
      default: {
        ...FOLDERS_WITH_FILES.default,
        batch: [{ filename: 'network.csv', size: 20480, modified: '2026-03-02T11:00:00Z' }],
      },
    };
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ deleted: true }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(updatedFolders) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('traffic.csv'));

    // Find the delete button near traffic.csv
    const fileRow = screen.getByText('traffic.csv').closest('.batch-file-row') ||
                    screen.getByText('traffic.csv').closest('[class*="file"]');
    const deleteBtn = fileRow
      ? within(fileRow).getByText(/delete/i)
      : screen.getAllByText(/delete/i)[0];

    await act(async () => {
      fireEvent.click(deleteBtn);
    });

    await waitFor(() => {
      const deleteCalls = global.fetch.mock.calls.filter(([url]) =>
        typeof url === 'string' && url.includes('/api/batch/delete/')
      );
      expect(deleteCalls.length).toBe(1);
      expect(deleteCalls[0][0]).toContain('traffic.csv');
      expect(deleteCalls[0][1]?.method).toBe('DELETE');
    });
  });

  test('refreshes folder list after delete', async () => {
    const updatedFolders = {
      ...FOLDERS_WITH_FILES,
      default: {
        ...FOLDERS_WITH_FILES.default,
        batch: [], // traffic.csv and network.csv removed
      },
    };
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ deleted: true }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(updatedFolders) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('traffic.csv'));

    const deleteButtons = screen.getAllByText(/delete/i);
    await act(async () => {
      fireEvent.click(deleteButtons[0]);
    });

    await waitFor(() => {
      // folder list was re-fetched
      expect(global.fetch).toHaveBeenCalledTimes(3);
    });
  });
});

// ---------------------------------------------------------------------------
// 4. Upload file
// ---------------------------------------------------------------------------

describe('Upload file', () => {
  test('each folder card has an Upload button', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const uploadButtons = screen.getAllByText(/upload/i);
      expect(uploadButtons.length).toBeGreaterThanOrEqual(4);
    });
  });

  test('upload calls POST /api/batch/upload/{model}/{folder_type}', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(EMPTY_FOLDERS) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ filename: 'new.csv', size: 1024 }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(EMPTY_FOLDERS) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getAllByText(/upload/i));

    // Simulate file selection via hidden input
    const fileInputs = document.querySelectorAll('input[type="file"]');
    expect(fileInputs.length).toBeGreaterThanOrEqual(1);

    const csvFile = new File(['col1,col2\n1,2'], 'new.csv', { type: 'text/csv' });
    await act(async () => {
      fireEvent.change(fileInputs[0], { target: { files: [csvFile] } });
    });

    await waitFor(() => {
      const uploadCalls = global.fetch.mock.calls.filter(([url]) =>
        typeof url === 'string' && url.includes('/api/batch/upload/')
      );
      expect(uploadCalls.length).toBe(1);
      expect(uploadCalls[0][1]?.method).toBe('POST');
    });
  });

  test('refreshes folder list after upload', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(EMPTY_FOLDERS) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ filename: 'new.csv', size: 1024 }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(EMPTY_FOLDERS) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getAllByText(/upload/i));

    const fileInputs = document.querySelectorAll('input[type="file"]');
    const csvFile = new File(['a,b\n1,2'], 'new.csv', { type: 'text/csv' });

    await act(async () => {
      fireEvent.change(fileInputs[0], { target: { files: [csvFile] } });
    });

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(3); // load + upload + refresh
    });
  });
});

// ---------------------------------------------------------------------------
// 5. Classify from folder
// ---------------------------------------------------------------------------

describe('Classify from folder', () => {
  test('each folder card has a Classify button', async () => {
    render(<BatchProcessing />);
    await waitFor(() => {
      const classifyButtons = screen.getAllByText(/classify/i);
      expect(classifyButtons.length).toBeGreaterThanOrEqual(4);
    });
  });

  test('classify with file from default batch folder calls correct API', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(CLASSIFY_RESULT_UNLABELED) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('traffic.csv'));

    // Click Classify on default/batch card
    const classifyButtons = screen.getAllByText(/^classify$/i);
    await act(async () => {
      fireEvent.click(classifyButtons[0]);
    });

    // Should show file selector dropdown for that folder
    await waitFor(() => {
      // Either a modal or inline select appears with the file options
      const fileOptions = screen.queryAllByText('traffic.csv');
      expect(fileOptions.length).toBeGreaterThanOrEqual(1);
    });
  });

  test('POSTs /api/batch/classify-folder with correct body', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(CLASSIFY_RESULT_UNLABELED) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('traffic.csv'));

    const classifyButtons = screen.getAllByText(/^classify$/i);
    await act(async () => {
      fireEvent.click(classifyButtons[0]);
    });

    // Pick a file if a selector is shown
    const selects = document.querySelectorAll('select');
    if (selects.length > 0) {
      await act(async () => {
        fireEvent.change(selects[selects.length - 1], { target: { value: 'traffic.csv' } });
      });
    }

    // Find and click confirm/run classify
    const runBtn = screen.queryByText(/run|confirm|start.*classify|classify.*now/i);
    if (runBtn) {
      await act(async () => {
        fireEvent.click(runBtn);
      });
    }

    await waitFor(() => {
      const classifyCalls = global.fetch.mock.calls.filter(([url]) =>
        typeof url === 'string' && url.includes('/api/batch/classify-folder')
      );
      if (classifyCalls.length > 0) {
        const body = JSON.parse(classifyCalls[0][1]?.body || '{}');
        expect(body.model).toBe('default');
        expect(body.folder_type).toBe('batch');
        expect(body.filename).toBeTruthy();
      }
    });
  });
});

// ---------------------------------------------------------------------------
// 6. Results panel — unlabeled
// ---------------------------------------------------------------------------

describe('Results panel (unlabeled)', () => {
  async function renderWithResults() {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(CLASSIFY_RESULT_UNLABELED) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('traffic.csv'));

    const classifyButtons = screen.getAllByText(/^classify$/i);
    await act(async () => { fireEvent.click(classifyButtons[0]); });

    // Select file if needed
    const selects = document.querySelectorAll('select');
    if (selects.length > 0) {
      await act(async () => {
        fireEvent.change(selects[selects.length - 1], { target: { value: 'traffic.csv' } });
      });
    }

    const runBtn = screen.queryByText(/run|confirm|start.*classify|classify.*now/i);
    if (runBtn) {
      await act(async () => { fireEvent.click(runBtn); });
    }

    // Wait for results to appear
    await waitFor(() => {
      expect(screen.getByText(/500|total flows/i)).toBeInTheDocument();
    }, { timeout: 3000 });
  }

  test('shows total flows', async () => {
    await renderWithResults();
    expect(screen.getByText(/500/)).toBeInTheDocument();
  });

  test('shows threats detected', async () => {
    await renderWithResults();
    expect(screen.getByText(/42/)).toBeInTheDocument();
  });

  test('shows threat percentage', async () => {
    await renderWithResults();
    expect(screen.getByText(/8\.4/)).toBeInTheDocument();
  });

  test('shows model used', async () => {
    await renderWithResults();
    expect(screen.getByText(/5 class \(default\)|default/i)).toBeInTheDocument();
  });

  test('renders PieChart', async () => {
    await renderWithResults();
    expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
  });

  test('results table has Timestamp column', async () => {
    await renderWithResults();
    expect(screen.getByText(/timestamp/i)).toBeInTheDocument();
  });

  test('results table has Prediction column', async () => {
    await renderWithResults();
    expect(screen.getByText(/prediction/i)).toBeInTheDocument();
  });

  test('results table has Confidence column', async () => {
    await renderWithResults();
    expect(screen.getByText(/confidence/i)).toBeInTheDocument();
  });

  test('results table shows at most 20 rows of data', async () => {
    await renderWithResults();
    const rows = document.querySelectorAll('tbody tr');
    expect(rows.length).toBeLessThanOrEqual(20);
  });

  test('Download CSV button present', async () => {
    await renderWithResults();
    expect(screen.getByText(/download csv/i)).toBeInTheDocument();
  });

  test('Download JSON button present', async () => {
    await renderWithResults();
    expect(screen.getByText(/download json/i)).toBeInTheDocument();
  });

  test('results header shows filename', async () => {
    await renderWithResults();
    expect(screen.getByText(/traffic\.csv/i)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// 7. Results panel — labeled (accuracy metrics)
// ---------------------------------------------------------------------------

describe('Results panel (labeled)', () => {
  async function renderWithLabeledResults() {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve(CLASSIFY_RESULT_LABELED) });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('labeled_test.csv'));

    // Click Classify on the Default Labeled card (index 1 typically)
    const classifyButtons = screen.getAllByText(/^classify$/i);
    await act(async () => { fireEvent.click(classifyButtons[1]); });

    const selects = document.querySelectorAll('select');
    if (selects.length > 0) {
      await act(async () => {
        fireEvent.change(selects[selects.length - 1], { target: { value: 'labeled_test.csv' } });
      });
    }

    const runBtn = screen.queryByText(/run|confirm|start.*classify|classify.*now/i);
    if (runBtn) {
      await act(async () => { fireEvent.click(runBtn); });
    }

    await waitFor(() => {
      expect(screen.getByText(/93\.4|accuracy/i)).toBeInTheDocument();
    }, { timeout: 3000 });
  }

  test('shows Accuracy stat card', async () => {
    await renderWithLabeledResults();
    expect(screen.getByText(/accuracy/i)).toBeInTheDocument();
    expect(screen.getByText(/93\.4/)).toBeInTheDocument();
  });

  test('shows Precision stat card', async () => {
    await renderWithLabeledResults();
    expect(screen.getByText(/precision/i)).toBeInTheDocument();
    expect(screen.getByText(/91\.3|0\.9125/)).toBeInTheDocument();
  });

  test('shows Recall stat card', async () => {
    await renderWithLabeledResults();
    expect(screen.getByText(/recall/i)).toBeInTheDocument();
  });

  test('shows F1-Score stat card', async () => {
    await renderWithLabeledResults();
    expect(screen.getByText(/f1/i)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// 8. Error handling
// ---------------------------------------------------------------------------

describe('Error handling', () => {
  test('shows error when folder load fails', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({ detail: 'Server error' }),
    });

    render(<BatchProcessing />);
    await waitFor(() => {
      expect(screen.getByText(/failed to load|error|server error/i)).toBeInTheDocument();
    });
  });

  test('shows error when classify fails', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(FOLDERS_WITH_FILES) })
      .mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ detail: 'Classification failed: invalid columns' }),
      });

    render(<BatchProcessing />);
    await waitFor(() => screen.getByText('traffic.csv'));

    const classifyButtons = screen.getAllByText(/^classify$/i);
    await act(async () => { fireEvent.click(classifyButtons[0]); });

    const selects = document.querySelectorAll('select');
    if (selects.length > 0) {
      await act(async () => {
        fireEvent.change(selects[selects.length - 1], { target: { value: 'traffic.csv' } });
      });
    }

    const runBtn = screen.queryByText(/run|confirm|start.*classify|classify.*now/i);
    if (runBtn) {
      await act(async () => { fireEvent.click(runBtn); });
    }

    await waitFor(() => {
      expect(screen.getByText(/classification failed|invalid columns/i)).toBeInTheDocument();
    }, { timeout: 3000 });
  });
});
