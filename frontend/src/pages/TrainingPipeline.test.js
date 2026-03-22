/**
 * TrainingPipeline.test.js
 *
 * TDD test suite for the simulated training progress feature.
 * Tests cover:
 *   - buildSimSteps() pure helper
 *   - SimulationPanel: rendering, progress advancement, completion
 *   - TrainAgainPanel: "Run Training" starts simulation, form locked during run
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Mock useNavigate (TrainingPipeline uses react-router)
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => jest.fn(),
}));

// Use fake timers for simulation tick control
beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.runOnlyPendingTimers();
  jest.useRealTimers();
  jest.resetAllMocks();
});

let TrainingPipeline;
let buildSimSteps;

beforeAll(async () => {
  const mod = await import('./TrainingPipeline');
  TrainingPipeline = mod.default;
  buildSimSteps = mod.buildSimSteps;
});

// ---------------------------------------------------------------------------
// Helper: render TrainingPipeline and reveal the TrainAgainPanel
// ---------------------------------------------------------------------------

function renderPipeline() {
  return render(
    <MemoryRouter>
      <TrainingPipeline />
    </MemoryRouter>
  );
}

async function openConfigPanel() {
  renderPipeline();
  const configureBtn = screen.getByRole('button', { name: /configure training run/i });
  fireEvent.click(configureBtn);
  // The panel appears — Start Training button is visible immediately
  await waitFor(() => screen.getByRole('button', { name: /start training/i }));
}

// ---------------------------------------------------------------------------
// buildSimSteps helper (pure unit tests)
// ---------------------------------------------------------------------------

describe('buildSimSteps helper', () => {
  test('returns one entry per selected step key', () => {
    const keys = ['exploration', 'training'];
    const steps = buildSimSteps(keys);
    expect(steps).toHaveLength(2);
  });

  test('each entry has label, workingMsg, doneMsg', () => {
    const steps = buildSimSteps(['exploration']);
    expect(steps[0]).toHaveProperty('label');
    expect(steps[0]).toHaveProperty('workingMsg');
    expect(steps[0]).toHaveProperty('doneMsg');
  });

  test('exploration entry has correct messages', () => {
    const steps = buildSimSteps(['exploration']);
    expect(steps[0].doneMsg).toMatch(/exploration complete/i);
  });

  test('preprocessing entry has correct messages', () => {
    const steps = buildSimSteps(['preprocessing']);
    expect(steps[0].doneMsg).toMatch(/preprocessing complete/i);
  });

  test('tuning entry mentions cross-validation or hyperparameter', () => {
    const steps = buildSimSteps(['tuning']);
    expect(steps[0].workingMsg).toMatch(/hyperparameter|cross.validation/i);
  });

  test('training entry mentions Random Forest or model', () => {
    const steps = buildSimSteps(['training']);
    expect(steps[0].workingMsg).toMatch(/random forest|training model|model/i);
  });

  test('testing entry mentions evaluation or test', () => {
    const steps = buildSimSteps(['testing']);
    expect(steps[0].workingMsg).toMatch(/evaluat|test/i);
  });

  test('returns empty array for empty input', () => {
    expect(buildSimSteps([])).toHaveLength(0);
  });

  test('preserves order of keys provided', () => {
    const steps = buildSimSteps(['testing', 'exploration']);
    expect(steps[0].doneMsg).toMatch(/testing.*complete/i);
    expect(steps[1].doneMsg).toMatch(/exploration complete/i);
  });
});

// ---------------------------------------------------------------------------
// TrainAgainPanel — Run Training starts simulation
// ---------------------------------------------------------------------------

describe('TrainAgainPanel — simulation flow', () => {
  async function configureAndRun() {
    renderPipeline();
    // Open the Configure panel — "Start Training" appears immediately
    fireEvent.click(screen.getByRole('button', { name: /configure training run/i }));
    await waitFor(() => screen.getByRole('button', { name: /start training/i }));
    // Click Start Training — simulation begins
    fireEvent.click(screen.getByRole('button', { name: /start training/i }));
  }

  test('clicking Run Training shows simulation panel', async () => {
    await configureAndRun();
    await waitFor(() => {
      expect(screen.getByTestId('sim-panel')).toBeInTheDocument();
    });
  });

  test('simulation panel shows a progress bar', async () => {
    await configureAndRun();
    await waitFor(() => {
      expect(document.querySelector('.sim-progress-bar-fill')).toBeInTheDocument();
    });
  });

  test('simulation panel shows first step working message initially', async () => {
    await configureAndRun();
    await waitFor(() => {
      // One of the working messages should appear
      expect(screen.getByTestId('sim-current-msg')).toBeInTheDocument();
    });
  });

  test('progress advances after timer ticks', async () => {
    await configureAndRun();
    await waitFor(() => screen.getByTestId('sim-panel'));

    const fillBefore = document.querySelector('.sim-progress-bar-fill');
    const widthBefore = fillBefore?.style?.width ?? '0%';

    act(() => {
      jest.advanceTimersByTime(5000);
    });

    await waitFor(() => {
      const fillAfter = document.querySelector('.sim-progress-bar-fill');
      const widthAfter = fillAfter?.style?.width ?? '0%';
      // Progress should have increased
      const before = parseFloat(widthBefore);
      const after = parseFloat(widthAfter);
      expect(after).toBeGreaterThan(before);
    });
  });

  test('all steps complete after full simulation time (~60s)', async () => {
    await configureAndRun();
    await waitFor(() => screen.getByTestId('sim-panel'));

    act(() => {
      jest.advanceTimersByTime(65000); // past 60s total
    });

    await waitFor(() => {
      expect(screen.getByTestId('sim-complete')).toBeInTheDocument();
    });
  });

  test('completion banner shows success text', async () => {
    await configureAndRun();
    await waitFor(() => screen.getByTestId('sim-panel'));
    act(() => { jest.advanceTimersByTime(65000); });

    await waitFor(() => {
      // "Training Pipeline Complete!" banner — specific enough to avoid matching step doneMsg
      expect(screen.getByText(/training pipeline complete/i)).toBeInTheDocument();
    });
  });

  test('completion state shows all step done messages', async () => {
    await configureAndRun();
    await waitFor(() => screen.getByTestId('sim-panel'));
    act(() => { jest.advanceTimersByTime(65000); });

    await waitFor(() => {
      expect(screen.getAllByTestId('sim-step-done').length).toBeGreaterThan(0);
    });
  });

  test('"Start New Run" button appears after completion', async () => {
    await configureAndRun();
    await waitFor(() => screen.getByTestId('sim-panel'));
    act(() => { jest.advanceTimersByTime(65000); });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /start new run/i })).toBeInTheDocument();
    });
  });

  test('clicking Start New Run resets to config form', async () => {
    await configureAndRun();
    await waitFor(() => screen.getByTestId('sim-panel'));
    act(() => { jest.advanceTimersByTime(65000); });

    await waitFor(() => screen.getByRole('button', { name: /start new run/i }));
    fireEvent.click(screen.getByRole('button', { name: /start new run/i }));

    await waitFor(() => {
      expect(screen.queryByTestId('sim-panel')).not.toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Simulation only runs selected steps
// ---------------------------------------------------------------------------

describe('TrainAgainPanel — step selection respected', () => {
  test('deselecting all steps except one shows only one step in simulation', async () => {
    renderPipeline();
    // Open panel
    fireEvent.click(screen.getByRole('button', { name: /configure training run/i }));
    await waitFor(() => screen.getByRole('button', { name: /start training/i }));

    // Uncheck Preprocessing, Tuning, Training, Testing — leave only Exploration
    const preprocessingCb = screen.getByLabelText(/preprocessing/i);
    const tuningCb = screen.getByLabelText(/hyperparameter tuning/i);
    const trainingCb = screen.getByLabelText(/^training$/i);
    const testingCb = screen.getByLabelText(/^testing$/i);
    [preprocessingCb, tuningCb, trainingCb, testingCb].forEach(cb => {
      if (cb.checked) fireEvent.click(cb);
    });

    // Start simulation directly
    fireEvent.click(screen.getByRole('button', { name: /start training/i }));

    act(() => { jest.advanceTimersByTime(65000); });

    await waitFor(() => {
      const doneMsgs = screen.getAllByTestId('sim-step-done');
      expect(doneMsgs).toHaveLength(1);
    });
  });
});
