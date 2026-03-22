/**
 * LiveClassification — TDD test suite (Phase 5)
 *
 * Tests cover:
 *  - Configuration panel renders when not running
 *  - Interface list loads from /api/live/interfaces
 *  - Model radio buttons (default / all)
 *  - Duration input with blank/zero continuous-mode note
 *  - Start Capture triggers POST /api/live/start and opens WebSocket
 *  - Running panel: stat cards, threat counters, live feed
 *  - WebSocket event types: status, threat (RED/YELLOW), complete, error
 *  - Stop button calls POST /api/live/stop/{sessionId}
 *  - Completion state shown after "complete" event
 *  - Error event resets to config panel
 *  - WebSocket disconnect shows "Connection lost"
 *  - Feed capped at 50 entries
 *  - Feed shows only RED and YELLOW events
 *  - GREEN flows increment green counter, not feed
 *  - Duration 0 sends 86400 to backend
 */

import React from 'react';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  act,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LiveClassification from './LiveClassification';

// ---------------------------------------------------------------------------
// WebSocket mock
// ---------------------------------------------------------------------------

class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = WebSocket.OPEN;
    MockWebSocket.instances.push(this);
    // Simulate async connection
    setTimeout(() => {
      if (this.onopen) this.onopen();
    }, 0);
  }
  send(data) { this._sent = (this._sent || []).concat(data); }
  close() {
    this.readyState = WebSocket.CLOSED;
    if (this.onclose) this.onclose({ code: 1000 });
  }
  // Test helper — dispatch a message event
  _emit(data) {
    if (this.onmessage) this.onmessage({ data: JSON.stringify(data) });
  }
  _emitRaw(raw) {
    if (this.onmessage) this.onmessage({ data: raw });
  }
}
MockWebSocket.CONNECTING = 0;
MockWebSocket.OPEN       = 1;
MockWebSocket.CLOSING    = 2;
MockWebSocket.CLOSED     = 3;
MockWebSocket.instances  = [];

// ---------------------------------------------------------------------------
// fetch mock helpers
// ---------------------------------------------------------------------------

function mockFetchSuccess(data) {
  return jest.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(data),
  });
}

function mockFetchFail(status, detail) {
  return jest.fn().mockResolvedValue({
    ok: false,
    status,
    json: () => Promise.resolve({ detail }),
  });
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  MockWebSocket.instances = [];
  global.WebSocket = MockWebSocket;

  global.fetch = mockFetchSuccess({ interfaces: ['eth0', 'wlan0'] });
});

afterEach(() => {
  jest.restoreAllMocks();
  delete global.WebSocket;
});

// ---------------------------------------------------------------------------
// Helper — start a session
// ---------------------------------------------------------------------------

async function startSession(overrideFetch) {
  const startFetch = overrideFetch ?? mockFetchSuccess({ session_id: 'sess-123' });
  global.fetch = jest.fn()
    .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
    .mockResolvedValueOnce({ ok: true, json: () => startFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-123' }) }) });

  // Simpler: reset fetch after interfaces load
  global.fetch = jest.fn()
    .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
    .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-123' }) });

  render(<LiveClassification />);
  await waitFor(() => expect(screen.getByRole('combobox')).toBeInTheDocument());

  await act(async () => {
    fireEvent.click(screen.getByText('Start Capture'));
  });

  await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
  return MockWebSocket.instances[0];
}

// ---------------------------------------------------------------------------
// 1. Configuration panel
// ---------------------------------------------------------------------------

describe('Configuration panel', () => {
  test('renders interface dropdown', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByRole('combobox')).toBeInTheDocument();
    });
  });

  test('populates interface options from API', async () => {
    global.fetch = mockFetchSuccess({ interfaces: ['eth0', 'wlan0', 'lo'] });
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByText('eth0')).toBeInTheDocument();
      expect(screen.getByText('wlan0')).toBeInTheDocument();
      expect(screen.getByText('lo')).toBeInTheDocument();
    });
  });

  test('shows "Loading interfaces..." while fetching', () => {
    // Never resolves during this test
    global.fetch = jest.fn(() => new Promise(() => {}));
    render(<LiveClassification />);
    expect(screen.getByText(/loading interfaces/i)).toBeInTheDocument();
  });

  test('shows "No interfaces found" when API returns empty list', async () => {
    global.fetch = mockFetchSuccess({ interfaces: [] });
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByText(/no interfaces found/i)).toBeInTheDocument();
    });
  });

  test('renders model radio buttons for default and all', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByLabelText(/5 class \(default\)/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/6 class \(all\)/i)).toBeInTheDocument();
    });
  });

  test('default model is "default"', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      const radio = screen.getByLabelText(/5 class \(default\)/i);
      expect(radio).toBeChecked();
    });
  });

  test('can switch model to "all"', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      const radioAll = screen.getByLabelText(/6 class \(all\)/i);
      fireEvent.click(radioAll);
      expect(radioAll).toBeChecked();
    });
  });

  test('renders Duration (seconds) input with default 120', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      const input = screen.getByLabelText(/duration \(seconds\)/i);
      expect(input).toBeInTheDocument();
      expect(input.value).toBe('120');
    });
  });

  test('shows continuous capture note', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByText(/leave blank or set 0 for continuous/i)).toBeInTheDocument();
    });
  });

  test('renders Start Capture button', async () => {
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByText('Start Capture')).toBeInTheDocument();
    });
  });

  test('Start Capture is disabled when no interface available', async () => {
    global.fetch = mockFetchSuccess({ interfaces: [] });
    render(<LiveClassification />);
    await waitFor(() => {
      expect(screen.getByText('Start Capture')).toBeDisabled();
    });
  });
});

// ---------------------------------------------------------------------------
// 2. Starting a session
// ---------------------------------------------------------------------------

describe('Starting a session', () => {
  test('POSTs to /api/live/start with correct body', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-abc' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2));
    const [url, opts] = global.fetch.mock.calls[1];
    expect(url).toBe('/api/live/start');
    expect(opts.method).toBe('POST');
    const body = JSON.parse(opts.body);
    expect(body.interface).toBe('eth0');
    expect(body.model_variant).toBe('default');
    expect(body.duration_seconds).toBe(120);
  });

  test('duration 0 sends 86400 (continuous workaround)', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-abc' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByLabelText(/duration \(seconds\)/i));

    fireEvent.change(screen.getByLabelText(/duration \(seconds\)/i), { target: { value: '0' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2));
    const body = JSON.parse(global.fetch.mock.calls[1][1].body);
    expect(body.duration_seconds).toBe(86400);
  });

  test('empty duration sends 86400', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-abc' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByLabelText(/duration \(seconds\)/i));

    fireEvent.change(screen.getByLabelText(/duration \(seconds\)/i), { target: { value: '' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2));
    const body = JSON.parse(global.fetch.mock.calls[1][1].body);
    expect(body.duration_seconds).toBe(86400);
  });

  test('opens WebSocket to correct URL after session start', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-xyz' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
    expect(MockWebSocket.instances[0].url).toMatch(/\/ws\/live\/sess-xyz/);
  });

  test('shows error message when /api/live/start fails', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: false, status: 500, json: () => Promise.resolve({ detail: 'Process failed to start' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => {
      expect(screen.getByText(/process failed to start/i)).toBeInTheDocument();
    });
  });

  test('shows Stop Capture button while running', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-123' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => {
      expect(screen.getByText('Stop Capture')).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// 3. WebSocket event handling
// ---------------------------------------------------------------------------

describe('WebSocket event handling', () => {
  async function renderAndStart() {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-123' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
    return MockWebSocket.instances[0];
  }

  test('status event updates stat cards', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({ type: 'status', elapsed: 30, packets: 1250, flows: 142, classified: 140, remaining: 90 });
    });

    await waitFor(() => {
      expect(screen.getByText('1250')).toBeInTheDocument(); // packets
      expect(screen.getByText('142')).toBeInTheDocument();  // flows
      expect(screen.getByText('140')).toBeInTheDocument();  // classified
      expect(screen.getByText('90')).toBeInTheDocument();   // remaining
    });
  });

  test('RED threat event increments red counter', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({
        type: 'threat', level: 'RED',
        timestamp: '2026-03-05 17:23:45',
        src_ip: '192.168.1.100', src_port: 54321,
        dst_ip: '10.0.0.50', dst_port: 80,
        prediction: 'DDoS', confidence: 0.995,
      });
    });

    await waitFor(() => {
      expect(screen.getByText(/RED.*1|1.*threat/i)).toBeInTheDocument();
    });
  });

  test('YELLOW threat event increments yellow counter', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({
        type: 'threat', level: 'YELLOW',
        timestamp: '2026-03-05 17:23:45',
        src_ip: '10.0.0.1', src_port: 1234,
        dst_ip: '8.8.8.8', dst_port: 443,
        prediction: 'BruteForce', confidence: 0.72,
      });
    });

    await waitFor(() => {
      expect(screen.getByText(/YELLOW.*1|1.*suspicious/i)).toBeInTheDocument();
    });
  });

  test('RED and YELLOW events appear in live feed', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({
        type: 'threat', level: 'RED',
        timestamp: '2026-03-05 17:00:00',
        src_ip: '1.2.3.4', src_port: 9999,
        dst_ip: '5.6.7.8', dst_port: 80,
        prediction: 'DDoS', confidence: 0.99,
      });
      ws._emit({
        type: 'threat', level: 'YELLOW',
        timestamp: '2026-03-05 17:00:01',
        src_ip: '9.8.7.6', src_port: 443,
        dst_ip: '1.1.1.1', dst_port: 53,
        prediction: 'BruteForce', confidence: 0.65,
      });
    });

    await waitFor(() => {
      expect(screen.getByText('DDoS')).toBeInTheDocument();
      expect(screen.getByText('BruteForce')).toBeInTheDocument();
    });
  });

  test('complete event shows completion panel with summary', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({
        type: 'complete',
        flows: 648, red: 158, yellow: 0, green: 490,
        report_folder: 'reports/simul_default_20260305',
      });
    });

    await waitFor(() => {
      expect(screen.getByText(/start new capture/i)).toBeInTheDocument();
    });
  });

  test('complete event shows report folder', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({
        type: 'complete',
        flows: 100, red: 5, yellow: 2, green: 93,
        report_folder: 'reports/simul_default_20260305',
      });
    });

    await waitFor(() => {
      expect(screen.getByText(/simul_default_20260305/)).toBeInTheDocument();
    });
  });

  test('error event shows error message and resets to config panel', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      ws._emit({ type: 'error', message: 'Interface not found' });
    });

    await waitFor(() => {
      expect(screen.getByText(/interface not found/i)).toBeInTheDocument();
      expect(screen.getByText('Start Capture')).toBeInTheDocument();
    });
  });

  test('invalid JSON on WebSocket is silently ignored', async () => {
    const ws = await renderAndStart();

    expect(() => {
      act(() => { ws._emitRaw('not-json{{{'); });
    }).not.toThrow();
  });

  test('feed capped at 50 entries', async () => {
    const ws = await renderAndStart();

    await act(async () => {
      for (let i = 0; i < 60; i++) {
        ws._emit({
          type: 'threat', level: 'RED',
          timestamp: `2026-03-05 17:00:${String(i).padStart(2, '0')}`,
          src_ip: `10.0.0.${i}`, src_port: 1000 + i,
          dst_ip: '8.8.8.8', dst_port: 80,
          prediction: 'DDoS', confidence: 0.99,
        });
      }
    });

    await waitFor(() => {
      // Feed container should not exceed 50 rows
      const feedRows = document.querySelectorAll('.live-feed-row');
      expect(feedRows.length).toBeLessThanOrEqual(50);
    });
  });

  test('GREEN flows do not appear in feed', async () => {
    const ws = await renderAndStart();
    const threatBefore = document.querySelectorAll('.live-feed-row').length;

    await act(async () => {
      // GREEN is inferred from status update, not a direct event type
      // No "threat" event with GREEN level should exist
      ws._emit({ type: 'status', elapsed: 10, packets: 500, flows: 50, classified: 49, remaining: 110 });
    });

    await waitFor(() => {
      const feedRows = document.querySelectorAll('.live-feed-row');
      expect(feedRows.length).toBe(threatBefore);
    });
  });
});

// ---------------------------------------------------------------------------
// 4. Stop button
// ---------------------------------------------------------------------------

describe('Stop button', () => {
  test('calls POST /api/live/stop/{sessionId}', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ session_id: 'sess-stop-test' }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ stopped: true }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => screen.getByText('Stop Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Stop Capture'));
    });

    await waitFor(() => {
      const stopCall = global.fetch.mock.calls.find(([url]) => url.includes('/api/live/stop/sess-stop-test'));
      expect(stopCall).toBeDefined();
      expect(stopCall[1].method).toBe('POST');
    });
  });

  test('closes WebSocket when stop is clicked', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-ws-close' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
    const ws = MockWebSocket.instances[0];

    await act(async () => {
      // suppress the stop fetch
      global.fetch = jest.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) });
      fireEvent.click(screen.getByText('Stop Capture'));
    });

    await waitFor(() => {
      expect(ws.readyState).toBe(WebSocket.CLOSED);
    });
  });
});

// ---------------------------------------------------------------------------
// 5. WebSocket disconnect
// ---------------------------------------------------------------------------

describe('WebSocket disconnect', () => {
  test('shows "Connection lost" message on unexpected close', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-disc' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => {
      fireEvent.click(screen.getByText('Start Capture'));
    });

    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
    const ws = MockWebSocket.instances[0];

    await act(async () => {
      // Simulate unexpected disconnect (not initiated by stop)
      if (ws.onclose) ws.onclose({ code: 1006, wasClean: false });
    });

    await waitFor(() => {
      expect(screen.getByText(/connection lost/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// 6. Completion — "Start New Capture" resets to config
// ---------------------------------------------------------------------------

describe('Completion state', () => {
  test('"Start New Capture" resets to config panel', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) })
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ session_id: 'sess-done' }) });

    render(<LiveClassification />);
    await waitFor(() => screen.getByText('Start Capture'));

    await act(async () => { fireEvent.click(screen.getByText('Start Capture')); });
    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
    const ws = MockWebSocket.instances[0];

    await act(async () => {
      ws._emit({ type: 'complete', flows: 200, red: 10, yellow: 5, green: 185, report_folder: 'reports/test' });
    });

    await waitFor(() => screen.getByText(/start new capture/i));

    // Reload interfaces mock for next render
    global.fetch = jest.fn()
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ interfaces: ['eth0'] }) });

    await act(async () => {
      fireEvent.click(screen.getByText(/start new capture/i));
    });

    await waitFor(() => {
      expect(screen.getByText('Start Capture')).toBeInTheDocument();
    });
  });
});
