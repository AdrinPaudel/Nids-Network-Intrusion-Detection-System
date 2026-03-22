import { useState, useEffect, useRef, useCallback } from 'react';
import { Card, Button, Grid, Section } from '../components/Common';
import '../styles/Pages.css';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FEED_EVENTS        = 50;
const POLL_INTERVAL_MS       = 500;
const DEFAULT_DURATION_SECS  = 120;
const CONTINUOUS_DURATION    = 86400;   // proxy for "unlimited" (backend cap is 86400)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts.replace(' ', 'T'));
    return d.toLocaleTimeString(undefined, { hour12: false });
  } catch {
    return ts;
  }
}

function threatRowBorderColor(level) {
  if (level === 'RED')    return '#ef4444';
  if (level === 'YELLOW') return '#f97316';
  return 'transparent';
}

function classifyLiveError(msg) {
  const lower = (msg || '').toLowerCase();
  if (
    lower.includes('permission') ||
    lower.includes('access denied') ||
    lower.includes('winerror 5') ||
    lower.includes('elevation') ||
    lower.includes('not permitted')
  ) {
    return 'Administrator privileges required. Run the backend as Administrator to capture network packets.';
  }
  if (lower.includes('interface') && lower.includes('not found')) {
    return 'Network interface not found. Please select a different interface.';
  }
  if (lower.includes('cicflowmeter') || lower.includes('scapy') || lower.includes('npcap')) {
    return 'cicflowmeter / Scapy / Npcap is not installed. Live capture is unavailable on this system.';
  }
  return msg;
}

function parseDuration(raw) {
  const n = parseInt(raw, 10);
  if (!raw || raw.trim() === '' || isNaN(n) || n <= 0) return CONTINUOUS_DURATION;
  return n;
}

// ---------------------------------------------------------------------------
// StatBox
// ---------------------------------------------------------------------------

function StatBox({ label, value, valueColor }) {
  return (
    <div className="live-stat-box">
      <div className="live-stat-label">{label}</div>
      <div className="live-stat-value" style={valueColor ? { color: valueColor } : {}}>
        {value}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Phase states
// ---------------------------------------------------------------------------

const PHASE = { CONFIG: 'config', RUNNING: 'running', COMPLETE: 'complete' };

// ---------------------------------------------------------------------------
// LiveClassification
// ---------------------------------------------------------------------------

function LiveClassification() {
  // Config
  const [interfaces, setInterfaces]       = useState([]);
  const [iface, setIface]                 = useState('');
  const [modelVariant, setModelVariant]   = useState('default');
  const [durationInput, setDurationInput] = useState(String(DEFAULT_DURATION_SECS));
  const [ifaceLoading, setIfaceLoading]   = useState(true);

  // Phase / session
  const [phase, setPhase]       = useState(PHASE.CONFIG);
  const [sessionId, setSessionId] = useState(null);
  const [startError, setStartError]     = useState(null);
  const [disconnected, setDisconnected] = useState(false);

  // Stats
  const [packets, setPackets]       = useState(0);
  const [flows, setFlows]           = useState(0);
  const [classified, setClassified] = useState(0);
  const [remaining, setRemaining]   = useState(0);
  const [redCount, setRedCount]     = useState(0);
  const [yellowCount, setYellowCount] = useState(0);
  const [feed, setFeed]             = useState([]);
  const [completeSummary, setCompleteSummary] = useState(null);

  // Poll state
  const pollRef         = useRef(null);
  const nextFromRef     = useRef(0);
  const timerRef        = useRef(null);   // 1-second remaining countdown
  const sessionStartRef = useRef(null);   // ms timestamp when session started
  const durationRef     = useRef(DEFAULT_DURATION_SECS);

  // Refs mirroring running state for complete-screen summary
  const classifiedRef  = useRef(0);
  const redCountRef    = useRef(0);
  const yellowCountRef = useRef(0);

  useEffect(() => { classifiedRef.current  = classified;  }, [classified]);
  useEffect(() => { redCountRef.current    = redCount;    }, [redCount]);
  useEffect(() => { yellowCountRef.current = yellowCount; }, [yellowCount]);

  // ---------------------------------------------------------------------------
  // Load interfaces
  // ---------------------------------------------------------------------------

  useEffect(() => {
    fetch('/api/live/interfaces')
      .then(res => res.json())
      .then(data => {
        const list = data.interfaces ?? [];
        setInterfaces(list);
        if (list.length > 0) setIface(list[0]);
      })
      .catch(err => console.error('Failed to load interfaces:', err))
      .finally(() => setIfaceLoading(false));
  }, []);

  // ---------------------------------------------------------------------------
  // Stop polling
  // ---------------------------------------------------------------------------

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const stopTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  useEffect(() => () => { stopPolling(); stopTimer(); }, [stopPolling, stopTimer]);

  // ---------------------------------------------------------------------------
  // Process event
  // ---------------------------------------------------------------------------

  const processEvent = useCallback((evt) => {
    switch (evt.type) {
      case 'status':
        setPackets(evt.packets    ?? 0);
        setFlows(evt.flows        ?? 0);
        setClassified(evt.classified ?? 0);
        setRemaining(evt.remaining  ?? 0);
        break;

      case 'threat':
        if (evt.level === 'RED')    setRedCount(prev => prev + 1);
        if (evt.level === 'YELLOW') setYellowCount(prev => prev + 1);
        if (evt.level === 'RED' || evt.level === 'YELLOW') {
          setFeed(prev => {
            const next = [evt, ...prev];
            return next.length > MAX_FEED_EVENTS ? next.slice(0, MAX_FEED_EVENTS) : next;
          });
        }
        break;

      case 'complete': {
        if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
        // Prefer backend summary; fall back to accumulated React state via refs
        const cl = classifiedRef.current;
        const rc = redCountRef.current;
        const yc = yellowCountRef.current;
        setCompleteSummary({
          flows:         evt.flows         ?? cl,
          red:           evt.red           ?? rc,
          yellow:        evt.yellow        ?? yc,
          green:         evt.green         ?? Math.max(0, cl - rc - yc),
          report_folder: evt.report_folder ?? '',
        });
        setPhase(PHASE.COMPLETE);
        stopPolling();
        break;
      }

      case 'error':
        if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
        setStartError(classifyLiveError(evt.message ?? 'Unknown error from server'));
        setPhase(PHASE.CONFIG);
        stopPolling();
        break;

      default:
        break;
    }
  }, [stopPolling]);

  // ---------------------------------------------------------------------------
  // Start session
  // ---------------------------------------------------------------------------

  const handleStart = async () => {
    setStartError(null);
    setDisconnected(false);
    setPackets(0); setFlows(0); setClassified(0); setRemaining(0);
    setRedCount(0); setYellowCount(0);
    setFeed([]);
    setCompleteSummary(null);
    nextFromRef.current = 0;

    const durationSeconds = parseDuration(durationInput);

    try {
      const res = await fetch('/api/live/start', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ interface: iface, model_variant: modelVariant, duration_seconds: durationSeconds }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `Server returned ${res.status}`);
      }

      const data = await res.json();
      const sid  = data.session_id;
      setSessionId(sid);
      setPhase(PHASE.RUNNING);

      // Start client-side remaining countdown (smooth 1-second ticks)
      sessionStartRef.current = Date.now();
      durationRef.current     = durationSeconds;
      if (durationSeconds < CONTINUOUS_DURATION) {
        timerRef.current = setInterval(() => {
          const elapsedSec = Math.floor((Date.now() - sessionStartRef.current) / 1000);
          setRemaining(Math.max(0, durationRef.current - elapsedSec));
        }, 1000);
      }

      // Start polling /api/live/events/{sid}?from=N
      pollRef.current = setInterval(async () => {
        try {
          const r = await fetch(`/api/live/events/${sid}?from=${nextFromRef.current}`);
          if (!r.ok) return;

          const payload = await r.json();
          const { events, next_from, done } = payload;
          nextFromRef.current = next_from;

          for (const evt of events) {
            processEvent(evt);
          }

          if (done && !events.some(e => e.type === 'complete' || e.type === 'error')) {
            if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
            const cl = classifiedRef.current;
            const rc = redCountRef.current;
            const yc = yellowCountRef.current;
            setCompleteSummary({
              flows:  cl,
              red:    rc,
              yellow: yc,
              green:  Math.max(0, cl - rc - yc),
              report_folder: '',
            });
            setPhase(PHASE.COMPLETE);
            stopPolling();
          }
        } catch (pollErr) {
          console.error('Poll error:', pollErr);
        }
      }, POLL_INTERVAL_MS);

    } catch (err) {
      setStartError(classifyLiveError(err.message));
      setPhase(PHASE.CONFIG);
    }
  };

  // ---------------------------------------------------------------------------
  // Stop session
  // ---------------------------------------------------------------------------

  const handleStop = async () => {
    // Signal the backend to gracefully flush in-flight flows before killing the subprocess.
    // Keep polling for up to DRAIN_POLL_MS so flushed events reach the UI.
    const DRAIN_POLL_MS = 8000;
    if (sessionId) {
      fetch(`/api/live/stop/${sessionId}`, { method: 'POST' }).catch(() => {});
    }
    // Continue polling during drain window — stop only when backend reports done or timeout
    await new Promise((resolve) => setTimeout(resolve, DRAIN_POLL_MS));
    stopPolling();
    stopTimer();
    setPhase(PHASE.CONFIG);
    setDisconnected(false);
  };

  // ---------------------------------------------------------------------------
  // Reset
  // ---------------------------------------------------------------------------

  const handleReset = () => {
    stopPolling();
    stopTimer();
    setPhase(PHASE.CONFIG);
    setSessionId(null);
    setStartError(null);
    setDisconnected(false);
    setPackets(0); setFlows(0); setClassified(0); setRemaining(0);
    setRedCount(0); setYellowCount(0);
    setFeed([]);
    setCompleteSummary(null);
    nextFromRef.current = 0;
  };

  const greenCount = Math.max(0, classified - redCount - yellowCount);
  const canStart   = !ifaceLoading && iface.length > 0;

  // ---------------------------------------------------------------------------
  // CONFIG PANEL
  // ---------------------------------------------------------------------------

  const configPanel = (
    <div className="live-config-panel">
      <Card title="Configure Capture" subtitle="Set up and start a live network capture session">
        <Grid cols={2}>
          <div className="form-group">
            <label htmlFor="live-iface-select">Network Interface</label>
            <select
              id="live-iface-select"
              value={iface}
              onChange={e => setIface(e.target.value)}
              disabled={ifaceLoading}
            >
              {ifaceLoading && <option>Loading interfaces...</option>}
              {!ifaceLoading && interfaces.length === 0 && <option value="">No interfaces found</option>}
              {!ifaceLoading && interfaces.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>

          <div className="form-group">
            <label>Model Variant</label>
            <div className="checkbox-group" style={{ flexDirection: 'row', gap: '1.5rem' }}>
              <div className="checkbox-item">
                <input type="radio" id="variant-default" name="modelVariant" value="default"
                  checked={modelVariant === 'default'} onChange={() => setModelVariant('default')} />
                <label htmlFor="variant-default">5 Class (Default)</label>
              </div>
              <div className="checkbox-item">
                <input type="radio" id="variant-all" name="modelVariant" value="all"
                  checked={modelVariant === 'all'} onChange={() => setModelVariant('all')} />
                <label htmlFor="variant-all">6 Class (All)</label>
              </div>
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="live-duration-input">Duration (seconds)</label>
            <input
              id="live-duration-input"
              type="number"
              value={durationInput}
              onChange={e => setDurationInput(e.target.value)}
              min="10"
              placeholder="e.g. 120"
            />
            <div className="live-duration-note">Leave blank or 0 for continuous capture.</div>
          </div>
        </Grid>

        {disconnected && (
          <div className="live-error-msg" style={{ marginBottom: '0.75rem' }}>
            The session was interrupted or completed unexpectedly.
          </div>
        )}
        {startError && <div className="live-error-msg">{startError}</div>}

        <div style={{ marginTop: '1.5rem' }}>
          <Button variant="primary" onClick={handleStart} disabled={!canStart}>
            Start Capture
          </Button>
        </div>
      </Card>
    </div>
  );

  // ---------------------------------------------------------------------------
  // RUNNING PANEL
  // ---------------------------------------------------------------------------

  const runningPanel = (
    <div className="live-running-panel">
      <div style={{ marginBottom: '1.5rem' }}>
        <Button variant="danger" onClick={handleStop}>Stop Capture</Button>
      </div>

      <Card title="Real-time Statistics" subtitle="Live metrics from the capture">
        <Grid cols={4}>
          <StatBox label="Packets Captured"   value={packets.toLocaleString()} />
          <StatBox label="Flows Captured"     value={flows.toLocaleString()} />
          <StatBox label="Flows Classified"   value={classified.toLocaleString()} />
          <StatBox label="Time Remaining (s)" value={remaining.toLocaleString()} valueColor="#f97316" />
        </Grid>
        {packets > 1000 && flows === 0 && (
          <div style={{
            marginTop: '0.75rem', fontSize: '0.82rem',
            color: 'var(--text-secondary)',
            padding: '0.5rem 0.75rem',
            background: 'rgba(148,163,184,0.07)',
            borderRadius: '6px',
            borderLeft: '3px solid var(--border)',
          }}>
            High packet count but 0 flows: this is normal for UDP-heavy traffic. Flows are only
            counted once a connection completes (TCP FIN/RST) or a UDP/ICMP session times out.
          </div>
        )}
      </Card>

      <Card title="Threat Level Breakdown" subtitle="Counts by severity">
        <Grid cols={3}>
          <div className="live-level-box live-level-red">
            <div className="live-level-label">RED — Confirmed Threats</div>
            <div className="live-level-count">{redCount}</div>
          </div>
          <div className="live-level-box live-level-yellow">
            <div className="live-level-label">YELLOW — Suspicious</div>
            <div className="live-level-count">{yellowCount}</div>
          </div>
          <div className="live-level-box live-level-green">
            <div className="live-level-label">GREEN — Clean</div>
            <div className="live-level-count">{greenCount}</div>
          </div>
        </Grid>
      </Card>

      <Card title="Live Threat Feed" subtitle={`Last ${MAX_FEED_EVENTS} RED / YELLOW events`}>
        {feed.length === 0 ? (
          <div className="live-feed-empty" style={{ color: '#22c55e' }}>
            No threats detected — traffic appears clean.
          </div>
        ) : (
          <div className="live-feed-scroll">
            {feed.map((evt, idx) => (
              <div key={idx} className="live-feed-row" style={{ borderLeftColor: threatRowBorderColor(evt.level) }}>
                <span className="live-feed-time">{formatTimestamp(evt.timestamp)}</span>
                <span className="live-feed-route">
                  {evt.dst_port
                    ? `\u2192 ${evt.dst_ip ?? '?'}:${evt.dst_port} (Proto:${evt.protocol ?? '?'})`
                    : (evt.src_ip ? `${evt.src_ip}:${evt.src_port} \u2192 ${evt.dst_ip}:${evt.dst_port}` : '\u2014')}
                </span>
                <span className="live-feed-label">{evt.prediction ?? '\u2014'}</span>
                <span className="live-feed-conf">
                  {evt.confidence != null ? `${(evt.confidence * 100).toFixed(1)}%` : '\u2014'}
                </span>
                <span className={`threat-badge ${evt.level === 'RED' ? 'threat-red' : 'threat-yellow'}`}>
                  {evt.level}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );

  // ---------------------------------------------------------------------------
  // COMPLETE PANEL
  // ---------------------------------------------------------------------------

  const completePanel = completeSummary && (
    <div className="live-complete-panel">
      <Card title="Session Complete" subtitle="Capture and classification finished">
        <Grid cols={4}>
          <StatBox label="Total Flows"         value={completeSummary.flows.toLocaleString()} />
          <StatBox label="Threats (RED)"       value={completeSummary.red.toLocaleString()}    valueColor="#ef4444" />
          <StatBox label="Suspicious (YELLOW)" value={completeSummary.yellow.toLocaleString()} valueColor="#f97316" />
          <StatBox label="Clean (GREEN)"       value={completeSummary.green.toLocaleString()}  valueColor="#22c55e" />
        </Grid>

        {completeSummary.report_folder && (
          <div style={{ marginTop: '1rem', fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
            Report folder:{' '}
            <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
              {completeSummary.report_folder}
            </span>
          </div>
        )}

        <div style={{ marginTop: '1.5rem' }}>
          <Button variant="primary" onClick={handleReset}>Start New Capture</Button>
        </div>
      </Card>
    </div>
  );

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <Section title="Live Classification">
      {phase === PHASE.CONFIG   && configPanel}
      {phase === PHASE.RUNNING  && runningPanel}
      {phase === PHASE.COMPLETE && completePanel}
    </Section>
  );
}

export default LiveClassification;
