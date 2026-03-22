import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import './styles/index.css';

// Components
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import LiveClassification from './pages/LiveClassification';
import BatchProcessing from './pages/BatchProcessing';
import Simulation from './pages/Simulation';
import Reports from './pages/Reports';
import TrainingPipeline from './pages/TrainingPipeline';

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [systemStatus, setSystemStatus] = useState('online');

  useEffect(() => {
    // Check health on app load
    fetch('/api/health')
      .then(res => res.json())
      .then(data => setSystemStatus(data.status))
      .catch(() => setSystemStatus('offline'));
  }, []);

  return (
    <Router>
      <div className="app-container">
        <Header currentPage={currentPage} systemStatus={systemStatus} />
        <div className="main-container">
          <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />
          <div className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/live-classification" element={<LiveClassification />} />
              <Route path="/batch-processing" element={<BatchProcessing />} />
              <Route path="/simulation" element={<Simulation />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/training" element={<TrainingPipeline />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}

export default App;
