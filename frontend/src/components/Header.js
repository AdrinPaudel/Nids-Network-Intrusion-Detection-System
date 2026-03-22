import React from 'react';
import '../styles/Header.css';

function Header({ currentPage, systemStatus }) {
  const pageNames = {
    'dashboard': 'Dashboard',
    'data-management': 'Data Management',
    'training': 'Training Pipeline',
    'live-classification': 'Live Classification',
    'batch-processing': 'Batch Processing',
    'simulation': 'Simulation',
    'reports': 'Reports & Results',
  };

  return (
    <header className="header">
      <div className="header-left">
        <div className="logo">⚔️ NIDS</div>
        <div className="breadcrumb">
          <span>{pageNames[currentPage] || 'Dashboard'}</span>
        </div>
      </div>
      <div className="header-right">
        <div className="status-indicator">
          <div className={`status-dot ${systemStatus === 'online' ? 'online' : 'offline'}`}></div>
          <span>System {systemStatus === 'online' ? 'Online' : 'Offline'}</span>
        </div>
        <div className="user-menu">
          <div className="avatar">AP</div>
        </div>
      </div>
    </header>
  );
}

export default Header;
