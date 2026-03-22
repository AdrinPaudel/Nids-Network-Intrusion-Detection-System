import React from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Sidebar.css';

function Sidebar({ currentPage, setCurrentPage }) {
  const navigate = useNavigate();

  const handleNavClick = (path, pageName) => {
    setCurrentPage(pageName);
    navigate(path);
  };

  const navItems = [
    {
      category: 'Core',
      items: [
        { icon: '📊', label: 'Dashboard', path: '/', id: 'dashboard' },
        { icon: '🚀', label: 'Training Pipeline', path: '/training', id: 'training' },
      ]
    },
    {
      category: 'Operations',
      items: [
        { icon: '🔍', label: 'Live Classification', path: '/live-classification', id: 'live-classification' },
        { icon: '📦', label: 'Batch Processing', path: '/batch-processing', id: 'batch-processing' },
        { icon: '🎮', label: 'Simulation', path: '/simulation', id: 'simulation' },
      ]
    },
    {
      category: 'Analysis',
      items: [
        { icon: '📈', label: 'Reports & Results', path: '/reports', id: 'reports' },
      ]
    },
  ];

  return (
    <aside className="sidebar">
      {navItems.map((section, idx) => (
        <div key={idx} className="nav-section">
          <div className="nav-label">{section.category}</div>
          {section.items.map((item, itemIdx) => (
            <div
              key={itemIdx}
              className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
              onClick={() => handleNavClick(item.path, item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </div>
          ))}
        </div>
      ))}
    </aside>
  );
}

export default Sidebar;
