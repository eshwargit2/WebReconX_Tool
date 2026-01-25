import React, { useState } from 'react';
import { X, Shield, Bug, Database, CheckCircle, Globe, FolderOpen, ShieldCheck } from 'lucide-react';

const ScanOptionsModal = ({ isOpen, onClose, onConfirm, url }) => {
  const [selectedTests, setSelectedTests] = useState({
    xss: false,
    sqli: false,
    ports: true,
    waf: true,
    tech: true,
    whois: true,
    directory: false,
    security_headers: false,
    ai_analysis: true  // Enable AI analysis by default
  });

  if (!isOpen) return null;

  const toggleTest = (test) => {
    setSelectedTests(prev => ({
      ...prev,
      [test]: !prev[test]
    }));
  };

  const handleConfirm = () => {
    onConfirm(selectedTests);
  };

  const tests = [
    {
      id: 'whois',
      name: 'Domain Lookup',
      description: 'Get domain registration information',
      icon: Globe,
      color: 'cyan',
      recommended: true
    },
    {
      id: 'ports',
      name: 'Port Scanning',
      description: 'Scan for open ports and services',
      icon: Shield,
      color: 'blue',
      recommended: true
    },
    {
      id: 'waf',
      name: 'WAF Detection',
      description: 'Check for Web Application Firewall',
      icon: Shield,
      color: 'purple',
      recommended: true
    },
    {
      id: 'tech',
      name: 'Technology Detection',
      description: 'Identify web technologies and frameworks',
      icon: Shield,
      color: 'green',
      recommended: true
    },
    {
      id: 'xss',
      name: 'XSS Vulnerability Test',
      description: 'Test for Cross-Site Scripting attacks',
      icon: Bug,
      color: 'orange',
      recommended: false
    },
    {
      id: 'sqli',
      name: 'SQL Injection Test',
      description: 'Test for SQL injection vulnerabilities',
      icon: Database,
      color: 'red',
      recommended: false
    },
    {
      id: 'directory',
      name: 'Directory Enumeration',
      description: 'Scan for exposed directories (200 OK status)',
      icon: FolderOpen,
      color: 'yellow',
      recommended: false
    },
    {
      id: 'security_headers',
      name: 'Security Headers Analysis',
      description: 'Check HTTP security headers configuration',
      icon: ShieldCheck,
      color: 'green',
      recommended: false
    }
  ];

  const selectedCount = Object.values(selectedTests).filter(Boolean).length;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-slate-800 border-b border-slate-700 p-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="w-6 h-6 text-cyan-400" />
              Select Security Tests
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Choose which security tests to run on: <span className="text-cyan-400 font-mono">{url}</span>
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-3">
          {tests.map((test) => {
            const IconComponent = test.icon;
            const isSelected = selectedTests[test.id];
            
            return (
              <button
                key={test.id}
                onClick={() => toggleTest(test.id)}
                className={`w-full text-left p-4 rounded-lg border-2 transition-all ${
                  isSelected
                    ? 'border-cyan-500 bg-cyan-500/10'
                    : 'border-slate-700 bg-slate-900/50 hover:border-slate-600'
                }`}
              >
                <div className="flex items-start gap-4">
                  <div className={`p-2 rounded-lg ${
                    isSelected ? 'bg-cyan-500/20' : 'bg-slate-700/50'
                  }`}>
                    <IconComponent className={`w-5 h-5 ${
                      isSelected ? 'text-cyan-400' : 'text-slate-400'
                    }`} />
                  </div>
                  
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className={`font-semibold ${
                        isSelected ? 'text-white' : 'text-slate-300'
                      }`}>
                        {test.name}
                      </h3>
                      {test.recommended && (
                        <span className="text-xs px-2 py-0.5 bg-green-500/20 text-green-400 rounded-full">
                          Recommended
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-slate-400 mt-1">
                      {test.description}
                    </p>
                  </div>

                  <div className={`mt-1 w-5 h-5 rounded border-2 flex items-center justify-center ${
                    isSelected
                      ? 'bg-cyan-500 border-cyan-500'
                      : 'border-slate-600'
                  }`}>
                    {isSelected && (
                      <CheckCircle className="w-4 h-4 text-white" />
                    )}
                  </div>
                </div>
              </button>
            );
          })}
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-slate-800 border-t border-slate-700 p-6 flex items-center justify-between">
          <div className="text-sm text-slate-400">
            <span className="font-semibold text-white">{selectedCount}</span> test{selectedCount !== 1 ? 's' : ''} selected
          </div>
          <div className="flex gap-3">
            <button
              onClick={onClose}
              className="px-6 py-2.5 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-semibold transition"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirm}
              disabled={selectedCount === 0}
              className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white rounded-lg font-semibold transition"
            >
              Start Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanOptionsModal;
