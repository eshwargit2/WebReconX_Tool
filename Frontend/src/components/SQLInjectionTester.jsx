import React, { useState } from 'react';
import { Database, Search, Loader2, AlertTriangle, CheckCircle } from 'lucide-react';
import { scanSQLInjection } from '../services/api';
import SQLInjection from './SQLInjection';

const SQLInjectionTester = () => {
  const [url, setUrl] = useState('');
  const [param, setParam] = useState('');
  const [method, setMethod] = useState('GET');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    
    if (!url) {
      setError('Please enter a URL');
      return;
    }

    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await scanSQLInjection(url, param || null, method);
      setResult(response.sqli_scan);
    } catch (err) {
      setError(err.message || 'Failed to scan for SQL injection');
      console.error('SQL injection scan error:', err);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-purple-500/20 rounded-lg">
          <Database className="w-6 h-6 text-purple-400" />
        </div>
        <div>
          <h2 className="text-2xl font-bold text-white">SQL Injection Tester</h2>
          <p className="text-sm text-slate-400">Test websites for SQL injection vulnerabilities</p>
        </div>
      </div>

      <form onSubmit={handleScan} className="space-y-4 mb-6">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Target URL
          </label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/page.php?id=1"
            className="w-full px-4 py-2 bg-slate-900/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            disabled={scanning}
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Parameter Name (Optional)
            </label>
            <input
              type="text"
              value={param}
              onChange={(e) => setParam(e.target.value)}
              placeholder="id, user, search (auto-detect if empty)"
              className="w-full px-4 py-2 bg-slate-900/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              disabled={scanning}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              HTTP Method
            </label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full px-4 py-2 bg-slate-900/50 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              disabled={scanning}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </div>
        </div>

        <button
          type="submit"
          disabled={scanning || !url}
          className="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white px-6 py-3 rounded-lg font-semibold transition"
        >
          {scanning ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Search className="w-5 h-5" />
              Scan for SQL Injection
            </>
          )}
        </button>
      </form>

      {/* Warning Notice */}
      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 mb-4">
        <div className="flex items-start gap-2">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-yellow-300">
            <strong>Legal Warning:</strong> Only test websites you own or have explicit permission to test. 
            Unauthorized testing may be illegal.
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 mb-4">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-red-400 font-semibold">Error</p>
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Scanning Progress */}
      {scanning && (
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 mb-4">
          <div className="flex items-center gap-3">
            <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
            <div className="text-sm text-blue-300">
              Testing SQL injection payloads... This may take a few moments.
            </div>
          </div>
        </div>
      )}

      {/* Results Display */}
      {result && !scanning && (
        <div className="mt-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span className="text-purple-400">📊</span>
            Scan Results
          </h3>
          <SQLInjection sqliData={result} />
        </div>
      )}
    </div>
  );
};

export default SQLInjectionTester;
