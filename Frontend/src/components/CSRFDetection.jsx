import React from 'react';
import { Shield, AlertTriangle, CheckCircle, AlertCircle, FileText, Lock } from 'lucide-react';

const CSRFDetection = ({ csrfData }) => {
  if (!csrfData) {
    return null;
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'high':
      case 'critical':
        return 'bg-red-500/20 border-red-500/50 text-red-400';
      case 'medium':
        return 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400';
      case 'low':
      case 'info':
        return 'bg-blue-500/20 border-blue-500/50 text-blue-400';
      default:
        return 'bg-slate-500/20 border-slate-500/50 text-slate-400';
    }
  };

  const isVulnerable = csrfData.is_vulnerable;
  const vulnerableCount = csrfData.vulnerable_forms_count || 0;
  const protectedCount = csrfData.protected_forms_count || 0;
  const totalForms = csrfData.total_forms || 0;

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-lg p-4 mb-6">
      {/* Compact CSRF Status */}
      <div className={`flex items-center justify-between p-3 rounded-lg border ${
        isVulnerable 
          ? 'bg-red-500/10 border-red-500/50' 
          : 'bg-green-500/10 border-green-500/50'
      }`}>
        <div className="flex items-center gap-3">
          {isVulnerable ? (
            <AlertTriangle className="w-5 h-5 text-red-400" />
          ) : (
            <CheckCircle className="w-5 h-5 text-green-400" />
          )}
          <div>
            <div className={`font-bold ${
              isVulnerable ? 'text-red-400' : 'text-green-400'
            }`}>
              CSRF {isVulnerable ? 'Vulnerable' : 'Protected'}
            </div>
            <div className="text-xs text-slate-400">
              {isVulnerable 
                ? `${vulnerableCount} form${vulnerableCount !== 1 ? 's' : ''} without CSRF tokens`
                : `${totalForms} form${totalForms !== 1 ? 's' : ''} checked`
              }
            </div>
          </div>
        </div>
        <div className={`px-3 py-1 rounded text-xs font-bold ${
          isVulnerable 
            ? 'bg-red-500/30 text-red-300' 
            : 'bg-green-500/30 text-green-300'
        }`}>
          {isVulnerable ? 'UNSAFE' : 'SAFE'}
        </div>
      </div>

      {/* Compact Summary */}
      <div className="grid grid-cols-3 gap-2 mt-3 text-xs">
        <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 text-center">
          <div className="text-blue-400 font-bold">{totalForms}</div>
          <div className="text-slate-400">Total Forms</div>
        </div>
        <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 text-center">
          <div className={`font-bold ${isVulnerable ? 'text-red-400' : 'text-slate-400'}`}>
            {vulnerableCount}
          </div>
          <div className="text-slate-400">Vulnerable</div>
        </div>
        <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 text-center">
          <div className="text-green-400 font-bold">{protectedCount}</div>
          <div className="text-slate-400">Protected</div>
        </div>
      </div>

      {/* Risk Level Badge */}
      {csrfData.risk_level && (
        <div className="mt-3 flex items-center justify-between">
          <span className="text-xs text-slate-400">Risk Level:</span>
          <span className={`px-2 py-1 rounded text-xs font-bold ${
            csrfData.risk_level === 'High' ? 'bg-red-500/30 text-red-300' :
            csrfData.risk_level === 'Medium' ? 'bg-yellow-500/30 text-yellow-300' :
            'bg-green-500/30 text-green-300'
          }`}>
            {csrfData.risk_level.toUpperCase()}
          </span>
        </div>
      )}

      {/* Vulnerable Forms Details */}
      {isVulnerable && csrfData.vulnerable_forms && csrfData.vulnerable_forms.length > 0 && (
        <div className="mt-3 space-y-2">
          <div className="text-xs font-semibold text-red-400 mb-2">
            ⚠️ Vulnerable Forms:
          </div>
          {csrfData.vulnerable_forms.map((form, index) => (
            <div 
              key={index}
              className="bg-red-500/10 border border-red-500/30 rounded p-2 text-xs"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-red-300 font-mono">{form.form_id}</span>
                <span className={`px-2 py-0.5 rounded ${
                  form.method === 'POST' ? 'bg-red-500/30 text-red-300' :
                  'bg-yellow-500/30 text-yellow-300'
                }`}>
                  {form.method}
                </span>
              </div>
              <div className="text-slate-400">
                Action: <span className="text-slate-300">{form.action}</span>
              </div>
              <div className="text-slate-400">
                Inputs: <span className="text-slate-300">{form.input_count}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Protected Forms Summary */}
      {!isVulnerable && csrfData.protected_forms && csrfData.protected_forms.length > 0 && (
        <div className="mt-3 p-2 bg-green-500/10 border border-green-500/30 rounded text-xs">
          <div className="flex items-center gap-2 text-green-400">
            <Lock className="w-4 h-4" />
            <span className="font-semibold">All forms are protected with CSRF tokens</span>
          </div>
        </div>
      )}

      {/* Recommendations */}
      {csrfData.recommendations && csrfData.recommendations.length > 0 && (
        <div className="mt-3 space-y-1">
          {csrfData.recommendations.slice(0, 2).map((rec, index) => (
            <div
              key={index}
              className={`p-2 rounded text-xs border ${getSeverityColor(rec.severity)}`}
            >
              <div className="font-semibold mb-0.5">{rec.title}</div>
              <div className="text-slate-400">{rec.description}</div>
            </div>
          ))}
        </div>
      )}

      {/* Error or Timeout Message */}
      {csrfData.scan_status === 'error' && (
        <div className="mt-3 p-2 bg-yellow-500/10 border border-yellow-500/30 rounded text-xs">
          <div className="flex items-center gap-2 text-yellow-400">
            <AlertCircle className="w-4 h-4" />
            <span>Could not complete CSRF scan: {csrfData.error}</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default CSRFDetection;
