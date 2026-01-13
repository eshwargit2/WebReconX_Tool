import React, { useState } from 'react';
import { Database, Shield, CheckCircle, AlertTriangle, ChevronDown, ChevronUp, Bug, Lock, Copy, Check } from 'lucide-react';

const SQLInjection = ({ sqliData }) => {
  const [expanded, setExpanded] = useState(true); // Auto-expand when loaded
  const [showAllPayloads, setShowAllPayloads] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);

  if (!sqliData) {
    return null;
  }

  const totalVulns = sqliData.total_vulnerabilities || 0;
  const isVulnerable = totalVulns > 0;
  const vulnerableParams = sqliData.vulnerable_params || [];
  const vulnerabilities = sqliData.vulnerabilities || [];
  const vulnerabilityTypes = sqliData.vulnerability_types || {};

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSeverityColor = (type) => {
    if (type.includes('Time-based') || type.includes('Error-based')) {
      return 'bg-red-500/20 border-red-500/50 text-red-400';
    } else if (type.includes('Union-based')) {
      return 'bg-orange-500/20 border-orange-500/50 text-orange-400';
    } else if (type.includes('Boolean-based')) {
      return 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400';
    }
    return 'bg-slate-500/20 border-slate-500/50 text-slate-400';
  };

  const getBadgeColor = (type) => {
    if (type.includes('Time-based') || type.includes('Error-based')) {
      return 'bg-red-500/30 text-red-300';
    } else if (type.includes('Union-based')) {
      return 'bg-orange-500/30 text-orange-300';
    } else if (type.includes('Boolean-based')) {
      return 'bg-yellow-500/30 text-yellow-300';
    }
    return 'bg-slate-500/30 text-slate-300';
  };

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-lg p-4 mb-6">
      {/* SQL Injection Status */}
      <div className={`flex items-center justify-between p-3 rounded-lg border ${
        isVulnerable 
          ? 'bg-red-500/10 border-red-500/50' 
          : 'bg-green-500/10 border-green-500/50'
      }`}>
        <div className="flex items-center gap-3">
          {isVulnerable ? (
            <Database className="w-5 h-5 text-red-400" />
          ) : (
            <Lock className="w-5 h-5 text-green-400" />
          )}
          <div>
            <div className={`font-bold ${
              isVulnerable ? 'text-red-400' : 'text-green-400'
            }`}>
              SQL Injection {isVulnerable ? 'Vulnerable' : 'Protected'}
            </div>
            <div className="text-xs text-slate-400">
              {isVulnerable 
                ? `${totalVulns} vulnerability${totalVulns !== 1 ? 'ies' : ''} detected`
                : 'No SQL injection vulnerabilities found'
              }
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className={`px-3 py-1 rounded text-xs font-bold ${
            isVulnerable 
              ? 'bg-red-500/30 text-red-300' 
              : 'bg-green-500/30 text-green-300'
          }`}>
            {isVulnerable ? 'CRITICAL' : 'SAFE'}
          </div>
          {isVulnerable && (
            <button
              onClick={() => setExpanded(!expanded)}
              className="p-1 hover:bg-slate-700/50 rounded transition-colors"
            >
              {expanded ? (
                <ChevronUp className="w-4 h-4 text-slate-400" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400" />
              )}
            </button>
          )}
        </div>
      </div>

      {/* Compact Summary - Only if vulnerable */}
      {isVulnerable && (
        <div className="grid grid-cols-3 gap-2 mt-3 text-xs">
          <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 text-center">
            <div className="text-red-400 font-bold">{totalVulns}</div>
            <div className="text-slate-400">Total Issues</div>
          </div>
          <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 text-center">
            <div className="text-orange-400 font-bold">
              {vulnerableParams.length}
            </div>
            <div className="text-slate-400">Parameters</div>
          </div>
          <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 text-center">
            <div className="text-purple-400 font-bold">
              {Object.keys(vulnerabilityTypes).length}
            </div>
            <div className="text-slate-400">Types</div>
          </div>
        </div>
      )}

      {/* Vulnerable Parameters */}
      {vulnerableParams && vulnerableParams.length > 0 && (
        <div className="mt-3 p-2 bg-red-500/5 border border-red-500/20 rounded text-xs">
          <div className="text-red-400 font-medium mb-1 flex items-center gap-1">
            <Bug className="w-3 h-3" />
            Vulnerable Parameters:
          </div>
          <div className="flex flex-wrap gap-1">
            {vulnerableParams.map((param, index) => (
              <span
                key={index}
                className="px-2 py-0.5 bg-red-500/20 text-red-300 rounded font-mono"
              >
                {param}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerability Types Summary */}
      {isVulnerable && Object.keys(vulnerabilityTypes).length > 0 && (
        <div className="mt-3 p-2 bg-slate-900/50 border border-slate-700/50 rounded text-xs">
          <div className="text-slate-300 font-medium mb-2">Detected Attack Types:</div>
          <div className="space-y-1">
            {Object.entries(vulnerabilityTypes).map(([type, count]) => (
              <div key={type} className="flex justify-between items-center">
                <span className="text-slate-400">{type}</span>
                <span className="px-2 py-0.5 bg-red-500/20 text-red-300 rounded font-bold">
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Expanded Vulnerability Details */}
      {expanded && isVulnerable && vulnerabilities.length > 0 && (
        <div className="mt-3 space-y-3">
          <div className="flex items-center justify-between border-t border-slate-700 pt-3">
            <div className="text-sm text-slate-300 font-medium">
              All Detected Payloads ({vulnerabilities.length}):
            </div>
            <button
              onClick={() => setShowAllPayloads(!showAllPayloads)}
              className="text-xs text-cyan-400 hover:text-cyan-300 underline"
            >
              {showAllPayloads ? 'Show Less' : 'Show All'}
            </button>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
            {(showAllPayloads ? vulnerabilities : vulnerabilities.slice(0, 10)).map((vuln, index) => (
              <div 
                key={index}
                className={`p-3 rounded border text-xs ${getSeverityColor(vuln.type)}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className={`px-2 py-0.5 rounded text-[10px] font-bold ${getBadgeColor(vuln.type)}`}>
                      {vuln.category?.toUpperCase() || 'SQLI'}
                    </div>
                    <div className="font-bold">{vuln.type}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs opacity-75">{vuln.method}</span>
                    <button
                      onClick={() => copyToClipboard(vuln.payload, index)}
                      className="p-1 hover:bg-black/30 rounded transition-colors"
                      title="Copy payload"
                    >
                      {copiedIndex === index ? (
                        <Check className="w-3 h-3 text-green-400" />
                      ) : (
                        <Copy className="w-3 h-3 opacity-75" />
                      )}
                    </button>
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex items-start gap-2">
                    <span className="opacity-75 flex-shrink-0">Param:</span>
                    <span className="font-mono bg-black/30 px-2 py-0.5 rounded">
                      {vuln.param}
                    </span>
                  </div>
                  <div>
                    <div className="opacity-75 mb-1">Payload:</div>
                    <div className="font-mono bg-black/40 px-2 py-1.5 rounded break-all text-[11px] border border-white/10">
                      {vuln.payload}
                    </div>
                  </div>
                  {vuln.evidence && (
                    <div>
                      <div className="opacity-75 mb-1">Evidence:</div>
                      <div className="bg-black/40 px-2 py-1.5 rounded text-[11px] border border-white/10">
                        {vuln.evidence}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          {!showAllPayloads && vulnerabilities.length > 10 && (
            <div className="text-center py-2">
              <button
                onClick={() => setShowAllPayloads(true)}
                className="text-sm text-cyan-400 hover:text-cyan-300 font-medium underline"
              >
                Show {vulnerabilities.length - 10} more vulnerabilities
              </button>
            </div>
          )}
        </div>
      )}

      {/* Recommendations */}
      {isVulnerable && (
        <div className="mt-3 p-2 bg-yellow-500/5 border border-yellow-500/20 rounded text-xs">
          <div className="text-yellow-400 font-medium mb-1 flex items-center gap-1">
            <Shield className="w-3 h-3" />
            Remediation Steps:
          </div>
          <ul className="text-yellow-300/80 space-y-0.5 ml-4 list-disc">
            <li>Use parameterized queries/prepared statements</li>
            <li>Implement proper input validation and sanitization</li>
            <li>Apply principle of least privilege to database accounts</li>
            <li>Enable Web Application Firewall (WAF) protection</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default SQLInjection;
