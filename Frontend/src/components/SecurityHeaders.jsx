import React, { useState } from 'react';
import { Shield, ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Info } from 'lucide-react';

const SecurityHeaders = ({ headersData }) => {
  const [expanded, setExpanded] = useState(false);

  if (!headersData || headersData.error) {
    return null;
  }

  const totalScore = headersData.total_score || 0;
  const maxScore = headersData.max_score || 0;
  const grade = headersData.security_grade || 'F';
  const headersFound = headersData.headers_found || [];
  const headersMissing = headersData.headers_missing || [];
  const percentage = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

  const getGradeColor = (grade) => {
    const colors = {
      'A': 'text-green-400 bg-green-500/10 border-green-500/50',
      'B': 'text-blue-400 bg-blue-500/10 border-blue-500/50',
      'C': 'text-yellow-400 bg-yellow-500/10 border-yellow-500/50',
      'D': 'text-orange-400 bg-orange-500/10 border-orange-500/50',
      'F': 'text-red-400 bg-red-500/10 border-red-500/50'
    };
    return colors[grade] || colors['F'];
  };

  const getRiskColor = (risk) => {
    const colors = {
      'Critical': 'text-red-400',
      'High': 'text-orange-400',
      'Medium': 'text-yellow-400',
      'Low': 'text-blue-400'
    };
    return colors[risk] || 'text-slate-400';
  };

  const getRiskBadge = (risk) => {
    const badges = {
      'Critical': 'bg-red-500/20 text-red-400 border-red-500/30',
      'High': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      'Medium': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'Low': 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    };
    return badges[risk] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
  };

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-lg p-4 mb-6">
      {/* Header */}
      <div className={`flex items-center justify-between p-4 rounded-lg border ${getGradeColor(grade)}`}>
        <div className="flex items-center gap-3">
          {grade === 'A' || grade === 'B' ? (
            <ShieldCheck className="w-6 h-6" />
          ) : grade === 'F' ? (
            <ShieldAlert className="w-6 h-6" />
          ) : (
            <Shield className="w-6 h-6" />
          )}
          <div>
            <h3 className="font-semibold text-slate-100 text-lg">Security Headers Analysis</h3>
            <p className="text-sm mt-1">
              Security Grade: <span className="font-bold text-xl">{grade}</span>
              <span className="ml-2 text-slate-300">({totalScore}/{maxScore} points • {percentage}%)</span>
            </p>
          </div>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="p-2 hover:bg-slate-700/50 rounded-lg transition-colors"
        >
          {expanded ? (
            <ChevronUp className="w-5 h-5 text-slate-400" />
          ) : (
            <ChevronDown className="w-5 h-5 text-slate-400" />
          )}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 space-y-4">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-xs text-slate-400">Present</span>
              </div>
              <div className="text-2xl font-bold text-green-400">{headersFound.length}</div>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <XCircle className="w-4 h-4 text-red-400" />
                <span className="text-xs text-slate-400">Missing</span>
              </div>
              <div className="text-2xl font-bold text-red-400">{headersMissing.length}</div>
            </div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <Info className="w-4 h-4 text-blue-400" />
                <span className="text-xs text-slate-400">Score</span>
              </div>
              <div className="text-2xl font-bold text-blue-400">{percentage}%</div>
            </div>
            <div className={`border rounded-lg p-3 ${getGradeColor(grade)}`}>
              <div className="flex items-center gap-2 mb-1">
                <Shield className="w-4 h-4" />
                <span className="text-xs text-slate-400">Grade</span>
              </div>
              <div className="text-2xl font-bold">{grade}</div>
            </div>
          </div>

          {/* Headers Found */}
          {headersFound.length > 0 && (
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
              <h4 className="font-semibold text-green-400 mb-3 flex items-center gap-2">
                <CheckCircle className="w-5 h-5" />
                Security Headers Present ({headersFound.length})
              </h4>
              <div className="space-y-3">
                {headersFound.map((header, index) => (
                  <div key={index} className="bg-slate-800/50 rounded-lg p-3 border border-green-500/20">
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <code className="text-green-400 font-semibold">{header.name}</code>
                          <span className="px-2 py-0.5 rounded text-xs bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            {header.source}
                          </span>
                          {header.value && header.value.includes('Report-Only') && (
                            <span className="px-2 py-0.5 rounded text-xs bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">
                              Report Mode
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-400 mb-2">{header.description}</p>
                        <div className="bg-slate-900/50 rounded p-2 border border-slate-700/30">
                          <code className="text-xs text-slate-300 break-all">{header.value}</code>
                        </div>
                      </div>
                      <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Headers Missing */}
          {headersMissing.length > 0 && (
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
              <h4 className="font-semibold text-red-400 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Missing Security Headers ({headersMissing.length})
              </h4>
              <div className="space-y-3">
                {headersMissing.map((header, index) => (
                  <div key={index} className="bg-slate-800/50 rounded-lg p-3 border border-red-500/20">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <code className="text-red-400 font-semibold">{header.name}</code>
                          <span className={`px-2 py-0.5 rounded text-xs border ${getRiskBadge(header.risk)}`}>
                            {header.risk} Risk
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mb-2">
                          <strong className="text-slate-300">Issue:</strong> {header.description}
                        </p>
                        <div className="bg-blue-500/10 border border-blue-500/30 rounded p-2">
                          <p className="text-xs text-blue-300">
                            <strong>💡 Recommendation:</strong> {header.recommendation}
                          </p>
                        </div>
                      </div>
                      <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Tips */}
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <h4 className="font-semibold text-blue-400 mb-2 flex items-center gap-2">
              <Info className="w-5 h-5" />
              About Security Headers
            </h4>
            <p className="text-sm text-slate-300 mb-3">
              Security headers are HTTP response headers that instruct browsers on how to behave when handling your site's content. 
              Implementing proper security headers helps protect against common web vulnerabilities like XSS, clickjacking, and data injection attacks.
            </p>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-3 mt-3">
              <p className="text-xs text-yellow-300">
                <strong>⚠️ Note:</strong> Some major sites (like Google) may show missing headers because they use alternative implementations, 
                different headers for specific services, or have other security measures in place. Always verify results and consider the 
                overall security posture, not just individual headers.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityHeaders;
