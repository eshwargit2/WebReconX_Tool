import React, { useState } from 'react';
import { Globe, Calendar, Server, Shield, Building, MapPin, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';

const WhoisInfo = ({ whoisData }) => {
  const [copiedField, setCopiedField] = useState(null);
  const [showRaw, setShowRaw] = useState(false);

  if (!whoisData || !whoisData.success) {
    return null;
  }

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const InfoRow = ({ icon: Icon, label, value, field }) => {
    if (!value || value === 'Not available' || value === 'None') return null;
    
    return (
      <div className="flex items-start gap-3 p-3 bg-slate-900/30 rounded-lg border border-slate-700/30 hover:border-slate-600/50 transition group">
        <Icon className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="text-xs text-slate-500 font-semibold mb-1">{label}</div>
          <div className="text-sm text-slate-200 font-mono break-all">{value}</div>
        </div>
        {field && (
          <button
            onClick={() => copyToClipboard(value, field)}
            className="p-1.5 hover:bg-slate-700 rounded transition opacity-0 group-hover:opacity-100"
            title="Copy"
          >
            {copiedField === field ? (
              <Check size={14} className="text-green-400" />
            ) : (
              <Copy size={14} className="text-slate-400" />
            )}
          </button>
        )}
      </div>
    );
  };

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-cyan-500/10 rounded-lg">
          <Globe className="w-6 h-6 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-2xl font-bold text-white">Domain Information</h2>
          <p className="text-sm text-slate-400">Domain Registration Details</p>
        </div>
      </div>

      {/* Domain Name */}
      <div className="mb-4 p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
        <div className="text-xs text-cyan-400 font-semibold mb-1">Domain</div>
        <div className="text-lg font-bold text-white font-mono">{whoisData.domain}</div>
      </div>

      {/* Grid Layout for Main Info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
        <InfoRow 
          icon={Building} 
          label="Registrar" 
          value={whoisData.registrar} 
          field="registrar"
        />
        
        <InfoRow 
          icon={Calendar} 
          label="Creation Date" 
          value={whoisData.creation_date} 
          field="creation_date"
        />
        
        <InfoRow 
          icon={Calendar} 
          label="Expiration Date" 
          value={whoisData.expiration_date} 
          field="expiration_date"
        />
        
        <InfoRow 
          icon={Calendar} 
          label="Last Updated" 
          value={whoisData.updated_date} 
          field="updated_date"
        />

        {whoisData.registrant_org && (
          <InfoRow 
            icon={Building} 
            label="Organization" 
            value={whoisData.registrant_org} 
            field="registrant_org"
          />
        )}

        {whoisData.registrant_country && (
          <InfoRow 
            icon={MapPin} 
            label="Country" 
            value={whoisData.registrant_country} 
            field="registrant_country"
          />
        )}

        <InfoRow 
          icon={Shield} 
          label="DNSSEC" 
          value={whoisData.dnssec} 
          field="dnssec"
        />
      </div>

      {/* Name Servers */}
      {whoisData.name_servers && whoisData.name_servers.length > 0 && (
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Server className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-semibold text-white">Name Servers</h3>
            <span className="text-xs text-slate-500">({whoisData.name_servers.length})</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {whoisData.name_servers.map((ns, idx) => (
              <div
                key={idx}
                className="p-2 bg-purple-500/5 border border-purple-500/20 rounded text-xs font-mono text-purple-300 flex items-center justify-between group"
              >
                <span className="truncate">{ns}</span>
                <button
                  onClick={() => copyToClipboard(ns, `ns-${idx}`)}
                  className="p-1 hover:bg-purple-500/20 rounded transition opacity-0 group-hover:opacity-100 ml-2 flex-shrink-0"
                >
                  {copiedField === `ns-${idx}` ? (
                    <Check size={12} className="text-green-400" />
                  ) : (
                    <Copy size={12} className="text-purple-400" />
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Domain Status */}
      {whoisData.status && whoisData.status.length > 0 && (
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-green-400" />
            <h3 className="text-sm font-semibold text-white">Domain Status</h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {whoisData.status.map((status, idx) => (
              <span
                key={idx}
                className="px-3 py-1 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-300 font-mono"
              >
                {status}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Raw WHOIS Data (Collapsible) */}
      {whoisData.raw_whois && (
        <div className="mt-4">
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-400 transition mb-2"
          >
            {showRaw ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            <span>Raw WHOIS Data</span>
          </button>
          {showRaw && (
            <div className="relative">
              <pre className="p-4 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 font-mono overflow-x-auto max-h-96 overflow-y-auto">
                {whoisData.raw_whois}
              </pre>
              <button
                onClick={() => copyToClipboard(whoisData.raw_whois, 'raw')}
                className="absolute top-2 right-2 p-2 bg-slate-800 hover:bg-slate-700 rounded border border-slate-600 transition"
                title="Copy raw WHOIS"
              >
                {copiedField === 'raw' ? (
                  <Check size={14} className="text-green-400" />
                ) : (
                  <Copy size={14} className="text-slate-400" />
                )}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default WhoisInfo;
