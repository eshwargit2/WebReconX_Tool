import React, { useState } from 'react';
import { FolderOpen, FolderLock, Shield, AlertTriangle, ChevronDown, ChevronUp, ExternalLink, Copy, Check } from 'lucide-react';

const DirectoryScan = ({ directoryData }) => {
  const [expanded, setExpanded] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [activeCategory, setActiveCategory] = useState('all');

  if (!directoryData) {
    return null;
  }

  const totalDirs = directoryData.total_directories || 0;
  const directories = directoryData.directories || [];
  const categories = directoryData.categories || {};

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getCategoryColor = (category) => {
    const colors = {
      admin: 'bg-red-500/20 border-red-500/50 text-red-400',
      config: 'bg-orange-500/20 border-orange-500/50 text-orange-400',
      backup: 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400',
      api: 'bg-blue-500/20 border-blue-500/50 text-blue-400',
      content: 'bg-purple-500/20 border-purple-500/50 text-purple-400',
      other: 'bg-slate-500/20 border-slate-500/50 text-slate-400'
    };
    return colors[category] || colors.other;
  };

  const getCategoryIcon = (category) => {
    if (category === 'admin' || category === 'config') {
      return <FolderLock className="w-4 h-4" />;
    }
    return <FolderOpen className="w-4 h-4" />;
  };

  const getCategoryLabel = (category) => {
    const labels = {
      admin: 'Admin & Control',
      config: 'Configuration',
      backup: 'Backup & Temp',
      api: 'API Endpoints',
      content: 'Content & Media',
      other: 'Other'
    };
    return labels[category] || category;
  };

  const filteredDirectories = activeCategory === 'all' 
    ? directories 
    : categories[activeCategory] || [];

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-lg p-4 mb-6">
      {/* Header */}
      <div className={`flex items-center justify-between p-3 rounded-lg border ${
        totalDirs > 0 
          ? 'bg-orange-500/10 border-orange-500/50' 
          : 'bg-green-500/10 border-green-500/50'
      }`}>
        <div className="flex items-center gap-3">
          {totalDirs > 0 ? (
            <FolderOpen className="w-5 h-5 text-orange-400" />
          ) : (
            <Shield className="w-5 h-5 text-green-400" />
          )}
          <div>
            <h3 className="font-semibold text-slate-100">Directory Enumeration</h3>
            <p className={`text-sm ${totalDirs > 0 ? 'text-orange-300' : 'text-green-300'}`}>
              {totalDirs > 0 
                ? `${totalDirs} accessible ${totalDirs === 1 ? 'directory' : 'directories'} found` 
                : 'No exposed directories detected'}
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

      {/* Content */}
      {expanded && totalDirs > 0 && (
        <div className="mt-4 space-y-4">
          {/* Category Filter */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setActiveCategory('all')}
              className={`px-3 py-1 rounded-lg text-sm transition-all ${
                activeCategory === 'all'
                  ? 'bg-blue-500/30 text-blue-300 border border-blue-500/50'
                  : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700'
              }`}
            >
              All ({totalDirs})
            </button>
            {Object.entries(categories).map(([category, dirs]) => (
              dirs.length > 0 && (
                <button
                  key={category}
                  onClick={() => setActiveCategory(category)}
                  className={`px-3 py-1 rounded-lg text-sm transition-all flex items-center gap-1.5 ${
                    activeCategory === category
                      ? getCategoryColor(category)
                      : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {getCategoryIcon(category)}
                  {getCategoryLabel(category)} ({dirs.length})
                </button>
              )
            ))}
          </div>

          {/* Critical Warning */}
          {(categories.admin?.length > 0 || categories.config?.length > 0) && (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-red-300 font-medium text-sm">Critical Exposure Detected</p>
                  <p className="text-red-300/80 text-xs mt-1">
                    Sensitive directories (admin/config) are publicly accessible. This may allow unauthorized access.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Directory List */}
          <div className="space-y-2">
            {filteredDirectories.map((dir, index) => {
              const category = Object.keys(categories).find(cat => 
                categories[cat].some(d => d.url === dir.url)
              ) || 'other';
              
              return (
                <div
                  key={index}
                  className="bg-slate-700/30 border border-slate-600/50 rounded-lg p-3 hover:bg-slate-700/50 transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        {getCategoryIcon(category)}
                        <code className="text-sm text-blue-300 font-mono break-all">
                          {dir.path}
                        </code>
                        <span className={`px-2 py-0.5 rounded text-xs ${getCategoryColor(category)}`}>
                          {getCategoryLabel(category)}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
                        <span>Status: <span className="text-green-400">200 OK</span></span>
                        <span>Size: <span className="text-slate-300">{formatFileSize(dir.size)}</span></span>
                        <span className="truncate">Type: {dir.content_type}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        onClick={() => copyToClipboard(dir.url, index)}
                        className="p-1.5 hover:bg-slate-600/50 rounded transition-colors"
                        title="Copy URL"
                      >
                        {copiedIndex === index ? (
                          <Check className="w-4 h-4 text-green-400" />
                        ) : (
                          <Copy className="w-4 h-4 text-slate-400" />
                        )}
                      </button>
                      <a
                        href={dir.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-1.5 hover:bg-slate-600/50 rounded transition-colors"
                        title="Open in new tab"
                      >
                        <ExternalLink className="w-4 h-4 text-slate-400" />
                      </a>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Statistics */}
          <div className="bg-slate-700/30 border border-slate-600/50 rounded-lg p-3">
            <h4 className="text-sm font-medium text-slate-300 mb-2">Scan Summary</h4>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
              <div>
                <p className="text-slate-400">Total Found</p>
                <p className="text-slate-100 font-semibold">{totalDirs}</p>
              </div>
              {Object.entries(categories).map(([category, dirs]) => (
                dirs.length > 0 && (
                  <div key={category}>
                    <p className="text-slate-400">{getCategoryLabel(category)}</p>
                    <p className="text-slate-100 font-semibold">{dirs.length}</p>
                  </div>
                )
              ))}
            </div>
          </div>
        </div>
      )}

      {/* No directories found */}
      {expanded && totalDirs === 0 && (
        <div className="mt-4 text-center py-8">
          <Shield className="w-12 h-12 text-green-400/50 mx-auto mb-3" />
          <p className="text-slate-300 text-sm">No publicly accessible directories detected</p>
          <p className="text-slate-400 text-xs mt-1">Common directories are properly protected or hidden</p>
        </div>
      )}
    </div>
  );
};

export default DirectoryScan;
