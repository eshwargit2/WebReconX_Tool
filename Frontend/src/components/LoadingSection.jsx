import { Loader2, Shield, Search, Globe, Lock, Bug, Database, FileText, FileCheck, FolderOpen, ShieldCheck } from "lucide-react"

export default function LoadingSection({ isLoading, currentOperation = "Initializing scan...", progress = 0, selectedTests = null }) {
  if (!isLoading) return null

  const allScanSteps = [
    { icon: Globe, label: "Resolving hostname", id: 'hostname', weight: 8, testKey: null },
    { icon: FileText, label: "Performing Domain lookup", id: 'whois', weight: 8, testKey: 'whois' },
    { icon: Search, label: "Scanning open ports", id: 'ports', weight: 20, testKey: 'ports' },
    { icon: Shield, label: "Detecting WAF protection", id: 'waf', weight: 12, testKey: 'waf' },
    { icon: Lock, label: "Detecting technologies", id: 'tech', weight: 12, testKey: 'tech' },
    { icon: Bug, label: "Testing XSS vulnerabilities", id: 'xss', weight: 15, testKey: 'xss' },
    { icon: Database, label: "Testing SQL injection", id: 'sqli', weight: 12, testKey: 'sqli' },
    { icon: FolderOpen, label: "Scanning hidden directories", id: 'directory', weight: 10, testKey: 'directory' },
    { icon: ShieldCheck, label: "Analyzing security headers", id: 'security_headers', weight: 8, testKey: 'security_headers' },
    { icon: Shield, label: "Generating AI security report", id: 'ai', weight: 13, testKey: 'ai_analysis', isAI: true },
  ]

  // Filter steps based on selected tests
  const scanSteps = selectedTests 
    ? allScanSteps.filter(step => !step.testKey || selectedTests[step.testKey] === true)
    : allScanSteps;

  // Calculate total weight of active steps
  const totalWeight = scanSteps.reduce((sum, step) => sum + step.weight, 0);

  // Calculate progress based on current operation
  const calculateProgress = () => {
    // If explicit progress is provided and valid, use it
    if (progress > 0 && progress <= 100) return progress;
    
    let completedWeight = 0;
    const currentStepIndex = scanSteps.findIndex(s => 
      currentOperation.toLowerCase().includes(s.label.toLowerCase())
    );
    
    if (currentStepIndex === -1) return 5; // Show minimal progress if no match
    
    // Add weight of all completed steps
    for (let i = 0; i < currentStepIndex; i++) {
      completedWeight += scanSteps[i].weight;
    }
    
    // Add half weight of current step
    completedWeight += scanSteps[currentStepIndex].weight / 2;
    
    // Convert to percentage based on total weight
    return Math.min(Math.round((completedWeight / totalWeight) * 100), 95);
  };

  const isStepCompleted = (label) => {
    const stepIndex = scanSteps.findIndex(s => s.label === label);
    const currentIndex = scanSteps.findIndex(s => 
      currentOperation.toLowerCase().includes(s.label.toLowerCase())
    );
    return currentIndex > stepIndex;
  };

  const currentProgress = calculateProgress();

  return (
    <div className="fixed inset-0 bg-slate-950/90 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full max-h-[90vh] overflow-hidden flex flex-col">
        <div className="rounded-lg bg-slate-800/90 border border-slate-700/50 backdrop-blur overflow-y-auto">
          <div className="p-8">
          {/* Animated Logo/Icon */}
          <div className="flex justify-center mb-8">
            <div className="relative">
              <Loader2 size={64} className="text-cyan-400 animate-spin" />
              <div className="absolute inset-0 flex items-center justify-center">
                <Shield size={32} className="text-cyan-300 animate-pulse" />
              </div>
            </div>
          </div>

          {/* Title */}
          <h2 className="text-2xl font-bold text-white text-center mb-2">
            Analyzing Website Security
          </h2>
          <p className="text-slate-400 text-center text-sm mb-4">
            {currentOperation}
          </p>

          {/* Progress Bar with Percentage */}
          <div className="mb-6">
            <div className="flex justify-between items-center mb-2">
              <span className="text-xs text-slate-400">Overall Progress</span>
              <span className="text-sm font-bold text-cyan-400">{Math.round(currentProgress)}%</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-500 rounded-full transition-all duration-500 ease-out relative"
                style={{ width: `${currentProgress}%` }}
              >
                <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
              </div>
            </div>
          </div>

          {/* Progress Steps - Scrollable */}
          <div className="space-y-3 mb-6 max-h-64 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-600 scrollbar-track-slate-800">
            {scanSteps.map((step, idx) => {
              const IconComponent = step.icon
              const isActive = currentOperation.toLowerCase().includes(step.label.toLowerCase())
              const isCompleted = isStepCompleted(step.label)
              
              return (
                <div
                  key={idx}
                  className={`flex items-center gap-3 p-2.5 rounded-lg transition-all ${
                    isActive ? 'bg-cyan-500/20 border border-cyan-500/50' : 
                    isCompleted ? 'bg-green-500/10 border border-green-500/30' :
                    'bg-slate-700/20 border border-slate-700/30'
                  }`}
                >
                  <div className={`p-2 rounded-full ${
                    isActive ? 'bg-cyan-500/30' : 
                    isCompleted ? 'bg-green-500/30' :
                    'bg-slate-700/30'
                  }`}>
                    <IconComponent size={18} className={
                      isActive ? 'text-cyan-300 animate-pulse' : 
                      isCompleted ? 'text-green-400' :
                      'text-slate-500'
                    } />
                  </div>
                  <div className="flex-1">
                    <span className={`text-sm block ${
                      isActive ? 'text-white font-semibold' : 
                      isCompleted ? 'text-green-400' :
                      'text-slate-500'
                    }`}>
                      {step.label}
                    </span>
                    {isActive && step.isAI && (
                      <span className="text-xs text-blue-400 block mt-0.5">
                        Using Gemini AI...
                      </span>
                    )}
                  </div>
                  {isActive && (
                    <Loader2 size={16} className="text-cyan-400 animate-spin" />
                  )}
                  {isCompleted && (
                    <span className="text-green-400 text-xs font-bold">✓</span>
                  )}
                </div>
              )
            })}
          </div>

          {/* Status Message */}
          <div className="text-center">
            <div className="flex items-center justify-center gap-2 text-xs text-slate-400">
              <span className="animate-pulse">●</span>
              <span>Scanning in progress...</span>
            </div>
            {currentOperation.toLowerCase().includes('ai') && (
              <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                <p className="text-xs text-blue-300 font-semibold flex items-center justify-center gap-2">
                  <Loader2 size={14} className="animate-spin" />
                  AI is analyzing security data... This may take 30-60 seconds
                </p>
              </div>
            )}
          </div>
          </div>
        </div>
      </div>
    </div>
  )
}
