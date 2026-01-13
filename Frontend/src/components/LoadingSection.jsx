import { Loader2, Shield, Search, Globe, Lock, Bug, Database } from "lucide-react"

export default function LoadingSection({ isLoading, currentOperation = "Initializing scan...", progress = 0, selectedTests = null }) {
  if (!isLoading) return null

  const allScanSteps = [
    { icon: Globe, label: "Resolving hostname", id: 'hostname', weight: 10, testKey: null },
    { icon: Search, label: "Scanning open ports", id: 'ports', weight: 25, testKey: 'ports' },
    { icon: Shield, label: "Detecting WAF protection", id: 'waf', weight: 15, testKey: 'waf' },
    { icon: Lock, label: "Detecting technologies", id: 'tech', weight: 15, testKey: 'tech' },
    { icon: Bug, label: "Testing XSS vulnerabilities", id: 'xss', weight: 20, testKey: 'xss' },
    { icon: Database, label: "Testing SQL injection", id: 'sqli', weight: 15, testKey: 'sqli' },
  ]

  // Filter steps based on selected tests
  const scanSteps = selectedTests 
    ? allScanSteps.filter(step => !step.testKey || selectedTests[step.testKey] === true)
    : allScanSteps;

  // Calculate progress based on current operation
  const calculateProgress = () => {
    if (progress > 0) return progress;
    
    let calculatedProgress = 0;
    for (const step of scanSteps) {
      if (currentOperation.toLowerCase().includes(step.label.toLowerCase())) {
        return calculatedProgress + (step.weight / 2);
      }
      if (isStepCompleted(step.label)) {
        calculatedProgress += step.weight;
      }
    }
    return calculatedProgress;
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
    <div className="fixed inset-0 bg-slate-950/90 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="max-w-md w-full mx-4">
        <div className="rounded-lg bg-slate-800/90 border border-slate-700/50 p-8 backdrop-blur">
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

          {/* Progress Steps */}
          <div className="space-y-3 mb-6">
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
                  <span className={`text-sm flex-1 ${
                    isActive ? 'text-white font-semibold' : 
                    isCompleted ? 'text-green-400' :
                    'text-slate-500'
                  }`}>
                    {step.label}
                  </span>
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
          </div>
        </div>
      </div>
    </div>
  )
}
