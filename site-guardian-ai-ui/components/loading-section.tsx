export default function LoadingSection() {
  return (
    <div className="bg-card rounded-lg p-6 border border-border">
      <div className="space-y-4">
        <h3 className="text-foreground font-semibold">Loading</h3>

        <div className="space-y-3">
          <div>
            <p className="text-sm text-muted-foreground mb-2">Collecting data: Frontend satellite Sennde...</p>
            <p className="text-xs text-muted-foreground">Scanning' for vulnerabilities.</p>
          </div>

          <div className="w-full bg-input rounded-full h-2 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-accent to-secondary animate-pulse"
              style={{
                width: "65%",
                animation: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
              }}
            />
          </div>

          <div className="pt-4 space-y-2 text-xs">
            <p className="text-muted-foreground">Uncommitted action: Unpubkskh tford SQL injection, favorites the</p>
            <p className="text-muted-foreground">tar attack surface.</p>
          </div>
        </div>

        <div className="h-px bg-border my-6" />

        <div className="aspect-video bg-input rounded-lg border border-border overflow-hidden relative">
          <div className="absolute inset-0 opacity-10">
            <svg className="w-full h-full" viewBox="0 0 400 300">
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path
                    d="M 40 0 L 0 0 0 40"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="0.5"
                    className="text-accent"
                  />
                </pattern>
              </defs>
              <rect width="400" height="300" fill="url(#grid)" className="text-accent" />
              <circle
                cx="200"
                cy="150"
                r="60"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                className="text-secondary"
              />
              <rect
                x="100"
                y="100"
                width="200"
                height="100"
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
                className="text-accent/50"
              />
            </svg>
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-accent/20 rounded-lg mb-2">
                <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
