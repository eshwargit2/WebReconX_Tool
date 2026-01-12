"use client"

import { useEffect, useState } from "react"

export default function RiskAssessment() {
  const [score, setScore] = useState(0)

  useEffect(() => {
    // Animate score from 0 to 65
    const interval = setInterval(() => {
      setScore((prev) => {
        if (prev >= 65) {
          clearInterval(interval)
          return 65
        }
        return prev + 1
      })
    }, 30)

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="bg-card rounded-lg p-6 border border-border h-full flex flex-col items-center justify-center">
      <h2 className="text-xl font-bold text-foreground mb-8">AI Risk Assessment</h2>

      <div className="relative w-48 h-48 mb-8">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 200 200">
          {/* Background circle */}
          <circle cx="100" cy="100" r="90" fill="none" stroke="currentColor" strokeWidth="8" className="text-border" />
          {/* Animated circle */}
          <circle
            cx="100"
            cy="100"
            r="90"
            fill="none"
            stroke="url(#gradient)"
            strokeWidth="8"
            strokeDasharray={`${(score / 100) * 565.5} 565.5`}
            strokeLinecap="round"
            className="transition-all duration-500"
          />
          <defs>
            <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor="#10b981" />
            </linearGradient>
          </defs>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold text-accent">{score}</div>
          <div className="text-sm text-muted-foreground">/100</div>
        </div>
      </div>

      <div className="w-full space-y-4 text-center">
        <div>
          <p className="text-sm text-muted-foreground mb-2">Status:</p>
          <p className="text-lg font-semibold text-destructive">Potentially Unsafe</p>
        </div>

        <div className="w-full bg-input rounded-full h-2 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-yellow-500 to-red-500 transition-all duration-1000"
            style={{ width: `${score}%` }}
          />
        </div>

        <p className="text-xs text-muted-foreground mt-4">
          Based on ultra real analysis, the website exists is medium severity low info governed. Unused vulnerable SQL
          injection in the contact surface.
        </p>
      </div>
    </div>
  )
}
