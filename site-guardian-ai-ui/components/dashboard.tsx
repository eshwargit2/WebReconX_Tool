"use client"

import WebsiteOverview from "./website-overview"
import RiskAssessment from "./risk-assessment"
import IssuesAndRecommendations from "./issues-recommendations"
import LoadingSection from "./loading-section"

export default function Dashboard() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
      {/* Left Column */}
      <WebsiteOverview />

      {/* Center Column */}
      <div className="lg:col-span-1 flex flex-col gap-6">
        <RiskAssessment />
      </div>

      {/* Right Column */}
      <div className="lg:col-span-1 flex flex-col gap-6">
        <LoadingSection />
        <IssuesAndRecommendations />
      </div>

      {/* Full Width Report Button */}
      <div className="lg:col-span-3 flex justify-center mt-4">
        <button className="bg-card hover:bg-card/80 border border-border text-foreground px-8 py-3 rounded-lg font-medium transition-colors">
          Generate PDF Report
        </button>
      </div>

      {/* Footer */}
      <div className="lg:col-span-3 text-center text-xs text-muted-foreground pt-4 border-t border-border">
        © 2026 SiteGuardian All. Share__retrqrited
      </div>
    </div>
  )
}
