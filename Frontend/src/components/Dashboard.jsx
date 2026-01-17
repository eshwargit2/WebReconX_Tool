import WebsiteOverview from "./WebsiteOverview"
import RiskAssessment from "./RiskAssessment"
import TechnologyStack from "./TechnologyStack"
import IssuesRecommendations from "./IssuesRecommendations"
import { FileDown } from "lucide-react"

export default function Dashboard({ data, selectedTests }) {
  const showTech = selectedTests?.tech !== false;
  const showPorts = selectedTests?.ports !== false;
  const showWAF = selectedTests?.waf !== false;

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <WebsiteOverview data={data} selectedTests={selectedTests} />
        <div id="tech-stack" className="lg:col-span-2 space-y-8 scroll-mt-20">
          {showTech && <TechnologyStack data={data} />}
        </div>
      </div>

      {/* AI Sections moved to bottom */}
      <div id="risk-assessment" className="scroll-mt-20">
        <RiskAssessment data={data} />
      </div>
      <div id="recommendations" className="scroll-mt-20">
        <IssuesRecommendations data={data} />
      </div>

      {/* <div className="flex justify-center pt-8 pb-4">
        <button className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-white px-8 py-3 rounded-lg font-semibold transition">
          <FileDown size={20} />
          Generate PDF Report
        </button>
      </div>

      <footer className="text-center text-sm text-slate-500 py-8 border-t border-slate-700/50">
        © 2025 SiteGuardian All. Share___reitgrified
      </footer> */}
    </div>
  )
}
