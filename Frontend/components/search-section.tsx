export default function SearchSection() {
  return (
    <div className="bg-card rounded-lg p-6 mb-8 border border-border">
      <div className="flex flex-col sm:flex-row gap-4 mb-4">
        <input
          type="text"
          placeholder="Enter website URL (e.g. example.com)"
          className="flex-1 bg-input border border-border rounded-lg px-4 py-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
        />
        <button className="bg-primary hover:bg-primary/90 text-primary-foreground px-8 py-3 rounded-lg font-medium transition-colors">
          Analyze
        </button>
      </div>
      <p className="text-sm text-muted-foreground">For educational and defensive security analysis only</p>
    </div>
  )
}
