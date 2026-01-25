import React from 'react';
import { Github, Linkedin, Mail, Globe, Shield, Code, Zap, Users, Heart, ExternalLink } from 'lucide-react';

const About = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <Shield className="w-20 h-20 text-cyan-400" />
          </div>
          <h1 className="text-5xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-4">
            WebReconX
          </h1>
          <p className="text-xl text-slate-400">
            Advanced Web Security Analysis Tool
          </p>
          <p className="text-sm text-slate-500 mt-2">Version 1.0.0 • January 2026</p>
        </div>

        {/* Project Description */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-2xl font-bold text-cyan-400 mb-4 flex items-center gap-2">
            <Info className="w-6 h-6" />
            About the Project
          </h2>
          <p className="text-slate-300 leading-relaxed mb-4">
            WebReconX is a comprehensive web security analysis tool designed to help security professionals, 
            developers, and researchers identify potential vulnerabilities in web applications. Built with 
            modern technologies and powered by AI, it provides intelligent insights into website security posture.
          </p>
          <p className="text-slate-300 leading-relaxed">
            This project combines traditional security testing methodologies with cutting-edge AI analysis 
            to deliver accurate, actionable security reports. It's developed as an educational tool to 
            demonstrate web security concepts and automated vulnerability scanning.
          </p>
        </div>

        {/* Features */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-2xl font-bold text-cyan-400 mb-4 flex items-center gap-2">
            <Zap className="w-6 h-6" />
            Key Features
          </h2>
          <div className="grid md:grid-cols-2 gap-4">
            <FeatureItem 
              icon={<Shield className="w-5 h-5 text-blue-400" />}
              text="XSS Vulnerability Detection"
            />
            <FeatureItem 
              icon={<Shield className="w-5 h-5 text-red-400" />}
              text="SQL Injection Scanning"
            />
            <FeatureItem 
              icon={<Globe className="w-5 h-5 text-purple-400" />}
              text="Directory Enumeration"
            />
            <FeatureItem 
              icon={<Shield className="w-5 h-5 text-green-400" />}
              text="WAF Detection"
            />
            <FeatureItem 
              icon={<Code className="w-5 h-5 text-yellow-400" />}
              text="Technology Stack Analysis"
            />
            <FeatureItem 
              icon={<Zap className="w-5 h-5 text-cyan-400" />}
              text="AI-Powered Security Analysis"
            />
            <FeatureItem 
              icon={<Globe className="w-5 h-5 text-orange-400" />}
              text="Port Scanning"
            />
            <FeatureItem 
              icon={<Shield className="w-5 h-5 text-indigo-400" />}
              text="WHOIS Lookup"
            />
          </div>
        </div>

        {/* Technology Stack */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-2xl font-bold text-cyan-400 mb-4 flex items-center gap-2">
            <Code className="w-6 h-6" />
            Technology Stack
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-lg font-semibold text-slate-200 mb-3">Frontend</h3>
              <ul className="space-y-2 text-slate-300">
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan-400 rounded-full"></span>
                  React 18
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan-400 rounded-full"></span>
                  Vite
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan-400 rounded-full"></span>
                  TailwindCSS
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan-400 rounded-full"></span>
                  Lucide Icons
                </li>
              </ul>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-slate-200 mb-3">Backend</h3>
              <ul className="space-y-2 text-slate-300">
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-400 rounded-full"></span>
                  Python 3.10+
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-400 rounded-full"></span>
                  Flask
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-400 rounded-full"></span>
                  Google Gemini AI
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-400 rounded-full"></span>
                  BeautifulSoup4
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Author Section */}
        <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-2xl font-bold text-cyan-400 mb-6 flex items-center gap-2">
            <Users className="w-6 h-6" />
            Project Author
          </h2>
          <div className="flex flex-col md:flex-row items-center gap-6">
            <div className="flex-shrink-0">
              <div className="w-24 h-24 bg-gradient-to-br from-cyan-400 to-blue-500 rounded-full flex items-center justify-center">
                <Users className="w-12 h-12 text-white" />
              </div>
            </div>
            <div className="flex-1 text-center md:text-left">
              <h3 className="text-2xl font-bold text-slate-100 mb-2">Soundhareshwaran S.R</h3>
              <p className="text-slate-400 mb-4">Ethical Hacker & Full Stack Developer & IOT</p>
              <p className="text-slate-300 leading-relaxed mb-4">
                Passionate about web security, ethical hacking, and building tools that help make 
                the internet safer. This project was developed as a college mini project to demonstrate 
                advanced web security analysis capabilities.
              </p>
              
              {/* Social Links */}
              <div className="flex flex-wrap gap-3 justify-center md:justify-start">
                <SocialLink 
                  href="https://github.com/eshwargit2" 
                  icon={<Github className="w-5 h-5" />}
                  label="GitHub"
                  color="hover:bg-slate-700"
                />
                <SocialLink 
                  href="https://in.linkedin.com/in/soundhareshwaran-s-r-85a1012a7" 
                  icon={<Linkedin className="w-5 h-5" />}
                  label="LinkedIn"
                  color="hover:bg-blue-600"
                />
                <SocialLink 
                  href="mailto:msselectronic57@gmail.com" 
                  icon={<Mail className="w-5 h-5" />}
                  label="Email"
                  color="hover:bg-red-600"
                />
                <SocialLink 
                  href="https://www.soundharesh.me" 
                  icon={<Globe className="w-5 h-5" />}
                  label="Website"
                  color="hover:bg-purple-600"
                />
              </div>
            </div>
          </div>
        </div>

        {/* GitHub Repository */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-2xl font-bold text-cyan-400 mb-4 flex items-center gap-2">
            <Github className="w-6 h-6" />
            GitHub Repository
          </h2>
          <p className="text-slate-300 mb-4">
            This project is open source and available on GitHub. Feel free to star, fork, and contribute!
          </p>
          <a 
            href="https://github.com/eshwargit2/WebReconX_Tool" 
            target="_blank" 
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-6 py-3 bg-slate-700 hover:bg-slate-600 border border-slate-600 rounded-lg transition-colors group"
          >
            <Github className="w-5 h-5" />
            <span className="font-semibold">View on GitHub</span>
            <ExternalLink className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </a>
          
          <div className="grid md:grid-cols-3 gap-4 mt-6">
            <div className="bg-slate-900/50 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-cyan-400 mb-1">⭐</div>
              <div className="text-slate-400 text-sm">Star on GitHub</div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-cyan-400 mb-1">🔱</div>
              <div className="text-slate-400 text-sm">Fork the Repo</div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-cyan-400 mb-1">🤝</div>
              <div className="text-slate-400 text-sm">Contribute</div>
            </div>
          </div>
        </div>

        {/* Educational Purpose */}
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6 mb-8">
          <h2 className="text-xl font-bold text-yellow-400 mb-3 flex items-center gap-2">
            ⚠️ Educational Purpose
          </h2>
          <p className="text-slate-300 leading-relaxed">
            This tool is developed for <strong>educational purposes only</strong>. Always ensure you have 
            explicit permission before scanning any website. Unauthorized security testing is illegal and 
            unethical. Use this tool responsibly on test environments or websites you own.
          </p>
        </div>

        {/* Acknowledgments */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-2xl font-bold text-cyan-400 mb-4 flex items-center gap-2">
            <Heart className="w-6 h-6" />
            Acknowledgments
          </h2>
          <ul className="space-y-2 text-slate-300">
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-1">•</span>
              <span>OWASP for web security testing guidelines</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-1">•</span>
              <span>Google Gemini AI for intelligent security analysis</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-1">•</span>
              <span>The open-source community for various tools and libraries</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-1">•</span>
              <span>Test websites (testphp.vulnweb.com, demo.testfire.net) for providing vulnerable environments</span>
            </li>
          </ul>
        </div>

        {/* License */}
        <div className="text-center text-slate-500 py-6 border-t border-slate-700/50">
          <p className="mb-2">© 2026 WebReconX. All rights reserved.</p>
          <p className="text-sm">
            Licensed under MIT License • Built with <Heart className="w-4 h-4 inline text-red-400" /> for the community
          </p>
        </div>
      </div>
    </div>
  );
};

// Helper Components
const FeatureItem = ({ icon, text }) => (
  <div className="flex items-center gap-3 p-3 bg-slate-900/30 rounded-lg border border-slate-700/30">
    {icon}
    <span className="text-slate-300">{text}</span>
  </div>
);

const SocialLink = ({ href, icon, label, color }) => (
  <a
    href={href}
    target="_blank"
    rel="noopener noreferrer"
    className={`flex items-center gap-2 px-4 py-2 bg-slate-700 ${color} border border-slate-600 rounded-lg transition-colors group`}
  >
    {icon}
    <span className="text-sm font-medium">{label}</span>
    <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
  </a>
);

// Import Info icon
const Info = ({ className }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

export default About;
