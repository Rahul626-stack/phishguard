import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Activity, Globe, Download, Zap, ChevronRight, X, ExternalLink, Search, CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';

const initialData = [
  { time: '10:00', detections: 2 },
  { time: '11:00', detections: 5 },
  { time: '12:00', detections: 1 },
  { time: '13:00', detections: 8 },
  { time: '14:00', detections: 12 },
  { time: '15:00', detections: 4 },
];

const initialTldData = [
  { name: '.com', count: 40 },
  { name: '.ru', count: 25 },
  { name: '.tk', count: 18 },
  { name: '.info', count: 12 },
  { name: '.net', count: 8 },
];

const COLORS = ['#38BDF8', '#6366F1', '#A78BFA', '#22C55E', '#FBBF24'];

function App() {
  const [data, setData] = useState(initialData);
  const [tldData, setTldData] = useState(initialTldData);
  const [recentScans, setRecentScans] = useState([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalType, setModalType] = useState('all');
  
  const [scanUrl, setScanUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  
  const [stats, setStats] = useState({
    scanned: 1248,
    blocked: 84,
    alerts: 12,
    nodes: 3
  });

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/stats');
        const json = await res.json();
        if (json.stats) setStats(json.stats);
        if (json.tldData) setTldData(json.tldData.length > 0 ? json.tldData : initialTldData);
        if (json.timelineData && json.timelineData.length > 0) setData(json.timelineData);
        if (json.recentScans) setRecentScans(json.recentScans);
      } catch (err) {
        console.error("Failed to fetch stats:", err);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 2500);

    return () => clearInterval(interval);
  }, []);

  const openModal = (type) => {
    setModalType(type);
    setIsModalOpen(true);
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!scanUrl) return;
    setIsScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('http://127.0.0.1:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl })
      });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      console.error("Failed to scan URL:", err);
      setScanResult({ error: "Failed to connect to scanner API." });
    } finally {
      setIsScanning(false);
    }
  };

  const exportReport = () => {
    if (recentScans.length === 0) {
      alert("No scans available to export yet.");
      return;
    }

    const headers = ['Timestamp', 'Scanned URL', 'Risk Score (%)', 'Severity', 'Reasons'];
    
    const csvRows = recentScans.map(scan => {
      const escapeStr = (str) => `"${String(str || '').replace(/"/g, '""')}"`;
      const reasonsStr = (scan.reasons || []).join('; ');
      
      return [
        escapeStr(scan.time),
        escapeStr(scan.url),
        scan.score,
        escapeStr(scan.severity),
        escapeStr(reasonsStr)
      ].join(',');
    });
    
    const csvContent = [headers.join(','), ...csvRows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    
    const dateStr = new Date().toISOString().split('T')[0];
    link.setAttribute('download', `PhishGuard_Report_${dateStr}.csv`);
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const displayedScans = modalType === 'all' 
    ? recentScans 
    : recentScans.filter(s => s.severity === 'High' || s.severity === 'Critical');

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white/90 backdrop-blur-xl border border-white/40 p-4 rounded-xl shadow-xl">
          <p className="text-[#64748B] text-sm mb-2">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-[#0F172A] font-bold text-sm flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }}></span>
              {entry.value} {entry.name === 'detections' ? 'Threats Detected' : 'Total Scans'}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] bg-gradient-to-br from-[#EEF4FF] via-[#F8FAFC] to-[#F3E8FF] text-[#0F172A] p-4 md:p-8 font-sans selection:bg-[#38BDF8]/30">
      
      {/* Header */}
      <header className="mb-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="relative group cursor-pointer">
            <div className="absolute inset-0 bg-[#38BDF8] rounded-xl blur-md opacity-40 group-hover:opacity-70 transition-opacity duration-500"></div>
            <div className="relative bg-white/65 backdrop-blur-md border border-white/40 p-3 rounded-xl flex items-center justify-center shadow-sm">
              <Shield className="w-8 h-8 text-[#38BDF8]" />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-[#0F172A] via-[#6366F1] to-[#38BDF8] bg-clip-text text-transparent">
              PhishGuard SOC
            </h1>
            <p className="text-[#64748B] text-sm font-medium flex items-center gap-1.5 mt-1">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#38BDF8] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#38BDF8]"></span>
              </span>
              Active Threat Intelligence Monitoring
            </p>
          </div>
        </div>
        <button 
          onClick={exportReport}
          className="group relative px-6 py-2.5 rounded-xl font-semibold text-sm transition-all duration-300 hover:scale-105"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-[#38BDF8] to-[#6366F1] rounded-xl opacity-0 group-hover:opacity-100 blur transition-opacity"></div>
          <div className="relative flex items-center gap-2 bg-white/90 backdrop-blur-md px-6 py-2.5 rounded-xl border border-white/40 text-[#0F172A] shadow-sm">
            <Download className="w-4 h-4 text-[#38BDF8]" />
            Export Report
          </div>
        </button>
      </header>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
        {[
          { label: 'Total Scanned', value: stats.scanned.toLocaleString(), icon: Globe, color: 'text-[#38BDF8]', glow: 'shadow-[#38BDF8]/20', action: () => openModal('all') },
          { label: 'Critical Alerts', value: stats.alerts.toLocaleString(), icon: AlertTriangle, color: 'text-[#F87171]', glow: 'shadow-[#F87171]/20', action: () => openModal('threats') },
          { label: 'Active ML Nodes', value: stats.nodes.toLocaleString(), icon: Activity, color: 'text-[#A78BFA]', glow: 'shadow-[#A78BFA]/20' }
        ].map((stat, i) => (
          <div 
            key={i} 
            onClick={stat.action}
            className={`group relative bg-white/65 backdrop-blur-xl border border-white/40 p-6 rounded-2xl shadow-[0_8px_30px_rgb(0,0,0,0.04)] hover:-translate-y-1 transition-all duration-300 overflow-hidden ${stat.action ? 'cursor-pointer hover:bg-white/80' : ''}`}
          >
            {/* Background Gradient Blob */}
            <div className={`absolute -right-10 -top-10 w-32 h-32 bg-[#38BDF8]/10 rounded-full blur-3xl group-hover:bg-[#38BDF8]/20 transition-colors duration-500`}></div>
            
            <div className="flex justify-between items-start mb-4 relative z-10">
              <div className={`p-3 rounded-xl bg-white/80 border border-white/40 ${stat.glow} shadow-sm`}>
                <stat.icon className={`w-5 h-5 ${stat.color}`} />
              </div>
              {stat.action && (
                <button className="text-[#64748B] group-hover:text-[#0F172A] transition-colors">
                  <ChevronRight className="w-5 h-5" />
                </button>
              )}
            </div>
            
            <div className="relative z-10">
              <p className="text-[#64748B] text-sm font-medium mb-1">{stat.label}</p>
              <div className="flex items-baseline gap-2">
                <p className="text-3xl font-bold text-[#0F172A] tracking-tight">{stat.value}</p>
                {i === 0 && <span className="text-xs font-semibold text-[#38BDF8] flex items-center"><Zap className="w-3 h-3 mr-0.5"/> Live</span>}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Scanner */}
      <div className="bg-white/65 backdrop-blur-xl border border-white/40 p-6 md:p-8 rounded-3xl shadow-[0_8px_30px_rgb(0,0,0,0.04)] relative overflow-hidden mb-10">
        <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-[#6366F1]/10 to-[#38BDF8]/10 rounded-full blur-3xl -z-10 translate-x-1/2 -translate-y-1/2"></div>
        
        <div className="flex flex-col md:flex-row items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-bold text-[#0F172A] flex items-center gap-2">
              <Search className="w-5 h-5 text-[#6366F1]" />
              Manual Threat Analysis
            </h2>
            <p className="text-[#64748B] text-sm mt-1">Instantly scan any URL against our ML and active intelligence pipeline.</p>
          </div>
        </div>

        <form onSubmit={handleScan} className="relative flex items-center mb-4">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
            <Globe className="w-5 h-5 text-[#94A3B8]" />
          </div>
          <input 
            type="text" 
            value={scanUrl}
            onChange={(e) => setScanUrl(e.target.value)}
            placeholder="https://example.com/login" 
            className="w-full pl-12 pr-32 py-4 bg-white/80 border border-[#E2E8F0] rounded-2xl focus:outline-none focus:ring-2 focus:ring-[#38BDF8]/50 focus:border-[#38BDF8] transition-all shadow-sm text-[#0F172A] placeholder:text-[#94A3B8]"
            required
          />
          <button 
            type="submit" 
            disabled={isScanning || !scanUrl}
            className="absolute right-2 top-2 bottom-2 px-6 bg-[#0F172A] text-white font-medium rounded-xl hover:bg-[#1E293B] disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {isScanning ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</>
            ) : (
              'Analyze'
            )}
          </button>
        </form>

        {/* Scan Result Dropdown */}
        {scanResult && (
          <div className={`mt-4 p-5 rounded-2xl border backdrop-blur-md animate-in fade-in slide-in-from-top-2 duration-300 ${
            scanResult.error ? 'bg-red-50/50 border-red-200' :
            scanResult.severity === 'Critical' ? 'bg-[#FEF2F2]/80 border-[#FECACA]' :
            scanResult.severity === 'High' ? 'bg-[#FFFBEB]/80 border-[#FDE68A]' :
            scanResult.severity === 'Medium' ? 'bg-[#F5F3FF]/80 border-[#DDD6FE]' :
            'bg-[#F0FDF4]/80 border-[#BBF7D0]'
          }`}>
            {scanResult.error ? (
              <p className="text-[#EF4444] font-medium flex items-center gap-2"><AlertTriangle className="w-5 h-5"/> {scanResult.error}</p>
            ) : (
              <div className="flex flex-col md:flex-row gap-6 md:items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`w-16 h-16 rounded-2xl flex items-center justify-center shrink-0 ${
                    scanResult.severity === 'Critical' ? 'bg-[#F87171] shadow-[0_0_15px_rgba(248,113,113,0.4)]' :
                    scanResult.severity === 'High' ? 'bg-[#FBBF24] shadow-[0_0_15px_rgba(251,191,36,0.4)]' :
                    scanResult.severity === 'Medium' ? 'bg-[#A78BFA] shadow-[0_0_15px_rgba(167,139,250,0.4)]' :
                    'bg-[#22C55E] shadow-[0_0_15px_rgba(34,197,94,0.4)]'
                  }`}>
                    {scanResult.severity === 'Critical' || scanResult.severity === 'High' ? (
                      <AlertTriangle className="w-8 h-8 text-white" />
                    ) : scanResult.severity === 'Medium' ? (
                      <Shield className="w-8 h-8 text-white" />
                    ) : (
                      <CheckCircle className="w-8 h-8 text-white" />
                    )}
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-[#0F172A] mb-1">
                      {scanResult.risk_score}% Risk Score
                    </h3>
                    <p className={`text-sm font-semibold uppercase tracking-wider ${
                      scanResult.severity === 'Critical' ? 'text-[#EF4444]' :
                      scanResult.severity === 'High' ? 'text-[#D97706]' :
                      scanResult.severity === 'Medium' ? 'text-[#7C3AED]' :
                      'text-[#16A34A]'
                    }`}>
                      {scanResult.severity} THREAT
                    </p>
                  </div>
                </div>

                <div className="flex-1 bg-white/60 rounded-xl p-4 border border-white/40">
                  <p className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-2">Detection Context</p>
                  <ul className="space-y-1.5">
                    {scanResult.reasons.map((reason, idx) => (
                      <li key={idx} className="text-sm text-[#0F172A] flex items-start gap-2">
                        <span className={`shrink-0 mt-1 w-1.5 h-1.5 rounded-full ${
                          scanResult.severity === 'Critical' || scanResult.severity === 'High' ? 'bg-[#EF4444]' : 'bg-[#38BDF8]'
                        }`}></span>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Main Chart */}
        <div className="lg:col-span-2 bg-white/65 backdrop-blur-xl border border-white/40 p-6 rounded-3xl shadow-[0_8px_30px_rgb(0,0,0,0.04)] relative overflow-hidden group">
          <div className="absolute top-0 left-1/4 w-1/2 h-px bg-gradient-to-r from-transparent via-[#38BDF8]/50 to-transparent"></div>
          
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-lg font-semibold text-[#0F172A] flex items-center gap-2">
              <Activity className="w-5 h-5 text-[#38BDF8]" />
              Real-time Detection Volume
            </h2>
            <div className="flex items-center gap-2 text-xs font-medium bg-white/80 px-3 py-1.5 rounded-full border border-white/40 text-[#64748B] shadow-sm">
              <span className="w-2 h-2 rounded-full bg-[#38BDF8] animate-pulse"></span>
              Last 6 Hours
            </div>
          </div>
          
          <div className="h-[320px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorDetections" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F87171" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#F87171" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#6366F1" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.06)" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" tick={{fill: '#64748B', fontSize: 12}} axisLine={false} tickLine={false} dy={10} />
                <YAxis stroke="#64748B" tick={{fill: '#64748B', fontSize: 12}} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(0,0,0,0.1)', strokeWidth: 1, strokeDasharray: '4 4' }} />
                <Area 
                  type="monotone" 
                  dataKey="scans" 
                  stroke="#38BDF8" 
                  strokeWidth={3} 
                  fillOpacity={1} 
                  fill="url(#colorScans)" 
                  activeDot={{ r: 6, fill: '#38BDF8', stroke: '#F8FAFC', strokeWidth: 2 }} 
                  isAnimationActive={true} 
                  animationDuration={800}
                />
                <Area 
                  type="monotone" 
                  dataKey="detections" 
                  stroke="#F87171" 
                  strokeWidth={3} 
                  fillOpacity={1} 
                  fill="url(#colorDetections)" 
                  activeDot={{ r: 6, fill: '#F87171', stroke: '#F8FAFC', strokeWidth: 2 }} 
                  isAnimationActive={true} 
                  animationDuration={800}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Secondary Chart */}
        <div className="bg-white/65 backdrop-blur-xl border border-white/40 p-6 rounded-3xl shadow-[0_8px_30px_rgb(0,0,0,0.04)] relative">
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-lg font-semibold text-[#0F172A] flex items-center gap-2">
              <Globe className="w-5 h-5 text-[#A78BFA]" />
              Targeted TLDs
            </h2>
          </div>
          
          <div className="h-[320px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={tldData} layout="vertical" margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.06)" horizontal={false} />
                <XAxis type="number" stroke="#64748B" axisLine={false} tickLine={false} tick={{fill: '#64748B', fontSize: 12}} />
                <YAxis dataKey="name" type="category" stroke="#0F172A" axisLine={false} tickLine={false} width={50} tick={{fontSize: 13, fontWeight: 500}} />
                <Tooltip cursor={{fill: 'rgba(99, 102, 241, 0.05)'}} content={<CustomTooltip />} />
                <Bar 
                  dataKey="count" 
                  radius={[0, 6, 6, 0]} 
                  barSize={24}
                  isAnimationActive={true} 
                  animationDuration={800}
                >
                  {tldData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop */}
          <div 
            className="absolute inset-0 bg-[#0F172A]/40 backdrop-blur-sm"
            onClick={() => setIsModalOpen(false)}
          ></div>
          
          {/* Modal Content */}
          <div className="relative bg-[#F8FAFC] border border-white/40 w-full max-w-4xl max-h-[80vh] rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between p-6 border-b border-black/5 bg-white/50">
              <h2 className="text-xl font-bold text-[#0F172A] flex items-center gap-2">
                {modalType === 'threats' ? <Shield className="w-5 h-5 text-[#F87171]" /> : <Globe className="w-5 h-5 text-[#38BDF8]" />}
                {modalType === 'threats' ? 'Identified Threats' : 'Recent Scans'}
              </h2>
              <button 
                onClick={() => setIsModalOpen(false)}
                className="p-2 hover:bg-black/5 rounded-lg text-[#64748B] hover:text-[#0F172A] transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="overflow-y-auto p-6 flex-1 bg-[#EEF4FF]/50">
              {displayedScans.length === 0 ? (
                <div className="text-center text-[#64748B] py-10">
                  No {modalType === 'threats' ? 'threats' : 'scans'} recorded yet. Test a URL to see it here!
                </div>
              ) : (
                <div className="space-y-3">
                  {displayedScans.map((scan, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-white border border-black/5 p-4 rounded-xl shadow-sm hover:shadow-md transition-all">
                      <div className="flex items-center gap-4 truncate">
                        <div className={`shrink-0 w-2 h-2 rounded-full ${
                          scan.severity === 'Critical' ? 'bg-[#F87171] shadow-[0_0_8px_#F87171]' : 
                          scan.severity === 'High' ? 'bg-[#FBBF24] shadow-[0_0_8px_#FBBF24]' : 
                          scan.severity === 'Medium' ? 'bg-[#A78BFA] shadow-[0_0_8px_#A78BFA]' : 
                          'bg-[#22C55E]'
                        }`}></div>
                        <div className="truncate">
                          <p className="text-[#0F172A] font-medium truncate mb-1">{scan.url}</p>
                          <p className="text-xs text-[#64748B] flex gap-3">
                            <span>Time: {scan.time}</span>
                            <span className={`font-semibold ${
                              scan.severity === 'Critical' || scan.severity === 'High' ? 'text-[#F87171]' : 'text-[#64748B]'
                            }`}>
                              Risk: {scan.score}% ({scan.severity})
                            </span>
                          </p>
                        </div>
                      </div>
                      <a 
                        href={scan.url} 
                        target="_blank" 
                        rel="noreferrer"
                        className="ml-4 shrink-0 p-2 text-[#64748B] hover:text-[#38BDF8] hover:bg-[#38BDF8]/10 rounded-lg transition-colors"
                        title="Open Link"
                      >
                        <ExternalLink className="w-4 h-4" />
                      </a>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
