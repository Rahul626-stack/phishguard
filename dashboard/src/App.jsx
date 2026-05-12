import { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity, Globe } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const dummyData = [
  { time: '10:00', detections: 2 },
  { time: '11:00', detections: 5 },
  { time: '12:00', detections: 1 },
  { time: '13:00', detections: 8 },
  { time: '14:00', detections: 12 },
  { time: '15:00', detections: 4 },
];

const tldData = [
  { name: '.com', count: 40 },
  { name: '.ru', count: 25 },
  { name: '.tk', count: 18 },
  { name: '.info', count: 12 },
];

function App() {
  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8">
      <header className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="bg-sky-500/20 p-2 rounded-lg">
            <Shield className="w-8 h-8 text-sky-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-sky-400 to-indigo-400 bg-clip-text text-transparent">PhishGuard SOC</h1>
            <p className="text-slate-400 text-sm">Active Threat Intelligence Dashboard</p>
          </div>
        </div>
        <button className="px-4 py-2 bg-indigo-500 hover:bg-indigo-600 rounded-md font-medium transition-colors shadow-lg shadow-indigo-500/20">
          Export Report
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Total Scanned', value: '1,248', icon: Globe, color: 'text-indigo-400', bg: 'bg-indigo-500/10' },
          { label: 'Threats Blocked', value: '84', icon: Shield, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
          { label: 'Critical Alerts', value: '12', icon: AlertTriangle, color: 'text-rose-400', bg: 'bg-rose-500/10' },
          { label: 'Active ML Nodes', value: '3', icon: Activity, color: 'text-sky-400', bg: 'bg-sky-500/10' }
        ].map((stat, i) => (
          <div key={i} className="bg-slate-800 border border-slate-700 p-6 rounded-xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:scale-110 transition-transform">
              <stat.icon className={`w-16 h-16 ${stat.color}`} />
            </div>
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center mb-4 ${stat.bg}`}>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <p className="text-slate-400 text-sm font-medium">{stat.label}</p>
            <p className="text-3xl font-bold mt-1">{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl">
          <h2 className="text-lg font-bold mb-6 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400" />
            Detection Timeline
          </h2>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={dummyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis dataKey="time" stroke="#94a3b8" tick={{fill: '#94a3b8'}} axisLine={false} />
                <YAxis stroke="#94a3b8" tick={{fill: '#94a3b8'}} axisLine={false} />
                <Tooltip contentStyle={{backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px'}} />
                <Line type="monotone" dataKey="detections" stroke="#818cf8" strokeWidth={3} dot={{r: 4, fill: '#818cf8', strokeWidth: 2}} activeDot={{r: 6}} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl">
          <h2 className="text-lg font-bold mb-6 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            Most Abused TLDs
          </h2>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={tldData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                <XAxis type="number" stroke="#94a3b8" axisLine={false} tick={{fill: '#94a3b8'}} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" axisLine={false} tick={{fill: '#94a3b8'}} />
                <Tooltip cursor={{fill: '#334155'}} contentStyle={{backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px'}} />
                <Bar dataKey="count" fill="#38bdf8" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
