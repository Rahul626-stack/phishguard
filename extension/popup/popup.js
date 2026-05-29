document.addEventListener('DOMContentLoaded', () => {
    function renderData(data) {
        const contentDiv = document.getElementById('content');
        let statusClass = "safe";
        let statusText = "SAFE (" + data.risk_score + "%)";

        if (data.severity === "Critical") { statusClass = "critical"; statusText = "CRITICAL RISK (" + data.risk_score + "%)"; }
        else if (data.severity === "High") { statusClass = "critical"; statusText = "HIGH RISK (" + data.risk_score + "%)"; }
        else if (data.severity === "Medium") { statusClass = "warning"; statusText = "MEDIUM RISK (" + data.risk_score + "%)"; }

        let reasonsHtml = data.reasons.map(r => `<li>${r}</li>`).join('');

        contentDiv.innerHTML = `
            <div class="status ${statusClass}">${statusText}</div>
            <div class="details">
                <strong>URL:</strong> <span style="word-break: break-all; color: #cbd5e1;">${data.url.substring(0, 50)}...</span>
                <br><br>
                <strong>Detection Reasons:</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">${reasonsHtml}</ul>
            </div>
        `;
    }

    if (window.location.search.includes('simulated=true')) {
        setTimeout(() => {
            const data = window.parent.getScanResult();
            if (data) {
                renderData(data);
            } else {
                document.getElementById('content').innerHTML = `<div class="loading">No scan data available. Try refreshing.</div>`;
            }
        }, 500); // slight delay to show loading state
    } else if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['currentUrlData'], function (result) {
            if (result.currentUrlData) {
                renderData(result.currentUrlData);
            } else {
                document.getElementById('content').innerHTML = `<div class="loading">No scan data available for this page yet. Try refreshing.</div>`;
            }
        });
    }

    // Handle Open SOC Dashboard click
    const dashboardBtn = document.getElementById('open-dashboard');
    if (dashboardBtn) {
        dashboardBtn.addEventListener('click', () => {
            const dashboardUrl = 'https://phishguard-z998.vercel.app'; // Replace with your actual Vercel dashboard URL
            if (typeof chrome !== 'undefined' && chrome.tabs) {
                chrome.tabs.create({ url: dashboardUrl });
            } else {
                window.open(dashboardUrl, '_blank');
            }
        });
    }
});
