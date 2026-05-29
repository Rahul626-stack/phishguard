document.addEventListener('DOMContentLoaded', () => {
    function renderData(data) {
        const contentDiv = document.getElementById('content');
        contentDiv.textContent = ''; // Clear securely

        let statusClass = "safe";
        let statusText = "SAFE (" + data.risk_score + "%)";

        if (data.severity === "Critical") { statusClass = "critical"; statusText = "CRITICAL RISK (" + data.risk_score + "%)"; }
        else if (data.severity === "High") { statusClass = "critical"; statusText = "HIGH RISK (" + data.risk_score + "%)"; }
        else if (data.severity === "Medium") { statusClass = "warning"; statusText = "MEDIUM RISK (" + data.risk_score + "%)"; }

        // Status Div
        const statusDiv = document.createElement('div');
        statusDiv.className = `status ${statusClass}`;
        statusDiv.textContent = statusText;
        contentDiv.appendChild(statusDiv);

        // Details Container
        const detailsDiv = document.createElement('div');
        detailsDiv.className = 'details';

        // URL label and span
        const urlStrong = document.createElement('strong');
        urlStrong.textContent = 'URL: ';
        detailsDiv.appendChild(urlStrong);

        const urlSpan = document.createElement('span');
        urlSpan.style.wordBreak = 'break-all';
        urlSpan.style.color = '#cbd5e1';
        urlSpan.textContent = data.url.substring(0, 50) + (data.url.length > 50 ? '...' : '');
        detailsDiv.appendChild(urlSpan);

        detailsDiv.appendChild(document.createElement('br'));
        detailsDiv.appendChild(document.createElement('br'));

        // Reasons Label
        const reasonsStrong = document.createElement('strong');
        reasonsStrong.textContent = 'Detection Reasons:';
        detailsDiv.appendChild(reasonsStrong);

        // Reasons List
        const reasonsUl = document.createElement('ul');
        reasonsUl.style.margin = '10px 0';
        reasonsUl.style.paddingLeft = '20px';

        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            reasonsUl.appendChild(li);
        });
        detailsDiv.appendChild(reasonsUl);

        contentDiv.appendChild(detailsDiv);
    }

    function showMessage(msg) {
        const contentDiv = document.getElementById('content');
        contentDiv.textContent = '';
        const msgDiv = document.createElement('div');
        msgDiv.className = 'loading';
        msgDiv.textContent = msg;
        contentDiv.appendChild(msgDiv);
    }

    if (window.location.search.includes('simulated=true')) {
        setTimeout(() => {
            const data = window.parent.getScanResult();
            if (data) {
                renderData(data);
            } else {
                showMessage("No scan data available. Try refreshing.");
            }
        }, 500); // slight delay to show loading state
    } else if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['currentUrlData'], function (result) {
            if (result.currentUrlData) {
                renderData(result.currentUrlData);
            } else {
                showMessage("No scan data available for this page yet. Try refreshing.");
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
