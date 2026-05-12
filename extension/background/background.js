chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0) {
        const url = details.url;
        if (!url.startsWith('http')) return;
        
        fetch("http://127.0.0.1:8000/scan", {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Scan result for", url, data);
            chrome.storage.local.set({ currentUrlData: data });
            if (data.severity === "Critical" || data.severity === "High") {
                chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId: details.tabId });
            }
        })
        .catch(error => console.error("Error connecting to PhishGuard backend:", error));
    }
});
