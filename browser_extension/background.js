chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId === 0) { // Only main frame
    const [tab] = await chrome.tabs.query({active: true, lastFocusedWindow: true});
    if (!tab || !tab.url.startsWith('http')) return;

    // Send to your backend
    fetch('http://localhost:5000/api/detect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        url: tab.url,
        user_agent: navigator.userAgent,
        source_ip: 'browser_extension'
      })
    });
  }
}, {url: [{schemes: ['http', 'https']}]}); 