document.getElementById('checkBtn').addEventListener('click', async () => {
    const resultDiv = document.getElementById('result');
    resultDiv.innerText = "Scanning...";
    resultDiv.className = "";

    // Current Tab se URL lo
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    try {
        const response = await fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        });

        const data = await response.json();
        
        if (data.result === "Safe") {
            resultDiv.innerText = "This site is Safe";
            resultDiv.className = "safe";
        } else {
            resultDiv.innerText = "DANGER: Phishing Detected!";
            resultDiv.className = "danger";
        }
    } catch (error) {
        resultDiv.innerText = "Error: Backend not running!";
    }
});