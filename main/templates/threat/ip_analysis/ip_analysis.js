// JavaScript for handling IP analysis functionality

document.getElementById('analyze_button').addEventListener('click', function() {
    const ipAddress = document.getElementById('ip_address').value;
    // Call the backend API to analyze the IP address
    fetch(`/api/analyze_ip?ip=${ipAddress}`)
        .then(response => response.json())
        .then(data => {
            // Update the UI with the results
            document.getElementById('threat_score').innerText = data.threat_score;
            document.getElementById('whois_info').innerHTML = '';
            const whoisTable = document.createElement('table');
            whoisTable.className = 'whois-info-table';
            whoisTable.innerHTML = `<thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>`;
            for (const [key, value] of Object.entries(data.whois_info)) {
                whoisTable.innerHTML += `<tr><td>${key}</td><td>${value}</td></tr>`;
            }
            whoisTable.innerHTML += `</tbody>`;
            document.getElementById('whois_info').appendChild(whoisTable);
            // Update platform scores and tables
            updatePlatformScores(data.results);
        });
});

function updatePlatformScores(results) {
    const platformScoresDiv = document.getElementById('platform_scores');
    platformScoresDiv.innerHTML = '';
    for (const [provider, data] of Object.entries(results)) {
        const scoreDiv = document.createElement('div');
        scoreDiv.innerHTML = `<strong>${provider}</strong>: ${data.score}`;
        platformScoresDiv.appendChild(scoreDiv);
        // Create table for platform response
        const table = document.createElement('table');
        table.className = 'table-responsive';
        table.innerHTML = `<thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>`;
        for (const [key, value] of Object.entries(data)) {
            if (key !== 'score') {
                table.innerHTML += `<tr><td>${key}</td><td>${value}</td></tr>`;
            }
        }
        table.innerHTML += `</tbody>`;
        platformScoresDiv.appendChild(table);
    }
}
