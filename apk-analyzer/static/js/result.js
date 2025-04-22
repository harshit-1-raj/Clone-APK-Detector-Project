document.addEventListener('DOMContentLoaded', function() {
    // Try to get data from both URL params and sessionStorage
    let resultData;
    
    // Check URL for scan_id parameter
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    
    if (scanId) {
    // Get data from API using scan_id
    fetchScanResults(scanId);
    } else {
    // Try to get from sessionStorage
    const storedResult = sessionStorage.getItem('apkAnalysisResult');
    if (storedResult) {
        resultData = JSON.parse(storedResult);
        displayResults(resultData);
    } else {
        // No data found, redirect to upload page
        alert('No scan data found. Please upload an APK file first.');
        window.location.href = 'upload.html';
    }
    }
    
    // Function to fetch results from API
    async function fetchScanResults(id) {
    try {
        const response = await fetch(`/api/results/${id}`);
        if (!response.ok) {
        throw new Error('Failed to fetch results');
        }
        
        resultData = await response.json();
        displayResults(resultData);
    } catch (error) {
        console.error('Error fetching results:', error);
        alert('Failed to load scan results. Please try again.');
    }
    }
    
    // Function to display results
    function displayResults(data) {
    console.log('Displaying results:', data);
    
    // For direct API response
    let analysis = data.analysis || data;
    
    // Basic info
    document.getElementById('appName').textContent = analysis.app_name || 'Unknown App';
    document.getElementById('packageName').textContent = `Package: ${analysis.package_name || 'Unknown'}`;
    document.getElementById('fileName').textContent = data.original_filename || analysis.original_filename || 'Unknown';
    document.getElementById('appVersion').textContent = analysis.version || 'Unknown';
    document.getElementById('scanDate').textContent = formatDate(data.scan_date || analysis.timestamp);
    document.getElementById('fileHash').textContent = analysis.file_hash;
    
    // Safety score
    const safetyScore = Math.round(analysis.overall_safety_score);
    const scoreElement = document.getElementById('safetyScore');
    const scoreCircle = document.getElementById('scoreCircle');
    
    scoreElement.textContent = safetyScore;
    
    // Set color based on score
    let scoreColor;
    if (safetyScore >= 75) {
        scoreColor = '#10b981'; // green
    } else if (safetyScore >= 50) {
        scoreColor = '#f59e0b'; // yellow
    } else {
        scoreColor = '#ef4444'; // red
    }
    
    scoreCircle.style.setProperty('--score-color', scoreColor);
    scoreCircle.style.setProperty('--score-percent', `${safetyScore}%`);
    
    // Assessment badge
    const assessment = analysis.assessment;
    const badgeElement = document.getElementById('assessmentBadge');
    badgeElement.textContent = assessment;
    
    if (assessment === 'Safe') {
        badgeElement.className = 'assessment-badge assessment-safe';
    } else if (assessment === 'Suspicious') {
        badgeElement.className = 'assessment-badge assessment-suspicious';
    } else {
        badgeElement.className = 'assessment-badge assessment-dangerous';
    }
    
    // Recommendations
    const recommendations = analysis.recommendations || [];
    const recommendationsContainer = document.getElementById('recommendationsList');
    
    if (recommendations.length > 0) {
        recommendationsContainer.innerHTML = recommendations.map(rec => 
        `<div class="recommendation-item">${rec}</div>`
        ).join('');
    } else {
        recommendationsContainer.innerHTML = '<p class="text-muted">No specific recommendations available.</p>';
    }
    
    // Permissions analysis
    const permissionAnalysis = analysis.permission_analysis || {};
    document.getElementById('totalPermissions').textContent = permissionAnalysis.total_permissions || 0;
    document.getElementById('dangerousPermissions').textContent = permissionAnalysis.dangerous_count || 0;
    document.getElementById('permissionRiskScore').textContent = Math.round(permissionAnalysis.risk_score || 0);
    
    // Permission list
    const permList = document.getElementById('permissionList');
    const permissions = analysis.permissions || [];
    const dangerousPermissions = permissionAnalysis.dangerous_permissions || [];
    
    if (permissions.length > 0) {
        permList.innerHTML = permissions.map(perm => {
        const isDangerous = dangerousPermissions.includes(perm);
        return `<span class="permission-pill ${isDangerous ? 'dangerous-pill' : ''}">${perm}</span>`;
        }).join(' ');
    } else {
        permList.innerHTML = '<p class="text-muted">No permissions found or required.</p>';
    }
    
    // Clone analysis
    const cloneAnalysis = analysis.clone_analysis || {};
    const cloneContainer = document.getElementById('cloneAnalysisContainer');
    
    if (cloneAnalysis.is_potential_clone) {
        const originalApp = cloneAnalysis.original_app || {};
        cloneContainer.innerHTML = `
        <div class="alert alert-warning">
            <h5 class="alert-heading"><i class="bi bi-exclamation-triangle-fill me-2"></i>Potential Clone Detected!</h5>
            <p>This application appears to be a clone of <strong>${originalApp.name || 'a legitimate app'}</strong>.</p>
            <hr>
            <p class="mb-0">Similarity Score: <strong>${Math.round((cloneAnalysis.similarity_score || 0) * 100)}%</strong></p>
            <p class="mb-0">Original Developer: <strong>${originalApp.developer || 'Unknown'}</strong></p>
        </div>
        `;
    } else if (cloneAnalysis.matched_legitimate_app) {
        cloneContainer.innerHTML = `
        <div class="alert alert-success">
            <h5 class="alert-heading"><i class="bi bi-check-circle-fill me-2"></i>Legitimate Application</h5>
            <p>This appears to be a legitimate application from <strong>${cloneAnalysis.matched_legitimate_app.developer || 'a known developer'}</strong>.</p>
        </div>
        `;
    } else {
        cloneContainer.innerHTML = `
        <div class="alert alert-info">
            <h5 class="alert-heading"><i class="bi bi-info-circle-fill me-2"></i>Not a Known Clone</h5>
            <p>This application does not match any known legitimate applications in our database.</p>
            <p class="mb-0">This doesn't necessarily mean it's safe - please review all analysis results.</p>
        </div>
        `;
    }
    
    // Malware analysis
    const malwarePatterns = analysis.malware_patterns || {};
    const malwareContainer = document.getElementById('malwareAnalysisContainer');
    
    if (malwarePatterns.malware_detected) {
        malwareContainer.innerHTML = `
        <div class="alert alert-danger mb-0">
            <i class="bi bi-bug-fill me-2"></i>
            <strong>Malware Detected</strong>
        </div>
        <div class="mt-3">
            <strong>Detection reasons:</strong>
            <ul class="mt-2 mb-0">
            ${malwarePatterns.detection_reasons.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
        </div>
        `;
    } else {
        malwareContainer.innerHTML = `
        <div class="alert alert-success mb-0">
            <i class="bi bi-shield-check me-2"></i>
            <strong>No Malware Detected</strong>
        </div>
        <p class="text-muted mt-3 mb-0">No known malware patterns were found in this application.</p>
        `;
    }
    
    // Code obfuscation
    const obfuscation = analysis.code_obfuscation || {};
    const obfuscationContainer = document.getElementById('obfuscationContainer');
    
    const obfuscationLevel = obfuscation.obfuscation_level || 0;
    const maxLevel = obfuscation.max_level || 4;
    const obfuscationPercent = (obfuscationLevel / maxLevel) * 100;
    
    obfuscationContainer.innerHTML = `
        <div class="mb-3">Obfuscation Level: <strong>${obfuscationLevel}/${maxLevel}</strong></div>
        // Continuing from the last line of the provided code
        <div class="progress" style="height: 10px;">
        <div class="progress-bar ${obfuscation.is_heavily_obfuscated ? 'bg-warning' : 'bg-success'}" 
                role="progressbar" style="width: ${obfuscationPercent}%" 
                aria-valuenow="${obfuscationPercent}" aria-valuemin="0" aria-valuemax="100"></div>
        </div>
        <div class="mt-3">
        ${obfuscation.is_heavily_obfuscated ? 
            '<div class="text-warning"><i class="bi bi-exclamation-triangle me-1"></i> Heavily obfuscated code can sometimes indicate malicious intent.</div>' : 
            '<div class="text-muted">Normal level of code obfuscation.</div>'}
        </div>
    `;
    
    // Network security
    const networkSecurity = analysis.network_security || {};
    const networkSecurityContainer = document.getElementById('networkSecurityContainer');
    
    if (networkSecurity.issues && networkSecurity.issues.length > 0) {
        networkSecurityContainer.innerHTML = `
        <div class="alert alert-${networkSecurity.critical_issues ? 'danger' : 'warning'} mb-3">
            <i class="bi bi-${networkSecurity.critical_issues ? 'x-circle' : 'exclamation-triangle'}-fill me-2"></i>
            <strong>${networkSecurity.critical_issues ? 'Critical' : 'Minor'} security issues found</strong>
        </div>
        <ul class="mb-0">
            ${networkSecurity.issues.map(issue => `<li>${issue}</li>`).join('')}
        </ul>
        `;
    } else {
        networkSecurityContainer.innerHTML = `
        <div class="alert alert-success mb-0">
            <i class="bi bi-lock-fill me-2"></i>
            <strong>Good Network Security</strong>
        </div>
        <p class="text-muted mt-3 mb-0">The app uses secure network protocols and practices.</p>
        `;
    }
    
    // Technical details
    document.getElementById('virusTotalResults').innerHTML = formatVirusTotalResults(analysis.virus_total);
    document.getElementById('sdkInfo').textContent = formatSdkInfo(analysis.sdk_info);
    
    // Activities list
    const activities = analysis.activities || [];
    const activitiesContainer = document.getElementById('activitiesList');
    
    if (activities.length > 0) {
        activitiesContainer.innerHTML = `
        <ul class="list-group list-group-flush">
            ${activities.map(activity => `
            <li class="list-group-item bg-transparent px-0">
                <span class="font-monospace small">${activity}</span>
            </li>
            `).join('')}
        </ul>
        `;
    } else {
        activitiesContainer.innerHTML = '<p class="text-muted">No activities information available.</p>';
    }
    
    // Set up download report button
    document.getElementById('downloadReportBtn').addEventListener('click', function() {
        generatePDF(analysis);
    });
    }
    
    // Format date helper
    function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    
    try {
        const date = new Date(dateString);
        return date.toLocaleString();
    } catch (e) {
        return dateString;
    }
    }
    
    // Format VirusTotal results
    function formatVirusTotalResults(vtResults) {
    if (!vtResults) return 'Not available';
    
    const { positives, total } = vtResults;
    
    if (typeof positives === 'undefined' || typeof total === 'undefined') {
        return 'Results pending or not available';
    }
    
    let alertClass = 'success';
    if (positives > 0) {
        alertClass = positives < 3 ? 'warning' : 'danger';
    }
    
    return `
        <div class="alert alert-${alertClass} py-2 px-3 mb-0">
        <span class="fw-medium">${positives} / ${total}</span> security vendors flagged this file
        </div>
        ${vtResults.permalink ? `<a href="${vtResults.permalink}" target="_blank" class="small d-inline-block mt-2">View full results</a>` : ''}
    `;
    }
    
    // Format SDK info
    function formatSdkInfo(sdkInfo) {
    if (!sdkInfo) return 'Not available';
    
    const { min_sdk, target_sdk, max_sdk } = sdkInfo;
    
    let result = '';
    if (min_sdk) result += `Min: API ${min_sdk} `;
    if (target_sdk) result += `Target: API ${target_sdk} `;
    if (max_sdk) result += `Max: API ${max_sdk}`;
    
    return result || 'Not specified';
    }
    
    // Generate PDF report 
    function generatePDF(data) {
    // This is a placeholder function - in a real application this would generate a PDF
    // For now we'll create a simple text file to demonstrate the functionality
    
    const appName = data.app_name || 'Unknown App';
    const reportDate = new Date().toISOString().split('T')[0];
    const filename = `${appName}_Security_Report_${reportDate}.txt`;
    
    let reportContent = `
APK SCANNER SECURITY REPORT
===========================
App Name: ${data.app_name || 'Unknown'}
Package: ${data.package_name || 'Unknown'}
Version: ${data.version || 'Unknown'}
Scan Date: ${formatDate(data.timestamp)}

OVERALL ASSESSMENT
-----------------
Safety Score: ${Math.round(data.overall_safety_score)}/100
Assessment: ${data.assessment}

KEY FINDINGS
-----------
`;

    // Add recommendations
    if (data.recommendations && data.recommendations.length > 0) {
        reportContent += `Recommendations:\n`;
        data.recommendations.forEach((rec, i) => {
        reportContent += `${i+1}. ${rec}\n`;
        });
        reportContent += '\n';
    }
    
    // Add permission info
    const permAnalysis = data.permission_analysis || {};
    reportContent += `
PERMISSION ANALYSIS
------------------
Total Permissions: ${permAnalysis.total_permissions || 0}
Dangerous Permissions: ${permAnalysis.dangerous_count || 0}
Permission Risk Score: ${Math.round(permAnalysis.risk_score || 0)}/100
`;

    // Add clone detection
    const cloneAnalysis = data.clone_analysis || {};
    reportContent += `
CLONE DETECTION
--------------
`;
    
    if (cloneAnalysis.is_potential_clone) {
        const originalApp = cloneAnalysis.original_app || {};
        reportContent += `Result: POTENTIAL CLONE DETECTED
Similar to: ${originalApp.name || 'Unknown app'}
Developer: ${originalApp.developer || 'Unknown'}
Similarity Score: ${Math.round((cloneAnalysis.similarity_score || 0) * 100)}%
`;
    } else {
        reportContent += `Result: No clone patterns detected\n`;
    }
    
    // Add security findings
    reportContent += `
SECURITY ANALYSIS
---------------
`;
    
    const malwarePatterns = data.malware_patterns || {};
    if (malwarePatterns.malware_detected) {
        reportContent += `Malware: DETECTED\nReasons:\n`;
        malwarePatterns.detection_reasons.forEach((reason, i) => {
        reportContent += `- ${reason}\n`;
        });
    } else {
        reportContent += `Malware: None detected\n`;
    }
    
    // Create download link
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(reportContent));
    element.setAttribute('download', filename);
    
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    }
});