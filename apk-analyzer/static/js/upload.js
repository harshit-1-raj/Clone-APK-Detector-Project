document.addEventListener('DOMContentLoaded', function() {
    // Get elements
    const dropZoneElement = document.querySelector(".drop-zone");
    const fileInput = document.getElementById('apkFileInput');
    const uploadButton = document.getElementById('uploadButton');
    const statusMessage = document.getElementById('uploadStatus');
    const progressBar = document.getElementById('progressBar');
    const progressBarFill = document.getElementById('progressBarFill');
    const spinner = document.getElementById('loadingSpinner');

    // Disable button initially
    uploadButton.disabled = true;

    // Handle drag & drop functionality
    dropZoneElement.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZoneElement.classList.add("drop-zone--over");
    });

    ["dragleave", "dragend"].forEach((type) => {
    dropZoneElement.addEventListener(type, () => {
        dropZoneElement.classList.remove("drop-zone--over");
    });
    });

    dropZoneElement.addEventListener("drop", (e) => {
    e.preventDefault();
    
    if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        updateThumbnail(dropZoneElement, e.dataTransfer.files[0]);
    }
    
    dropZoneElement.classList.remove("drop-zone--over");
    });

    // When the drop zone is clicked
    dropZoneElement.addEventListener("click", () => {
    fileInput.click();
    });

    // When file is selected via file input
    fileInput.addEventListener("change", () => {
    if (fileInput.files.length) {
        updateThumbnail(dropZoneElement, fileInput.files[0]);
    }
    });

    // Function to update thumbnail and button state
    function updateThumbnail(dropZoneElement, file) {
    let thumbnailElement = dropZoneElement.querySelector(".drop-zone__thumb");

    // First time - remove the prompt
    if (!thumbnailElement) {
        const promptElement = dropZoneElement.querySelector(".drop-zone__prompt");
        if (promptElement) {
        promptElement.remove();
        }
        
        // Create thumbnail element
        thumbnailElement = document.createElement("div");
        thumbnailElement.classList.add("drop-zone__thumb");
        dropZoneElement.appendChild(thumbnailElement);
    }

    // Show the file name
    let fileIcon = '';
    if (file.name.toLowerCase().endsWith('.apk')) {
        fileIcon = '<i class="bi bi-file-earmark-zip text-5xl mb-2"></i>';
    } else {
        fileIcon = '<i class="bi bi-file-earmark-x text-5xl mb-2 text-red-500"></i>';
    }
    
    thumbnailElement.innerHTML = `
        ${fileIcon}
        <div>
        <div class="font-medium">${file.name}</div>
        <div class="text-sm text-gray-500">${formatFileSize(file.size)}</div>
        </div>
    `;

    // File validation
    if (!file.name.toLowerCase().endsWith('.apk')) {
        statusMessage.textContent = 'Please select a valid APK file';
        statusMessage.className = 'status-message text-red-500 mt-3';
        uploadButton.disabled = true;
        return;
    }

    // Check file size (100MB maximum)
    if (file.size > 100 * 1024 * 1024) {
        statusMessage.textContent = 'File size exceeds 100MB limit';
        statusMessage.className = 'status-message text-red-500 mt-3';
        uploadButton.disabled = true;
        return;
    }

    // Update status if valid
    statusMessage.textContent = `${file.name} ready for analysis`;
    statusMessage.className = 'status-message text-green-500 mt-3';
    uploadButton.disabled = false;
    }

    // Handle upload button click
    uploadButton.addEventListener('click', async function() {
    if (!fileInput.files.length) return;
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);

    // Update UI for upload
    uploadButton.disabled = true;
    uploadButton.innerHTML = '<div id="loadingSpinner" class="loading-spinner" style="display: inline-block;"></div><span>Analyzing...</span>';
    progressBar.style.display = 'block';
    statusMessage.textContent = 'Uploading and analyzing APK...';
    statusMessage.className = 'status-message text-blue-500 mt-3';

    try {
        // Simulate progress (since fetch doesn't report progress by default)
        let progress = 0;
        const progressInterval = setInterval(() => {
        progress += 5;
        if (progress > 90) {
            clearInterval(progressInterval);
        }
        progressBarFill.style.width = `${progress}%`;
        }, 500);

        // Send to backend API
        const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData
        });

        clearInterval(progressInterval);
        progressBarFill.style.width = '100%';

        if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Upload failed');
        }

        const result = await response.json();
        
        // Save result and redirect
        statusMessage.textContent = 'Analysis complete! Redirecting to results...';
        statusMessage.className = 'status-message text-green-500 mt-3';
        
        // Store results in sessionStorage
        sessionStorage.setItem('apkAnalysisResult', JSON.stringify(result));
        
        // Redirect to results page after a short delay
        setTimeout(() => {
        window.location.href = '/result';
        }, 1500);
        
    } catch (error) {
        console.error('Error:', error);
        statusMessage.textContent = error.message || 'Analysis failed';
        statusMessage.className = 'status-message text-red-500 mt-3';
        uploadButton.disabled = false;
        uploadButton.innerHTML = '<span>Analyze APK</span>';
        progressBar.style.display = 'none';
    }
    });

    // Format file size
    function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else return (bytes / 1048576).toFixed(1) + ' MB';
    }
});