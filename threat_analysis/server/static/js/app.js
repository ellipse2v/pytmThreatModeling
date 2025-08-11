document.addEventListener('DOMContentLoaded', function() {
    const svgContainer = document.getElementById('svg-container');
    const svgWrapper = document.getElementById('svg-wrapper');
    const legendContainer = document.getElementById('legend-container');
    const errorMessageDiv = document.getElementById('errorMessage');
    let debounceTimer;
    let panZoomInstance;
    let protocolVisibilityState = {}; // Stores { 'protocol_name': 'hidden' / 'visible' }

    // Initialize CodeMirror
    const editor = CodeMirror.fromTextArea(document.getElementById('markdown-editor'), {
        mode: 'markdown',
        theme: 'material',
        lineNumbers: true,
        lineWrapping: true,
    });

    // Set initial markdown content from server
    editor.setValue(atob("{{ initial_markdown | e }}"));

    // Initialize Split.js
    Split(['#editor-split', '#preview-split'], {
        sizes: [50, 50],
        minSize: 200,
        gutterSize: 10,
        cursor: 'col-resize'
    });

    editor.on('change', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(updatePreview, 500); // Debounce requests
    });

    function showErrorMessage(message) {
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
    }

    function hideErrorMessage() {
        errorMessageDiv.textContent = '';
        errorMessageDiv.style.display = 'none';
    }

    // Add event listener for legend item clicks using event delegation
    legendContainer.addEventListener('click', (event) => {
        const legendItem = event.target.closest('.legend-item');
        if (legendItem) {
            const protocolClass = legendItem.dataset.protocol;
            if (protocolClass) {
                toggleProtocolVisibility(protocolClass);
            }
        }
    });

    async function updatePreview() {
        hideErrorMessage(); // Clear previous errors
        const markdownContent = editor.getValue();
        try {
            const response = await fetch('/api/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ markdown: markdownContent }),
            });
            if (!response.ok) {
                const errorData = await response.json();
                showErrorMessage(`Error updating diagram: ${errorData.error}`);
                svgWrapper.innerHTML = ''; // Clear diagram on error
                legendContainer.innerHTML = '';
                if (panZoomInstance) {
                    panZoomInstance.destroy();
                    panZoomInstance = null;
                }
                return;
            }
            const data = await response.json();

            // Destroy previous instance if it exists
            if (panZoomInstance) {
                panZoomInstance.destroy();
            }

            // Update SVG and Legend
            svgWrapper.innerHTML = data.diagram_svg;
            legendContainer.innerHTML = data.legend_html;

            // Update the model name in the header
            const modelNameSpan = document.querySelector('.header h1 span');
            if (modelNameSpan) {
                modelNameSpan.textContent = `- ${data.model_name}`;
            }

            // Apply current visibility state to the newly loaded SVG
            applyProtocolVisibility();

            // Initialize svg-pan-zoom
            const svgElement = svgWrapper.querySelector('svg');
            if (svgElement) {
                panZoomInstance = svgPanZoom(svgElement, {
                    zoomEnabled: true,
                    panEnabled: true,
                    controlIconsEnabled: false, // Disable default controls
                    fit: true,
                    center: true,
                    minZoom: 0.1,
                    maxZoom: 10
                });
            }

        } catch (error) {
            showErrorMessage(`Failed to fetch preview: ${error.message}`);
            svgWrapper.innerHTML = ''; // Clear diagram on error
            legendContainer.innerHTML = '';
             if (panZoomInstance) {
                panZoomInstance.destroy();
                panZoomInstance = null;
            }
        }
    }

    function saveMarkdown() {
        const markdownContent = editor.getValue();
        const blob = new Blob([markdownContent], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat_model.md';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async function exportFile(format) {
        const markdownContent = editor.getValue();
        try {
            const response = await fetch('/api/export', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ markdown: markdownContent, format: format }),
            });
            if (!response.ok) {
                const errorData = await response.json();
                alert(`Export failed: ${errorData.error}`);
                return;
            }
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = response.headers.get('Content-Disposition')?.split('filename=')[1] || `export.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Export error:', error);
            alert('An error occurred during export.');
        }
    }

    async function exportAllFiles() {
        const markdownContent = editor.getValue();
        try {
            const response = await fetch('/api/export_all', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ markdown: markdownContent }),
            });
            if (!response.ok) {
                const errorData = await response.json();
                alert(`Export All failed: ${errorData.error}`);
                return;
            }
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = response.headers.get('Content-Disposition')?.split('filename=')[1] || 'threat_model_export.zip';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Export All error:', error);
            alert('An error occurred during export all.');
        }
    }

    // Function to load markdown from a file
    function loadMarkdownFile(event) {
        const file = event.target.files[0];
        if (!file) {
            return;
        }
        const reader = new FileReader();
        reader.onload = (e) => {
            editor.setValue(e.target.result);
        };
        reader.readAsText(file);
    }

    // Initial empty state
    updatePreview();

    // Fonction pour masquer/afficher les éléments SVG par protocole
    function toggleProtocolVisibility(protocolClass) {
        // Update the state
        if (protocolVisibilityState[protocolClass] === 'hidden') {
            protocolVisibilityState[protocolClass] = 'visible';
        } else {
            protocolVisibilityState[protocolClass] = 'hidden';
        }
         console.log(`Toggling ${protocolClass} to ${protocolVisibilityState[protocolClass]}`);
        // Apply the new state
        applyProtocolVisibility();
    }

    // Function to apply the current visibility state to SVG elements
    function applyProtocolVisibility() {
        const svg = svgWrapper.querySelector('svg');
        if (!svg) return;

        for (const protocolClass in protocolVisibilityState) {
            const elements = svg.querySelectorAll(`.${protocolClass}`);
            const isHidden = protocolVisibilityState[protocolClass] === 'hidden';

            console.log(`Applying state for ${protocolClass}: ${isHidden ? 'hidden' : 'visible'}. Found ${elements.length} elements.`);

            elements.forEach(el => {
                if (isHidden) {
                    el.classList.add('svg-element-hidden');
                } else {
                    el.classList.remove('svg-element-hidden');
                }
            });
        }
    }
});
