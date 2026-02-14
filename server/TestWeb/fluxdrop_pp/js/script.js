//
// script.js
//
// This file contains all the JavaScript logic and event listeners for the FluxDrop Preview Program.
// All the JavaScript logic from the original HTML file is placed here.
//

document.addEventListener('DOMContentLoaded', () => {
    //
    // DOM Element References
    //
    const dropZone = document.getElementById('drop-zone');
    const dropZoneOverlay = document.getElementById('drop-zone-overlay');
    const fileInput = document.getElementById('file-input');
    const fileList = document.getElementById('file-list');
    const currentPathElement = document.getElementById('current-path');
    const pathSegmentsContainer = document.getElementById('path-segments');
    const uploadButton = document.getElementById('upload-button');
    const newFolderButton = document.getElementById('new-folder-button');
    const toggleSelectionButton = document.getElementById('toggle-selection-button');
    const deleteSelectedButton = document.getElementById('delete-selected-button');
    const copySelectedButton = document.getElementById('copy-selected-button');
    const moveSelectedButton = document.getElementById('move-selected-button');
    const clearSelectionButton = document.getElementById('clear-selection-button');

    const modals = {
        'agreement-modal': document.getElementById('agreement-modal'),
        'agreement-required-modal': document.getElementById('agreement-required-modal'),
        'confirmation-modal': document.getElementById('confirmation-modal'),
        'executable-warning-modal': document.getElementById('executable-warning-modal'),
        'preview-modal': document.getElementById('preview-modal'),
        'terms-modal': document.getElementById('terms-modal'),
        'message-modal': document.getElementById('message-modal'),
        'loading-modal': document.getElementById('loading-modal'),
        'destination-chooser-modal': document.getElementById('destination-chooser-modal')
    };

    const modalButtons = {
        'agreement-decline-button': document.getElementById('agreement-decline-button'),
        'agreement-agree-button': document.getElementById('agreement-agree-button'),
        'terms-confirm-button': document.getElementById('terms-confirm-button'),
        'terms-view-button': document.getElementById('terms-view-button'),
        'privacy-view-button': document.getElementById('privacy-view-button'),
        'agreement-required-ok-button': document.getElementById('agreement-required-ok-button'),
        'confirmation-yes-button': document.getElementById('confirmation-yes-button'),
        'confirmation-no-button': document.getElementById('confirmation-no-button'),
        'executable-warning-yes-button': document.getElementById('executable-warning-yes-button'),
        'executable-warning-no-button': document.getElementById('executable-warning-no-button'),
        'preview-close-button': document.getElementById('preview-close-button'),
        'message-ok-button': document.getElementById('message-ok-button'),
        'loading-close-button': document.getElementById('loading-close-button'),
        'destination-back-button': document.getElementById('destination-back-button'),
        'choose-destination-button': document.getElementById('choose-destination-button'),
        'cancel-destination-button': document.getElementById('cancel-destination-button')
    };

    //
    // State Management
    //
    let currentPath = '';
    let isAgreed = localStorage.getItem('fluxdrop_agreement') === 'true';
    let currentOperationType = null; // 'copy' or 'move'
    let selectedItems = []; // Array of selected file/folder paths
    let isSelectionMode = false;
    let confirmationPromise = null;
    let previewContent = null; // Stores the content to be displayed in the preview modal
    let previewType = null; // 'image', 'video', 'audio', 'text', 'markdown', 'iframe', 'unknown'
    let currentDestinationPath = '';

    const translations = {
        en: {
            // General
            appName: 'FluxDrop',
            loadingMessage: 'Loading...',
            success: 'Success',
            error: 'Error',
            warning: 'Warning',
            processing: 'Processing',
            // Agreement Modal
            agreementTitle: 'User Agreement and Terms',
            agreementText: 'By using FluxDrop, you agree to our Terms of Service and Privacy Policy. These terms govern your use of the service and outline our data handling practices. It is important to read and understand them before proceeding.',
            viewTerms: 'View Terms',
            viewPrivacy: 'View Privacy Policy',
            agree: 'Agree',
            decline: 'Decline',
            // Agreement Required Modal
            agreementRequiredTitle: 'Agreement Required',
            agreementRequiredMessage: 'You must agree to the terms to use the FluxDrop service. Please click "Agree" to continue.',
            ok: 'OK',
            // File Manager
            filesAndFolders: 'Files and Folders',
            upload: 'Upload',
            newFolder: 'New Folder',
            toggleSelection: 'Toggle Selection',
            deleteSelected: 'Delete Selected',
            copySelected: 'Copy Selected',
            moveSelected: 'Move Selected',
            clearSelection: 'Clear Selection',
            noItems: 'No files or folders in this directory.',
            noItemsSelectedMessage: 'No items are selected.',
            selectItemsToDelete: 'Select items to delete.',
            selectionModeTitle: 'Selection Mode',
            exitSelectionMode: 'Exit Selection Mode',
            // Preview Modal
            previewTitle: 'File Preview',
            unsupportedFileType: 'Unsupported file type for preview.',
            download: 'Download',
            previewInNewTab: 'Preview in New Tab',
            // Confirmation Modal
            confirmationTitle: 'Confirmation',
            confirmationMessage: 'Are you sure you want to proceed?',
            yes: 'Yes',
            no: 'No',
            // Executable Warning
            executableWarningTitle: 'Executable File Warning',
            executableWarningMessage: 'This file may contain executable code. Running it could be a security risk. Are you sure you want to proceed?',
            // New Folder Modal
            newFolderTitle: 'Create New Folder',
            newFolderMessage: 'Enter the name for the new folder:',
            newFolderNamePlaceholder: 'Folder name...',
            create: 'Create',
            cancel: 'Cancel',
            // Delete Confirmation
            deleteConfirmMessage: (count) => `Are you sure you want to delete ${count} selected item(s)? This action cannot be undone.`,
            // Destination Chooser
            destinationChooserTitle: 'Choose Destination',
            destinationMessage: 'Select a destination folder for the operation.',
            chooseDestination: 'Choose Destination',
            copyOperationMessage: (count, path) => `Copying ${count} item(s) to "${path}"`,
            moveOperationMessage: (count, path) => `Moving ${count} item(s) to "${path}"`,
            operationCancelled: 'Operation cancelled.',
        }
    };
    const currentLanguage = 'en';

    //
    // Helper Functions
    //
    const getTranslatedString = (key, ...args) => {
        const value = translations[currentLanguage][key];
        if (typeof value === 'function') {
            return value(...args);
        }
        return value || key; // Return key if translation is not found
    };

    function showModal(id) {
        const modal = modals[id];
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    function hideModal(id) {
        const modal = modals[id];
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    function showMessage(title, message, isHtml = false) {
        document.getElementById('message-title').textContent = title;
        const messageTextElement = document.getElementById('message-text');
        if (isHtml) {
            messageTextElement.innerHTML = message;
        } else {
            messageTextElement.textContent = message;
        }
        showModal('message-modal');
    }

    function showConfirmation(message) {
        document.getElementById('confirmation-text').textContent = message;
        showModal('confirmation-modal');
        return new Promise((resolve) => {
            confirmationPromise = resolve;
        });
    }

    function showExecutableWarning() {
        document.getElementById('executable-warning-text').textContent = getTranslatedString('executableWarningMessage');
        showModal('executable-warning-modal');
        return new Promise((resolve) => {
            confirmationPromise = resolve;
        });
    }

    function showLoading(message) {
        document.getElementById('loading-message').textContent = message;
        showModal('loading-modal');
    }

    function hideLoading() {
        hideModal('loading-modal');
    }

    function generateRipple(event) {
        const button = event.currentTarget;
        const rect = button.getBoundingClientRect();
        const ripple = document.createElement('span');
        const diameter = Math.max(rect.width, rect.height);
        const radius = diameter / 2;

        ripple.style.width = ripple.style.height = `${diameter}px`;
        ripple.style.left = `${event.clientX - rect.left - radius}px`;
        ripple.style.top = `${event.clientY - rect.top - radius}px`;
        ripple.classList.add('ripple');
        button.appendChild(ripple);

        // Remove the ripple element after the animation
        ripple.addEventListener('animationend', () => {
            ripple.remove();
        });
    }

    //
    // File/Folder Handling (Mock Functions)
    // In a real application, these would be replaced with API calls
    //
    const fileSystem = {
        '': [
            { name: 'Documents', isFolder: true, size: null },
            { name: 'Images', isFolder: true, size: null },
            { name: 'video.mp4', isFolder: false, size: 1024 * 1024 * 50 },
            { name: 'document.pdf', isFolder: false, size: 1024 * 200 }
        ],
        'Documents': [
            { name: 'report.docx', isFolder: false, size: 1024 * 150 },
            { name: 'presentation.pptx', isFolder: false, size: 1024 * 500 }
        ],
        'Images': [
            { name: 'photo1.jpg', isFolder: false, size: 1024 * 1024 * 2 }
        ]
    };

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function renderFileList(path) {
        fileList.innerHTML = '';
        currentPath = path;

        // Render path segments
        pathSegmentsContainer.innerHTML = '';
        const pathParts = path.split('/').filter(p => p.length > 0);
        let accumulatedPath = '';
        const homeSegment = document.createElement('span');
        homeSegment.textContent = getTranslatedString('appName');
        homeSegment.className = 'path-segment font-bold';
        homeSegment.addEventListener('click', () => {
            renderFileList('');
        });
        pathSegmentsContainer.appendChild(homeSegment);
        pathParts.forEach((part, index) => {
            const separator = document.createElement('span');
            separator.textContent = ' / ';
            separator.className = 'mx-0.5 text-gray-400';
            pathSegmentsContainer.appendChild(separator);
            const segment = document.createElement('span');
            segment.textContent = part;
            segment.className = 'path-segment';
            accumulatedPath += (accumulatedPath ? '/' : '') + part;
            const currentSegmentPath = accumulatedPath;
            segment.addEventListener('click', () => {
                renderFileList(currentSegmentPath);
            });
            pathSegmentsContainer.appendChild(segment);
        });

        // Set the path display
        currentPathElement.textContent = path === '' ? getTranslatedString('filesAndFolders') : '';

        const items = fileSystem[path] || [];

        if (items.length === 0) {
            fileList.innerHTML = `<p class="text-center text-gray-500 p-4">${getTranslatedString('noItems')}</p>`;
            return;
        }

        items.forEach(item => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.setAttribute('data-name', item.name);
            fileItem.setAttribute('data-is-folder', item.isFolder);

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'selection-checkbox';
            checkbox.addEventListener('click', (e) => {
                e.stopPropagation(); // Prevent the parent click event from firing
                toggleSelection(fileItem);
            });
            fileItem.appendChild(checkbox);

            const icon = document.createElement('i');
            icon.className = `file-icon fas ${item.isFolder ? 'fa-folder folder-icon' : getFileIcon(item.name)}`;
            fileItem.appendChild(icon);

            const name = document.createElement('span');
            name.className = 'file-name';
            name.textContent = item.name;
            fileItem.appendChild(name);

            if (!item.isFolder) {
                const size = document.createElement('span');
                size.className = 'file-size';
                size.textContent = formatBytes(item.size);
                fileItem.appendChild(size);
            }

            const actions = document.createElement('div');
            actions.className = 'file-actions';

            if (!item.isFolder) {
                const downloadBtn = document.createElement('button');
                downloadBtn.className = 'file-action-btn';
                downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
                downloadBtn.title = 'Download';
                downloadBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    showMessage(getTranslatedString('success'), `Downloading ${item.name}...`);
                });
                actions.appendChild(downloadBtn);

                const previewBtn = document.createElement('button');
                previewBtn.className = 'file-action-btn';
                previewBtn.innerHTML = '<i class="fas fa-eye"></i>';
                previewBtn.title = 'Preview';
                previewBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    previewFile(item.name, item.isFolder);
                });
                actions.appendChild(previewBtn);
            }

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'file-action-btn';
            deleteBtn.innerHTML = '<i class="fas fa-trash-alt"></i>';
            deleteBtn.title = 'Delete';
            deleteBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                showConfirmation(`Are you sure you want to delete "${item.name}"?`).then(result => {
                    if (result) {
                        deleteFileOrFolder(item.name);
                    }
                });
            });
            actions.appendChild(deleteBtn);

            fileItem.appendChild(actions);

            fileItem.addEventListener('click', () => {
                if (isSelectionMode) {
                    toggleSelection(fileItem);
                } else if (item.isFolder) {
                    const newPath = path ? `${path}/${item.name}` : item.name;
                    renderFileList(newPath);
                } else {
                    previewFile(item.name);
                }
            });

            fileList.appendChild(fileItem);
        });

        // Re-apply selection state after re-rendering
        updateSelectionModeDisplay();
    }

    function getFileIcon(fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        switch (ext) {
            case 'pdf': return 'fa-file-pdf';
            case 'jpg':
            case 'jpeg':
            case 'png':
            case 'gif': return 'fa-file-image';
            case 'mp4':
            case 'avi':
            case 'mov': return 'fa-file-video';
            case 'mp3':
            case 'wav': return 'fa-file-audio';
            case 'zip':
            case 'rar': return 'fa-file-archive';
            case 'js':
            case 'html':
            case 'css': return 'fa-file-code';
            case 'txt': return 'fa-file-alt';
            default: return 'fa-file';
        }
    }

    function deleteFileOrFolder(name) {
        const items = fileSystem[currentPath];
        const index = items.findIndex(item => item.name === name);
        if (index > -1) {
            items.splice(index, 1);
            showMessage(getTranslatedString('success'), `Deleted "${name}" successfully.`);
            renderFileList(currentPath);
        }
    }

    function createNewFolder(folderName) {
        if (!folderName) {
            showMessage(getTranslatedString('error'), 'Folder name cannot be empty.');
            return;
        }
        if (fileSystem[currentPath].some(item => item.name === folderName && item.isFolder)) {
            showMessage(getTranslatedString('error'), `A folder named "${folderName}" already exists.`);
            return;
        }
        fileSystem[currentPath].push({ name: folderName, isFolder: true, size: null });
        showMessage(getTranslatedString('success'), `Folder "${folderName}" created.`);
        renderFileList(currentPath);
    }

    function handleFileUpload(files) {
        // In a real app, this would be an API call to upload files
        for (const file of files) {
            // Check if file already exists
            if (fileSystem[currentPath].some(item => item.name === file.name)) {
                showConfirmation(`A file named "${file.name}" already exists. Do you want to overwrite it?`).then(result => {
                    if (result) {
                        // Simulate file overwrite
                        deleteFileOrFolder(file.name);
                        fileSystem[currentPath].push({ name: file.name, isFolder: false, size: file.size });
                        showMessage(getTranslatedString('success'), `File "${file.name}" uploaded successfully.`);
                        renderFileList(currentPath);
                    }
                });
            } else {
                fileSystem[currentPath].push({ name: file.name, isFolder: false, size: file.size });
                showMessage(getTranslatedString('success'), `File "${file.name}" uploaded successfully.`);
                renderFileList(currentPath);
            }
        }
    }

    function previewFile(fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        let content = '';
        let type = 'unknown';
        let isExecutable = false;

        switch (ext) {
            case 'jpg':
            case 'jpeg':
            case 'png':
            case 'gif':
                type = 'image';
                content = `https://placehold.co/600x400/3b82f6/ffffff?text=${fileName}`;
                break;
            case 'mp4':
            case 'avi':
            case 'mov':
                type = 'video';
                content = `<video controls src="https://www.w3schools.com/html/mov_bbb.mp4"></video>`;
                break;
            case 'mp3':
            case 'wav':
                type = 'audio';
                content = `<audio controls src="https://www.w3schools.com/html/horse.mp3"></audio>`;
                break;
            case 'html':
                type = 'iframe';
                content = `<iframe srcdoc="<h1>Hello World!</h1><p>This is an iframe preview of an HTML file.</p>"></iframe>`;
                break;
            case 'md':
                type = 'markdown';
                content = `### Markdown Preview
This is a **Markdown** file.
- Item 1
- Item 2
`;
                break;
            case 'js':
            case 'css':
            case 'json':
            case 'txt':
            case 'xml':
            case 'log':
                type = 'text';
                content = `// Mock content for ${fileName}\nconsole.log("This is a preview of a text-based file.");`;
                isExecutable = ext === 'js';
                break;
            case 'exe':
            case 'sh':
            case 'bat':
                type = 'unknown';
                isExecutable = true;
                break;
            default:
                type = 'unknown';
                content = getTranslatedString('unsupportedFileType');
        }

        if (isExecutable) {
            showExecutableWarning().then(result => {
                if (result) {
                    showPreviewModal(fileName, content, type);
                } else {
                    showMessage(getTranslatedString('warning'), getTranslatedString('operationCancelled'));
                }
            });
        } else {
            showPreviewModal(fileName, content, type);
        }
    }

    function showPreviewModal(fileName, content, type) {
        const previewTitle = document.getElementById('preview-title');
        const previewContentArea = document.getElementById('preview-content-area');
        const previewDownloadButton = document.getElementById('preview-download-button');
        const previewNewTabButton = document.getElementById('preview-new-tab-button');

        previewTitle.textContent = getTranslatedString('previewTitle') + `: ${fileName}`;
        previewContentArea.innerHTML = '';
        previewDownloadButton.onclick = () => showMessage(getTranslatedString('success'), `Downloading ${fileName}...`);
        previewNewTabButton.onclick = () => showMessage(getTranslatedString('error'), 'This feature is not yet implemented.');

        if (type === 'text' || type === 'markdown') {
            const pre = document.createElement('pre');
            if (type === 'markdown') {
                pre.innerHTML = marked.parse(content);
            } else {
                pre.textContent = content;
            }
            previewContentArea.appendChild(pre);
        } else if (type === 'image' || type === 'video' || type === 'audio' || type === 'iframe') {
            previewContentArea.innerHTML = content;
        } else {
            previewContentArea.textContent = content;
        }

        showModal('preview-modal');
    }

    //
    // Selection Mode Logic
    //

    function toggleSelectionMode() {
        isSelectionMode = !isSelectionMode;
        if (!isSelectionMode) {
            selectedItems = [];
            updateSelectionModeDisplay();
        }
        updateSelectionButtons();
    }

    function updateSelectionModeDisplay() {
        if (isSelectionMode) {
            fileList.classList.add('file-list-selection-mode');
            toggleSelectionButton.innerHTML = `<i class="fas fa-times-circle mr-2"></i> ${getTranslatedString('exitSelectionMode')}`;
        } else {
            fileList.classList.remove('file-list-selection-mode');
            toggleSelectionButton.innerHTML = `<i class="fas fa-check-square mr-2"></i> ${getTranslatedString('toggleSelection')}`;
        }
        // Update the visual state of each file item's checkbox
        fileList.querySelectorAll('.file-item').forEach(item => {
            const itemName = item.getAttribute('data-name');
            if (selectedItems.includes(itemName)) {
                item.classList.add('selected');
                item.querySelector('.selection-checkbox').checked = true;
            } else {
                item.classList.remove('selected');
                item.querySelector('.selection-checkbox').checked = false;
            }
        });
    }

    function updateSelectionButtons() {
        const allSelectionButtons = [
            deleteSelectedButton,
            copySelectedButton,
            moveSelectedButton,
            clearSelectionButton
        ];

        if (isSelectionMode) {
            allSelectionButtons.forEach(btn => btn.classList.remove('hidden'));
            uploadButton.classList.add('hidden');
            newFolderButton.classList.add('hidden');
        } else {
            allSelectionButtons.forEach(btn => btn.classList.add('hidden'));
            uploadButton.classList.remove('hidden');
            newFolderButton.classList.remove('hidden');
        }

        if (selectedItems.length > 0) {
            clearSelectionButton.classList.remove('opacity-50', 'cursor-not-allowed');
            deleteSelectedButton.classList.remove('opacity-50', 'cursor-not-allowed');
            copySelectedButton.classList.remove('opacity-50', 'cursor-not-allowed');
            moveSelectedButton.classList.remove('opacity-50', 'cursor-not-allowed');
        } else {
            clearSelectionButton.classList.add('opacity-50', 'cursor-not-allowed');
            deleteSelectedButton.classList.add('opacity-50', 'cursor-not-allowed');
            copySelectedButton.classList.add('opacity-50', 'cursor-not-allowed');
            moveSelectedButton.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }

    function toggleSelection(fileItem) {
        const itemName = fileItem.getAttribute('data-name');
        const isSelected = selectedItems.includes(itemName);

        if (isSelected) {
            // Deselect
            selectedItems = selectedItems.filter(item => item !== itemName);
            fileItem.classList.remove('selected');
            fileItem.querySelector('.selection-checkbox').checked = false;
        } else {
            // Select
            selectedItems.push(itemName);
            fileItem.classList.add('selected');
            fileItem.querySelector('.selection-checkbox').checked = true;
        }
        updateSelectionButtons();
    }

    //
    // Destination Chooser Modal
    //
    function showDestinationChooser() {
        currentDestinationPath = '';
        renderDestinationChooserList('');
        showModal('destination-chooser-modal');
    }

    function renderDestinationChooserList(path) {
        const destinationList = document.getElementById('destination-list');
        const destinationPathSegments = document.getElementById('destination-path-segments');
        destinationList.innerHTML = '';
        currentDestinationPath = path;

        // Update path display
        destinationPathSegments.innerHTML = '';
        const pathParts = path.split('/').filter(p => p.length > 0);
        let accumulatedPath = '';
        const homeSegment = document.createElement('span');
        homeSegment.textContent = getTranslatedString('appName');
        homeSegment.className = 'path-segment font-bold';
        homeSegment.addEventListener('click', () => {
            renderDestinationChooserList('');
        });
        destinationPathSegments.appendChild(homeSegment);
        pathParts.forEach((part, index) => {
            const separator = document.createElement('span');
            separator.textContent = ' / ';
            separator.className = 'mx-0.5 text-gray-400';
            destinationPathSegments.appendChild(separator);
            const segment = document.createElement('span');
            segment.textContent = part;
            segment.className = 'path-segment';
            accumulatedPath += (accumulatedPath ? '/' : '') + part;
            const currentSegmentPath = accumulatedPath;
            segment.addEventListener('click', () => {
                renderDestinationChooserList(currentSegmentPath);
            });
            destinationPathSegments.appendChild(segment);
        });

        const folders = (fileSystem[path] || []).filter(item => item.isFolder);

        if (folders.length === 0) {
            destinationList.innerHTML = `<p class="text-center text-gray-500 p-4">No subfolders.</p>`;
        }

        folders.forEach(folder => {
            const folderItem = document.createElement('div');
            folderItem.className = 'file-item';
            folderItem.innerHTML = `
                <i class="file-icon fas fa-folder folder-icon"></i>
                <span class="file-name">${folder.name}</span>
            `;
            folderItem.addEventListener('click', () => {
                const newPath = path ? `${path}/${folder.name}` : folder.name;
                renderDestinationChooserList(newPath);
            });
            destinationList.appendChild(folderItem);
        });
    }

    function handleCopyMoveOperation() {
        if (selectedItems.length === 0) {
            showMessage(getTranslatedString('error'), getTranslatedString('noItemsSelectedMessage'));
            return;
        }

        const message = currentOperationType === 'copy'
            ? getTranslatedString('copyOperationMessage', selectedItems.length, currentDestinationPath || getTranslatedString('appName'))
            : getTranslatedString('moveOperationMessage', selectedItems.length, currentDestinationPath || getTranslatedString('appName'));

        showLoading(message);

        // Simulate a delay for the operation
        setTimeout(() => {
            hideLoading();
            // In a real app, this would perform the copy/move logic
            showMessage(getTranslatedString('success'), `Operation "${currentOperationType}" completed successfully.`);
            hideModal('destination-chooser-modal');
            // Clear selection mode after a successful operation
            toggleSelectionMode();
            renderFileList(currentPath); // Re-render the file list
        }, 1500);
    }

    //
    // Initial State & Event Listeners
    //
    if (!isAgreed) {
        showModal('agreement-modal');
    } else {
        renderFileList(currentPath);
    }

    //
    // Event Listeners for Buttons
    //

    // Agreement Modal Buttons
    modalButtons['agreement-decline-button'].addEventListener('click', () => {
        hideModal('agreement-modal');
        showModal('agreement-required-modal');
    });
    modalButtons['agreement-agree-button'].addEventListener('click', () => {
        isAgreed = true;
        localStorage.setItem('fluxdrop_agreement', 'true');
        hideModal('agreement-modal');
        renderFileList(currentPath);
    });

    modalButtons['terms-view-button'].addEventListener('click', () => {
        const termsContent = document.getElementById('terms-content');
        // This is a static markdown content for the terms
        const markdown = `
# Terms of Service

## 1. Introduction
Welcome to FluxDrop. By accessing or using our service, you agree to be bound by these Terms of Service ("Terms").

## 2. Use of Service
You agree to use FluxDrop only for lawful purposes and in a way that does not infringe the rights of, restrict, or inhibit anyone else's use and enjoyment of the service. Prohibited behavior includes harassing or causing distress or inconvenience to any other user, transmitting obscene or offensive content, or disrupting the normal flow of dialogue within FluxDrop.

## 3. User Content
You are responsible for any content you upload, share, or otherwise make available on FluxDrop. You retain all rights to your content, but you grant FluxDrop a worldwide, non-exclusive, royalty-free license to use, reproduce, adapt, publish, and distribute such content on the service.

## 4. Privacy
Your privacy is important to us. Our Privacy Policy, which is incorporated by reference into these Terms, describes how we collect, use, and protect your personal information.

## 5. Termination
We may terminate or suspend your access to FluxDrop immediately, without prior notice or liability, for any reason whatsoever, including without limitation if you breach the Terms.

## 6. Disclaimer of Warranties
The FluxDrop service is provided "as is" and "as available" without any warranties of any kind, either express or implied.

## 7. Limitation of Liability
In no event shall FluxDrop be liable for any indirect, incidental, special, consequential, or punitive damages arising out of your use of the service.
        `;
        document.getElementById('terms-content-markdown').innerHTML = marked.parse(markdown);
        showModal('terms-modal');
    });

    modalButtons['privacy-view-button'].addEventListener('click', () => {
        const privacyContent = document.getElementById('privacy-content');
        const markdown = `
# Privacy Policy

## 1. Data Collection
We collect minimal information required to provide the service, such as anonymous usage data and file metadata (e.g., file names, sizes). We do not collect personal identifying information unless you choose to provide it.

## 2. Use of Data
The data we collect is used solely to operate, maintain, and improve the features and functionality of FluxDrop. We do not sell or share your data with third parties for marketing purposes.

## 3. Data Storage
Your files are stored securely. We employ industry-standard security measures to protect your data from unauthorized access, alteration, disclosure, or destruction.

## 4. Cookies
We may use cookies to maintain your session and preferences. You can configure your browser to reject cookies, but this may affect the functionality of the service.

## 5. Changes to this Policy
We reserve the right to modify this Privacy Policy at any time. We will notify you of any changes by posting the new policy on this page.
        `;
        document.getElementById('terms-content-markdown').innerHTML = marked.parse(markdown);
        showModal('terms-modal');
    });

    modalButtons['terms-confirm-button'].addEventListener('click', () => {
        hideModal('terms-modal');
    });

    modalButtons['agreement-required-ok-button'].addEventListener('click', () => {
        hideModal('agreement-required-modal');
        showModal('agreement-modal');
    });

    // Modal Close Buttons
    document.querySelectorAll('.close-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const modalId = e.target.closest('.modal-overlay').id;
            hideModal(modalId);
        });
    });

    // Confirmation Modal
    modalButtons['confirmation-yes-button'].addEventListener('click', () => {
        if (confirmationPromise) {
            confirmationPromise(true);
            confirmationPromise = null;
        }
        hideModal('confirmation-modal');
    });

    modalButtons['confirmation-no-button'].addEventListener('click', () => {
        if (confirmationPromise) {
            confirmationPromise(false);
            confirmationPromise = null;
        }
        hideModal('confirmation-modal');
    });

    // Executable Warning Modal
    modalButtons['executable-warning-yes-button'].addEventListener('click', () => {
        if (confirmationPromise) {
            confirmationPromise(true);
            confirmationPromise = null;
        }
        hideModal('executable-warning-modal');
    });

    modalButtons['executable-warning-no-button'].addEventListener('click', () => {
        if (confirmationPromise) {
            confirmationPromise(false);
            confirmationPromise = null;
        }
        hideModal('executable-warning-modal');
    });

    // Preview Modal
    modalButtons['preview-close-button'].addEventListener('click', () => {
        hideModal('preview-modal');
    });

    // Message Modal
    modalButtons['message-ok-button'].addEventListener('click', () => {
        hideModal('message-modal');
    });

    // Main UI Buttons
    uploadButton.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        handleFileUpload(e.target.files);
    });

    newFolderButton.addEventListener('click', () => {
        showConfirmation(getTranslatedString('newFolderMessage')).then(result => {
            if (result) {
                // For demonstration, we'll prompt a new folder name
                const folderName = window.prompt("Enter new folder name:"); // Use a custom modal in a real app
                if (folderName) {
                    createNewFolder(folderName);
                }
            }
        });
    });

    toggleSelectionButton.addEventListener('click', () => {
        toggleSelectionMode();
        updateSelectionModeDisplay();
    });

    clearSelectionButton.addEventListener('click', () => {
        if (selectedItems.length > 0) {
            selectedItems = [];
            updateSelectionModeDisplay();
            updateSelectionButtons();
            showMessage(getTranslatedString('success'), 'Selection cleared.');
        } else {
            showMessage(getTranslatedString('error'), getTranslatedString('noItemsSelectedMessage'));
        }
    });

    deleteSelectedButton.addEventListener('click', () => {
        if (selectedItems.length === 0) {
            showMessage(getTranslatedString('error'), getTranslatedString('noItemsSelectedMessage'));
            return;
        }
        showConfirmation(getTranslatedString('deleteConfirmMessage', selectedItems.length)).then(result => {
            if (result) {
                showLoading(getTranslatedString('processing'));
                setTimeout(() => {
                    hideLoading();
                    selectedItems.forEach(item => {
                        deleteFileOrFolder(item);
                    });
                    selectedItems = [];
                    updateSelectionModeDisplay();
                    updateSelectionButtons();
                    showMessage(getTranslatedString('success'), `Deleted ${selectedItems.length} item(s).`);
                }, 1500);
            }
        });
    });

    copySelectedButton.addEventListener('click', () => {
        if (selectedItems.length === 0) {
            showMessage(getTranslatedString('error'), getTranslatedString('noItemsSelectedMessage'));
            return;
        }
        currentOperationType = 'copy';
        showDestinationChooser();
    });

    moveSelectedButton.addEventListener('click', () => {
        if (selectedItems.length === 0) {
            showMessage(getTranslatedString('error'), getTranslatedString('noItemsSelectedMessage'));
            return;
        }
        currentOperationType = 'move';
        showDestinationChooser();
    });

    // Destination Chooser Modal Buttons
    modalButtons['destination-back-button'].addEventListener('click', () => {
        const pathParts = currentDestinationPath.split('/');
        pathParts.pop();
        const newPath = pathParts.join('/');
        renderDestinationChooserList(newPath);
    });

    modalButtons['choose-destination-button'].addEventListener('click', handleCopyMoveOperation);

    modalButtons['cancel-destination-button'].addEventListener('click', () => {
        hideModal('destination-chooser-modal');
    });

    // Drag and Drop Event Listeners
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!isSelectionMode) {
            dropZoneOverlay.classList.add('drag-over');
        }
    });

    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZoneOverlay.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZoneOverlay.classList.remove('drag-over');
        if (!isSelectionMode) {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFileUpload(files);
            }
        }
    });

    // Ripple effect event listener for all buttons
    document.querySelectorAll('.btn').forEach(button => {
        button.addEventListener('click', generateRipple);
    });
});

