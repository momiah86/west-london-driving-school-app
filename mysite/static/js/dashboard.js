function initializeDashboard(appData) {
    // Initialize DataTable
    const table = $('#logsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']],
        language: {
            search: "Search lessons:",
            lengthMenu: "Show _MENU_ lessons per page",
            info: "Showing _START_ to _END_ of _TOTAL_ lessons"
        }
    });

    // Handle export buttons
    $('.export-btn').on('click', function(e) {
        e.preventDefault();
        const format = $(this).data('format');
        const url = appData.urls[format];
        if (url) {
            window.location.href = url;
        }
    });

    // Handle note buttons
    $('.view-notes-btn').on('click', function() {
        const notes = $(this).data('notes');
        const lessonNumber = $(this).data('lesson-number');
        
        Swal.fire({
            title: `Notes for Lesson #${lessonNumber}`,
            text: notes || 'No notes available for this lesson.',
            icon: 'info',
            confirmButtonColor: '#0d6efd'
        });
    });

    // Handle action buttons
    $('[data-action]').on('click', function() {
        const action = $(this).data('action');
        const logId = $(this).data('log-id');
        
        if (action === 'view') {
            viewDetails(logId);
        } else if (action === 'download') {
            downloadCertificate(logId);
        }
    });
} 