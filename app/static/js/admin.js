(() => {
    const toggle = document.getElementById('theme-toggle');
    if (!toggle) return;

    const root = document.documentElement;
    const label = toggle.querySelector('.theme-label');

    function updateToggle(theme) {
        const isDark = theme === 'dark';
        toggle.setAttribute('aria-pressed', String(isDark));
        toggle.setAttribute('aria-label', `Switch to ${isDark ? 'light' : 'dark'} mode`);
        if (label) label.textContent = isDark ? 'Light mode' : 'Dark mode';
    }

    updateToggle(root.dataset.theme || 'light');
    toggle.addEventListener('click', () => {
        const theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
        root.dataset.theme = theme;
        updateToggle(theme);
        try {
            localStorage.setItem('sams-theme', theme);
        } catch (_) {
            // The current page theme still changes when browser storage is unavailable.
        }
    });
})();
