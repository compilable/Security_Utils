// Theme Management
let isDarkTheme = localStorage.getItem('theme') === 'dark';

function toggleTheme() {
    isDarkTheme = !isDarkTheme;
    applyTheme();
    localStorage.setItem('theme', isDarkTheme ? 'dark' : 'light');
}

function applyTheme() {
    const body = document.body;
    const themeIcon = document.getElementById('theme-icon');
    
    if (isDarkTheme) {
        body.setAttribute('data-theme', 'dark');
        themeIcon.className = 'bi bi-sun-fill';
    } else {
        body.removeAttribute('data-theme');
        themeIcon.className = 'bi bi-moon-stars';
    }
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', function() {
    applyTheme();
    
    // Add theme toggle event listener
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
    
    // Add smooth scrolling for any anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Add loading animation for tool cards
    const cards = document.querySelectorAll('.tool-card');
    cards.forEach((card, index) => {
        card.classList.add('card-loading');
        
        setTimeout(() => {
            card.classList.remove('card-loading');
            card.classList.add('card-loaded');
        }, index * 200);
    });
});

// Add some interactive feedback
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.btn-launch').forEach(btn => {
        btn.addEventListener('click', function(e) {
            // Add ripple effect
            const rect = this.getBoundingClientRect();
            const ripple = document.createElement('span');
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.width = size + 'px';
            ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            ripple.classList.add('ripple-effect');
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
});