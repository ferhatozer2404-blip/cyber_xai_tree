const fs = require('fs');

// Design 1: Magnifying glass with centered decision tree inside the lens
const svg1 = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="none">
    <circle cx="10.5" cy="10.5" r="6.5" stroke="#38BDF8" stroke-width="1.8"/>
    <path d="M15.5 15.5L20.5 20.5" stroke="#38BDF8" stroke-width="2.2" stroke-linecap="round"/>
    <path d="M10.5 7V9.6M10.5 9.6L7.8 12.8M10.5 9.6L13.2 12.8" stroke="#38BDF8" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="10.5" cy="6.8" r="1.1" fill="#38BDF8"/>
    <circle cx="7.8" cy="12.8" r="1.1" fill="#38BDF8"/>
    <circle cx="13.2" cy="12.8" r="1.1" fill="#38BDF8"/>
</svg>`;

// Design 2: Centered Decision Tree with Magnifying Glass inspecting the root/fork
const svg2 = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="none">
    <!-- Tree Trunk & Branches -->
    <path d="M12 21V14M12 14L6 8M12 14L18 8" stroke="#38BDF8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="6" cy="8" r="2.2" fill="#38BDF8"/>
    <circle cx="18" cy="8" r="2.2" fill="#38BDF8"/>
    <circle cx="12" cy="21" r="1.8" fill="#38BDF8"/>
    <!-- Magnifying Glass over Decision Junction -->
    <circle cx="12" cy="12" r="4.2" stroke="#38BDF8" stroke-width="1.8" fill="#060913"/>
    <path d="M15.2 15.2L18.5 18.5" stroke="#38BDF8" stroke-width="2" stroke-linecap="round"/>
</svg>`;

// Design 3: Symmetrical, centered Decision Tree inside Magnifying Lens with clear optics
const svg3 = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="none">
    <circle cx="10.5" cy="10.5" r="7" stroke="#38BDF8" stroke-width="2"/>
    <path d="M15.8 15.8L21 21" stroke="#38BDF8" stroke-width="2.4" stroke-linecap="round"/>
    <path d="M10.5 6.2V9.5M10.5 9.5L7.2 13M10.5 9.5L13.8 13" stroke="#38BDF8" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="10.5" cy="6.2" r="1.2" fill="#38BDF8"/>
    <circle cx="7.2" cy="13" r="1.2" fill="#38BDF8"/>
    <circle cx="13.8" cy="13" r="1.2" fill="#38BDF8"/>
</svg>`;

console.log('SVG Options generated.');
