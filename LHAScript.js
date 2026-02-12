// ==UserScript==
// @name         LHA School Synergy QoL Mod Menu
// @namespace    http://tampermonkey.net/
// @version      0.2
// @description  QoL improvements for LHA School Synergy, including custom backgrounds, text customization, and image redirection.
// @author       Antigravity
// @match        https://lha.schoolsynergy.co.uk/*
// @grant        GM_addStyle
// @grant        GM_setValue
// @grant        GM_getValue
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    // --- Configuration & Constants ---
    const SETTINGS_PATH = '/mod/settings';
    const REDIRECTS = [
        {
            from: 'https://lha.schoolsynergy.co.uk/schooldata/schid_5/_images/shield.png',
            to: 'https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/LHAModded.png'
        },
        {
            from: 'https://lha.schoolsynergy.co.uk/schooldata/schid_5/_images/login_shield.png',
            to: 'https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/LHAModded.png'
        }
    ];

    const STORAGE_KEYS = {
        BACKGROUND_URL: 'lha_mod_background_url',
        FONT_FAMILY: 'lha_mod_font_family',
        TEXT_COLOR: 'lha_mod_text_color'
    };

    // --- Utility Functions ---
    const injectStyles = () => {
        const bgUrl = GM_getValue(STORAGE_KEYS.BACKGROUND_URL, '');
        const fontFamily = GM_getValue(STORAGE_KEYS.FONT_FAMILY, '');
        const textColor = GM_getValue(STORAGE_KEYS.TEXT_COLOR, '');

        let styles = `
            :root {
                --lha-mod-bg: #1a1a1a;
                --lha-mod-card-bg: #2d2d2d;
                --lha-mod-text: #e0e0e0;
                --lha-mod-accent: #4a9eff;
                --lha-mod-hover: #3d3d3d;
            }

            .lha-mod-settings-btn {
                position: fixed;
                bottom: 20px;
                right: 20px;
                width: 50px;
                height: 50px;
                background-color: var(--lha-mod-card-bg);
                color: var(--lha-mod-text);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                box-shadow: 0 4px 10px rgba(0,0,0,0.3);
                z-index: 9999;
                transition: transform 0.2s, background-color 0.2s;
                border: 1px solid rgba(255,255,255,0.1);
                text-decoration: none;
                font-family: sans-serif;
                font-weight: bold;
                font-size: 20px;
            }

            .lha-mod-settings-btn:hover {
                background-color: var(--lha-mod-hover);
                transform: scale(1.1);
            }

            /* Custom Background Logic */
            ${bgUrl ? `
                body, .page-wrapper, #main-wrapper { 
                    background-image: url('${bgUrl}') !important;
                    background-size: cover !important;
                    background-position: center !important;
                    background-attachment: fixed !important;
                }
            ` : ''}

            /* Custom Typography Logic */
            html, body, p, div, span, a, h1, h2, h3, h4, h5, h6, input, button, select, textarea {
                ${fontFamily ? `font-family: '${fontFamily}', sans-serif !important;` : ''}
                ${textColor ? `color: ${textColor} !important;` : ''}
            }

            /* Robust Image Redirection via CSS */
            #defaultshield, #loginshield, img[src*="shield.png"], img[src*="login_shield.png"] {
                content: url('https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/LHAModded.png') !important;
                background-image: url('https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/LHAModded.png') !important;
                background-size: contain !important;
                background-repeat: no-repeat !important;
                object-fit: contain !important;
            }

            /* UI Element Removal */
            #main-menuhelper, 
            .e-text-content:has(a[href*="mobile/home/home.aspx"]),
            #about_attend,
            #about_attend_logo,
            #about_schoolsynergy {
                display: none !important;
            }

            /* Custom Logout Icon */
            .nav-icon-studentlogout {
                background-image: url('https://cdn-icons-png.flaticon.com/512/660/660350.png') !important;
                background-size: contain !important;
                background-repeat: no-repeat !important;
                width: 26px !important;
                height: 20px !important;
                margin-left: 30px !important;
                filter: invert(1) !important; /* Default invert */
            }

            /* Stop inverting when parent LI is hovered */
            .e-list-item:hover .nav-icon-studentlogout,
            .e-list-item[data-uid="391"]:hover .nav-icon-studentlogout {
                filter: invert(51%) sepia(4%) saturate(331%) hue-rotate(162deg) brightness(93%) contrast(86%) !important;
            }

            /* Shrink images in Bulletin Panels */
            div.ss-panel img, 
            div.ss-panel-content img,
            .entry-Message img {
                max-width: 180px !important;
                width: auto !important;
                height: auto !important;
                border-radius: 8px;
                margin: 10px 0;
                cursor: zoom-in !important;
                transition: max-width 0.3s ease-in-out, transform 0.2s;
                display: block !important;
            }

            /* Expanded state: Return to original size */
            div.ss-panel img.lha-mod-expanded, 
            div.ss-panel-content img.lha-mod-expanded,
            .entry-Message img.lha-mod-expanded {
                max-width: 100% !important;
                cursor: zoom-out !important;
                transform: none !important;
            }

            div.ss-panel img:hover:not(.lha-mod-expanded), 
            div.ss-panel-content img:hover:not(.lha-mod-expanded), 
            .entry-Message img:hover:not(.lha-mod-expanded) {
                transform: scale(1.05);
            }

            /* Read All Button Styling */
            #lha-read-all-btn {
                position: absolute;
                left: 95.00%;
                top: 40px;
                transform: translate(-50%, -50%);
                padding: 10px 20px;
                background-color: rgb(0, 0, 0);
                color: rgb(255, 255, 255);
                font-size: 16px;
                font-family: "MS Shell Dlg 2", sans-serif;
                border: 1px solid rgb(255, 255, 255);
                cursor: pointer;
                border-radius: 5px;
                z-index: 10000;
                width: 144px;
                height: 55px;
                box-sizing: border-box;
                transition: opacity 0.2s;
                font-weight: normal;
                box-shadow: 0 4px 15px rgba(0,0,0,0.5);
            }

            #lha-read-all-btn:hover {
                opacity: 0.8;
            }

            #lha-read-all-btn:disabled {
                background-color: #333;
                color: #888;
                cursor: not-allowed;
            }

            /* Privacy Toggle CSS */
            .lha-mod-privacy-hidden {
                display: none !important;
            }

            .lha-mod-privacy-placeholder {
                opacity: 0.5;
                font-style: italic;
                font-family: monospace;
            }

            #lha-privacy-btn {
                background-color: var(--lha-mod-card-bg);
                color: var(--lha-mod-text);
                border: 1px solid rgba(255,255,255,0.1);
                padding: 6px 12px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 13px;
                margin-bottom: 15px;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                transition: background 0.2s;
            }

            #lha-privacy-btn:hover {
                background-color: var(--lha-mod-hover);
            }
        `;

        // If on settings page, use specific layout
        if (window.location.pathname === SETTINGS_PATH) {
            styles += `
                body {
                    background-color: var(--lha-mod-bg) !important;
                    color: var(--lha-mod-text) !important;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
                    font-size: 16px !important;
                    margin: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }
                .lha-mod-container {
                    background-color: var(--lha-mod-card-bg);
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                    width: 100%;
                    max-width: 500px;
                    border: 1px solid rgba(255,255,255,0.05);
                }
                .lha-mod-header {
                    font-size: 24px;
                    margin-bottom: 20px;
                    border-bottom: 2px solid var(--lha-mod-accent);
                    padding-bottom: 10px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .lha-mod-section {
                    margin-bottom: 20px;
                }
                .lha-mod-field {
                    margin-bottom: 15px;
                }
                .lha-mod-label {
                    display: block;
                    margin-bottom: 5px;
                    font-size: 14px;
                    opacity: 0.8;
                }
                .lha-mod-input {
                    width: 100%;
                    padding: 10px;
                    border-radius: 6px;
                    border: 1px solid #444;
                    background: #1a1a1a;
                    color: #fff;
                    box-sizing: border-box;
                }
                .lha-mod-row {
                    display: flex;
                    gap: 10px;
                }
                .lha-mod-row .lha-mod-field {
                    flex: 1;
                }
                .lha-mod-btn-save {
                    background-color: var(--lha-mod-accent);
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 6px;
                    cursor: pointer;
                    width: 100%;
                    font-size: 16px;
                    font-weight: bold;
                    margin-top: 10px;
                }
                .lha-mod-btn-save:hover {
                    opacity: 0.9;
                }
                .lha-mod-back {
                    color: var(--lha-mod-accent);
                    text-decoration: none;
                    font-size: 14px;
                }
            `;
        }

        GM_addStyle(styles);
    };

    // --- Image Redirection Logic ---
    const handleImageRedirection = () => {
        const targetUrl = REDIRECTS[0].to;

        const fixShield = () => {
            const targetUrl = 'https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/LHAModded.png';
            const shields = [
                document.getElementById('defaultshield'),
                document.getElementById('loginshield'),
                document.querySelector('img[src*="shield.png"]'),
                document.querySelector('img[src*="login_shield.png"]'),
                document.querySelector('img[alt*="Shield"]'),
                document.querySelector('.school-logo img')
            ].filter(Boolean);

            shields.forEach(shield => {
                if (shield.src !== targetUrl) {
                    shield.src = targetUrl;
                    if (shield.srcset) shield.srcset = targetUrl;
                }
                // Force display in case it was hidden or filtered
                shield.style.display = 'block';
                shield.style.visibility = 'visible';
                shield.style.opacity = '1';
            });
        };

        // 1. Try immediately
        fixShield();

        // 2. Observer for dynamic changes or late loading
        const observer = new MutationObserver((mutations) => {
            fixShield();
        });

        observer.observe(document.documentElement || document, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src', 'srcset', 'id']
        });

        // 3. Periodic check for a few seconds as a fallback
        let checks = 0;
        const interval = setInterval(() => {
            fixShield();
            if (++checks > 20) clearInterval(interval);
        }, 500);
    };

    // --- Image Preview/Expansion Logic ---
    const handleImageExpansion = () => {
        const attachClickListener = (node) => {
            const imgs = (node.tagName === 'IMG' ? [node] : node.querySelectorAll?.('.ss-panel img, .ss-panel-content img, .entry-Message img')) || [];
            imgs.forEach(img => {
                if (!img.dataset.expansionInit) {
                    img.dataset.expansionInit = 'true';

                    const setupExpansion = () => {
                        if (img.naturalWidth > 180) {
                            // Only shrink if it's large
                            img.style.width = '180px';
                            img.style.height = 'auto';
                            img.style.display = 'block';
                            img.style.cursor = 'zoom-in';

                            img.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const isExpanded = img.classList.toggle('lha-mod-expanded');

                                if (isExpanded) {
                                    img.style.width = '';
                                    img.style.maxWidth = '100% !important';
                                } else {
                                    img.style.width = '180px';
                                    img.style.maxWidth = '180px';
                                }
                            });
                        }
                    };

                    if (img.complete) {
                        setupExpansion();
                    } else {
                        img.addEventListener('load', setupExpansion);
                    }
                }
            });
        };

        // Initial scan
        attachClickListener(document.documentElement);

        // Scan for new bulletin content
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) attachClickListener(node);
                });
            });
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    };

    // --- Privacy Toggle Logic ---
    const handlePrivacyToggle = () => {
        const targetIds = [
            'ctl00_ContentPlaceHolder1_lblussforename',
            'ctl00_ContentPlaceHolder1_lblusssurname',
            'ctl00_ContentPlaceHolder1_lblussemail'
        ];

        const setupPrivacy = () => {
            const table = document.querySelector('.datatable');
            if (!table || document.getElementById('lha-privacy-btn')) return;

            const btn = document.createElement('button');
            btn.id = 'lha-privacy-btn';
            btn.type = 'button';
            btn.innerHTML = '👁️ Show information';

            let isHidden = true;

            const updateFields = (hide) => {
                targetIds.forEach(id => {
                    const el = document.getElementById(id);
                    if (el) {
                        if (hide) {
                            el.classList.add('lha-mod-privacy-hidden');
                            if (!el.parentNode.querySelector('.lha-mod-privacy-placeholder')) {
                                const placeholder = document.createElement('span');
                                placeholder.className = 'lha-mod-privacy-placeholder';
                                placeholder.innerText = '[HIDDEN]';
                                el.parentNode.appendChild(placeholder);
                            }
                        } else {
                            el.classList.remove('lha-mod-privacy-hidden');
                            el.parentNode.querySelector('.lha-mod-privacy-placeholder')?.remove();
                        }
                    }
                });
            };

            btn.onclick = (e) => {
                e.preventDefault();
                isHidden = !isHidden;
                btn.innerHTML = isHidden ? '👁️ Show information' : '🔒 Hide information';
                updateFields(isHidden);
            };

            // Initial state
            updateFields(true);
            table.parentNode.insertBefore(btn, table);
        };

        const observer = new MutationObserver(setupPrivacy);
        observer.observe(document.documentElement, { childList: true, subtree: true });
        setupPrivacy();
    };

    // --- Bulletin Automation ---
    const handleReadAllBulletins = () => {
        if (!window.location.pathname.includes('/bulletin.aspx')) return;

        const addReadAllButton = () => {
            if (document.getElementById('lha-read-all-btn')) return;

            const btn = document.createElement('button');
            btn.id = 'lha-read-all-btn';
            btn.innerHTML = 'Mark All As Read';

            btn.onclick = async () => {
                const bubbles = document.querySelectorAll('.incompletebubble');
                if (bubbles.length === 0) {
                    alert('All bulletins are already read!');
                    return;
                }

                if (!confirm(`Mark ${bubbles.length} bulletins as read?`)) return;

                btn.disabled = true;
                btn.innerHTML = 'Marking...';

                for (let i = 0; i < bubbles.length; i++) {
                    bubbles[i].click();
                    btn.innerHTML = `(${i + 1}/${bubbles.length})`;
                    await new Promise(resolve => setTimeout(resolve, 300));
                }

                btn.innerHTML = 'Refreshing...';
                setTimeout(() => location.reload(), 1000);
            };

            document.body.appendChild(btn);
        };

        const observer = new MutationObserver(() => {
            addReadAllButton();
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
        addReadAllButton();
    };

    // --- Settings Page Rendering ---
    const renderSettingsPage = () => {
        document.title = "LHA Mod Menu - Settings";

        const currentBg = GM_getValue(STORAGE_KEYS.BACKGROUND_URL, '');
        const currentFont = GM_getValue(STORAGE_KEYS.FONT_FAMILY, '');
        const currentColor = GM_getValue(STORAGE_KEYS.TEXT_COLOR, '');

        document.body.innerHTML = `
            <div class="lha-mod-container">
                <div class="lha-mod-header">
                    <span>Mod Settings</span>
                    <a href="#" id="lha-back-btn" class="lha-mod-back">← Back to Site</a>
                </div>
                
                <div class="lha-mod-section">
                    <div class="lha-mod-field">
                        <label class="lha-mod-label">Custom Background Image URL</label>
                        <input type="text" id="lha-bg-url" class="lha-mod-input" placeholder="https://example.com/image.jpg" value="${currentBg}">
                    </div>
                </div>

                <div class="lha-mod-section">
                    <div class="lha-mod-field">
                        <label class="lha-mod-label">Font Family (e.g. Arial, Verdana, Inter)</label>
                        <input type="text" id="lha-font-family" class="lha-mod-input" placeholder="System Default" value="${currentFont}">
                    </div>

                    <div class="lha-mod-row">
                        <div class="lha-mod-field">
                            <label class="lha-mod-label">Text Color (Hex/Name)</label>
                            <input type="text" id="lha-text-color" class="lha-mod-input" placeholder="#e0e0e0" value="${currentColor}">
                        </div>
                    </div>
                </div>

                <button id="lha-save-btn" class="lha-mod-btn-save">Save Settings</button>
            </div>
        `;

        document.getElementById('lha-save-btn').addEventListener('click', () => {
            GM_setValue(STORAGE_KEYS.BACKGROUND_URL, document.getElementById('lha-bg-url').value);
            GM_setValue(STORAGE_KEYS.FONT_FAMILY, document.getElementById('lha-font-family').value);
            GM_setValue(STORAGE_KEYS.TEXT_COLOR, document.getElementById('lha-text-color').value);
            alert('Settings saved! Refreshing...');
            location.reload();
        });

        document.getElementById('lha-back-btn').addEventListener('click', (e) => {
            e.preventDefault();
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = '/';
            }
        });
    };

    // --- Settings Button Rendering ---
    const addSettingsButton = () => {
        if (window.location.pathname === SETTINGS_PATH) return;
        if (document.getElementById('lha-mod-settings-link')) return;

        const btn = document.createElement('a');
        btn.id = 'lha-mod-settings-link';
        btn.href = window.location.origin + SETTINGS_PATH;
        btn.className = 'lha-mod-settings-btn';
        btn.innerHTML = '⚙️';
        btn.title = 'LHA Mod Menu Settings';

        document.body.appendChild(btn);
    };

    // --- Initialization ---
    const init = () => {
        injectStyles();
        handleImageRedirection();
        handleImageExpansion();
        handleReadAllBulletins();
        handlePrivacyToggle();

        if (window.location.pathname === SETTINGS_PATH) {
            const handleDomReady = () => {
                renderSettingsPage();
            };

            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', handleDomReady);
            } else {
                handleDomReady();
            }
        } else {
            if (document.readyState === 'complete') {
                addSettingsButton();
            } else {
                window.addEventListener('load', addSettingsButton);
            }
        }
    };

    init();
})();
