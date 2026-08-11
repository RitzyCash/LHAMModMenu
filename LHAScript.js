// ==UserScript==
// @name         LHA School Synergy QoL Mod Menu
// @namespace    http://tampermonkey.net/
// @version      0.3
// @description  QoL improvements for LHA School Synergy, including custom backgrounds (with local upload), text customization, and image redirection.
// @author       SwiftSeal
// @match        https://lha.schoolsynergy.co.uk/*
// @grant        GM_addStyle
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @connect      raw.githubusercontent.com
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    // --- Configuration & Constants ---
    const SETTINGS_PATH = '/mod/settings';
    const BULLETIN_PATH = '/portal/students_v2/desktop/bulletin/bulletin.aspx';
    const HOME_PATH = '/portal/students_v2/desktop/home/home.aspx';
    const DEFAULT_LOGO_URL = 'https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/LHAModded.png';
    const FAVICON_URL = 'https://raw.githubusercontent.com/RitzyCash/LHAModMenu/refs/heads/main/favicon.ico';

    const CURRENT_HASH = 'Updt_AF11082026';
    const VERSION_URL = 'https://raw.githubusercontent.com/RitzyCash/LHAMModMenu/refs/heads/main/Version.txt';

    const STORAGE_KEYS = {
        BACKGROUND_URL: 'lha_mod_background_url',
        BACKGROUND_DATA: 'lha_mod_background_data',  // uploaded background, stored as base64
        FONT_FAMILY: 'lha_mod_font_family',
        TEXT_COLOR: 'lha_mod_text_color'
    };

    // --- Background Resolution ---
    // Precedence: uploaded (base64) > custom URL > none (site default)
    const getActiveBackgroundUrl = () => {
        const data = GM_getValue(STORAGE_KEYS.BACKGROUND_DATA, '');
        if (data) return data;

        return GM_getValue(STORAGE_KEYS.BACKGROUND_URL, '');
    };

    // --- Instant settings-page takeover ---
    // /mod/settings isn't a real server route, so the browser navigates
    // there and starts receiving/painting the site's actual 404 response.
    // Hiding it with CSS alone still leaves a gap while bytes keep
    // streaming in — so we also call window.stop() to cut the real page
    // load off entirely as early as possible, then build our own DOM
    // instead of waiting on the (now-aborted) parser.
    const IS_SETTINGS_PAGE = window.location.pathname === SETTINGS_PATH;
    if (IS_SETTINGS_PAGE) {
        GM_addStyle(`html, html body { visibility: hidden !important; background: #1a1a1a !important; }`);
        if (document.documentElement) {
            document.documentElement.style.visibility = 'hidden';
        }
        try { window.stop(); } catch (e) { /* not fatal, CSS hide is the fallback */ }
    }

    // --- Utility Functions ---
    const NotificationSystem = {
        container: null,
        stylesInjected: false,

        init() {
            if (this.container && document.body.contains(this.container)) return;

            if (!document.body) {
                window.addEventListener('DOMContentLoaded', () => this.init());
                return;
            }

            if (!this.container) {
                this.container = document.createElement('div');
                this.container.id = 'lha-notification-container';
                this.container.style.cssText = `
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    z-index: 10000;
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                `;
            }

            if (!document.body.contains(this.container)) {
                document.body.appendChild(this.container);
            }

            if (!this.stylesInjected) {
                GM_addStyle(`
                    .lha-toast {
                        background: #2d2d2d;
                        color: #fff;
                        padding: 12px 20px;
                        border-radius: 8px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
                        display: flex;
                        align-items: center;
                        min-width: 250px;
                        max-width: 350px;
                        animation: lha-slide-in 0.3s ease-out forwards;
                        border-left: 4px solid #4a9eff;
                        font-family: 'Segoe UI', sans-serif;
                        font-size: 14px;
                        pointer-events: auto;
                    }
                    .lha-toast.success { border-left-color: #2ecc71; }
                    .lha-toast.error { border-left-color: #e74c3c; }
                    .lha-toast.info { border-left-color: #4a9eff; }

                    @keyframes lha-slide-in {
                        from { transform: translateX(100%); opacity: 0; }
                        to { transform: translateX(0); opacity: 1; }
                    }

                    @keyframes lha-slide-out {
                        from { transform: translateX(0); opacity: 1; }
                        to { transform: translateX(100%); opacity: 0; }
                    }
                `);
                this.stylesInjected = true;
            }
        },

        show(message, type = 'info', duration = 3000, onClick = null) {
            this.init();
            const toast = document.createElement('div');
            toast.className = `lha-toast ${type}`;
            if (onClick) {
                toast.style.cursor = 'pointer';
                toast.onclick = (e) => {
                    e.stopPropagation();
                    onClick();
                    toast.remove();
                };
            }
            toast.innerHTML = `<span>${message}</span>`;

            this.container.appendChild(toast);

            setTimeout(() => {
                if (toast.parentNode) {
                    toast.style.animation = 'lha-slide-out 0.3s ease-in forwards';
                    setTimeout(() => toast.remove(), 300);
                }
            }, duration);
        }
    };

    // Update checks now run once per browser session (per tab), not on every
    // page navigation, using sessionStorage as the guard.
    const checkForUpdates = () => {
        if (sessionStorage.getItem('lha_update_checked')) return;
        sessionStorage.setItem('lha_update_checked', '1');

        console.log('[LHA Mod] Checking for updates...');
        GM_xmlhttpRequest({
            method: "GET",
            url: VERSION_URL,
            onload: function (response) {
                const remoteHash = response.responseText.trim();
                console.log('[LHA Mod] Local Hash:', CURRENT_HASH);
                console.log('[LHA Mod] Remote Hash:', remoteHash);

                if (remoteHash && remoteHash !== CURRENT_HASH) {
                    console.log('[LHA Mod] Update available!');
                    NotificationSystem.show('Update Available! Please check GitHub for the latest version.', 'info', 10000);
                } else {
                    console.log('[LHA Mod] Script is up to date.');
                }
            },
            onerror: function (err) {
                console.error('[LHA Mod] Update check failed', err);
            }
        });
    };

    const handleHomeworkAlerts = () => {
        const HW_DATA_URL = 'https://lha.schoolsynergy.co.uk/portal/students_v2/desktop/homework/DataHandler.ashx?type=students_v2_desktop_homework_upcominggrid_get';

        const checkHw = () => {
            console.log('[LHA Mod] Checking for new homework...');
            GM_xmlhttpRequest({
                method: "GET",
                url: HW_DATA_URL,
                onload: function (response) {
                    console.log('[LHA Mod] Received homework response:', response.status);
                    try {
                        const data = JSON.parse(response.responseText);
                        const rawHtml = data.htHomework;
                        if (!rawHtml) {
                            console.log('[LHA Mod] No htHomework found in response.');
                            return;
                        }

                        const parser = new DOMParser();
                        const doc = parser.parseFromString(rawHtml, 'text/html');
                        const panels = doc.querySelectorAll('.ss-panel-content');
                        console.log(`[LHA Mod] Found ${panels.length} homework panels.`);

                        const knownHwIds = GM_getValue('lha_known_hw_ids', []);
                        const isFirstRun = knownHwIds.length === 0;
                        const currentHwIds = [];

                        panels.forEach(panel => {
                            const onclickState = panel.getAttribute('onclick');
                            const match = onclickState?.match(/viewHomework\((\d+),\s*(\d+),\s*(\d+)\)/);

                            if (match) {
                                const [_, hwId, classId, subjectId] = match;
                                currentHwIds.push(hwId);

                                if (!isFirstRun && !knownHwIds.includes(hwId)) {
                                    const subject = panel.querySelector('.hwk-classcode')?.innerText.trim() || 'Homework';
                                    const title = panel.querySelector('.hwk-title')?.innerText.trim() || 'New Assignment';

                                    console.log(`[LHA Mod] New homework detected: ${title} (${hwId})`);
                                    NotificationSystem.show(`New Homework: ${subject} - ${title}`, 'success', 10000, () => {
                                        window.location.href = `https://lha.schoolsynergy.co.uk/portal/students_v2/desktop/classwork/classwork.aspx?c=${classId}&s=${subjectId}#homework_${hwId}`;
                                    });
                                }
                            } else {
                                console.log('[LHA Mod] Could not match onclick:', onclickState);
                            }
                        });

                        console.log('[LHA Mod] Saving HW IDs:', currentHwIds);
                        GM_setValue('lha_known_hw_ids', currentHwIds);
                    } catch (e) {
                        console.error('[LHA Mod] Failed to parse homework alerts', e);
                        console.log('[LHA Mod] Raw response:', response.responseText);
                    }
                }
            });
        };

        checkHw();
        setInterval(checkHw, 10 * 60 * 1000); // 10 minutes
    };

    const injectStyles = () => {
        const bgUrl = getActiveBackgroundUrl();
        const fontFamily = GM_getValue(STORAGE_KEYS.FONT_FAMILY, '');
        const textColor = GM_getValue(STORAGE_KEYS.TEXT_COLOR, '');
        const isBulletinPage = window.location.pathname.includes(BULLETIN_PATH);
        const isHomePage = window.location.pathname.includes(HOME_PATH);

        let styles = `
            :root {
                --lha-mod-bg: #1a1a1a;
                --lha-mod-card-bg: #2d2d2d;
                --lha-mod-text: #e0e0e0;
                --lha-mod-accent: #4a9eff;
                --lha-mod-hover: #3d3d3d;
            }

            .lha-mod-settings-btn {
                position: absolute;
                left: 97.12%;
                top: 8.74%;
                transform: translate(-50%, -50%);
                width: 42px;
                height: 42px;
                background-color: rgba(45, 45, 45, 0.85);
                backdrop-filter: blur(6px);
                color: var(--lha-mod-accent);
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                box-shadow: 0 4px 10px rgba(0,0,0,0.35);
                z-index: 9999;
                transition: transform 0.2s, background-color 0.2s, box-shadow 0.2s;
                border: 1px solid rgba(255,255,255,0.08);
                text-decoration: none;
            }

            .lha-mod-settings-btn svg {
                width: 20px;
                height: 20px;
                transition: transform 0.4s ease;
            }

            .lha-mod-settings-btn:hover {
                background-color: rgba(61, 61, 61, 0.95);
                box-shadow: 0 6px 16px rgba(0,0,0,0.45);
                transform: translate(-50%, -50%) translateY(-1px);
            }

            .lha-mod-settings-btn:hover svg {
                transform: rotate(45deg);
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

            /* Robust Image Redirection via CSS (bundled GitHub logo) */
            #defaultshield, #loginshield, img[src*="shield.png"], img[src*="login_shield.png"] {
                content: url('${DEFAULT_LOGO_URL}') !important;
                background-image: url('${DEFAULT_LOGO_URL}') !important;
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

            /* Custom Panel Coloring */
            #main-topbar-right {
                background-color: #2d2d2d !important;
            }

            #default_panel {
                background-color: rgba(45, 45, 45, 0.8) !important;
                backdrop-filter: blur(5px);
            }

            .defaultheadbar_right {
                background-color: #2d2d2d !important;
            }

            .schoolname-title {
                color: #ccc !important;
            }

            /* Custom Logout Icon */
            .nav-icon-studentlogout {
                background-image: url('https://cdn-icons-png.flaticon.com/512/660/660350.png') !important;
                background-size: contain !important;
                background-repeat: no-repeat !important;
                width: 26px !important;
                height: 20px !important;
                margin-left: 10px !important;
                position: relative !important;
                left: 5px !important;
                filter: invert(1) !important; /* Default invert */
            }

            /* Stop inverting when parent LI is hovered */
            .e-list-item:hover .nav-icon-studentlogout,
            .e-list-item[data-uid="391"]:hover .nav-icon-studentlogout {
                filter: invert(51%) sepia(4%) saturate(331%) hue-rotate(162deg) brightness(93%) contrast(86%) !important;
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
                font-size: 13px;
                margin-left: 5px;
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

        // Shrink/click-to-expand images only applies on the bulletin page itself,
        // not everywhere .ss-panel/.entry-Message markup happens to appear.
        if (isBulletinPage) {
            styles += `
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
            `;
        }

        // The header back button's hover effect does nothing useful on the
        // homepage (there's nothing to go "back" to), so strip it there only.
        if (isHomePage) {
            styles += `
                body.mainpage div.ss-header div.ss-header-back:hover,
                body.mainpage div.ss-header div.ss-header-back:hover * {
                    transition: none !important;
                    animation: none !important;
                    pointer-events: none !important;
                }
            `;
        }

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
                .lha-mod-section-title {
                    font-size: 13px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    color: var(--lha-mod-accent);
                    margin-bottom: 10px;
                    opacity: 0.9;
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
                .lha-mod-hint {
                    font-size: 12px;
                    opacity: 0.55;
                    margin-top: 4px;
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
                .lha-mod-preview-row {
                    display: flex;
                    align-items: center;
                    gap: 14px;
                    margin-bottom: 12px;
                }
                .lha-mod-preview-box {
                    width: 56px;
                    height: 56px;
                    border-radius: 8px;
                    background: #1a1a1a;
                    border: 1px solid #444;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    overflow: hidden;
                    flex-shrink: 0;
                }
                .lha-mod-preview-box.lha-mod-preview-wide {
                    width: 96px;
                }
                .lha-mod-preview-box img {
                    max-width: 100%;
                    max-height: 100%;
                    object-fit: contain;
                }
                .lha-mod-file-btn {
                    display: inline-block;
                    padding: 8px 14px;
                    background: #1a1a1a;
                    border: 1px solid #444;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 13px;
                    text-align: center;
                }
                .lha-mod-file-btn:hover {
                    background: #222;
                }
                .lha-mod-btn-secondary {
                    background: transparent;
                    color: var(--lha-mod-text);
                    border: 1px solid #444;
                    padding: 8px 12px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 13px;
                }
                .lha-mod-btn-secondary:hover {
                    background: #222;
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
        const fixShield = () => {
            const targetUrl = DEFAULT_LOGO_URL;
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
                // Note: we intentionally do NOT force display/visibility/opacity here.
                // Some matched elements (e.g. a login-page shield) are deliberately
                // hidden by the site on pages where they don't apply — forcing them
                // visible was causing a second copy of the logo to render alongside
                // the real one, especially noticeable with a custom uploaded image.
            });
        };

        // 1. Try immediately
        fixShield();

        // 2. Observer for dynamic changes or late loading
        const observer = new MutationObserver(() => fixShield());

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

    // --- Favicon Replacement ---
    const handleFaviconReplacement = () => {
        const ICON_RELS = ['icon', 'shortcut icon', 'apple-touch-icon'];

        const fixFavicon = () => {
            const existingIcons = Array.from(document.querySelectorAll('link[rel]'))
                .filter(link => ICON_RELS.includes((link.getAttribute('rel') || '').toLowerCase()));

            if (existingIcons.length === 0) {
                // No favicon link at all — create one so the browser has something to show.
                const link = document.createElement('link');
                link.rel = 'icon';
                link.href = FAVICON_URL;
                (document.head || document.documentElement).appendChild(link);
                return;
            }

            existingIcons.forEach(link => {
                if (link.href !== FAVICON_URL) {
                    link.href = FAVICON_URL;
                }
            });
        };

        // 1. Try immediately
        fixFavicon();

        // 2. Observer in case the site sets/resets its favicon dynamically
        const observer = new MutationObserver(() => fixFavicon());
        observer.observe(document.head || document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['href', 'rel']
        });

        // 3. Periodic check for a few seconds as a fallback
        let checks = 0;
        const interval = setInterval(() => {
            fixFavicon();
            if (++checks > 20) clearInterval(interval);
        }, 500);
    };

    // --- Image Preview/Expansion Logic ---
    const handleImageExpansion = () => {
        if (!window.location.pathname.includes(BULLETIN_PATH)) return;

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
        if (!window.location.pathname.includes(BULLETIN_PATH)) return;

        const addReadAllButton = () => {
            if (document.getElementById('lha-read-all-btn')) return;

            const btn = document.createElement('button');
            btn.id = 'lha-read-all-btn';
            btn.innerHTML = 'Mark All As Read';

            btn.onclick = async () => {
                const bubbles = document.querySelectorAll('.incompletebubble');
                if (bubbles.length === 0) {
                    NotificationSystem.show('All bulletins are already read!', 'info');
                    return;
                }

                if (!confirm(`Mark ${bubbles.length} bulletins as read?`)) return;

                btn.disabled = true;
                btn.innerHTML = 'Marking...';

                for (let i = 0; i < bubbles.length; i++) {
                    bubbles[i].click();
                    if (i % 5 === 0) NotificationSystem.show(`Marking ${i + 1}/${bubbles.length}...`, 'info', 1000);
                    await new Promise(resolve => setTimeout(resolve, 300));
                }

                NotificationSystem.show('All bulletins marked as read!', 'success');
                btn.innerHTML = 'Refreshing...';
                setTimeout(() => location.reload(), 1500);
            };

            document.body.appendChild(btn);
        };

        const observer = new MutationObserver(() => {
            addReadAllButton();
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
        addReadAllButton();
    };

    // --- Force Complete Logic ---
    // NOTE: left exactly as originally written/unmodified.
    const handleForceComplete = () => {
        const isTargetPage = window.location.href.includes('upcominggrid.aspx');
        if (!isTargetPage) return;

        const attachForceButton = () => {
            const incompleteBubbles = document.querySelectorAll('.incompletebubble:not(.lha-force-complete-processed)');

            incompleteBubbles.forEach(bubble => {
                const checkbox = bubble.querySelector('input[id*="cbcomplete"]');

                if (checkbox) {
                    bubble.classList.add('lha-force-complete-processed');
                    const hwId = checkbox.id.split('_').pop();

                    if (getComputedStyle(bubble).position === 'static') {
                        bubble.style.position = 'relative';
                    }
                    bubble.style.overflow = 'visible';

                    const container = document.createElement('div');
                    container.className = 'lha-force-btn-container';
                    container.style.cssText = `
                        position: absolute !important;
                        right: calc(100% + 15px) !important;
                        top: 50% !important;
                        transform: translateY(-50%) !important;
                        display: flex !important;
                        align-items: center !important;
                        justify-content: center !important;
                        z-index: 2147483647 !important;
                        background-color: #333 !important;
                        padding: 3px 18px !important;
                        min-width: 90px !important;
                        border-radius: 4px !important;
                        border: 1px solid #555 !important;
                        white-space: nowrap !important;
                        box-shadow: 0 4px 8px rgba(0,0,0,0.5) !important;
                        cursor: pointer !important;
                        transition: background-color 0.2s;
                    `;

                    container.innerHTML = `
                        <span style="font-size: 11px !important; color: #ccc !important; font-weight: bold !important; user-select: none !important; text-transform: uppercase; letter-spacing: 0.5px;">
                            Complete
                        </span>
                    `;

                    container.onmouseover = () => { container.style.backgroundColor = '#444'; };
                    container.onmouseout = () => { container.style.backgroundColor = '#333'; };

                    container.onclick = async (e) => {
                        e.stopPropagation();

                        try {
                            const response = await fetch("https://lha.schoolsynergy.co.uk/portal/students_v2/desktop/homework/DataHandler.ashx?type=students_v2_desktop_homework_stucomplete_set", {
                                method: "POST",
                                headers: {
                                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                                    "X-Requested-With": "XMLHttpRequest"
                                },
                                body: `mhwid=${hwId}&mhdstucomplete=1`
                            });

                            if (response.ok) {
                                container.innerHTML = '<span style="color: #4a9eff;">Done!</span>';
                                container.style.pointerEvents = 'none';
                                NotificationSystem.show('Homework marked as completed!', 'success');
                                setTimeout(() => {
                                    location.reload();
                                }, 1500);
                            }
                        } catch (err) {
                            console.error('[LHA Mod] Force Complete failed', err);
                            NotificationSystem.show('Failed to update status.', 'error');
                        }
                    };

                    bubble.appendChild(container);
                }
            });
        };

        try {
            const observer = new MutationObserver(attachForceButton);
            observer.observe(document.documentElement || document, { childList: true, subtree: true });
            attachForceButton();
        } catch (e) { }

        setInterval(attachForceButton, 1500);
    };

    // --- Settings Page Rendering ---
    const renderSettingsPage = () => {
        document.title = "LHA Mod Menu - Settings";

        const currentBgUrl = GM_getValue(STORAGE_KEYS.BACKGROUND_URL, '');
        const currentFont = GM_getValue(STORAGE_KEYS.FONT_FAMILY, '');
        const currentColor = GM_getValue(STORAGE_KEYS.TEXT_COLOR, '');
        const activeBg = getActiveBackgroundUrl();

        document.body.innerHTML = `
            <div class="lha-mod-container">
                <div class="lha-mod-header">
                    <span>Mod Settings</span>
                    <a href="#" id="lha-back-btn" class="lha-mod-back">← Back to Site</a>
                </div>

                <div class="lha-mod-section">
                    <div class="lha-mod-section-title">Background</div>
                    <div class="lha-mod-preview-row">
                        <div class="lha-mod-preview-box lha-mod-preview-wide">
                            ${activeBg ? `<img id="lha-bg-preview-img" src="${activeBg}" alt="Background preview">` : `<span id="lha-bg-preview-img" style="font-size:11px; opacity:0.5;">None</span>`}
                        </div>
                        <div style="flex:1;">
                            <label class="lha-mod-file-btn" for="lha-bg-file">Upload image…</label>
                            <input type="file" id="lha-bg-file" accept="image/*" style="display:none;">
                            <div class="lha-mod-hint">Uploaded images are stored locally in your browser.</div>
                        </div>
                    </div>
                    <div class="lha-mod-field">
                        <label class="lha-mod-label">Or use a Background Image URL</label>
                        <input type="text" id="lha-bg-url" class="lha-mod-input" placeholder="https://example.com/image.jpg" value="${currentBgUrl}">
                        <div class="lha-mod-hint">A pasted URL is ignored while an uploaded image is set. Clear both to remove the background.</div>
                    </div>
                    <button type="button" id="lha-bg-reset-btn" class="lha-mod-btn-secondary">Remove background</button>
                </div>

                <div class="lha-mod-section">
                    <div class="lha-mod-section-title">Appearance</div>
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

        // Track the pending uploaded background (base64) separately so we only
        // write it to storage once the user hits Save.
        let pendingBgData = null;
        let pendingBgCleared = false;

        const preview = document.getElementById('lha-bg-preview-img');
        const fileInput = document.getElementById('lha-bg-file');
        const urlInput = document.getElementById('lha-bg-url');

        const setPreview = (src) => {
            if (!preview) return;
            if (preview.tagName === 'IMG') {
                if (src) {
                    preview.src = src;
                } else {
                    preview.replaceWith(Object.assign(document.createElement('span'), {
                        id: 'lha-bg-preview-img',
                        style: 'font-size:11px; opacity:0.5;',
                        textContent: 'None'
                    }));
                }
            } else if (src) {
                const img = document.createElement('img');
                img.id = 'lha-bg-preview-img';
                img.src = src;
                img.alt = 'Background preview';
                preview.replaceWith(img);
            }
        };

        fileInput.addEventListener('change', () => {
            const file = fileInput.files?.[0];
            if (!file) return;

            if (!file.type.startsWith('image/')) {
                alert('Please choose an image file.');
                fileInput.value = '';
                return;
            }

            const reader = new FileReader();
            reader.onload = () => {
                pendingBgData = reader.result; // base64 data URL
                pendingBgCleared = false;
                setPreview(pendingBgData);
            };
            reader.onerror = () => {
                NotificationSystem.show('Could not read that image file.', 'error');
            };
            reader.readAsDataURL(file);
        });

        urlInput.addEventListener('input', () => {
            // Typing a URL supersedes any newly-chosen upload in this session
            pendingBgData = null;
            pendingBgCleared = false;
            fileInput.value = '';
            setPreview(urlInput.value.trim());
        });

        document.getElementById('lha-bg-reset-btn').addEventListener('click', () => {
            pendingBgData = null;
            pendingBgCleared = true;
            fileInput.value = '';
            urlInput.value = '';
            setPreview('');
        });

        document.getElementById('lha-save-btn').addEventListener('click', () => {
            GM_setValue(STORAGE_KEYS.FONT_FAMILY, document.getElementById('lha-font-family').value);
            GM_setValue(STORAGE_KEYS.TEXT_COLOR, document.getElementById('lha-text-color').value);

            if (pendingBgCleared) {
                GM_setValue(STORAGE_KEYS.BACKGROUND_DATA, '');
                GM_setValue(STORAGE_KEYS.BACKGROUND_URL, '');
            } else if (pendingBgData) {
                GM_setValue(STORAGE_KEYS.BACKGROUND_DATA, pendingBgData);
                GM_setValue(STORAGE_KEYS.BACKGROUND_URL, '');
            } else {
                // No new upload this session — respect whatever the URL field says,
                // but don't clobber a previously uploaded image unless the field
                // was actually edited (pendingBgCleared covers the explicit clear).
                const typedUrl = urlInput.value.trim();
                if (typedUrl) {
                    GM_setValue(STORAGE_KEYS.BACKGROUND_DATA, '');
                    GM_setValue(STORAGE_KEYS.BACKGROUND_URL, typedUrl);
                }
            }

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
        btn.title = 'LHA Mod Menu Settings';
        btn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="3"></circle>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
        `;

        document.body.appendChild(btn);
    };

    // Since we call window.stop() on the settings route, the parser may
    // have been cut off before <body> ever arrived. Rather than waiting on
    // a parser that's no longer running, create the body ourselves if it's
    // missing so we can render into it immediately.
    const ensureBody = (callback) => {
        if (document.body) {
            callback();
            return;
        }
        if (document.documentElement) {
            const body = document.createElement('body');
            document.documentElement.appendChild(body);
            callback();
            return;
        }
        // <html> itself doesn't exist yet — vanishingly rare at document-start,
        // but wait one tick and try again rather than fail silently.
        setTimeout(() => ensureBody(callback), 0);
    };

    const revealSettingsPage = () => {
        if (document.documentElement) {
            document.documentElement.style.visibility = '';
        }
        // Overrides the earlier "hidden" stylesheet rule — same specificity
        // and both !important, so the later rule (this one) wins.
        GM_addStyle(`html, html body { visibility: visible !important; }`);
    };

    // --- Initialization ---
    const init = () => {
        injectStyles(); // Vital styles, keep outside try-catch

        try { handleImageRedirection(); } catch (e) { console.error('LHA Mod: handleImageRedirection failed', e); }
        try { handleFaviconReplacement(); } catch (e) { console.error('LHA Mod: handleFaviconReplacement failed', e); }
        try { handleImageExpansion(); } catch (e) { console.error('LHA Mod: handleImageExpansion failed', e); }
        try { handleReadAllBulletins(); } catch (e) { console.error('LHA Mod: handleReadAllBulletins failed', e); }
        try { handleForceComplete(); } catch (e) { console.error('LHA Mod: handleForceComplete failed', e); }
        try { handlePrivacyToggle(); } catch (e) { console.error('LHA Mod: handlePrivacyToggle failed', e); }
        try { checkForUpdates(); } catch (e) { console.error('LHA Mod: checkForUpdates failed', e); }
        try { handleHomeworkAlerts(); } catch (e) { console.error('LHA Mod: handleHomeworkAlerts failed', e); }

        // Welcome Notification (With Cooldown)
        if (window.location.pathname.includes(HOME_PATH)) {
            const lastWelcomeTime = GM_getValue('lha_last_welcome_time', 0);
            const now = Date.now();
            const COOLDOWN = 60 * 60 * 1000; // 1 Hour

            if (now - lastWelcomeTime > COOLDOWN) {
                const showWelcome = () => {
                    setTimeout(() => {
                        NotificationSystem.show('Welcome to LHA School Synergy', 'info');
                        GM_setValue('lha_last_welcome_time', now);
                    }, 1000);
                };

                if (document.readyState === 'complete') {
                    showWelcome();
                } else {
                    window.addEventListener('load', showWelcome);
                }
            }
        }

        if (window.location.pathname === SETTINGS_PATH) {
            ensureBody(() => {
                renderSettingsPage();
                revealSettingsPage();
            });
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
