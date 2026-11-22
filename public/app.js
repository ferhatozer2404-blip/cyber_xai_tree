/**
 * cyber_xai_tree - SOC Dashboard & XAI Engine Frontend
 * Güvenli Onay/Bildirim Akışı, XAI Karar Yolu, Karşı-Olgusal Analiz ve Akademik Değerlendirme
 */

let lastBatchResults = [];
let lastBatchQuality = null;
let lastBatchSchemaMapping = null;
let cachedLogs = [];
let currentQuarantineIps = new Set();

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeAttr(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '&quot;');
}

function isPrivateIpClient(ip = '') {
    const clean = String(ip).trim();
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
    const m = clean.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
    return m ? Number(m[1]) >= 16 && Number(m[1]) <= 31 : false;
}

function getIpScopeBadge(ip = '') {
    const isPrivate = isPrivateIpClient(ip);
    return isPrivate
        ? `<span class="badge-private-ip">İç Ağ (Özel)</span>`
        : `<span class="badge-public-ip">Dış Ağ (Genel)</span>`;
}

async function refreshQuarantineSet() {
    try {
        const res = await fetch('/api/quarantine');
        const list = await res.json();
        if (Array.isArray(list)) {
            currentQuarantineIps = new Set(list.map(item => item.ip));
        }
    } catch {
        // sessizce geç
    }
}

if (typeof window !== 'undefined') {
    window.addEventListener('DOMContentLoaded', () => {
        refreshQuarantineSet();
    });
}

/* ==========================================================================
   SOC BİLDİRİM SİSTEMİ (TOAST NOTIFICATIONS)
   ========================================================================== */
function showToast(message, type = 'info', title = '') {
    let container = document.getElementById('socToastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'socToastContainer';
        container.className = 'soc-toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `soc-toast soc-toast-${type}`;

    const defaultTitles = {
        success: 'İşlem Başarılı',
        error: 'Sistem Hatası',
        warning: 'Eksik veya Geçersiz Veri',
        info: 'Sistem Bildirimi'
    };

    const typeBadges = {
        success: 'BAŞARILI',
        error: 'HATA',
        warning: 'UYARI',
        info: 'BİLGİ'
    };

    const toastTitle = title || defaultTitles[type] || 'Bildirim';

    toast.innerHTML = `
        <div class="soc-toast-badge soc-toast-badge-${type}">${typeBadges[type] || 'BİLGİ'}</div>
        <div class="soc-toast-content">
            <div class="soc-toast-title">${escapeHtml(toastTitle)}</div>
            <div class="soc-toast-msg">${escapeHtml(message)}</div>
        </div>
        <button type="button" class="soc-toast-close" aria-label="Kapat">&times;</button>
    `;

    container.appendChild(toast);

    const closeBtn = toast.querySelector('.soc-toast-close');
    let timer;

    const dismiss = () => {
        if (toast.classList.contains('soc-toast-hiding')) return;
        toast.classList.add('soc-toast-hiding');
        setTimeout(() => toast.remove(), 240);
    };

    closeBtn.addEventListener('click', dismiss);
    timer = setTimeout(dismiss, 4200);

    toast.addEventListener('mouseenter', () => clearTimeout(timer));
    toast.addEventListener('mouseleave', () => {
        timer = setTimeout(dismiss, 2000);
    });
}

/* ==========================================================================
   SOC ONAY MODALI (MODAL CONFIRMATION DIALOG)
   ========================================================================== */
function showConfirmModal({
    title = 'İşlem Onayı',
    message = 'Bu işlemi gerçekleştirmek istediğinize emin misiniz?',
    target = '',
    warning = '',
    confirmText = 'Onayla',
    cancelText = 'İptal',
    danger = false
} = {}) {
    return new Promise((resolve) => {
        const existing = document.getElementById('socConfirmModal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'socConfirmModal';
        modal.className = 'soc-modal-backdrop';

        modal.innerHTML = `
            <div class="soc-modal-card ${danger ? 'soc-modal-danger' : ''}">
                <div class="soc-modal-header">
                    <div class="soc-modal-title">${escapeHtml(title)}</div>
                </div>
                <div class="soc-modal-body">
                    <p class="soc-modal-message">${escapeHtml(message)}</p>
                    ${warning ? `<div class="internal-network-warning" style="margin-top:10px;">${escapeHtml(warning)}</div>` : ''}
                    ${target ? `<div class="soc-modal-target" style="margin-top:10px;"><span>Hedef:</span> <code>${escapeHtml(target)}</code></div>` : ''}
                </div>
                <div class="soc-modal-footer">
                    <button type="button" class="soc-btn-cancel">${escapeHtml(cancelText)}</button>
                    <button type="button" class="soc-btn-confirm ${danger ? 'soc-btn-danger' : 'soc-btn-primary'}">${escapeHtml(confirmText)}</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        requestAnimationFrame(() => modal.classList.add('soc-modal-visible'));

        const cancelBtn = modal.querySelector('.soc-btn-cancel');
        const confirmBtn = modal.querySelector('.soc-btn-confirm');

        const cleanup = (result) => {
            modal.classList.remove('soc-modal-visible');
            setTimeout(() => modal.remove(), 220);
            window.removeEventListener('keydown', keyHandler);
            resolve(result);
        };

        const keyHandler = (e) => {
            if (e.key === 'Escape') cleanup(false);
            if (e.key === 'Enter') cleanup(true);
        };

        window.addEventListener('keydown', keyHandler);
        cancelBtn.addEventListener('click', () => cleanup(false));
        confirmBtn.addEventListener('click', () => cleanup(true));
        modal.addEventListener('click', (e) => {
            if (e.target === modal) cleanup(false);
        });

        confirmBtn.focus();
    });
}

/* ==========================================================================
   YARDIMCI FONKSİYONLAR & DOĞRULAMA
   ========================================================================== */
function getRiskStyles(risk) {
    if (risk === 'Yüksek') return { badge: 'badge-high', banner: 'banner-high' };
    if (risk === 'Orta') return { badge: 'badge-med', banner: 'banner-med' };
    return { badge: 'badge-low', banner: 'banner-low' };
}

function isValidIpv4(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
        if (!/^\d+$/.test(p)) return false;
        const n = Number(p);
        return n >= 0 && n <= 255;
    });
}

function getThresholdsPayload() {
    const pkt = document.getElementById('packetThreshold');
    const fail = document.getElementById('failedLoginThreshold');
    const rate = document.getElementById('requestRateThreshold');

    return {
        packetThreshold: pkt ? Number(pkt.value) : 1500,
        failedLoginThreshold: fail ? Number(fail.value) : 3,
        requestRateThreshold: rate ? Number(rate.value) : 80
    };
}

/* ==========================================================================
   HIZLI SENARYO BUTONLARI (PRESETS)
   ========================================================================== */
function applyPreset(type) {
    const presets = {
        ddos: {
            sourceIp: '185.220.101.42',
            packetSize: 2450,
            duration: 0.1,
            isKnownPort: 'true',
            failedLogins: 0,
            requestRate: 140,
            name: 'DDoS / Flood'
        },
        bruteforce: {
            sourceIp: '91.132.44.19',
            packetSize: 420,
            duration: 6.5,
            isKnownPort: 'false',
            failedLogins: 8,
            requestRate: 25,
            name: 'Brute-Force'
        },
        portscan: {
            sourceIp: '45.83.64.11',
            packetSize: 110,
            duration: 0.05,
            isKnownPort: 'false',
            failedLogins: 0,
            requestRate: 65,
            name: 'Port Taraması'
        },
        exfil: {
            sourceIp: '172.16.40.88',
            packetSize: 3800,
            duration: 12.4,
            isKnownPort: 'false',
            failedLogins: 0,
            requestRate: 15,
            name: 'Veri Sızdırma'
        },
        normal: {
            sourceIp: '192.168.1.24',
            packetSize: 540,
            duration: 1.6,
            isKnownPort: 'true',
            failedLogins: 0,
            requestRate: 12,
            name: 'Normal Trafik'
        }
    };

    const p = presets[type] || presets.normal;
    document.getElementById('sourceIp').value = p.sourceIp;
    document.getElementById('packetSize').value = p.packetSize;
    document.getElementById('duration').value = p.duration;
    document.getElementById('isKnownPort').value = p.isKnownPort;
    document.getElementById('failedLogins').value = p.failedLogins;
    document.getElementById('requestRate').value = p.requestRate;

    document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('active'));
    const clickedBtn = document.querySelector(`.preset-btn[data-preset="${type}"]`);
    if (clickedBtn) clickedBtn.classList.add('active');

    showToast(`"${p.name}" test senaryosu yüklendi ve analiz ediliyor...`, 'info', 'Senaryo Yüklendi');
    analyzeTraffic();
}

/* ==========================================================================
   TEKİL ANALİZ: XAI KARAR YOLU, KATKI ANALİZİ, SINIR DUYARLILIĞI, SOC PLAYBOOK
   ========================================================================== */
async function analyzeTraffic() {
    const sourceIpEl = document.getElementById('sourceIp');
    const packetSizeEl = document.getElementById('packetSize');
    const durationEl = document.getElementById('duration');
    const isKnownPortEl = document.getElementById('isKnownPort');
    const failedLoginsEl = document.getElementById('failedLogins');
    const requestRateEl = document.getElementById('requestRate');

    const sourceIp = sourceIpEl ? sourceIpEl.value.trim() : '';
    const packetSize = packetSizeEl ? packetSizeEl.value.trim() : '';
    const duration = durationEl ? durationEl.value.trim() : '';
    const failedLogins = failedLoginsEl ? failedLoginsEl.value.trim() : '';
    const requestRate = requestRateEl ? requestRateEl.value.trim() : '';

    if (!sourceIp) {
        showToast('Lütfen geçerli bir Kaynak IP adresi girin.', 'warning', 'Eksik Alan');
        if (sourceIpEl) sourceIpEl.focus();
        return;
    }

    if (packetSize === '' || Number(packetSize) < 0) {
        showToast('Paket boyutu 0 veya pozitif bir sayı olmalıdır.', 'warning', 'Geçersiz Paket Boyutu');
        if (packetSizeEl) packetSizeEl.focus();
        return;
    }

    if (duration === '' || Number(duration) < 0) {
        showToast('Bağlantı süresi 0 veya pozitif bir saniye değeri olmalıdır.', 'warning', 'Geçersiz Bağlantı Süresi');
        if (durationEl) durationEl.focus();
        return;
    }

    if (requestRate === '' || Number(requestRate) < 0) {
        showToast('İstek hızı pozitif bir req/s değeri olmalıdır.', 'warning', 'Geçersiz İstek Hızı');
        if (requestRateEl) requestRateEl.focus();
        return;
    }

    if (failedLogins === '' || Number(failedLogins) < 0) {
        showToast('Başarısız giriş sayısı negatif olamaz.', 'warning', 'Geçersiz Giriş Sayısı');
        if (failedLoginsEl) failedLoginsEl.focus();
        return;
    }

    const payload = {
        sourceIp,
        packetSize: Number(packetSize),
        duration: Number(duration),
        isKnownPort: isKnownPortEl ? isKnownPortEl.value : 'false',
        failedLogins: Number(failedLogins),
        requestRate: Number(requestRate),
        thresholds: getThresholdsPayload()
    };

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await res.json();
        if (result.error) {
            showToast(result.error, 'error', 'Analiz Başarısız');
            return;
        }

        const styles = getRiskStyles(result.riskLevel);
        const emptyState = document.getElementById('emptyState');
        const resultArea = document.getElementById('resultArea');

        if (emptyState) emptyState.style.display = 'none';
        if (resultArea) resultArea.style.display = 'block';

        // 1. Sonuç Banner'ı
        const banner = document.getElementById('resultBanner');
        if (banner) banner.className = 'result-banner ' + styles.banner;

        const typeEl = document.getElementById('resType');
        if (typeEl) typeEl.innerText = result.attackType;

        const riskEl = document.getElementById('resRisk');
        if (riskEl) {
            riskEl.innerText = `${result.riskLevel} Risk`;
            riskEl.className = 'risk-badge ' + styles.badge;
        }

        // 2. 4'lü Metrikler
        const scoreEl = document.getElementById('resScore');
        if (scoreEl) scoreEl.innerText = `${result.riskScore} / 100`;

        const confEl = document.getElementById('resConfidence');
        if (confEl) confEl.innerText = `%${result.confidence}`;

        const sens = result.boundarySensitivity;
        const stabSub = document.getElementById('resStabilitySub');
        if (stabSub && sens) {
            stabSub.innerText = `Kararlılık: ${sens.sensitivityLevel.split(' ')[0]} (%${sens.marginPercentage})`;
        }

        const scopeEl = document.getElementById('resScope');
        if (scopeEl) scopeEl.innerHTML = getIpScopeBadge(result.input.sourceIp);

        const qStatusEl = document.getElementById('resQuarantineStatus');
        if (qStatusEl) {
            if (result.isQuarantined) {
                qStatusEl.innerHTML = '<span style="color:#fb7185; font-weight:700;">Karantinada</span>';
            } else {
                qStatusEl.innerHTML = '<span style="color:#34d399; font-weight:700;">Aktif / Listede Değil</span>';
            }
        }

        // 3. SOC Önerisi (İç Ağ Uyarılı)
        const recEl = document.getElementById('resRecommendation');
        if (recEl) {
            let recText = result.recommendation;
            if (result.socPlaybook && result.socPlaybook.privateWarning) {
                recText = `[İç Ağ IP Uyarısı: ${result.input.sourceIp} yerel ağa (RFC 1918) aittir] ${recText}`;
            }
            recEl.innerText = recText;
        }

        // 4. Sınır Duyarlılığı ve Karar Yolu
        const boundNote = document.getElementById('resBoundaryNote');
        if (boundNote && sens) {
            boundNote.innerText = `Sınır Duyarlılığı: %${sens.marginPercentage} mesafe (${sens.sensitivityLevel})`;
        }

        const pathEl = document.getElementById('resPath');
        if (pathEl) {
            pathEl.innerHTML = '';
            const flowContainer = document.createElement('div');
            flowContainer.className = 'tree-flow-wrap';

            const steps = result.decisionPath || [];
            steps.forEach((step, idx) => {
                const card = document.createElement('div');
                card.className = 'tree-step-card';

                const isYes = String(step.branch).toUpperCase() === 'EVET';
                const branchHtml = isYes
                    ? `<span class="branch-badge branch-badge-yes">EVET (Koşul Sağlandı)</span>`
                    : `<span class="branch-badge branch-badge-no">HAYIR (Koşul Sağlanmadı)</span>`;

                card.innerHTML = `
                    <div class="tree-step-header">
                        <div class="tree-step-badge">ADIM ${idx + 1}: ${escapeHtml(step.node)}</div>
                        ${branchHtml}
                    </div>
                    <div class="tree-step-rule"><strong>Koşul:</strong> ${escapeHtml(step.condition || step.rule)}</div>
                    <div style="font-size:0.78rem; color:var(--text-secondary); margin-top:6px;">
                        Girdi: <code>${escapeHtml(step.actualValue || '-')}</code> | Eşik: <code>${escapeHtml(step.threshold || '-')}</code>
                    </div>
                    ${step.evaluation ? `<div style="font-size:0.77rem; color:var(--text-muted); margin-top:4px;">${escapeHtml(step.evaluation)}</div>` : ''}
                `;
                flowContainer.appendChild(card);

                if (idx < steps.length - 1) {
                    const conn = document.createElement('div');
                    conn.className = 'tree-connector';
                    conn.innerHTML = `<span class="tree-connector-line"></span>`;
                    flowContainer.appendChild(conn);
                }
            });

            // Nihai Karar Düğümü
            const finalCard = document.createElement('div');
            finalCard.className = 'tree-final-card';
            finalCard.innerHTML = `
                <span style="font-size:0.84rem; font-weight:700; color:var(--text-primary);">Sınıflandırma Kararı: ${escapeHtml(result.attackType)}</span>
                <span class="risk-badge ${styles.badge}">${escapeHtml(result.riskLevel)}</span>
            `;
            flowContainer.appendChild(finalCard);
            pathEl.appendChild(flowContainer);
        }

        // 5. Dinamik Özellik Katkı Analizi (Feature Attribution)
        const faEl = document.getElementById('resFeatureAttribution');
        if (faEl) {
            faEl.innerHTML = '';
            const faList = result.featureAttribution || [];
            faList.forEach(item => {
                const div = document.createElement('div');
                div.className = 'fa-item';
                div.innerHTML = `
                    <div class="fa-header">
                        <span class="fa-label">${escapeHtml(item.label)}</span>
                        <span class="fa-value">${escapeHtml(item.value)} (%${item.weight})</span>
                    </div>
                    <div class="fa-bar-track">
                        <div class="fa-bar-fill" style="width: ${item.weight}%"></div>
                    </div>
                `;
                faEl.appendChild(div);
            });
        }

        // 6. Karşı-Olgusal Analiz (Sparsity & Cost Metrik Satırı İle)
        const cfEl = document.getElementById('resCounterfactuals');
        if (cfEl) {
            cfEl.innerHTML = '';
            const cfData = result.counterfactuals || {};
            const cfs = Array.isArray(result.counterfactuals)
                ? result.counterfactuals
                : (cfData.explanation ? [cfData.explanation] : []);

            const sparsityVal = cfData.sparsity !== undefined ? cfData.sparsity : 1;
            const costVal = cfData.cost !== undefined ? cfData.cost : 0.18;

            if (!cfs.length) {
                cfEl.innerHTML = `<div class="cf-card">Belirlenen sınırlar dahilinde alternatif karar dalı bulunmuyor.</div>`;
            } else {
                cfs.forEach((cfText) => {
                    const card = document.createElement('div');
                    card.className = 'cf-card';
                    card.innerHTML = `
                        <div class="cf-header">Alternatif Karar Koşulu (Karşı-Olgusal)</div>
                        <div style="line-height:1.55;">${escapeHtml(cfText)}</div>
                        <div style="margin-top:8px; padding-top:6px; border-top:1px solid rgba(245, 158, 11, 0.2); font-size:0.77rem; font-family:'JetBrains Mono',monospace; color:var(--text-secondary);">
                            Değişen Özellik Sayısı (Sparsity): <span style="color:#fbbf24; font-weight:700;">${sparsityVal}</span> &nbsp;|&nbsp; Normalize Değişim Maliyeti (Cost): <span style="color:#fbbf24; font-weight:700;">${costVal}</span>
                        </div>
                    `;
                    cfEl.appendChild(card);
                });
            }
        }
    } catch (err) {
        showToast('Sunucuya bağlanırken bir hata oluştu: ' + err.message, 'error', 'Bağlantı Hatası');
    }
}

/* ==========================================================================
   KARANTİNA İŞLEMLERİ (ONAY MODALLI VE İÇ AĞ UYARILI)
   ========================================================================== */
async function quarantineCurrentIp() {
    const ipEl = document.getElementById('sourceIp');
    const typeEl = document.getElementById('resType');

    const ip = ipEl ? ipEl.value.trim() : '';
    if (!ip) {
        showToast('Karantinaya almak için lütfen geçerli bir Kaynak IP girin.', 'warning', 'Eksik IP Adresi');
        if (ipEl) ipEl.focus();
        return;
    }

    const reason = typeEl && typeEl.innerText !== '-' ? typeEl.innerText : 'Tekil analiz müdahalesi';
    const isPrivate = isPrivateIpClient(ip);
    const internalWarning = isPrivate
        ? `İç Ağ IP Uyarısı: ${ip} yerel ağa (RFC 1918) aittir. Karantina uygulandığında kritik iç servislerin kesintiye uğramayacağını doğrulayın.`
        : '';

    const confirmed = await showConfirmModal({
        title: 'IP Karantinaya Alınsın mı?',
        message: 'Bu IP adresi güvenlik karantina listesine kaydedilecektir. Karantinadaki IP adreslerinden gelen tüm akışlarda risk seviyesi otomatik olarak artırılır.',
        target: `${ip} (${reason})`,
        warning: internalWarning,
        confirmText: 'Karantinaya Al',
        cancelText: 'Vazgeç',
        danger: true
    });

    if (!confirmed) return;

    try {
        const res = await fetch('/api/quarantine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason })
        });

        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error', 'Karantina Hatası');
            return;
        }

        currentQuarantineIps.add(ip);
        showToast(`${ip} başarıyla karantina listesine eklendi.`, 'success', 'Karantina Aktif');
        const qStatus = document.getElementById('resQuarantineStatus');
        if (qStatus) {
            qStatus.innerHTML = '<span style="color:#fb7185; font-weight:700;">Karantinada</span>';
        }
    } catch (err) {
        showToast('Karantina işlemi başarısız: ' + err.message, 'error');
    }
}

async function quarantineIpFromRow(ip, reason) {
    ip = String(ip || '').trim();
    if (!ip) {
        showToast('Karantinaya alınacak IP adresi bulunamadı.', 'warning', 'Eksik IP');
        return;
    }

    const isPrivate = isPrivateIpClient(ip);
    const internalWarning = isPrivate
        ? `İç Ağ IP Uyarısı: ${ip} yerel ağa aittir. Karantina uygularken iç servisleri aksatmadığınızdan emin olun.`
        : '';

    const confirmed = await showConfirmModal({
        title: 'IP Karantinaya Alınsın mı?',
        message: 'Bu IP adresi güvenlik karantina listesine kaydedilecek ve denetim bayrağı eklenecektir.',
        target: `${ip} (${reason || 'Şüpheli Trafik'})`,
        warning: internalWarning,
        confirmText: 'Karantinaya Al',
        cancelText: 'Vazgeç',
        danger: true
    });

    if (!confirmed) return;

    try {
        const res = await fetch('/api/quarantine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: reason || 'Güvenlik Denetim Müdahalesi' })
        });
        const list = await res.json();
        if (list.error) {
            showToast(list.error, 'error', 'Karantina Hatası');
            return;
        }

        if (Array.isArray(list)) {
            currentQuarantineIps = new Set(list.map(item => item.ip));
        } else {
            currentQuarantineIps.add(ip);
        }

        showToast(`${ip} başarıyla karantina listesine eklendi.`, 'success', 'Karantina Aktif');

        if (document.getElementById('csvTableBody') && lastBatchResults.length > 0) {
            renderBatchTable();
        }
        if (document.getElementById('quarantineTableBody')) {
            renderQuarantineTable(list);
        }
        if (document.getElementById('logsTableBody') && cachedLogs.length > 0) {
            renderFilteredLogs();
        }
    } catch (err) {
        showToast('Karantina işlemi başarısız: ' + err.message, 'error');
    }
}

async function addManualQuarantine() {
    const input = document.getElementById('manualQuarantineIp');
    const ip = input ? input.value.trim() : '';

    if (!ip) {
        showToast('Lütfen karantinaya eklenecek geçerli bir IP adresi girin.', 'warning', 'Eksik IP Bilgisi');
        if (input) input.focus();
        return;
    }

    if (!isValidIpv4(ip)) {
        showToast('Lütfen geçerli bir IPv4 formatı girin (Örn: 185.220.101.42).', 'warning', 'Geçersiz Format');
        if (input) input.focus();
        return;
    }

    const isPrivate = isPrivateIpClient(ip);
    const internalWarning = isPrivate
        ? `İç Ağ IP Uyarısı: ${ip} yerel ağ IP adresidir.`
        : '';

    const confirmed = await showConfirmModal({
        title: 'Manuel Karantina Onayı',
        message: 'Belirtilen IP adresi SOC güvenlik karantina listesine kaydedilecek ve trafik denetimine tabi tutulacaktır.',
        target: ip,
        warning: internalWarning,
        confirmText: 'Karantinaya Ekle',
        cancelText: 'İptal',
        danger: true
    });

    if (!confirmed) return;

    try {
        const res = await fetch('/api/quarantine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: 'Manuel SOC Karantina' })
        });
        const list = await res.json();
        if (list.error) {
            showToast(list.error, 'error', 'Kayıt Hatası');
            return;
        }

        if (Array.isArray(list)) {
            currentQuarantineIps = new Set(list.map(item => item.ip));
        } else {
            currentQuarantineIps.add(ip);
        }

        input.value = '';
        renderQuarantineTable(list);
        if (document.getElementById('logsTableBody') && cachedLogs.length > 0) {
            renderFilteredLogs();
        }
        showToast(`${ip} karantina listesine kaydedildi.`, 'success', 'Karantina Eklendi');
    } catch (err) {
        showToast('İşlem sırasında hata oluştu: ' + err.message, 'error');
    }
}

async function removeFromQuarantine(encodedIp) {
    const targetIp = decodeURIComponent(encodedIp);

    const confirmed = await showConfirmModal({
        title: 'Karantinadan Çıkarılsın mı?',
        message: 'Bu IP adresinin karantina kısıtlaması kaldırılacak ve standart ağ izleme durumuna döndürülecektir.',
        target: targetIp,
        confirmText: 'Karantinayı Kaldır',
        cancelText: 'Vazgeç',
        danger: true
    });

    if (!confirmed) return;

    try {
        const res = await fetch(`/api/quarantine/${encodedIp}`, { method: 'DELETE' });
        const list = await res.json();
        if (Array.isArray(list)) {
            currentQuarantineIps = new Set(list.map(item => item.ip));
        } else {
            currentQuarantineIps.delete(targetIp);
        }
        renderQuarantineTable(list);
        if (document.getElementById('logsTableBody') && cachedLogs.length > 0) {
            renderFilteredLogs();
        }
        if (document.getElementById('csvTableBody') && lastBatchResults.length > 0) {
            renderBatchTable();
        }
        showToast(`${targetIp} karantina listesinden başarıyla kaldırıldı.`, 'info', 'Karantina Kaldırıldı');
    } catch (err) {
        showToast('Karantina kaldırma başarısız: ' + err.message, 'error');
    }
}

async function clearAllLogs() {
    const confirmed = await showConfirmModal({
        title: 'Analiz Geçmişini Temizle',
        message: 'Tüm analiz log kayıtları ve geçmiş denetim verileri kalıcı olarak silinecektir. Bu işlem geri alınamaz. Devam etmek istiyor musunuz?',
        confirmText: 'Tüm Geçmişi Sil',
        cancelText: 'Vazgeç',
        danger: true
    });

    if (!confirmed) return;

    try {
        const res = await fetch('/api/logs', { method: 'DELETE' });
        const data = await res.json();
        if (data.ok) {
            showToast('Tüm analiz logları ve geçmiş kayıtlar başarıyla temizlendi.', 'success', 'Geçmiş Sıfırlandı');
            loadLogsAndQuarantine();
        } else {
            showToast('Loglar silinirken bir sorun oluştu.', 'error');
        }
    } catch (err) {
        showToast('İşlem başarısız: ' + err.message, 'error');
    }
}

/* ==========================================================================
   CSV TOPLU ANALİZ, ETİKETLİ DOĞRULUK, DRIFT VE TEKRARLI IP YÖNETİMİ
   ========================================================================== */
function fillSampleCSVInput() {
    const sample = [
        'Kaynak IP, Paket Boyutu, Süre, Bilinen Port, Hatalı Giriş, İstek Hızı, Gerçek Etiket',
        '185.220.101.42, 2450, 0.1, true, 0, 140, DDoS / Flood Saldırısı',
        '91.132.44.19, 420, 6.5, false, 8, 25, Kaba Kuvvet (Brute-Force) Saldırısı',
        '45.83.64.11, 110, 0.05, false, 0, 65, Port Taraması ve Keşif Aktivitesi',
        '172.16.40.88, 3800, 12.4, false, 0, 15, Veri Sızdırma / Şüpheli Transfer',
        '192.168.1.24, 540, 1.6, true, 0, 12, Normal Trafik',
        '185.220.101.42, 2600, 0.15, true, 0, 150, DDoS / Flood Saldırısı',
        '10.0.0.45, 1900, 0.2, true, 0, 95, DDoS / Flood Saldırısı'
    ].join('\n');

    const textarea = document.getElementById('csvRawInput');
    const details = document.getElementById('csvDetailsWrap');
    if (textarea) textarea.value = sample;
    if (details) details.open = true;

    showToast('Örnek etiketli CSV veri seti yapıştırıldı. Analiz Et butonuna basabilirsiniz.', 'info', 'Örnek Veri Hazır');
}

function downloadSampleCSV() {
    const sampleCSV = [
        'Kaynak IP, Paket Boyutu, Süre, Bilinen Port, Hatalı Giriş, İstek Hızı, Gerçek Etiket',
        '185.220.101.42, 2450, 0.1, true, 0, 140, DDoS / Flood Saldırısı',
        '91.132.44.19, 420, 6.5, false, 8, 25, Kaba Kuvvet (Brute-Force) Saldırısı',
        '45.83.64.11, 110, 0.05, false, 0, 65, Port Taraması ve Keşif Aktivitesi',
        '172.16.40.88, 3800, 12.4, false, 0, 15, Veri Sızdırma / Şüpheli Transfer',
        '192.168.1.24, 540, 1.6, true, 0, 12, Normal Trafik',
        '10.0.0.45, 1900, 0.2, true, 0, 95, DDoS / Flood Saldırısı'
    ].join('\n');

    const blob = new Blob(['\uFEFF' + sampleCSV], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ornek_etiketli_ag_trafigi.csv';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Örnek etiketli CSV veri seti indirildi.', 'success', 'Dosya Hazır');
}

async function uploadAndAnalyzeCSV() {
    const fileInput = document.getElementById('csvFileInput');
    const rawTextarea = document.getElementById('csvRawInput');
    let csvContent = '';

    if (fileInput && fileInput.files && fileInput.files.length > 0) {
        csvContent = await fileInput.files[0].text();
    } else if (rawTextarea && rawTextarea.value.trim()) {
        csvContent = rawTextarea.value.trim();
    } else {
        showToast('Lütfen bir .csv dosyası seçin veya metin alanına geçerli CSV içeriği yapıştırın.', 'warning', 'CSV Verisi Eksik');
        return;
    }

    showToast('CSV verisi analiz ediliyor...', 'info', 'Toplu İşlem Başlatıldı');

    try {
        const res = await fetch('/api/analyze-csv', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                csvContent,
                thresholds: getThresholdsPayload()
            })
        });

        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error', 'CSV Analiz Hatası');
            return;
        }

        await refreshQuarantineSet();
        lastBatchResults = data.results || [];
        lastBatchQuality = data.dataQuality || null;
        lastBatchSchemaMapping = data.schemaMapping || null;
        const resultArea = document.getElementById('csvResultArea');
        if (resultArea) resultArea.style.display = 'block';

        // 1. Veri Kalitesi, Şema Eşleme ve Dağılım Farkı Özeti
        const dq = data.dataQuality || {};
        const dqText = document.getElementById('dataQualityText');
        const dqPills = document.getElementById('dataQualityPills');

        if (dqText) {
            dqText.innerText = dq.summaryText || (dq.isClean
                ? 'Tüm satırlar veri bütünlüğü korunarak başarıyla işlendi.'
                : `${dq.skippedRowsCount} adet boş veya hatalı format satırı çökme olmadan atlandı.`);
        }

        if (dqPills) {
            dqPills.innerHTML = `
                <span class="quality-pill ${dq.isClean ? 'quality-pill-clean' : 'quality-pill-warn'}">İşlenen: ${dq.validRowsProcessed || lastBatchResults.length} Satır</span>
                <span class="quality-pill ${dq.skippedRowsCount > 0 ? 'quality-pill-warn' : 'quality-pill-clean'}">Atlanan: ${dq.skippedRowsCount || 0} Satır</span>
            `;
        }

        const schemaEl = document.getElementById('schemaMappingText');
        if (schemaEl) {
            if (data.schemaMapping && data.schemaMapping.summaryText) {
                schemaEl.innerText = data.schemaMapping.summaryText;
                schemaEl.style.display = 'block';
            } else {
                schemaEl.style.display = 'none';
            }
        }

        const driftEl = document.getElementById('driftSummaryText');
        if (driftEl) {
            if (data.driftAnalysis && data.driftAnalysis.summaryText) {
                driftEl.innerText = data.driftAnalysis.summaryText;
                driftEl.style.display = 'block';
            } else {
                driftEl.style.display = 'none';
            }
        }

        // 2. Özet Kartları
        document.getElementById('batchTotal').innerText = data.summary.total;
        document.getElementById('batchHigh').innerText = data.summary.highRisk;
        document.getElementById('batchMed').innerText = data.summary.mediumRisk;
        document.getElementById('batchLow').innerText = data.summary.lowRisk;

        // 3. Akademik Değerlendirme & Karışıklık Matrisi (Etiketli Veri Varsa)
        const evalBox = document.getElementById('evalBox');
        if (evalBox) {
            if (data.evaluation && data.evaluation.labeledCount > 0) {
                evalBox.style.display = 'block';
                const ev = data.evaluation;

                if (document.getElementById('evalAccuracy')) document.getElementById('evalAccuracy').innerText = `%${ev.accuracy}`;
                if (document.getElementById('evalMacroF1')) document.getElementById('evalMacroF1').innerText = `%${ev.macroF1 || ev.f1Score}`;
                if (document.getElementById('evalWeightedF1')) document.getElementById('evalWeightedF1').innerText = `%${ev.weightedF1 || ev.accuracy}`;
                if (document.getElementById('evalPrecision')) document.getElementById('evalPrecision').innerText = `%${ev.macroPrecision || ev.precision}`;

                const detailEl = document.getElementById('evalDetail');
                if (detailEl) {
                    detailEl.innerText = `${ev.matchedCount} / ${ev.labeledCount} etiket eşleşti (Doğruluk: %${ev.accuracy}, Macro-F1: %${ev.macroF1 || ev.f1Score})`;
                }

                // FN / FP Güvenlik Özeti
                const sec = ev.securitySummary || {};
                if (document.getElementById('evalFnCount')) document.getElementById('evalFnCount').innerText = sec.falseNegatives || 0;
                if (document.getElementById('evalFnDesc')) {
                    document.getElementById('evalFnDesc').innerText = sec.criticalWarning || 'Saldırı kaçırma durumu tespit edilmedi.';
                }
                if (document.getElementById('evalFpCount')) document.getElementById('evalFpCount').innerText = sec.falsePositives || 0;
                if (document.getElementById('evalFpDesc')) {
                    document.getElementById('evalFpDesc').innerText = `Normal trafiğin saldırı sanılarak engellenmesi (Yanlış Pozitif Oranı: %${sec.fpRate || 0}).`;
                }

                // Sınıf Bazlı Tablo
                const cmBody = document.getElementById('evalClassMetricsBody');
                if (cmBody && ev.classMetrics) {
                    cmBody.innerHTML = Object.entries(ev.classMetrics).map(([cls, met]) => `
                        <tr>
                            <td><strong>${escapeHtml(cls)}</strong></td>
                            <td>${met.support}</td>
                            <td style="color:#34d399; font-family:'JetBrains Mono',monospace;">%${met.precision}</td>
                            <td style="color:#fbbf24; font-family:'JetBrains Mono',monospace;">%${met.recall}</td>
                            <td style="color:#38bdf8; font-weight:700; font-family:'JetBrains Mono',monospace;">%${met.f1}</td>
                        </tr>
                    `).join('');
                }

                // Karışıklık Matrisi (Confusion Matrix) Tablosu
                const cmWrap = document.getElementById('confusionMatrixWrap');
                if (cmWrap && ev.confusionMatrix) {
                    const cList = ev.confusionMatrix.classes || [];
                    const mat = ev.confusionMatrix.matrix || {};

                    let tableHtml = `<table class="confusion-matrix-table"><thead><tr><th class="matrix-header-cell">Gerçek \\ Tahmin</th>`;
                    cList.forEach(c => {
                        tableHtml += `<th>${escapeHtml(c)}</th>`;
                    });
                    tableHtml += `</tr></thead><tbody>`;

                    cList.forEach(act => {
                        tableHtml += `<tr><td class="matrix-header-cell">${escapeHtml(act)}</td>`;
                        cList.forEach(pred => {
                            const val = (mat[act] && mat[act][pred] !== undefined) ? mat[act][pred] : 0;
                            const isDiag = act === pred;
                            const cellClass = isDiag
                                ? 'matrix-cell-diagonal'
                                : (val > 0 ? 'matrix-cell-off has-error' : 'matrix-cell-off');
                            tableHtml += `<td class="${cellClass}">${val}</td>`;
                        });
                        tableHtml += `</tr>`;
                    });

                    tableHtml += `</tbody></table>`;
                    cmWrap.innerHTML = tableHtml;
                }
            } else {
                evalBox.style.display = 'none';
            }
        }

        // 4. Sınıf Dağılımı Tablosu
        const distTbody = document.getElementById('batchClassDistTable');
        if (distTbody && data.classDistribution) {
            distTbody.innerHTML = data.classDistribution.map(item => `
                <tr>
                    <td><strong>${escapeHtml(item.className)}</strong></td>
                    <td>${item.count.toLocaleString('tr-TR')}</td>
                    <td>
                        <div style="display:flex; align-items:center; gap:8px;">
                            <div class="fa-bar-track" style="max-width:120px; height:6px;">
                                <div class="fa-bar-fill" style="width:${item.percentage}%"></div>
                            </div>
                            <span style="font-family:'JetBrains Mono',monospace; font-size:0.78rem;">%${item.percentage}</span>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        // 5. Dağılım Kayması (Data Drift)
        const driftWrap = document.getElementById('driftStatusText');
        const driftList = document.getElementById('driftItemsList');
        if (driftWrap && driftList && data.driftAnalysis) {
            const da = data.driftAnalysis;
            driftWrap.innerText = da.hasPreviousBatch
                ? (da.significantDriftDetected ? 'Belirgin dağılım kayması (>= %10 değişim) tespit edildi.' : 'Dağılım önceki analize göre stabil seyrediyor.')
                : 'İlk toplu analiz tamamlandı. Referans dağılımı kaydedildi.';

            driftList.innerHTML = (da.classDrift || []).map(d => {
                const isUp = d.deltaPct > 0;
                const isDown = d.deltaPct < 0;
                const deltaClass = isUp ? 'drift-delta-up' : (isDown ? 'drift-delta-down' : 'drift-delta-neutral');
                const sign = isUp ? '+' : '';
                return `
                    <div class="drift-item">
                        <span>${escapeHtml(d.className)}: <strong>%${d.currentPct}</strong></span>
                        <span class="${deltaClass}">${sign}%${d.deltaPct} ${da.hasPreviousBatch ? '(Öncekine göre)' : '(Referans)'}</span>
                    </div>
                `;
            }).join('');
        }

        // 6. Tekrarlı Şüpheli IP Özeti
        const repSec = document.getElementById('repeatedIpsSection');
        const repBody = document.getElementById('repeatedIpsBody');
        if (repSec && repBody) {
            const repeated = data.repeatedIps || [];
            if (repeated.length > 0) {
                repSec.style.display = 'block';
                repBody.innerHTML = repeated.map(r => {
                    const isQ = currentQuarantineIps.has(r.ip);
                    const actionBtn = isQ
                        ? `<span class="badge-quarantined">Karantinada</span>`
                        : `<button type="button" class="btn-table-action btn-danger" onclick="quarantineIpFromRow('${escapeAttr(r.ip)}', '${escapeAttr(r.attackTypes)}')">Karantinaya Al</button>`;
                    return `
                        <tr>
                            <td><strong style="color:#fb7185;">${escapeHtml(r.ip)}</strong></td>
                            <td>${getIpScopeBadge(r.ip)}</td>
                            <td><span style="font-family:'JetBrains Mono',monospace; font-weight:700;">${r.flowCount} Akış</span></td>
                            <td><span class="risk-badge ${getRiskStyles(r.highestRisk).badge}">${r.highestRisk}</span></td>
                            <td style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(r.attackTypes)}</td>
                            <td class="col-action" style="text-align:right;">${actionBtn}</td>
                        </tr>
                    `;
                }).join('');
            } else {
                repSec.style.display = 'none';
            }
        }

        // 7. Toplu Tabloyu Doldur
        renderBatchTable();

        showToast(`${data.results.length} adet ağ akışı başarıyla sınıflandırıldı.`, 'success', 'Toplu Analiz Tamamlandı');
    } catch (err) {
        showToast('CSV işleme sırasında sunucu hatası: ' + err.message, 'error');
    }
}

function renderBatchTable() {
    const tbody = document.getElementById('csvTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    lastBatchResults.forEach((item) => {
        const styles = getRiskStyles(item.riskLevel);
        const tr = document.createElement('tr');

        const actual = item.input.actualLabel || '';
        let matchBadge = '';
        if (actual) {
            const pred = (item.attackType || '').toLowerCase();
            const act = actual.toLowerCase();
            const matched = pred.includes(act) || act.includes(pred);
            matchBadge = matched
                ? `<span style="display:inline-block; margin-left:6px; color:#34d399; font-size:0.75rem;">(Eşleşti)</span>`
                : `<span style="display:inline-block; margin-left:6px; color:#fbbf24; font-size:0.75rem;">(Farklı)</span>`;
        }

        const ip = item.input.sourceIp || '';
        const isQuarantined = currentQuarantineIps.has(ip);
        const actionHtml = isQuarantined
            ? `<span class="badge-quarantined">Karantinada</span>`
            : `<button type="button" class="btn-table-action btn-danger" onclick="quarantineIpFromRow('${escapeAttr(ip)}', '${escapeAttr(item.attackType)}')">Karantinaya Al</button>`;

        tr.innerHTML = `
            <td><strong>${escapeHtml(item.input.sourceIp)}</strong></td>
            <td>${getIpScopeBadge(item.input.sourceIp)}</td>
            <td>${item.input.packetSize} B</td>
            <td>${item.input.duration} s</td>
            <td>${item.input.isKnownPort ? 'Standart' : 'Bilinmeyen'}</td>
            <td>${item.input.failedLogins}</td>
            <td>${item.input.requestRate} req/s</td>
            <td style="font-family:'Inter',sans-serif; font-weight:700;">${escapeHtml(item.attackType)}</td>
            <td style="font-family:'Inter',sans-serif; color:var(--text-secondary);">${escapeHtml(actual || '-')}${matchBadge}</td>
            <td>${item.riskScore} / 100</td>
            <td><span class="risk-badge ${styles.badge}">${item.riskLevel}</span></td>
            <td class="col-action">${actionHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

function exportBatchResultsCSV() {
    if (!lastBatchResults.length) {
        showToast('Dışa aktarılacak analiz sonucu bulunmuyor. Önce bir CSV analizi yapın.', 'warning', 'Sonuç Bulunamadı');
        return;
    }

    const escapeCsv = (val) => {
        if (val === null || val === undefined) return '""';
        return `"${String(val).replace(/"/g, '""')}"`;
    };

    const meta = [
        '=== TOPLU TRAFİK ANALİZİ VE MODEL ÇIKARIM RAPORU ===',
        `Kural Seti Sürümü,${escapeCsv('cyber_xai_tree v2.4 (Karar Ağaçları & Açıklanabilir Yapay Zeka)')}`,
        `Rapor Analiz Zamanı,${escapeCsv(new Date().toLocaleString('tr-TR'))}`,
        `Eşlenen Veri Seti / Kaynak,${escapeCsv(lastBatchSchemaMapping?.datasetName || 'Standart Şema')}`,
        `Şema Eşleme Özeti,${escapeCsv(lastBatchSchemaMapping?.summaryText || 'Standart Sütun Eşlemesi')}`,
        `Toplam Okunan Satır Sayısı,${escapeCsv(lastBatchDataQuality?.totalLinesRead || lastBatchResults.length)}`,
        `Geçerli İşlenen Satır Sayısı,${escapeCsv(lastBatchDataQuality?.validRowsProcessed || lastBatchResults.length)}`,
        `Atlanan (Geçersiz/Boş) Satır Sayısı,${escapeCsv(lastBatchDataQuality?.skippedRowsCount || 0)}`,
        `Veri Kalite Durumu,${escapeCsv(lastBatchDataQuality?.isClean ? 'Tam Bütünlük (0 Atlanan Satır)' : `${lastBatchDataQuality?.skippedRowsCount || 0} Satır Atlandı (Veri Temizliği Yapıldı)`)}`,
        '',
        '=== TOPLU SINIFLANDIRMA SONUÇLARI ==='
    ];

    const header = 'Kaynak IP,Ağ Kapsamı,Paket Boyutu (B),Süre (sn),Port Türü,Hatalı Giriş,İstek Hızı (req/s),Tahmin Sınıfı,Risk Seviyesi,Risk Skoru,Güven Skoru';
    const lines = lastBatchResults.map((r) => [
        `"${r.input.sourceIp}"`,
        `"${r.input.ipScope}"`,
        r.input.packetSize,
        r.input.duration,
        r.input.isKnownPort ? 'Standart Port' : 'Bilinmeyen Port',
        r.input.failedLogins,
        r.input.requestRate,
        `"${r.attackType}"`,
        r.riskLevel,
        r.riskScore,
        r.confidence
    ].join(','));

    const csvOutput = '\uFEFF' + [...meta, header, ...lines].join('\r\n');
    const blob = new Blob([csvOutput], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ag_guvenlik_toplu_analiz_sonuclari.csv';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Sonuçlar CSV dosyası olarak dışa aktarıldı.', 'success', 'İndirme Başarılı');
}

/* ==========================================================================
   RAPOR İNDİR VE AÇILIR MENÜ (DROPDOWN)
   ========================================================================== */
function printEventReport() {
    window.print();
}

function downloadLogsReportCSV() {
    window.location.href = '/api/logs/download-csv';
}

function toggleReportMenu(e) {
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }
    const menu = document.getElementById('reportMenu');
    if (!menu) return;
    menu.classList.toggle('show');
}

function closeReportMenu() {
    const menu = document.getElementById('reportMenu');
    if (menu) menu.classList.remove('show');
}

if (typeof window !== 'undefined') {
    window.addEventListener('click', (e) => {
        const wrap = document.querySelector('.report-dropdown-wrap');
        if (wrap && !wrap.contains(e.target)) {
            closeReportMenu();
        }
    });

    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeReportMenu();
        }
    });
}

/* ==========================================================================
   LOGLAR VE KARANTİNA YÖNETİMİ (logs.html)
   ========================================================================== */
async function loadLogsAndQuarantine() {
    try {
        const [logsRes, qRes] = await Promise.all([
            fetch('/api/logs'),
            fetch('/api/quarantine')
        ]);

        cachedLogs = await logsRes.json();
        const quarantineList = await qRes.json();
        if (Array.isArray(quarantineList)) {
            currentQuarantineIps = new Set(quarantineList.map(item => item.ip));
        }

        if (document.getElementById('statTotal')) {
            document.getElementById('statTotal').innerText = cachedLogs.length;
            document.getElementById('statHigh').innerText = cachedLogs.filter((l) => l.output && l.output.riskLevel === 'Yüksek').length;
            document.getElementById('statMed').innerText = cachedLogs.filter((l) => l.output && l.output.riskLevel === 'Orta').length;
            document.getElementById('statLow').innerText = cachedLogs.filter((l) => l.output && l.output.riskLevel === 'Düşük').length;
        }

        renderFilteredLogs();
        renderQuarantineTable(quarantineList);
    } catch (err) {
        showToast('Veriler yüklenirken hata oluştu: ' + err.message, 'error', 'Bağlantı Hatası');
    }
}

function renderFilteredLogs() {
    const tbody = document.getElementById('logsTableBody');
    if (!tbody) return;

    const riskFilter = document.getElementById('riskFilter') ? document.getElementById('riskFilter').value : 'ALL';
    const searchQuery = document.getElementById('searchFilter') ? document.getElementById('searchFilter').value.trim().toLowerCase() : '';

    const filtered = cachedLogs.filter((log) => {
        const out = log.output || {};
        const matchesRisk = riskFilter === 'ALL' || out.riskLevel === riskFilter;
        const ip = (log.input && log.input.sourceIp ? log.input.sourceIp : '').toLowerCase();
        const type = (out.attackType || '').toLowerCase();
        const matchesSearch = !searchQuery || ip.includes(searchQuery) || type.includes(searchQuery);
        return matchesRisk && matchesSearch;
    });

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#94a3b8; padding:20px;">Filtreye uygun olay kaydı bulunamadı.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.slice(0, 80).map((log) => {
        const out = log.output || {};
        const styles = getRiskStyles(out.riskLevel);
        const ip = log.input && log.input.sourceIp ? log.input.sourceIp : '-';
        const score = out.riskScore !== undefined ? `${out.riskScore}/100` : '-';
        const isQuarantined = currentQuarantineIps.has(ip);
        let actionHtml = '-';
        if (ip && ip !== '-') {
            actionHtml = isQuarantined
                ? `<span class="badge-quarantined">Karantinada</span>`
                : `<button type="button" class="btn-table-action btn-danger" onclick="quarantineIpFromRow('${escapeAttr(ip)}', '${escapeAttr(out.attackType || 'Olay Günlüğü')}')">Karantinaya Al</button>`;
        }
        return `
            <tr>
                <td>${new Date(log.timestamp).toLocaleString('tr-TR')}</td>
                <td><strong>${escapeHtml(ip)}</strong></td>
                <td>${getIpScopeBadge(ip)}</td>
                <td style="font-family:'Inter',sans-serif; color:var(--text-secondary);">${escapeHtml(log.source)}</td>
                <td style="font-family:'Inter',sans-serif; font-weight:700;">${escapeHtml(out.attackType || '-')}</td>
                <td>${score}</td>
                <td><span class="risk-badge ${styles.badge}">${out.riskLevel || 'Düşük'}</span></td>
                <td class="col-action">${actionHtml}</td>
            </tr>
        `;
    }).join('');
}

function renderQuarantineTable(list) {
    const tbody = document.getElementById('quarantineTableBody');
    if (!tbody) return;

    if (!list || !list.length) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#94a3b8; padding:20px;">Karantinaya alınmış IP adresi bulunmuyor.</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map((item) => `
        <tr>
            <td><strong style="color:#fb7185;">${escapeHtml(item.ip)}</strong></td>
            <td>${getIpScopeBadge(item.ip)}</td>
            <td style="font-family:'Inter',sans-serif;">${escapeHtml(item.reason)}</td>
            <td><span style="font-family:'JetBrains Mono',monospace; font-weight:700;">${item.triggerCount || 1} kez</span></td>
            <td>${new Date(item.addedAt).toLocaleString('tr-TR')}</td>
            <td class="col-action" style="text-align:right;">
                <button type="button" class="btn-table-action btn-danger" onclick="removeFromQuarantine('${encodeURIComponent(item.ip)}')">
                    Karantinadan Çıkar
                </button>
            </td>
        </tr>
    `).join('');
}
