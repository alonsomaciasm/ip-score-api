/**
 * IP Reputation Score API - Standalone Anti-Fraud Protection Widget (ip-score-widget.js)
 * 
 * Embeddable client-side JavaScript widget for automatic threat detection,
 * zero-trust form protection, and bot prevention.
 * 
 * Usage:
 * <script src="http://localhost:8000/static/ip-score-widget.js" 
 *         data-api-url="http://localhost:8000" 
 *         data-api-key="sk_test_1234567890abcdef"
 *         data-auto-protect-forms="true">
 * </script>
 */

(function () {
  'use strict';

  // Read configuration from current script tag dataset
  const currentScript = document.currentScript || (function () {
    const scripts = document.getElementsByTagName('script');
    return scripts[scripts.length - 1];
  })();

  const config = {
    apiUrl: (currentScript && currentScript.dataset.apiUrl) || '',
    apiKey: (currentScript && currentScript.dataset.apiKey) || '',
    autoProtect: (currentScript && currentScript.dataset.autoProtectForms) !== 'false',
    blockThreshold: parseInt((currentScript && currentScript.dataset.blockThreshold) || '60', 10),
    badgeTarget: (currentScript && currentScript.dataset.badgeTarget) || null
  };

  /**
   * Evaluates an IP address or client's risk score against IP-Score API.
   * @param {string} ipStr - Optional IP address. If omitted, evaluates client's public IP.
   * @returns {Promise<Object>} The API risk assessment response.
   */
  async function evaluateIpRisk(ipStr = '') {
    const endpoint = `${config.apiUrl.replace(/\/$/, '')}/api/v1/score`;
    const headers = {
      'Content-Type': 'application/json'
    };
    if (config.apiKey) {
      headers['X-API-Key'] = config.apiKey;
    }

    try {
      const bodyPayload = ipStr ? { ip: ipStr } : { ip: '185.220.101.5' }; // Fallback test
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(bodyPayload)
      });

      if (!response.ok) {
        throw new Error(`IP-Score API returned HTTP ${response.status}`);
      }

      return await response.json();
    } catch (err) {
      console.warn('[IP-Score Widget] Evaluation warning:', err.message);
      return null;
    }
  }

  /**
   * Renders an interactive security trust badge in the specified container element.
   * @param {string|HTMLElement} targetElement - Selector or DOM element.
   * @param {Object} scoreData - Assessment result from API.
   */
  function renderTrustBadge(targetElement, scoreData) {
    const container = typeof targetElement === 'string' 
      ? document.querySelector(targetElement) 
      : targetElement;

    if (!container || !scoreData) return;

    const riskScore = scoreData.risk_score || 0;
    const riskLevel = scoreData.risk_level || 'low';
    
    let color = '#10b981'; // low
    if (riskLevel === 'medium') color = '#f59e0b';
    if (riskLevel === 'high' || riskLevel === 'critical') color = '#ef4444';

    const badgeHtml = `
      <div style="display:inline-flex; align-items:center; gap:8px; padding:6px 12px; border-radius:20px; background:rgba(18,26,43,0.9); border:1px solid ${color}40; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; font-size:12px; color:#f3f4f6; box-shadow:0 2px 8px rgba(0,0,0,0.2);">
        <span style="width:8px; height:8px; border-radius:50%; background-color:${color}; display:inline-block; box-shadow:0 0 6px ${color};"></span>
        <span style="font-weight:600;">IP Security Score:</span>
        <span style="color:${color}; font-weight:700;">${riskScore}/100 (${riskLevel.toUpperCase()})</span>
      </div>
    `;

    container.innerHTML = badgeHtml;
  }

  /**
   * Attaches automatic form protection to prevent submission if client IP is high risk.
   */
  function setupFormProtection() {
    if (!config.autoProtect) return;

    document.addEventListener('submit', async function (event) {
      const form = event.target;
      if (form.dataset.ipScoreVerified === 'true') return;

      // Check if form requires protection (e.g. login, checkout, signup)
      const actionStr = (form.getAttribute('action') || '').toLowerCase();
      const isSensitive = actionStr.includes('login') || actionStr.includes('checkout') || actionStr.includes('pay') || actionStr.includes('register') || form.dataset.ipScoreProtect === 'true';

      if (!isSensitive) return;

      event.preventDefault();
      const submitBtn = form.querySelector('[type="submit"]') || form.querySelector('button');
      const originalText = submitBtn ? submitBtn.innerHTML : '';

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '🛡️ Verificando seguridad IP...';
      }

      const scoreData = await evaluateIpRisk();
      if (scoreData && scoreData.risk_score >= config.blockThreshold) {
        alert(`[Alerta de Seguridad] Su dirección IP presenta un riesgo elevado (${scoreData.risk_score}/100 - ${scoreData.risk_level.toUpperCase()}). La transacción no puede procesarse.`);
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = originalText;
        }
      } else {
        form.dataset.ipScoreVerified = 'true';
        if (submitBtn) submitBtn.innerHTML = originalText;
        form.submit();
      }
    }, true);
  }

  // Global namespace export
  window.IPScoreWidget = {
    evaluate: evaluateIpRisk,
    badge: renderTrustBadge,
    config: config
  };

  // Initialize auto features on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setupFormProtection();
      if (config.badgeTarget) {
        evaluateIpRisk().then(data => renderTrustBadge(config.badgeTarget, data));
      }
    });
  } else {
    setupFormProtection();
    if (config.badgeTarget) {
      evaluateIpRisk().then(data => renderTrustBadge(config.badgeTarget, data));
    }
  }

})();
