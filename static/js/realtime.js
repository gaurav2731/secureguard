// Real-time Updates and 3D Effects for SecureGuard

class SecureGuardRealtime {
    constructor() {
        this.updateInterval = 5000; // 5 seconds
        this.animationFrame = null;
        this.isRunning = false;
        this.threeScene = null;
        this.threeRenderer = null;
        this.threeCamera = null;
        this.particles = [];
        this.init();
    }

    init() {
        this.setup3DScene();
        this.startRealtimeUpdates();
        this.setupEventListeners();
        this.createParticleSystem();
        this.animate();
    }

    setup3DScene() {
        // Check if Three.js is available
        if (typeof THREE === 'undefined') {
            console.warn('Three.js not loaded, skipping 3D effects');
            return;
        }

        try {
            // Create scene
            this.threeScene = new THREE.Scene();
            this.threeScene.background = new THREE.Color(0x0a0a0a);

            // Create camera
            this.threeCamera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
            this.threeCamera.position.z = 5;

            // Create renderer
            this.threeRenderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
            this.threeRenderer.setSize(window.innerWidth, window.innerHeight);
            this.threeRenderer.setClearColor(0x000000, 0);

            // Add to DOM
            const container = document.createElement('div');
            container.id = 'threejs-container';
            container.style.position = 'fixed';
            container.style.top = '0';
            container.style.left = '0';
            container.style.zIndex = '-1';
            container.style.pointerEvents = 'none';
            container.appendChild(this.threeRenderer.domElement);
            document.body.appendChild(container);

            // Add ambient light
            const ambientLight = new THREE.AmbientLight(0x404040, 0.6);
            this.threeScene.add(ambientLight);

            // Add point light
            const pointLight = new THREE.PointLight(0x00ffff, 1, 100);
            pointLight.position.set(10, 10, 10);
            this.threeScene.add(pointLight);

            console.log('3D scene initialized');
        } catch (error) {
            console.error('Failed to initialize 3D scene:', error);
        }
    }

    createParticleSystem() {
        if (!this.threeScene) return;

        const particleCount = 1000;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        for (let i = 0; i < particleCount; i++) {
            positions[i * 3] = (Math.random() - 0.5) * 20;
            positions[i * 3 + 1] = (Math.random() - 0.5) * 20;
            positions[i * 3 + 2] = (Math.random() - 0.5) * 20;

            colors[i * 3] = Math.random() * 0.5;     // R
            colors[i * 3 + 1] = Math.random() * 0.5; // G
            colors[i * 3 + 2] = Math.random() * 0.8; // B (more blue)
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 0.02,
            vertexColors: true,
            transparent: true,
            opacity: 0.6
        });

        const particles = new THREE.Points(geometry, material);
        this.threeScene.add(particles);
        this.particles.push(particles);
    }

    animate() {
        if (!this.isRunning) return;

        this.animationFrame = requestAnimationFrame(() => this.animate());

        if (this.threeScene && this.threeRenderer && this.threeCamera) {
            // Rotate particles slowly
            this.particles.forEach((particleSystem, index) => {
                particleSystem.rotation.x += 0.001 * (index + 1);
                particleSystem.rotation.y += 0.001 * (index + 1);
            });

            // Subtle camera movement
            this.threeCamera.position.x = Math.sin(Date.now() * 0.0005) * 0.5;
            this.threeCamera.position.y = Math.cos(Date.now() * 0.0003) * 0.3;

            this.threeCamera.lookAt(0, 0, 0);
            this.threeRenderer.render(this.threeScene, this.threeCamera);
        }
    }

    startRealtimeUpdates() {
        this.isRunning = true;
        this.updateStats();
        this.updateIntervalId = setInterval(() => this.updateStats(), this.updateInterval);
    }

    stopRealtimeUpdates() {
        this.isRunning = false;
        if (this.updateIntervalId) {
            clearInterval(this.updateIntervalId);
        }
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
        }
    }

    async updateStats() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();

            if (data.error) {
                console.error('Stats update error:', data.error);
                return;
            }

            // Update packet count
            const packetElement = document.querySelector('.metric-value');
            if (packetElement && data.packet_count !== undefined) {
                this.animateNumber(packetElement, parseInt(packetElement.textContent) || 0, data.packet_count);
            }

            // Update system metrics
            if (data.system_load) {
                this.updateSystemMetrics(data.system_load);
            }

            // Update threat indicators
            if (data.threat_intelligence) {
                this.updateThreatIndicators(data.threat_intelligence);
            }

            // Update ML status
            if (data.ml_status) {
                this.updateMLStatus(data.ml_status);
            }

        } catch (error) {
            console.error('Failed to update stats:', error);
        }
    }

    animateNumber(element, from, to) {
        const duration = 1000;
        const start = Date.now();
        const step = () => {
            const progress = Math.min((Date.now() - start) / duration, 1);
            const current = Math.floor(from + (to - from) * this.easeOutCubic(progress));
            element.textContent = current.toLocaleString();
            if (progress < 1) {
                requestAnimationFrame(step);
            }
        };
        requestAnimationFrame(step);
    }

    easeOutCubic(t) {
        return 1 - Math.pow(1 - t, 3);
    }

    updateSystemMetrics(metrics) {
        // Update CPU usage
        const cpuElement = document.querySelector('[data-metric="cpu"] .status-value');
        if (cpuElement) {
            cpuElement.textContent = `${metrics.cpu_usage?.toFixed(1) || 0}%`;
            this.updateProgressBar(cpuElement, metrics.cpu_usage || 0);
        }

        // Update Memory usage
        const memElement = document.querySelector('[data-metric="memory"] .status-value');
        if (memElement) {
            memElement.textContent = `${metrics.memory_usage?.toFixed(1) || 0}%`;
            this.updateProgressBar(memElement, metrics.memory_usage || 0);
        }

        // Update Disk usage
        const diskElement = document.querySelector('[data-metric="disk"] .status-value');
        if (diskElement) {
            diskElement.textContent = `${metrics.disk_usage?.toFixed(1) || 0}%`;
            this.updateProgressBar(diskElement, metrics.disk_usage || 0);
        }
    }

    updateProgressBar(element, value) {
        const color = value > 80 ? '#ff0040' : value > 60 ? '#ff8000' : '#00ff00';
        element.style.color = color;
        element.style.textShadow = `0 0 10px ${color}40`;
    }

    updateThreatIndicators(threats) {
        // Update threat counts in the dashboard
        Object.keys(threats).forEach(type => {
            const element = document.querySelector(`[data-threat="${type}"] .status-value`);
            if (element) {
                this.animateNumber(element, parseInt(element.textContent) || 0, threats[type]);
            }
        });
    }

    updateMLStatus(mlStatus) {
        const mlIndicator = document.querySelector('.ml-status');
        if (mlIndicator) {
            if (mlStatus.enabled) {
                mlIndicator.className = 'status-indicator good';
                mlIndicator.innerHTML = '<i class="fas fa-brain"></i> ML Active';
            } else {
                mlIndicator.className = 'status-indicator warning';
                mlIndicator.innerHTML = '<i class="fas fa-brain"></i> ML Disabled';
            }
        }
    }

    setupEventListeners() {
        // Handle window resize for 3D scene
        window.addEventListener('resize', () => {
            if (this.threeRenderer && this.threeCamera) {
                this.threeCamera.aspect = window.innerWidth / window.innerHeight;
                this.threeCamera.updateProjectionMatrix();
                this.threeRenderer.setSize(window.innerWidth, window.innerHeight);
            }
        });

        // Add click effects to cards
        document.addEventListener('click', (e) => {
            const card = e.target.closest('.card');
            if (card) {
                this.createClickEffect(e.clientX, e.clientY);
            }
        });

        // Add hover effects
        document.addEventListener('mouseover', (e) => {
            if (e.target.closest('.btn, .nav-link, .metric-card')) {
                this.createHoverEffect(e.target);
            }
        });
    }

    createClickEffect(x, y) {
        const effect = document.createElement('div');
        effect.style.position = 'fixed';
        effect.style.left = `${x - 25}px`;
        effect.style.top = `${y - 25}px`;
        effect.style.width = '50px';
        effect.style.height = '50px';
        effect.style.borderRadius = '50%';
        effect.style.background = 'radial-gradient(circle, rgba(0,255,255,0.3) 0%, transparent 70%)';
        effect.style.pointerEvents = 'none';
        effect.style.zIndex = '9999';
        effect.style.animation = 'clickEffect 0.6s ease-out forwards';

        document.body.appendChild(effect);

        setTimeout(() => effect.remove(), 600);
    }

    createHoverEffect(element) {
        element.style.animation = 'none';
        setTimeout(() => {
            element.style.animation = '';
        }, 10);
    }

    // Utility methods
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out forwards';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // Cleanup method
    destroy() {
        this.stopRealtimeUpdates();

        if (this.threeRenderer) {
            this.threeRenderer.dispose();
            const container = document.getElementById('threejs-container');
            if (container) {
                container.remove();
            }
        }
    }
}

// CSS for click effects and notifications
const additionalStyles = `
@keyframes clickEffect {
    0% { transform: scale(0); opacity: 1; }
    100% { transform: scale(2); opacity: 0; }
}

@keyframes slideOut {
    0% { transform: translateX(0); opacity: 1; }
    100% { transform: translateX(100%); opacity: 0; }
}

.notification {
    position: fixed;
    top: 90px;
    right: 20px;
    padding: 15px 20px;
    background: var(--secondary-bg);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--primary-text);
    z-index: 10000;
    animation: slideIn 0.3s ease-out;
    display: flex;
    align-items: center;
    gap: 10px;
    box-shadow: var(--glow-shadow);
}

.notification-success { border-color: var(--neon-green); }
.notification-error { border-color: var(--neon-red); }
.notification-warning { border-color: var(--neon-orange); }
.notification-info { border-color: var(--neon-blue); }
`;

// Add styles to document
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.secureGuardRealtime = new SecureGuardRealtime();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.secureGuardRealtime) {
        window.secureGuardRealtime.destroy();
    }
});
