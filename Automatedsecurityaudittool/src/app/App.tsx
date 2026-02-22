import { useEffect, useMemo, useState } from 'react';
import { Terminal, type TerminalLine } from './components/Terminal';
import { ScanProgress } from './components/ScanProgress';
import { ScanResults } from './components/ScanResults';
import type { AggregatedResults } from '../types/scan';
import { runA02Scan, mapRunnerJsonToAggregatedResults, runA02SingleScan, getA02ScansList, fetchArtifact, AuthRequiredError } from '../utils/a02-api';

type AuthStep =
    | 'idle'
    | 'login_username'
    | 'login_password'
    | 'register_email'
    | 'register_username'
    | 'register_password';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000';

export default function App() {
    const [lines, setLines] = useState<TerminalLine[]>([
        {
            type: 'success',
            content: 'Pentest Assistant v1.0.0 - OWASP Top 10 A02 Security Misconfiguration Scanner',
            timestamp: new Date()
        },
        {
            type: 'info',
            content: 'Type "help" pour voir les commandes disponibles',
            timestamp: new Date()
        },
        {
            type: 'info',
            content: 'Backend requis: démarrez l’API Python sur http://127.0.0.1:8000',
            timestamp: new Date()
        }
    ]);

    const [isProcessing, setIsProcessing] = useState(false);
    const [scanResults, setScanResults] = useState<AggregatedResults | null>(null);
    const [scanStartedAt, setScanStartedAt] = useState<Date | null>(null);

    // --- Auth state (Linux terminal style) ---
    const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'));
    const [authStep, setAuthStep] = useState<AuthStep>(() => (localStorage.getItem('token') ? 'idle' : 'login_username'));
    const [authDraft, setAuthDraft] = useState<{ email?: string; username?: string; password?: string }>({});
    const [currentUsername, setCurrentUsername] = useState<string | null>(() => localStorage.getItem('currentUsername'));
    const [currentUserId, setCurrentUserId] = useState<number | null>(() => {
        const stored = localStorage.getItem('currentUserId');
        return stored ? parseInt(stored, 10) : null;
    });
    const [currentUserRole, setCurrentUserRole] = useState<string | null>(() => localStorage.getItem('currentUserRole'));

    const isAuthed = useMemo(() => Boolean(token), [token]);

    // Fonction pour décoder le JWT et extraire user_id + role
    const decodeJWT = (jwtToken: string): { user_id?: number; role?: string } => {
        try {
            const parts = jwtToken.split('.');
            if (parts.length !== 3) return {};
            const decoded = JSON.parse(atob(parts[1]));
            return { user_id: decoded.user_id, role: decoded.role };
        } catch {
            return {};
        }
    };

    const addLine = (line: Omit<TerminalLine, 'timestamp'>) => {
        setLines(prev => [...prev, { ...line, timestamp: new Date() }]);
    };

    const pushInfo = (s: string) => addLine({ type: 'info', content: s });
    const pushOk = (s: string) => addLine({ type: 'success', content: s });
    const pushErr = (s: string) => addLine({ type: 'error', content: s });
    const pushOut = (s: string) => addLine({ type: 'output', content: s });

    // Invite login au lancement si pas connecté
    useEffect(() => {
        if (!token) {
            pushInfo('Welcome. Please authenticate.');
            pushOut('login:');
        } else {
            // Session restaurée: essayer de synchroniser user_id/role depuis le token.
            const decoded = decodeJWT(token);
            if (decoded.user_id && decoded.role) {
                setCurrentUserId(decoded.user_id);
                setCurrentUserRole(decoded.role);
                localStorage.setItem('currentUserId', decoded.user_id.toString());
                localStorage.setItem('currentUserRole', decoded.role);
            }
            pushOk('Session restored (token localStorage).');
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Fetch helper qui ajoute Authorization si token
    async function apiFetch(path: string, init: RequestInit = {}) {
        const headers: Record<string, string> = { ...(init.headers as any) };
        if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
            throw new Error(data?.error || data?.message || `HTTP ${res.status}`);
        }
        return data;
    }

    function logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('currentUsername');
        localStorage.removeItem('currentUserId');
        localStorage.removeItem('currentUserRole');
        setToken(null);
        setCurrentUsername(null);
        setCurrentUserId(null);
        setCurrentUserRole(null);
        setAuthDraft({});
        setAuthStep('login_username');
        pushOk('Logged out.');
        pushOut('login:');
    }

    // Affiche les commandes disponibles selon état auth
    const handleHelp = () => {
        if (!isAuthed) {
            [
                '=============================================================================',
                'AUTH (terminal style):',
                '  (au prompt login:) tapez votre username puis Enter',
                '  (au prompt password:) tapez votre password puis Enter (masqué)',
                '  register          Lance la création de compte (email -> username -> password)',
                '  help              Affiche cette aide',
                '  clear             Efface le terminal',
                '============================================================================='
            ].forEach(t => pushOut(t));
            pushOut('login:');
            return;
        }

        const helpText = [
            '=============================================================================',
            'Commandes disponibles:',
            '  scan <target>     Lance un scan A02 sur la cible via l\'API Python locale',
            '                    Ex: scan example.com ou scan https://example.com',
            '  scanmod <module> <target>  Lance un module A02 spécifique (sous-scan)',
            '                    Ex: scanmod port_scanner_aggressive 127.0.0.1',
            '  scans             Affiche la liste des sous-scans/modules disponibles',
            '  whoami            Affiche les infos de l\'utilisateur connecté',
            '  logout            Déconnexion',
            '  clear             Efface le terminal',
            '  version           Affiche la version',
            '  help              Affiche cette aide',
            '============================================================================='
        ];

        helpText.forEach(text => pushOut(text));
    };

    // --- Auth flow inside terminal ---
    async function handleAuthFlow(raw: string) {
        const input = raw; // ne pas trim pour password si tu veux garder espaces
        const trimmed = raw.trim();

        // Commande spéciale: "register"
        if (authStep === 'login_username' && trimmed.toLowerCase() === 'register') {
            setAuthDraft({});
            setAuthStep('register_email');
            pushOut('email:');
            return;
        }

        // Commande spéciale: "help" / "clear" avant login
        if (!trimmed) {
            // si l'utilisateur appuie Enter vide: on redemande le prompt
            if (authStep === 'login_username') pushOut('login:');
            else if (authStep === 'login_password') pushOut('password:');
            else if (authStep === 'register_email') pushOut('email:');
            else if (authStep === 'register_username') pushOut('username:');
            else if (authStep === 'register_password') pushOut('password:');
            return;
        }
        if (trimmed.toLowerCase() === 'help') {
            handleHelp();
            return;
        }
        if (trimmed.toLowerCase() === 'clear') {
            setLines([]);
            // réafficher prompt courant
            if (authStep === 'login_username') pushOut('login:');
            else if (authStep === 'login_password') pushOut('password:');
            else if (authStep === 'register_email') pushOut('email:');
            else if (authStep === 'register_username') pushOut('username:');
            else if (authStep === 'register_password') pushOut('password:');
            return;
        }

        // Login: username
        if (authStep === 'login_username') {
            setAuthDraft({ username: trimmed });
            setAuthStep('login_password');
            pushOut('password:');
            return;
        }

        // Login: password
        if (authStep === 'login_password') {
            const username = authDraft.username!;
            const password = input;

            pushInfo('Authenticating...');

            try {
                const data = await apiFetch('/auth/login', {
                    method: 'POST',
                    body: JSON.stringify({ username, password })
                });

                const t = data?.token as string | undefined;
                if (!t) throw new Error('token manquant dans la réponse');

                // Décoder le token pour extraire user_id et role
                const decoded = decodeJWT(t);
                const userId = decoded.user_id || 0;
                const role = decoded.role || 'user';

                localStorage.setItem('token', t);
                localStorage.setItem('currentUsername', username);
                localStorage.setItem('currentUserId', userId.toString());
                localStorage.setItem('currentUserRole', role);

                setToken(t);
                setCurrentUsername(username);
                setCurrentUserId(userId);
                setCurrentUserRole(role);
                setAuthStep('idle');
                setAuthDraft({});
                pushOk(`Welcome ${username}.`);
                pushOk('You are now logged in.');
            } catch (e: any) {
                pushErr(`Login failed: ${e?.message || e}`);
                setAuthDraft({});
                setAuthStep('login_username');
                pushOut('login:');
            }
            return;
        }

        // Register: email
        if (authStep === 'register_email') {
            setAuthDraft({ email: trimmed });
            setAuthStep('register_username');
            pushOut('username:');
            return;
        }

        // Register: username
        if (authStep === 'register_username') {
            setAuthDraft(prev => ({ ...prev, username: trimmed }));
            setAuthStep('register_password');
            pushOut('password:');
            return;
        }

        // Register: password
        if (authStep === 'register_password') {
            const email = authDraft.email!;
            const username = authDraft.username!;
            const password = input;

            pushInfo('Creating account...');

            try {
                const data = await apiFetch('/auth/register', {
                    method: 'POST',
                    body: JSON.stringify({ email, username, password })
                });

                const t = data?.token as string | undefined;
                if (!t) throw new Error('token manquant dans la réponse');

                // Décoder le token pour extraire user_id et role
                const decoded = decodeJWT(t);
                const userId = decoded.user_id || 0;
                const role = decoded.role || 'user';

                localStorage.setItem('token', t);
                localStorage.setItem('currentUsername', username);
                localStorage.setItem('currentUserId', userId.toString());
                localStorage.setItem('currentUserRole', role);

                setToken(t);
                setCurrentUsername(username);
                setCurrentUserId(userId);
                setCurrentUserRole(role);
                setAuthStep('idle');
                setAuthDraft({});
                pushOk(`Account created. Welcome ${username}.`);
            } catch (e: any) {
                pushErr(`Register failed: ${e?.message || e}`);
                // revenir au login
                setAuthDraft({});
                setAuthStep('login_username');
                pushOut('login:');
            }
            return;
        }
    }

    // --- Main command handler ---
    const handleCommand = (command: string) => {
        // ✅ Echo terminal input (mais masque password)
        const isSecret = authStep === 'login_password' || authStep === 'register_password';
        addLine({ type: 'input', content: isSecret ? '*'.repeat(command.length || 8) : command });

        // Si pas authentifié => flow login/register
        if (!isAuthed) {
            void handleAuthFlow(command);
            return;
        }

        // Authenticated normal commands
        const parts = command.split(' ');
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);

        switch (cmd) {
            case 'help':
                handleHelp();
                break;

            case 'logout':
                logout();
                break;

            case 'scan':
                if (args.length === 0) {
                    pushErr('Usage: scan <target>');
                } else {
                    handleScan(args[0]);
                }
                break;

            case 'scans':
                handleListScans();
                break;

            case 'scanmod':
                if (args.length < 2) {
                    pushErr('Usage: scanmod <module> <target>');
                    pushInfo('Ex: scanmod port_scanner_aggressive 127.0.0.1');
                } else {
                    handleSingleModuleScan(args[0], args[1]);
                }
                break;

            case 'clear':
                setLines([]);
                break;

            case 'version':
                pushInfo('Pentest Assistant v1.0.0');
                break;

            case 'whoami':
                if (currentUsername && currentUserId !== null && currentUserRole) {
                    pushOut('┌─────────────────────────────────────────┐');
                    pushOut('│          Current User Info              │');
                    pushOut('├─────────────────────────────────────────┤');
                    pushOut(`│ Username: ${currentUsername.padEnd(32)}       │`);
                    pushOut('└─────────────────────────────────────────┘');
                } else {
                    pushErr('Not authenticated');
                }
                break;

            default:
                pushErr(`Commande inconnue: ${cmd}. Tapez "help" pour l'aide.`);
        }
    };

    const handleScan = (targetStr: string) => {
        setIsProcessing(true);
        setScanStartedAt(new Date());

        pushInfo(`Envoi du scan à l'API (target=${targetStr})...`);

        setScanResults({
            scanId: crypto.randomUUID(),
            target: { raw: targetStr, type: 'hostname', hostname: targetStr },
            timestamp: new Date(),
            totalDuration: 0,
            overallSeverity: 'info',
            riskScore: 0,
            summary: {
                totalModules: 16,
                completedModules: 0,
                failedModules: 0,
                totalFindings: 0,
                findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
            },
            results: Array.from({ length: 16 }).map((_, i) => ({
                moduleId: `A02_Module_${i + 1}`,
                moduleName: `A02 Module #${i + 1}`,
                status: 'started',
                startTime: new Date(),
                endTime: new Date(),
                duration: 0,
                severity: 'info',
                confidence: 'tentative',
                findings: []
            })),
            metadata: { version: '1.0.0', aggressiveness: 'normal', timeout: 30000 }
        });

        // ⚠️ IMPORTANT:
        // Tes fonctions runA02Scan/getA02ScansList doivent envoyer Authorization: Bearer <token>.
        // Si ton utils/a02-api lit localStorage("token"), c'est déjà OK.
        // Sinon, dis-moi et je te donne le patch a02-api.ts pour ajouter le header.

        runA02Scan({
            target: targetStr,
            connectTimeout: 3,
            readTimeout: 6,
            retries: 1,
            perScanTimebox: 120,
            turbo: false,
            generatePdf: true
        })
            .then((data) => {
                const aggregated = mapRunnerJsonToAggregatedResults(targetStr, data);
                setScanResults(aggregated);

                pushOk('Scan terminé avec succès (via API)!');
                pushInfo(`Score de risque: ${aggregated.riskScore}/100 (${aggregated.overallSeverity.toUpperCase()})`);
                pushInfo(`Constats trouvés: ${aggregated.summary.totalFindings}`);
                if (aggregated.artifacts?.pdf) {
                    pushOk('PDF généré côté serveur (bouton Export PDF disponible)');
                } else {
                    pushErr('PDF non généré côté serveur. Vérifiez le backend (logs) et relancez le scan.');
                }
            })
            .catch((error) => {
                if (error instanceof AuthRequiredError) {
                    pushErr('Session expirée/invalide. Merci de vous reconnecter.');
                    logout();
                    return;
                }
                pushErr(error instanceof Error ? error.message : 'Erreur inconnue');
            })
            .finally(() => {
                setIsProcessing(false);
            });
    };

    const handleSingleModuleScan = (moduleId: string, targetStr: string) => {
        setIsProcessing(true);
        setScanStartedAt(new Date());

        pushInfo(`Envoi du sous-scan à l'API (scan=${moduleId}, target=${targetStr})...`);
        pushInfo('Note: le PDF est généré uniquement lors de la commande "scan" (full scan), pas via "scanmod".');

        setScanResults({
            scanId: crypto.randomUUID(),
            target: { raw: targetStr, type: 'hostname', hostname: targetStr },
            timestamp: new Date(),
            totalDuration: 0,
            overallSeverity: 'info',
            riskScore: 0,
            summary: {
                totalModules: 1,
                completedModules: 0,
                failedModules: 0,
                totalFindings: 0,
                findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
            },
            results: [
                {
                    moduleId,
                    moduleName: moduleId,
                    status: 'started',
                    startTime: new Date(),
                    endTime: new Date(),
                    duration: 0,
                    severity: 'info',
                    confidence: 'tentative',
                    findings: []
                }
            ],
            metadata: { version: '1.0.0', aggressiveness: 'normal', timeout: 30000 }
        });

        runA02SingleScan({
            target: targetStr,
            scan: moduleId,
            connectTimeout: 3,
            readTimeout: 6,
            retries: 1,
            perScanTimebox: 120
        })
            .then((data) => {
                const aggregated = mapRunnerJsonToAggregatedResults(targetStr, data);
                setScanResults(aggregated);
                pushOk(`Sous-scan terminé (${moduleId})`);
                pushInfo(`Constats trouvés: ${aggregated.summary.totalFindings}`);
                pushInfo('PDF: non disponible en mode "scanmod". Utilisez "scan <target>" pour générer un PDF.');
            })
            .catch((error) => {
                pushErr(error instanceof Error ? error.message : 'Erreur inconnue');
            })
            .finally(() => {
                setIsProcessing(false);
            });
    };

    const handleExportJSON = () => {
        if (!scanResults) return;

        const json = JSON.stringify(scanResults, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pentest-${scanResults.scanId}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        pushOk('Rapport JSON exporté');
    };

    const handleExportPDF = async () => {
        if (!scanResults?.artifacts?.pdf) {
            pushErr('Aucun PDF disponible. Relancez un scan (PDF généré côté serveur).');
            return;
        }

        pushInfo('Téléchargement du PDF...');

        try {
            const resp = await fetchArtifact(scanResults.artifacts.pdf);

            if (!resp || !resp.ok) {
                pushErr('Échec du téléchargement du PDF. Vérifiez votre authentification.');
                return;
            }

            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `pentest-${scanResults.scanId}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            pushOk('PDF téléchargé avec succès');
        } catch (error) {
            if (error instanceof AuthRequiredError) {
                pushErr('Session expirée/invalide. Merci de vous reconnecter.');
                logout();
                return;
            }
            pushErr(`Erreur lors du téléchargement: ${error instanceof Error ? error.message : 'Erreur inconnue'}`);
        }
    };

    const handleListScans = () => {
        pushInfo('Récupération de la liste des sous-scans depuis l\'API…');
        getA02ScansList()
            .then((data) => {
                pushOk(`Sous-scans disponibles (${data.count}) :`);
                data.scans.forEach((s: string) => pushOut(`  - ${s}`));
                pushInfo('Exemple: scanmod port_scanner_aggressive 127.0.0.1');
            })
            .catch((error) => {
                if (error instanceof AuthRequiredError) {
                    pushErr('Session expirée/invalide. Merci de vous reconnecter.');
                    logout();
                    return;
                }
                pushErr(error instanceof Error ? error.message : 'Erreur inconnue');
            });
    };

    return (
        <div className="h-screen w-screen overflow-hidden bg-[#0d1117] flex">
            {/* Colonne gauche: fixe (pas de scroll global) */}
            <div className="w-1/2 p-4 border-r border-[#30363d] h-full overflow-hidden">
                <Terminal
                    onCommand={handleCommand}
                    lines={lines}
                    isProcessing={isProcessing}
                />
            </div>

            {/* Colonne droite: scrollable uniquement ici */}
            <div className="w-1/2 h-full overflow-hidden">
                <div className="h-full overflow-y-auto">
                    <div className="p-4 space-y-4">
                        {scanResults && (
                            <ScanProgress
                                results={scanResults.results}
                                isScanning={isProcessing}
                                startedAt={scanStartedAt ?? undefined}
                            />
                        )}
                    </div>

                    <ScanResults
                        results={scanResults}
                        onExportJSON={handleExportJSON}
                        onExportPDF={handleExportPDF}
                    />
                </div>
            </div>
        </div>
    );
}

