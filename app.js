/*
// Modifications Copyright (C) 2025 KSEC - Erez Kalman
// SPDX-License-Identifier: (AGPL-3.0-or-later OR LicenseRef-Erez_Kalman_KSEC-Commercial)
//
// ----------------- Original Copyright Notice Below -----------------
//
// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause
*/

class ExtensionCalculator {
    constructor(baseScore, extensionRules) {
        this.baseScore = baseScore;
        this.rules = extensionRules;
    }
    calculate(extensionVector) {
        if (!this.rules || this.baseScore === null || typeof this.baseScore === 'undefined') {
            return { score: null, severity: null, metricModifiers: {}, comboModifiers: {}, allCombos: [], validCombos: [], winningCombo: null };
        }
        const allMetricModifiers = this._calculateAllMetricModifiers(extensionVector);
        const allComboModifiers = this._calculateAllComboModifiers();
        const validCombos = this._getValidCombos(extensionVector);
        const winningCombo = this._getWinningCombo(validCombos, allComboModifiers);
        let finalScore = this.baseScore;
        const metricsInValidCombos = new Set();
        validCombos.forEach(combo => {
            combo.conditions.forEach(cond => metricsInValidCombos.add(cond.metric));
        });
        for (const metricName in allMetricModifiers) {
            if (!metricsInValidCombos.has(metricName)) {
                finalScore += allMetricModifiers[metricName];
            }
        }
        if (winningCombo) {
            finalScore += allComboModifiers[winningCombo.name];
        }
        finalScore = Math.max(0, Math.min(10, finalScore));
        const finalScoreRounded = Math.round(finalScore * 10) / 10;
        return {
            score: finalScoreRounded,
            severity: this._calculateSeverityRating(finalScoreRounded),
            metricModifiers: allMetricModifiers,
            comboModifiers: allComboModifiers,
            allCombos: this.rules.combos || [],
            validCombos: validCombos,
            winningCombo: winningCombo ? { ...winningCombo, value: allComboModifiers[winningCombo.name] } : null
        };
    }
    _getModifierValue(operation, value) {
        switch (operation) {
            case 'ADD': return value;
            case 'MUL': return this.baseScore * value;
            default: return 0;
        }
    }
    _calculateAllMetricModifiers(extensionVector) {
        const modifiers = {};
        if (!this.rules.metrics) return modifiers;
        for (const metricName in this.rules.metrics) {
            const rule = this.rules.metrics[metricName];
            const vectorValue = extensionVector[metricName];
            if (vectorValue === undefined) continue;
            let modifier = null;
            if (rule.type === 'BOOL') {
                modifier = (vectorValue === 'T') ? rule.if_true : rule.if_false;
            } else if (Array.isArray(rule.type)) {
                modifier = rule.values[vectorValue];
            }
            if (modifier) {
                modifiers[metricName] = this._getModifierValue(modifier.math, modifier.val);
            }
        }
        return modifiers;
    }
    _calculateAllComboModifiers() {
        const modifiers = {};
        if (!this.rules.combos) return modifiers;
        this.rules.combos.forEach(combo => {
            modifiers[combo.name] = this._getModifierValue(combo.modifier.math, combo.modifier.val);
        });
        return modifiers;
    }
    _getValidCombos(extensionVector) {
        const validCombos = [];
        if (!this.rules.combos) return validCombos;
        this.rules.combos.forEach(combo => {
            const isMatch = combo.conditions.every(cond => {
                const vectorValue = extensionVector[cond.metric];
                if (vectorValue === undefined) return false;
                if (Array.isArray(cond.value)) {
                    return cond.value.includes(vectorValue);
                }
                return vectorValue === cond.value;
            });
            if (isMatch) {
                validCombos.push(combo);
            }
        });
        return validCombos;
    }
    _getWinningCombo(validCombos, allComboModifiers) {
        if (validCombos.length === 0) return null;
        if (validCombos.length === 1) return validCombos[0];
        let winningCombo = validCombos[0];
        let maxModifier = -Infinity;
        validCombos.forEach(combo => {
            const modifierValue = allComboModifiers[combo.name];
            if (modifierValue > maxModifier) {
                maxModifier = modifierValue;
                winningCombo = combo;
            }
        });
        return winningCombo;
    }
    _calculateSeverityRating(score) {
        if (score === 0.0) return "None";
        if (score >= 0.1 && score <= 3.9) return "Low";
        if (score >= 4.0 && score <= 6.9) return "Medium";
        if (score >= 7.0 && score <= 8.9) return "High";
        if (score >= 9.0 && score <= 10.0) return "Critical";
        return "Unknown";
    }
}


const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null,
            extensionYAML: null,
            showDetails: false,
            header_height: 0,
            macroVector: null,
            vectorInstance: new Vector(),
            cvssInstance: null,
            isLoadingFromHash: false,
            availableExtensions: [],
            selectedExtension: 'None',
            availableVersions: [],
            selectedVersion: '',
            extensionName: '',
            extensionVersion: '',
            finalScore: null,
            finalSeverity: '',
            extensionCalculationDetails: null,
            currentTLP: 'TLP:CLEAR',
            tlpColors: {
                'TLP:RED': { color: 'rgb(255, 0, 51)', backgroundColor: 'rgb(0, 0, 0)' },
                'TLP:AMBER': { color: 'rgb(255, 192, 0)', backgroundColor: 'rgb(0, 0, 0)' },
                'TLP:GREEN': { color: 'rgb(51, 255, 0)', backgroundColor: 'rgb(0, 0, 0)' },
                'TLP:CLEAR': { color: 'rgb(255, 255, 255)', backgroundColor: 'rgb(0, 0, 0)' }
            },
            showScrollToTop: false
        };
    },
    watch: {
        selectedExtension(newExt) {
            if (this.isLoadingFromHash) return;

            if (newExt === 'None') {
                this.availableVersions = [];
                this.selectedVersion = '';
            } else {
                this.availableVersions = Object.keys(this.extensionYAML.extensions[newExt])
                    .filter(key => typeof this.extensionYAML.extensions[newExt][key] === 'object' && this.extensionYAML.extensions[newExt][key].metrics);

                if (this.availableVersions.length > 0) {
                    this.selectedVersion = this.availableVersions[0];
                } else {
                    this.selectedVersion = '';
                }
            }
        },
        selectedVersion() {
            if (this.isLoadingFromHash) return;
            this.updateVectorWithExtension();
        }
    },
    methods: {
        isMetricDisabled(metricData, metricType) {
            return this.activeRules.disable.has(metricType) || this.activeRules.disable.has(metricData.short);
        },
        async loadConfigData() {
            try {
                const response = await fetch('./metrics.json');
                this.cvssConfigData = await response.json();
            } catch (error) {
                console.error("Failed to load metrics.json:", error);
            }
        },
        async loadExtensionData() {
            try {
                const response = await fetch('./extension.yaml');
                const yamlText = await response.text();
                this.extensionYAML = jsyaml.load(yamlText);
                if (this.extensionYAML && this.extensionYAML.extensions) {
                    this.availableExtensions = Object.keys(this.extensionYAML.extensions);
                }
            } catch (error) {
                console.error("Failed to load or parse extension.yaml:", error);
                this.extensionYAML = null;
            }
        },
        updateVectorWithExtension() {
            const baseMetrics = {};
            for (const key in Vector.ALL_METRICS) {
                if (this.vectorInstance.metrics[key]) {
                    baseMetrics[key] = this.vectorInstance.metrics[key];
                }
            }
            this.vectorInstance.metrics = baseMetrics;

            if (this.selectedExtension !== 'None' && this.selectedVersion) {
                this.vectorInstance.metrics[this.selectedExtension] = this.selectedVersion;
                const extMetrics = this.extensionYAML.extensions[this.selectedExtension][this.selectedVersion].metrics;
                for (const metricKey in extMetrics) {
                    const metricDef = extMetrics[metricKey];
                    if (metricDef.type === 'BOOL') {
                        this.vectorInstance.metrics[metricKey] = 'F';
                    } else if (Array.isArray(metricDef.type)) {
                        this.vectorInstance.metrics[metricKey] = metricDef.type[0];
                    }
                }
            }

            window.location.hash = this.vectorInstance.raw;
            this.updateScores();
        },
        getExtensionOptions(metricData) {
            if (metricData.type === 'BOOL') {
                return [
                    { text: 'True (T)', value: 'T' },
                    { text: 'False (F)', value: 'F' }
                ];
            }
            return metricData.type.map(opt => {
                let buttonText = opt;
                if (metricData.values && metricData.values[opt] && metricData.values[opt].name) {
                    buttonText = `${metricData.values[opt].name} (${opt})`;
                }
                return { text: buttonText, value: opt };
            });
        },
        getExtensionOptionHelp(metricData, optionValue) {
            if (metricData.type === 'BOOL') {
                return optionValue === 'T' ? metricData.help_true : metricData.help_false;
            }
            if (metricData.values && metricData.values[optionValue] && metricData.values[optionValue].help) {
                return metricData.values[optionValue].help;
            }
            return metricData.help || '';
        },
        buttonClass(isPrimary, big = false) {
            return `btn btn-m ${isPrimary ? "btn-primary" : ""} ${!big ? "btn-sm" : ""}`;
        },
        getSeverityClass(severityRating) {
            const severityClasses = {
                "Low": "c-hand text-success",
                "Medium": "c-hand text-warning",
                "High": "c-hand text-error text-bold",
                "Critical": "c-hand text-error text-bold",
                "None": "c-hand text-gray"
            };
            return severityClasses[severityRating] || "c-hand text-gray";
        },
        copyVector() {
            navigator.clipboard.writeText(this.vector);
            window.location.hash = this.vector;
        },
        onButton(metric, value) {
            this.vectorInstance.updateMetric(metric, value);
            window.location.hash = this.vector;
        },
        setButtonsToVector(vector) {
            this.isLoadingFromHash = true;
            try {
                const tempMetrics = vector.split('/').slice(1).reduce((acc, part) => {
                    const [key, val] = part.split(':');
                    if (key) acc[key] = val;
                    return acc;
                }, {});

                let extNameFromVector = 'None';
                let extVersionFromVector = '';

                if (this.extensionYAML && this.extensionYAML.extensions) {
                    for (const extName in this.extensionYAML.extensions) {
                        if (tempMetrics[extName]) {
                            extNameFromVector = extName;
                            extVersionFromVector = tempMetrics[extName];
                            break;
                        }
                    }
                }

                this.selectedExtension = extNameFromVector;
                if (extNameFromVector !== 'None') {
                    this.availableVersions = Object.keys(this.extensionYAML.extensions[extNameFromVector])
                        .filter(key => typeof this.extensionYAML.extensions[extNameFromVector][key] === 'object' && this.extensionYAML.extensions[extNameFromVector][key].metrics);
                } else {
                    this.availableVersions = [];
                }
                this.selectedVersion = extVersionFromVector;

                this.vectorInstance.updateMetricsFromVectorString(vector);

                if (extNameFromVector !== 'None' && this.selectedVersion) {
                    const extMetrics = this.extensionYAML.extensions[extNameFromVector][extVersionFromVector].metrics;
                    for (const metricKey in extMetrics) {
                        if (this.vectorInstance.metrics[metricKey] === undefined) {
                            const metricDef = extMetrics[metricKey];
                             if (metricDef.type === 'BOOL') {
                                this.vectorInstance.metrics[metricKey] = 'F';
                            } else if (Array.isArray(metricDef.type)) {
                                this.vectorInstance.metrics[metricKey] = metricDef.type[0];
                            }
                        }
                    }
                }

                this.updateScores();
            } catch (error) {
                 console.error("Error updating vector:", error.message);
            } finally {
                this.$nextTick(() => {
                    this.isLoadingFromHash = false;
                });
            }
        },
        setDefaultExtension() {
            if (this.extensionYAML && Array.isArray(this.extensionYAML.default_ext) && this.extensionYAML.default_ext.length === 2) {
                const [defaultExt, defaultVer] = this.extensionYAML.default_ext;
                if (this.availableExtensions.includes(defaultExt)) {
                    this.isLoadingFromHash = true; // Block watchers during programmatic update
                    this.selectedExtension = defaultExt;
                    this.availableVersions = Object.keys(this.extensionYAML.extensions[defaultExt])
                        .filter(key => typeof this.extensionYAML.extensions[defaultExt][key] === 'object' && this.extensionYAML.extensions[defaultExt][key].metrics);
                    
                    if(this.availableVersions.includes(defaultVer)) {
                        this.selectedVersion = defaultVer;
                    } else {
                        this.selectedVersion = this.availableVersions.length > 0 ? this.availableVersions[0] : '';
                    }

                    this.updateVectorWithExtension();
                    
                    this.$nextTick(() => {
                        this.isLoadingFromHash = false; // Re-enable watchers
                    });
                } else {
                    this.updateScores();
                }
            } else {
                this.updateScores();
            }
        },
        updateScores() {
            this.cvssInstance = new CVSS40(this.vectorInstance);
            this.macroVector = this.vectorInstance.equivalentClasses;

            this.finalScore = null;
            this.extensionName = '';
            this.extensionVersion = '';
            this.finalSeverity = '';
            this.extensionCalculationDetails = null;

            if (!this.extensionYAML) return;

            let tlpColor = this.extensionYAML.TLP || 'CLEAR';
            if (this.selectedExtension !== 'None' && this.extensionYAML.extensions[this.selectedExtension]) {
                const extensionLevel = this.extensionYAML.extensions[this.selectedExtension];
                if (extensionLevel.TLP) {
                    tlpColor = extensionLevel.TLP;
                }
                const versionLevel = extensionLevel[this.selectedVersion];
                if (versionLevel && versionLevel.TLP) {
                    tlpColor = versionLevel.TLP;
                }
            }
            this.currentTLP = `TLP:${tlpColor}`;

            if (this.selectedExtension === 'None') return;

            const currentExtRules = this.extensionYAML.extensions[this.selectedExtension][this.selectedVersion];
            if (!currentExtRules) return;

            this.extensionName = this.selectedExtension;
            this.extensionVersion = this.selectedVersion;

            const calculator = new ExtensionCalculator(this.score, currentExtRules);
            const result = calculator.calculate(this.vectorInstance.metrics);

            if (result.score !== null) {
                this.finalScore = result.score;
                this.finalSeverity = result.severity;

                const metricsInValidCombos = new Set();
                result.validCombos.forEach(combo => {
                    combo.conditions.forEach(cond => metricsInValidCombos.add(cond.metric));
                });

                const displayableMetrics = Object.keys(currentExtRules.metrics).map(metricKey => {
                    const rule = currentExtRules.metrics[metricKey];
                    const value = this.vectorInstance.metrics[metricKey];
                    const modifierValue = result.metricModifiers[metricKey];
                    return {
                        key: metricKey,
                        name: rule.name,
                        value: value === 'T' ? 'True' : (value === 'F' ? 'False' : value),
                        modifier: modifierValue,
                        inValidCombo: metricsInValidCombos.has(metricKey)
                    };
                });

                const displayableCombos = result.allCombos.map(combo => {
                    const isValid = result.validCombos.some(c => c.name === combo.name);
                    let status = 'invalid';
                    if (isValid) {
                        if (result.winningCombo && result.winningCombo.name === combo.name) {
                            status = 'winning';
                        } else {
                            status = 'losing_valid';
                        }
                    }
                    return {
                        name: combo.name,
                        isValid: isValid,
                        status: status,
                        modifier: result.comboModifiers[combo.name]
                    };
                });

                this.extensionCalculationDetails = {
                    metrics: displayableMetrics,
                    combos: displayableCombos,
                };
            }
        },
        onReset() {
            window.location.hash = "";
            this.vectorInstance.resetMetrics();
            this.setDefaultExtension();
        },
        scrollToExtensionMetrics() {
            const el = document.getElementById('extension-metrics-section');
            if (el) {
                el.scrollIntoView({ behavior: 'smooth' });
            }
        },
        scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        },
        handleScroll() {
            const baseMetricsEl = document.getElementById('Base-Metrics');
            if (baseMetricsEl) {
                const rect = baseMetricsEl.getBoundingClientRect();
                this.showScrollToTop = rect.bottom < 0;
            }
        }
    },
    computed: {
        activeRules() {
            const rules = { hide: new Set(), disable: new Set() };
            if (!this.extensionYAML) return rules;

            const getRulesFromLevel = (level, ruleType) => {
                if (level && level[ruleType]) {
                    const val = level[ruleType];
                    return Array.isArray(val) ? val : [val];
                }
                return null;
            };

            let hideRule = getRulesFromLevel(this.extensionYAML, 'hide') || ['none'];
            let disableRule = getRulesFromLevel(this.extensionYAML, 'disable') || ['none'];

            if (this.selectedExtension !== 'None') {
                const extLevel = this.extensionYAML.extensions[this.selectedExtension];
                if (extLevel) {
                    hideRule = getRulesFromLevel(extLevel, 'hide') || hideRule;
                    disableRule = getRulesFromLevel(extLevel, 'disable') || disableRule;

                    if (this.selectedVersion) {
                        const verLevel = extLevel[this.selectedVersion];
                        if (verLevel) {
                            hideRule = getRulesFromLevel(verLevel, 'hide') || hideRule;
                            disableRule = getRulesFromLevel(verLevel, 'disable') || disableRule;
                        }
                    }
                }
            }
            
            if (hideRule.length > 0 && hideRule[0].toLowerCase() !== 'none') {
                hideRule.forEach(val => rules.hide.add(val));
            }
            if (disableRule.length > 0 && disableRule[0].toLowerCase() !== 'none') {
                disableRule.forEach(val => rules.disable.add(val));
            }

            return rules;
        },
        vector() {
            return this.vectorInstance.raw;
        },
        score() {
            return this.cvssInstance ? this.cvssInstance.score : null;
        },
        severityRating() {
            return this.cvssInstance ? this.cvssInstance.severity : "None";
        },
        currentExtensionMetrics() {
            if (this.selectedExtension !== 'None' && this.selectedVersion && this.extensionYAML) {
                return this.extensionYAML.extensions[this.selectedExtension][this.selectedVersion].metrics;
            }
            return null;
        },
        tlpStyle() {
            return this.tlpColors[this.currentTLP] || this.tlpColors['TLP:CLEAR'];
        }
    },
    async beforeMount() {
        await this.loadConfigData();
        await this.loadExtensionData();

        if (window.location.hash) {
           this.setButtonsToVector(window.location.hash.slice(1));
        } else {
           this.setDefaultExtension();
        }
    },
    mounted() {
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash.slice(1));
        });

        window.addEventListener('scroll', this.handleScroll);

        const headerElement = document.getElementById('header');
        if (headerElement) {
            const resizeObserver = new ResizeObserver(() => {
                this.header_height = headerElement.clientHeight;
            });
            resizeObserver.observe(headerElement);
        } else {
            console.error("Header element not found");
        }
    },
    beforeUnmount() {
        window.removeEventListener('scroll', this.handleScroll);
    }
});

app.mount("#app");