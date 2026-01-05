import * as d3 from 'd3';
import {
    SBOMNode,
    SBOMLink,
    SBOMGraphData,
    VisualizationOptions,
    VisualizationFilters,
    VisualizationConfig,
    VisualizationCallbacks
} from '../types/sbom-types';

/**
 * Base class for all SBOM visualizations
 * Provides common functionality and interface for different layout engines
 */
export abstract class BaseVisualization {
    protected data: SBOMGraphData;
    protected container: HTMLElement;
    protected options: VisualizationOptions;
    protected svg: d3.Selection<SVGGElement, unknown, null, undefined> | null = null;
    protected containerSvg: d3.Selection<SVGSVGElement, unknown, null, undefined> | null = null;

    constructor(data: SBOMGraphData, container: HTMLElement, options: Partial<VisualizationOptions> = {}) {
        this.data = data;
        this.container = container;
        this.options = this.mergeDefaultOptions(options);

        this.validateData();
        this.initializeContainer();
    }

    /**
     * Merge user options with defaults
     */
    private mergeDefaultOptions(options: Partial<VisualizationOptions>): VisualizationOptions {
        const defaultConfig: VisualizationConfig = {
            width: 800,
            height: 600,
            nodeRadius: 8,
            linkDistance: 120,
            chargeStrength: -400,
            collisionRadius: 15,
            enableZoom: true,
            enableTooltips: true,
            enableNodeDrag: true
        };

        const defaultFilters: VisualizationFilters = {
            showVulnerable: true,
            showSafe: true,
            showDependencies: true,
            showLicenses: true,
            vulnerabilitySeverity: ['critical', 'high', 'medium', 'low'],
            licenseTypes: ['permissive', 'copyleft', 'proprietary', 'unknown']
        };

        const defaultCallbacks: VisualizationCallbacks = {};

        return {
            config: { ...defaultConfig, ...options.config },
            filters: { ...defaultFilters, ...options.filters },
            callbacks: { ...defaultCallbacks, ...options.callbacks },
            gnnPredictions: options.gnnPredictions || {}
        };
    }

    /**
     * Validate input data structure
     */
    private validateData(): void {
        if (!this.data || !Array.isArray(this.data.nodes) || !Array.isArray(this.data.links)) {
            throw new Error('Invalid SBOM data: must contain nodes and links arrays');
        }

        // Check for required node properties
        this.data.nodes.forEach((node, index) => {
            if (!node.id || !node.label) {
                throw new Error(`Invalid node at index ${index}: missing id or label`);
            }
        });
    }

    /**
     * Initialize the SVG container
     */
    private initializeContainer(): void {
        // Clear existing content
        d3.select(this.container).selectAll('*').remove();

        this.containerSvg = d3.select(this.container)
            .append('svg')
            .attr('class', 'visualization-svg')
            .attr('width', '100%')
            .attr('height', '100%');

        this.svg = this.containerSvg.append('g');

        // Add zoom behavior if enabled
        if (this.options.config.enableZoom) {
            this.setupZoom();
        }
    }

    /**
     * Setup zoom and pan behavior
     */
    private setupZoom(): void {
        const zoom = d3.zoom<SVGSVGElement, unknown>()
            .scaleExtent([0.1, 10])
            .on('zoom', (event) => {
                if (this.svg) {
                    this.svg.attr('transform', event.transform);
                }
                if (this.options.callbacks.onZoom) {
                    this.options.callbacks.onZoom(event.transform);
                }
            });

        if (this.containerSvg) {
            this.containerSvg.call(zoom);
        }
    }

    /**
     * Get container dimensions
     */
    protected getContainerDimensions(): { width: number; height: number } {
        const rect = this.container.getBoundingClientRect();
        return {
            width: rect.width || this.options.config.width,
            height: rect.height || this.options.config.height
        };
    }

    /**
     * Filter nodes based on current filter settings
     */
    protected filterNodes(nodes: SBOMNode[]): SBOMNode[] {
        return nodes.filter(node => {
            const filters = this.options.filters;

            // Vulnerability filters
            if (node.isVulnerable && !filters.showVulnerable) return false;
            if (!node.isVulnerable && !node.isDependent && !filters.showSafe) return false;

            // Type filters
            if (node.type === 'LICENSE' && !filters.showLicenses) return false;

            // Severity filters
            if (node.vulnerabilities && node.vulnerabilities.length > 0) {
                const hasMatchingSeverity = node.vulnerabilities.some(vuln =>
                    filters.vulnerabilitySeverity.includes(vuln.cvss_severity || 'unknown')
                );
                if (!hasMatchingSeverity) return false;
            }

            // License type filters
            if (node.licenses && node.licenses.length > 0) {
                const hasMatchingLicense = node.licenses.some(license =>
                    filters.licenseTypes.includes(license.type)
                );
                if (!hasMatchingLicense) return false;
            }

            return true;
        });
    }

    /**
     * Apply search term filtering
     */
    protected applySearchFilter(nodes: SBOMNode[], searchTerm: string): SBOMNode[] {
        if (!searchTerm) return nodes;

        const term = searchTerm.toLowerCase();
        return nodes.filter(node =>
            node.label.toLowerCase().includes(term) ||
            node.fullLabel?.toLowerCase().includes(term) ||
            node.id.toLowerCase().includes(term)
        );
    }

    /**
     * Handle node click events
     */
    protected handleNodeClick = (event: MouseEvent, node: SBOMNode): void => {
        event.stopPropagation();
        if (this.options.callbacks.onNodeClick) {
            this.options.callbacks.onNodeClick(node);
        }
    };

    /**
     * Handle node hover events
     */
    protected handleNodeHover = (event: MouseEvent, node: SBOMNode | null): void => {
        if (this.options.callbacks.onNodeHover) {
            this.options.callbacks.onNodeHover(node, event);
        }
    };

    /**
     * Abstract methods to be implemented by subclasses
     */
    abstract render(): void;
    abstract applyFilters(filters: VisualizationFilters, searchTerm?: string): void;
    abstract resetView(): void;
    abstract exportSVG(): void;

    /**
     * Cleanup resources
     */
    destroy(): void {
        if (this.svg) {
            this.svg.selectAll('*').remove();
        }
        if (this.containerSvg) {
            this.containerSvg.remove();
        }
    }

    /**
     * Update visualization options
     */
    updateOptions(newOptions: Partial<VisualizationOptions>): void {
        this.options = this.mergeDefaultOptions({ ...this.options, ...newOptions });
    }

    /**
     * Get current visualization statistics
     */
    getStatistics(): Record<string, number> {
        const nodes = this.data.nodes;
        const vulnerableNodes = nodes.filter(n => n.isVulnerable);
        const safeNodes = nodes.filter(n => !n.isVulnerable && !n.isDependent);

        return {
            totalNodes: nodes.length,
            totalLinks: this.data.links.length,
            vulnerableCount: vulnerableNodes.length,
            safeCount: safeNodes.length,
            libraryCount: nodes.filter(n => n.type === 'LIBRARY').length,
            licenseCount: nodes.filter(n => n.type === 'LICENSE').length
        };
    }
}
