import { BaseVisualization } from '../core/base-visualization';
import {
    SBOMNode,
    SBOMLink,
    SBOMGraphData,
    VisualizationOptions,
    VisualizationFilters
} from '../types/sbom-types';

// Note: We'll use global d3 for now until we set up proper module bundling
declare const d3: any;

/**
 * Force-directed network visualization for SBOM data
 * Uses D3's force simulation to create an interactive network graph
 */
export class ForceDirectedVisualization extends BaseVisualization {
    private simulation: any = null;
    private nodeElements: any = null;
    private linkElements: any = null;
    private labelElements: any = null;

    constructor(data: SBOMGraphData, container: HTMLElement, options: Partial<VisualizationOptions> = {}) {
        super(data, container, options);
    }

    render(): void {
        console.log("ForceDirectedVisualization render() called with data:", this.data);

        if (!this.svg) return;

        // Clear existing elements
        this.svg.selectAll('*').remove();

        const { width, height } = this.getContainerDimensions();
        console.log(`SVG dimensions: ${width}x${height}`);

        // Process and filter data
        const nodes = this.filterNodes([...this.data.nodes]);
        const links = this.filterLinks([...this.data.links], nodes);

        // Separate isolated nodes (no connections)
        const connectedNodeIds = new Set<string>();
        links.forEach(link => {
            connectedNodeIds.add(typeof link.source === 'string' ? link.source : link.source.id);
            connectedNodeIds.add(typeof link.target === 'string' ? link.target : link.target.id);
        });

        const isolatedNodes = nodes.filter(node => !connectedNodeIds.has(node.id));
        const connectedNodes = nodes.filter(node => connectedNodeIds.has(node.id));

        console.log(`Rendering ${nodes.length} nodes (${connectedNodes.length} connected, ${isolatedNodes.length} isolated) and ${links.length} links`);

        // Create links first (so they appear behind nodes)
        this.linkElements = this.svg.selectAll('.link')
            .data(links)
            .enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke', (d: SBOMLink) => d.color || '#999')
            .attr('stroke-width', (d: SBOMLink) => d.width || 1)
            .attr('stroke-opacity', 0.6);

        // Create nodes with improved styling
        this.nodeElements = this.svg.selectAll('.node')
            .data(nodes)
            .enter()
            .append('circle')
            .attr('class', 'node')
            .attr('r', (d: SBOMNode) => Math.max(6, (d.size || 20) / 3))
            .attr('fill', (d: SBOMNode) => this.getNodeColor(d))
            .attr('stroke', '#333')
            .attr('stroke-width', 1.5)
            .style('cursor', 'pointer')
            .on('click', (event: MouseEvent, d: SBOMNode) => this.handleNodeClick(event, d))
            .on('mouseover', (event: MouseEvent, d: SBOMNode) => this.handleNodeHover(event, d))
            .on('mouseout', () => this.handleNodeHover({} as MouseEvent, null));

        // Add node labels with better contrast
        this.labelElements = this.svg.selectAll('.label')
            .data(nodes)
            .enter()
            .append('text')
            .attr('class', 'label')
            .attr('text-anchor', 'middle')
            .attr('dy', '0.3em')
            .style('font-size', '9px')
            .style('fill', 'white')
            .style('stroke', '#000')
            .style('stroke-width', '1px')
            .style('paint-order', 'stroke fill')
            .style('font-weight', 'bold')
            .style('pointer-events', 'none')
            .text((d: SBOMNode) => {
                // Truncate long labels to prevent overlap
                const label = d.label || d.id;
                return label.length > 12 ? label.substring(0, 10) + '...' : label;
            });

        // Create force simulation
        this.simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id((d: SBOMNode) => d.id).distance(this.options.config.linkDistance))
            .force('charge', d3.forceManyBody().strength(this.options.config.chargeStrength))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius((d: SBOMNode) => (d.size || 20) / 2 + this.options.config.collisionRadius))
            .force('isolatedCluster', this.createIsolatedClusterForce(isolatedNodes, width, height));

        // Handle simulation tick events
        this.simulation.on('tick', () => {
            this.updatePositions();
        });

        // Add isolated components cluster label
        if (isolatedNodes.length > 0) {
            this.addIsolatedClusterLabel(isolatedNodes, width, height);
        }

        // Add drag behavior if enabled
        if (this.options.config.enableNodeDrag) {
            this.setupNodeDrag();
        }
    }

    /**
     * Get appropriate color for a node based on its properties
     */
    private getNodeColor(node: SBOMNode): string {
        if (node.color) return node.color;

        if (node.isVulnerable) return '#e74c3c'; // Red for vulnerable
        if (node.isDependent) return '#f39c12'; // Orange for dependent on vulnerable
        if (node.type === 'LICENSE') return '#9b59b6'; // Purple for licenses
        return '#27ae60'; // Green for safe components
    }

    /**
     * Filter links based on available nodes
     */
    private filterLinks(links: SBOMLink[], nodes: SBOMNode[]): SBOMLink[] {
        const nodeIds = new Set(nodes.map(n => n.id));
        return links.filter(link => {
            const sourceId = typeof link.source === 'string' ? link.source : link.source.id;
            const targetId = typeof link.target === 'string' ? link.target : link.target.id;
            return nodeIds.has(sourceId) && nodeIds.has(targetId);
        });
    }

    /**
     * Create force for clustering isolated nodes
     */
    private createIsolatedClusterForce(isolatedNodes: SBOMNode[], width: number, height: number): () => void {
        const clusterX = width * 0.75;
        const clusterY = height * 0.25;
        const clusterRadius = Math.min(60, isolatedNodes.length * 3 + 35);

        return () => {
            isolatedNodes.forEach((node, i) => {
                const angle = (i / isolatedNodes.length) * 2 * Math.PI;
                const radius = Math.min(clusterRadius, isolatedNodes.length * 3);
                const targetX = clusterX + Math.cos(angle) * radius;
                const targetY = clusterY + Math.sin(angle) * radius;

                node.vx = (node.vx || 0) + (targetX - (node.x || 0)) * 0.1;
                node.vy = (node.vy || 0) + (targetY - (node.y || 0)) * 0.1;
            });
        };
    }

    /**
     * Add label for isolated components cluster
     */
    private addIsolatedClusterLabel(isolatedNodes: SBOMNode[], width: number, height: number): void {
        const clusterX = width * 0.75;
        const clusterY = height * 0.25;
        const clusterRadius = Math.min(90, isolatedNodes.length * 3 + 35);

        this.svg?.append('text')
            .attr('x', clusterX)
            .attr('y', clusterY + clusterRadius + 20)
            .attr('text-anchor', 'middle')
            .style('font-size', '11px')
            .style('fill', 'rgba(255, 255, 255, 0.8)')
            .style('stroke', '#000')
            .style('stroke-width', '0.5px')
            .style('paint-order', 'stroke fill')
            .style('font-weight', 'bold')
            .style('pointer-events', 'none')
            .text(`Isolated Components (${isolatedNodes.length})`);
    }

    /**
     * Setup node drag behavior
     */
    private setupNodeDrag(): void {
        const drag = d3.drag()
            .on('start', (event: any, d: SBOMNode) => {
                if (!event.active) this.simulation?.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            })
            .on('drag', (event: any, d: SBOMNode) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on('end', (event: any, d: SBOMNode) => {
                if (!event.active) this.simulation?.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            });

        if (this.nodeElements) {
            this.nodeElements.call(drag);
        }
    }

    /**
     * Update element positions during simulation
     */
    private updatePositions(): void {
        if (this.linkElements) {
            this.linkElements
                .attr('x1', (d: any) => d.source.x)
                .attr('y1', (d: any) => d.source.y)
                .attr('x2', (d: any) => d.target.x)
                .attr('y2', (d: any) => d.target.y);
        }

        if (this.nodeElements) {
            this.nodeElements
                .attr('cx', (d: SBOMNode) => d.x)
                .attr('cy', (d: SBOMNode) => d.y);
        }

        if (this.labelElements) {
            this.labelElements
                .attr('x', (d: SBOMNode) => d.x)
                .attr('y', (d: SBOMNode) => d.y);
        }
    }

    applyFilters(filters: VisualizationFilters, searchTerm?: string): void {
        if (!this.nodeElements) return;

        this.nodeElements
            .style('opacity', (d: SBOMNode) => {
                if (searchTerm && !d.label.toLowerCase().includes(searchTerm.toLowerCase())) {
                    return 0.2;
                }
                if (!filters.showVulnerable && d.isVulnerable) {
                    return 0.2;
                }
                if (!filters.showSafe && !d.isVulnerable && !d.isDependent) {
                    return 0.2;
                }
                return 1;
            });

        if (this.labelElements) {
            this.labelElements
                .style('opacity', (d: SBOMNode) => {
                    if (searchTerm && !d.label.toLowerCase().includes(searchTerm.toLowerCase())) {
                        return 0.2;
                    }
                    return 1;
                });
        }
    }

    resetView(): void {
        if (this.simulation) {
            this.simulation.alpha(1).restart();
        }
    }

    exportSVG(): void {
        if (!this.containerSvg) {
            console.warn('No SVG element to export');
            return;
        }

        // Create a copy of the SVG
        const svgNode = this.containerSvg.node();
        if (!svgNode) return;

        const serializer = new XMLSerializer();
        const svgString = serializer.serializeToString(svgNode);

        // Create download link
        const blob = new Blob([svgString], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);

        const link = document.createElement('a');
        link.href = url;
        link.download = 'sbom-force-directed.svg';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        URL.revokeObjectURL(url);
    }

    destroy(): void {
        if (this.simulation) {
            this.simulation.stop();
        }
        super.destroy();
    }
}
