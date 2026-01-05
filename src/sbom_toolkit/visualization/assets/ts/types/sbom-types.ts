/**
 * TypeScript type definitions for SBOM visualization data structures
 */

export interface SBOMMetadata {
    component?: {
        name?: string;
        version?: string;
        type?: string;
        supplier?: string;
    };
    repository?: {
        name?: string;
        url?: string;
        branch?: string;
    };
    timestamp?: string;
    tools?: string[];
}

export interface Vulnerability {
    id?: string;
    cve_id?: string;
    description?: string;
    cvss_severity?: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
    cvss_score?: number;
    source?: string;
    url?: string;
}

export interface License {
    name: string;
    type: 'permissive' | 'copyleft' | 'proprietary' | 'unknown';
    url?: string;
}

export interface SBOMNode {
    id: string;
    label: string;
    fullLabel?: string;
    type: 'LIBRARY' | 'LICENSE' | 'ROOT' | 'UNKNOWN';
    size?: number;
    color?: string;
    isVulnerable?: boolean;
    isDependent?: boolean;
    vulnerabilities?: Vulnerability[];
    licenses?: License[];
    version?: string;
    supplier?: string;
    // D3 simulation properties
    x?: number;
    y?: number;
    vx?: number;
    vy?: number;
    fx?: number | null;
    fy?: number | null;
}

export interface SBOMLink {
    source: string | SBOMNode;
    target: string | SBOMNode;
    type?: string;
    color?: string;
    width?: number;
}

export interface SBOMGraphData {
    nodes: SBOMNode[];
    links: SBOMLink[];
}

export interface HierarchicalNode extends SBOMNode {
    children?: HierarchicalNode[];
    parent?: HierarchicalNode;
    depth?: number;
}

export interface VisualizationFilters {
    showVulnerable: boolean;
    showSafe: boolean;
    showDependencies: boolean;
    showLicenses: boolean;
    vulnerabilitySeverity: string[];
    licenseTypes: string[];
}

export interface VisualizationStatistics {
    total_components: number;
    total_licenses: number;
    total_dependencies: number;
    total_vulnerabilities: number;
    vulnerable_count: number;
    safe_count: number;
    total_links: number;
    vulnerability_severity_breakdown: Record<string, number>;
    license_type_breakdown: Record<string, number>;
}

export interface GNNPrediction {
    nodeId: string;
    riskScore: number;
    predictions: {
        isVulnerable: number;
        hasHighRiskDependencies: number;
        attackVectorProbability: number;
    };
    confidence: number;
}

export interface VisualizationConfig {
    width: number;
    height: number;
    nodeRadius: number;
    linkDistance: number;
    chargeStrength: number;
    collisionRadius: number;
    enableZoom: boolean;
    enableTooltips: boolean;
    enableNodeDrag: boolean;
}

export interface TemplateData {
    title: string;
    sbom_metadata: SBOMMetadata;
    visualization_data: Record<string, any>;
    statistics: VisualizationStatistics;
    available_layouts: string[];
    default_layout: string;
    gnn_predictions: Record<string, GNNPrediction>;
    features: {
        has_vulnerabilities: boolean;
        has_dependencies: boolean;
        has_licenses: boolean;
        has_gnn_predictions: boolean;
    };
}

export interface VisualizationCallbacks {
    onNodeClick?: (node: SBOMNode) => void;
    onNodeHover?: (node: SBOMNode | null, event?: MouseEvent) => void;
    onLinkClick?: (link: SBOMLink) => void;
    onBackgroundClick?: () => void;
    onZoom?: (transform: any) => void;
}

export interface VisualizationOptions {
    config: VisualizationConfig;
    callbacks: VisualizationCallbacks;
    filters: VisualizationFilters;
    gnnPredictions?: Record<string, GNNPrediction>;
}

export type LayoutType = 'force-directed' | 'hierarchical' | 'circular';

export interface LayoutEngine {
    process_sbom_data(data: SBOMGraphData): any;
    get_layout_config(): VisualizationConfig;
}
