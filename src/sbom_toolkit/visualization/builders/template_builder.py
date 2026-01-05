"""
Modular template builder for SBOM visualizations.

This module replaces the monolithic HTML templates with a flexible system
that combines separate CSS, TypeScript, and HTML components.
"""

import json
import logging
from pathlib import Path
from typing import Any


class TemplateBuilder:
    """Builds HTML templates from modular components."""

    def __init__(self):
        """Initialize template builder."""
        self.logger = logging.getLogger(__name__)
        self.assets_dir = Path(__file__).parent.parent / "assets"

        # Load CSS files
        self.css_files = ["css/base.css", "css/sidebar.css", "css/controls.css"]

        # TypeScript files (will be compiled to JS eventually)
        self.ts_files = [
            "ts/types/sbom-types.ts",
            "ts/core/base-visualization.ts",
            "ts/visualizations/force-directed.ts",
        ]

    def build_unified_template(
        self, template_data: dict[str, Any], include_layouts: list[str] | None = None
    ) -> str:
        """Build a unified visualization template.

        Args:
            template_data: Data to inject into template
            include_layouts: List of layout types to include

        Returns:
            Complete HTML template string
        """
        if include_layouts is None:
            include_layouts = ["force-directed", "hierarchical", "circular"]

        # Build CSS
        css_content = self._load_css_files()

        # Build JavaScript (for now, we'll include a placeholder)
        js_content = self._build_javascript_placeholder(include_layouts)

        # Build HTML structure
        html_content = self._build_html_structure(template_data, css_content, js_content)

        return html_content

    def _load_css_files(self) -> str:
        """Load and combine CSS files."""
        css_content = []

        for css_file in self.css_files:
            css_path = self.assets_dir / css_file
            if css_path.exists():
                with open(css_path, encoding="utf-8") as f:
                    css_content.append(f.read())
            else:
                self.logger.warning(f"CSS file not found: {css_path}")

        return "\n\n".join(css_content)

    def _build_javascript_placeholder(self, include_layouts: list[str]) -> str:
        """Build JavaScript content (placeholder for now until we set up TS compilation)."""
        # For now, we'll create a simplified version that uses global d3
        # Later this will be replaced with compiled TypeScript

        js_template = """
        // Modular SBOM Visualization System
        // Note: This will be replaced with compiled TypeScript

        let currentVisualization = null;
        let visualizationData = null;
        let filters = {
            showVulnerable: true,
            showSafe: true,
            showDependencies: true,
            showLicenses: true,
            vulnerabilitySeverity: ['critical', 'high', 'medium', 'low'],
            licenseTypes: ['permissive', 'copyleft', 'proprietary', 'unknown']
        };
        let searchTerm = '';

        // Initialize application
        function initializeApp() {
            console.log('Initializing modular SBOM visualization app...');

            // Load data from template
            try {
                visualizationData = {{VISUALIZATION_DATA}};
                console.log('Loaded visualization data:', visualizationData);

                // Initialize default layout
                const defaultLayout = '{{DEFAULT_LAYOUT}}';
                if (visualizationData[defaultLayout]) {
                    switchLayout(defaultLayout);
                }

                // Setup event listeners
                setupEventListeners();

            } catch (error) {
                console.error('Failed to initialize app:', error);
            }
        }

        // Switch between layout types
        function switchLayout(layoutType) {
            console.log('Switching to layout:', layoutType);

            // Clean up current visualization
            if (currentVisualization && currentVisualization.destroy) {
                currentVisualization.destroy();
            }

            // Update active button
            document.querySelectorAll('.layout-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`[onclick="switchLayout('${layoutType}')"]`)?.classList.add('active');

            // Create new visualization
            const container = document.getElementById('visualization-container');
            if (!container) {
                console.error('Visualization container not found');
                return;
            }

            // For now, create a simple placeholder
            // This will be replaced with actual TypeScript classes
            createPlaceholderVisualization(container, layoutType, visualizationData[layoutType]);
        }

        // Force-directed visualization implementation
        function createForceDirectedVisualization(container, data) {
            container.innerHTML = '';

            const svg = d3.select(container)
                .append('svg')
                .attr('class', 'visualization-svg')
                .attr('width', '100%')
                .attr('height', '100%');

            const width = container.clientWidth;
            const height = container.clientHeight;

            const graphData = data.data;
            const config = data.config;

            // Create force simulation
            const simulation = d3.forceSimulation(graphData.nodes)
                .force('link', d3.forceLink(graphData.links)
                    .id(d => d.id)
                    .distance(config.simulation.linkDistance)
                    .strength(config.simulation.linkStrength))
                .force('charge', d3.forceManyBody()
                    .strength(config.simulation.charge))
                .force('center', d3.forceCenter(width / 2, height / 2)
                    .strength(config.simulation.centerStrength))
                .force('collision', d3.forceCollide()
                    .radius(config.simulation.collisionRadius))
                .velocityDecay(config.simulation.velocityDecay);

            // Create links
            const link = svg.append('g')
                .selectAll('line')
                .data(graphData.links)
                .join('line')
                .attr('stroke', d => d.color)
                .attr('stroke-width', d => d.width)
                .attr('stroke-opacity', config.link_settings.opacity);

            // Create nodes
            const node = svg.append('g')
                .selectAll('circle')
                .data(graphData.nodes)
                .join('circle')
                .attr('r', d => Math.max(config.node_settings.min_radius,
                    Math.min(config.node_settings.max_radius, d.size / 2)))
                .attr('fill', d => d.color)
                .attr('stroke', '#fff')
                .attr('stroke-width', config.node_settings.stroke_width)
                .attr('opacity', config.node_settings.opacity)
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended))
                .on('click', function(event, d) {
                    showNodeDetails(d);
                })
                .on('mouseover', function(event, d) {
                    showTooltip(event, d);
                })
                .on('mouseout', hideTooltip);

            // Create labels
            const label = svg.append('g')
                .selectAll('text')
                .data(graphData.nodes)
                .join('text')
                .text(d => d.label)
                .attr('text-anchor', 'middle')
                .attr('dy', '.35em')
                .style('font-size', '11px')
                .style('font-weight', '500')
                .style('fill', '#fff')
                .style('text-shadow', '1px 1px 2px rgba(0,0,0,0.8)')
                .style('pointer-events', 'none');

            // Update positions on simulation tick
            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                node
                    .attr('cx', d => Math.max(20, Math.min(width - 20, d.x)))
                    .attr('cy', d => Math.max(20, Math.min(height - 20, d.y)));

                label
                    .attr('x', d => Math.max(20, Math.min(width - 20, d.x)))
                    .attr('y', d => Math.max(20, Math.min(height - 20, d.y)));
            });

            // Drag functions
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            return {
                destroy: () => svg.remove(),
                resetView: () => {
                    simulation.alpha(1).restart();
                },
                applyFilters: (filters, searchTerm) => {
                    // Implement filtering logic here
                    node.style('opacity', d => {
                        if (searchTerm && !d.label.toLowerCase().includes(searchTerm)) {
                            return 0.2;
                        }
                        if (!filters.showVulnerable && d.isVulnerable) return 0.2;
                        if (!filters.showSafe && !d.isVulnerable && !d.isDependent) return 0.2;
                        return config.node_settings.opacity;
                    });
                }
            };
        }

        // Placeholder for other visualization types
        function createPlaceholderVisualization(container, layoutType, data) {
            if (layoutType === 'force-directed') {
                return createForceDirectedVisualization(container, data);
            }

            // Fallback for other layouts
            container.innerHTML = '';
            const svg = d3.select(container)
                .append('svg')
                .attr('class', 'visualization-svg')
                .attr('width', '100%')
                .attr('height', '100%');

            const width = container.clientWidth;
            const height = container.clientHeight;

            svg.append('text')
                .attr('x', width / 2)
                .attr('y', height / 2)
                .attr('text-anchor', 'middle')
                .style('font-size', '18px')
                .style('fill', 'rgba(255, 255, 255, 0.8)')
                .style('font-weight', 'bold')
                .text(`${layoutType.charAt(0).toUpperCase() + layoutType.slice(1)} Layout`);

            svg.append('text')
                .attr('x', width / 2)
                .attr('y', height / 2 + 30)
                .attr('text-anchor', 'middle')
                .style('font-size', '14px')
                .style('fill', 'rgba(255, 255, 255, 0.6)')
                .text('Implementation coming soon...');

            return { destroy: () => svg.remove() };
        }

        // Setup event listeners
        function setupEventListeners() {
            // Search functionality
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.addEventListener('input', (e) => {
                    searchTerm = e.target.value.toLowerCase();
                    applyFilters();
                });
            }

            // Filter checkboxes
            document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
                checkbox.addEventListener('change', updateFilters);
            });
        }

        // Update filters from UI
        function updateFilters() {
            const vulnerableCheckbox = document.getElementById('show-vulnerable');
            const safeCheckbox = document.getElementById('show-safe');

            if (vulnerableCheckbox) filters.showVulnerable = vulnerableCheckbox.checked;
            if (safeCheckbox) filters.showSafe = safeCheckbox.checked;

            applyFilters();
        }

        // Show node details in sidebar
        function showNodeDetails(nodeData) {
            const detailsPanel = document.getElementById('node-details');
            const detailsContent = document.getElementById('details-content');

            if (!detailsPanel || !detailsContent) return;

            let html = `
                <div class="detail-item">
                    <div class="detail-label">Name</div>
                    <div class="detail-value">${nodeData.fullLabel}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Type</div>
                    <div class="detail-value">${nodeData.type}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Status</div>
                    <div class="detail-value">${nodeData.status}</div>
                </div>
            `;

            if (nodeData.vulnerabilities && nodeData.vulnerabilities.length > 0) {
                html += '<div class="detail-item"><div class="detail-label">Vulnerabilities</div>';
                nodeData.vulnerabilities.forEach(vuln => {
                    html += `
                        <div class="detail-value" style="margin: 8px 0; padding: 8px; background: rgba(255, 82, 82, 0.1); border-radius: 4px;">
                            <strong>${vuln.cve_id}</strong><br/>
                            <small>Severity: ${vuln.cvss_severity} (${vuln.cvss_score})</small><br/>
                            <small>${vuln.description}</small>
                        </div>
                    `;
                });
                html += '</div>';
            }

            detailsContent.innerHTML = html;
            detailsPanel.classList.add('show');
        }

        // Show tooltip on hover
        function showTooltip(event, nodeData) {
            const tooltip = document.getElementById('tooltip');
            if (!tooltip) return;

            let content = `<h4>${nodeData.label}</h4>`;
            content += `<p>Type: ${nodeData.type}</p>`;
            content += `<p>Status: ${nodeData.status}</p>`;

            if (nodeData.vulnerabilities && nodeData.vulnerabilities.length > 0) {
                content += `<p>Vulnerabilities: ${nodeData.vulnerabilities.length}</p>`;
            }

            tooltip.innerHTML = content;
            tooltip.style.display = 'block';
            tooltip.style.left = (event.pageX + 10) + 'px';
            tooltip.style.top = (event.pageY - 10) + 'px';
        }

        // Hide tooltip
        function hideTooltip() {
            const tooltip = document.getElementById('tooltip');
            if (tooltip) {
                tooltip.style.display = 'none';
            }
        }

        // Apply current filters
        function applyFilters() {
            if (currentVisualization && currentVisualization.applyFilters) {
                currentVisualization.applyFilters(filters, searchTerm);
            }
        }

        // Utility functions
        function resetZoom() {
            if (currentVisualization && currentVisualization.resetView) {
                currentVisualization.resetView();
            }
        }

        function exportSVG() {
            if (currentVisualization && currentVisualization.exportSVG) {
                currentVisualization.exportSVG();
            }
        }

        function toggleFullscreen() {
            const container = document.querySelector('.main-content');
            if (!document.fullscreenElement) {
                container.requestFullscreen().catch(err => {
                    console.error('Error attempting to enable fullscreen:', err);
                });
            } else {
                document.exitFullscreen();
            }
        }

        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeApp);
        } else {
            initializeApp();
        }
        """

        return js_template

    def _build_html_structure(
        self, template_data: dict[str, Any], css_content: str, js_content: str
    ) -> str:
        """Build the complete HTML structure."""

        # Extract data for template
        title = template_data.get("title", "SBOM Visualization")
        stats = template_data.get("statistics", {})
        available_layouts = template_data.get("available_layouts", ["force-directed"])
        default_layout = template_data.get("default_layout", "force-directed")

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
{css_content}
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <h1>{title}</h1>

            <!-- Layout Selection -->
            <div class="layout-selection">
                <h3>Visualization Layout</h3>
                <div class="layout-buttons">
                    {self._build_layout_buttons(available_layouts)}
                </div>
            </div>

            <!-- Statistics -->
            <div class="stats-section">
                <h3>Statistics</h3>
                <div class="stats-grid">
                    {self._build_stats_cards(stats)}
                </div>
            </div>

            <!-- Controls -->
            <div class="controls">
                <h3>Filters</h3>

                <div class="control-group">
                    <div class="search-box">
                        <input type="text" id="search-input" class="search-input" placeholder="Search components...">
                        <span class="search-icon">🔍</span>
                        <button class="clear-search" onclick="document.getElementById('search-input').value=''; applyFilters();">✕</button>
                    </div>
                </div>

                <div class="control-group">
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="show-vulnerable" class="filter-checkbox" checked>
                            <label for="show-vulnerable">Show Vulnerable</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="show-safe" class="filter-checkbox" checked>
                            <label for="show-safe">Show Safe</label>
                        </div>
                    </div>
                </div>

                <div class="action-buttons">
                    <button class="action-btn secondary" onclick="resetZoom()">Reset View</button>
                    <button class="action-btn primary" onclick="exportSVG()">Export SVG</button>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <div class="visualization-container" id="visualization-container">
                <!-- Visualization will be rendered here -->
            </div>

            <!-- Toolbar -->
            <div class="toolbar">
                <button class="toolbar-btn" onclick="resetZoom()" title="Reset View">🔄</button>
                <button class="toolbar-btn" onclick="exportSVG()" title="Export SVG">📥</button>
                <button class="toolbar-btn" onclick="toggleFullscreen()" title="Toggle Fullscreen">⛶</button>
            </div>

            <!-- Node Details Panel -->
            <div class="node-details" id="node-details">
                <h3>Component Details</h3>
                <div id="details-content">
                    Click on a component to view details
                </div>
            </div>

            <!-- Tooltip -->
            <div class="tooltip" id="tooltip"></div>
        </div>
    </div>

    <script>
{js_content}
    </script>
</body>
</html>"""

        # Sanitize visualization data for JSON serialization
        visualization_data = self._sanitize_for_json(template_data.get("visualization_data", {}))

        # Replace placeholders with actual data
        html_template = html_template.replace(
            "{{VISUALIZATION_DATA}}", json.dumps(visualization_data)
        )
        html_template = html_template.replace("{{DEFAULT_LAYOUT}}", default_layout)

        return html_template

    def _build_layout_buttons(self, available_layouts: list[str]) -> str:
        """Build layout selection buttons."""
        buttons = []
        for layout in available_layouts:
            layout_name = layout.replace("-", " ").title()
            buttons.append(
                f'<button class="layout-btn" onclick="switchLayout(\'{layout}\')">{layout_name}</button>'
            )
        return "\n                    ".join(buttons)

    def _build_stats_cards(self, stats: dict[str, Any]) -> str:
        """Build statistics cards."""
        cards = []

        # Default stats structure
        default_stats = {
            "total_components": 0,
            "vulnerable_count": 0,
            "safe_count": 0,
            "total_licenses": 0,
        }

        stats = {**default_stats, **stats}

        # Components card
        cards.append(
            f"""
                    <div class="stat-card">
                        <div class="stat-number">{stats.get("total_components", 0)}</div>
                        <div class="stat-label">Components</div>
                    </div>"""
        )

        # Vulnerable card
        cards.append(
            f"""
                    <div class="stat-card danger">
                        <div class="stat-number">{stats.get("vulnerable_count", 0)}</div>
                        <div class="stat-label">Vulnerable</div>
                    </div>"""
        )

        # Safe card
        cards.append(
            f"""
                    <div class="stat-card success">
                        <div class="stat-number">{stats.get("safe_count", 0)}</div>
                        <div class="stat-label">Safe</div>
                    </div>"""
        )

        # Licenses card
        cards.append(
            f"""
                    <div class="stat-card">
                        <div class="stat-number">{stats.get("total_licenses", 0)}</div>
                        <div class="stat-label">Licenses</div>
                    </div>"""
        )

        return "\n".join(cards)

    def _sanitize_for_json(self, data: Any) -> Any:
        """Sanitize data to make it JSON serializable.

        Args:
            data: Data to sanitize

        Returns:
            JSON-serializable version of the data
        """
        if callable(data):
            # Skip functions
            return None
        elif isinstance(data, dict):
            # Recursively sanitize dictionary values
            return {
                key: self._sanitize_for_json(value)
                for key, value in data.items()
                if not callable(value)
            }
        elif isinstance(data, list | tuple):
            # Recursively sanitize list/tuple items
            return [self._sanitize_for_json(item) for item in data if not callable(item)]
        elif isinstance(data, str | int | float | bool) or data is None:
            # These types are already JSON serializable
            return data
        else:
            # For other types, try to convert to string or skip
            try:
                # Try to serialize to test if it's JSON compatible
                json.dumps(data)
                return data
            except (TypeError, ValueError):
                # If it fails, convert to string representation
                return str(data)
