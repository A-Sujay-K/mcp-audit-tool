import React, { useRef, useEffect, useCallback } from 'react';
import { CAPABILITY_LABELS } from '../utils/constants';

/**
 * Interactive force-directed capability graph rendered on canvas.
 * Shows tools as nodes colored by capability, edges as data-flow paths,
 * and highlights lethal-trifecta chains in red.
 *
 * Uses a simple custom physics simulation (no external graph lib dependency).
 */

const NODE_COLORS = {
  reads_sensitive_data: '#ff6b6b',
  ingests_untrusted_content: '#ffd93d',
  sends_data_out: '#00d4ff',
  executes_code: '#8b5cf6',
  modifies_filesystem: '#ffa050',
  manages_credentials: '#ff50a0',
};

const EDGE_COLORS = {
  data_exfiltration: '#ff6b6b',
  injection_surface: '#ffd93d',
  rce_path: '#8b5cf6',
  credential_theft: '#ff50a0',
  default: 'rgba(255,255,255,0.08)',
};

export default function CapabilityGraph({ graphData, width = 800, height = 500 }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const nodesRef = useRef([]);
  const edgesRef = useRef([]);
  const dragRef = useRef(null);
  const mouseRef = useRef({ x: 0, y: 0 });
  const hoveredRef = useRef(null);

  // Initialize nodes with random positions
  useEffect(() => {
    if (!graphData?.nodes) return;

    const nodes = graphData.nodes.map((n, i) => ({
      ...n,
      x: width / 2 + (Math.random() - 0.5) * width * 0.6,
      y: height / 2 + (Math.random() - 0.5) * height * 0.6,
      vx: 0,
      vy: 0,
      radius: 8 + (n.capabilities?.length || 1) * 3,
      color: getPrimaryColor(n.capabilities),
    }));

    const edges = (graphData.edges || []).map((e) => ({
      ...e,
      sourceNode: nodes.find((n) => n.id === e.source),
      targetNode: nodes.find((n) => n.id === e.target),
    })).filter((e) => e.sourceNode && e.targetNode);

    nodesRef.current = nodes;
    edgesRef.current = edges;
  }, [graphData, width, height]);

  // Physics + render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function tick() {
      const nodes = nodesRef.current;
      const edges = edgesRef.current;

      // Repulsion between nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = 800 / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          nodes[i].vx -= fx;
          nodes[i].vy -= fy;
          nodes[j].vx += fx;
          nodes[j].vy += fy;
        }
      }

      // Attraction along edges
      for (const edge of edges) {
        const dx = edge.targetNode.x - edge.sourceNode.x;
        const dy = edge.targetNode.y - edge.sourceNode.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist - 120) * 0.005;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        edge.sourceNode.vx += fx;
        edge.sourceNode.vy += fy;
        edge.targetNode.vx -= fx;
        edge.targetNode.vy -= fy;
      }

      // Center gravity
      for (const node of nodes) {
        node.vx += (width / 2 - node.x) * 0.001;
        node.vy += (height / 2 - node.y) * 0.001;
      }

      // Apply velocity with damping
      for (const node of nodes) {
        if (dragRef.current === node) continue;
        node.vx *= 0.85;
        node.vy *= 0.85;
        node.x += node.vx;
        node.y += node.vy;
        node.x = Math.max(node.radius, Math.min(width - node.radius, node.x));
        node.y = Math.max(node.radius, Math.min(height - node.radius, node.y));
      }

      // Draw
      ctx.clearRect(0, 0, width, height);

      // Edges
      for (const edge of edges) {
        ctx.beginPath();
        ctx.moveTo(edge.sourceNode.x, edge.sourceNode.y);
        ctx.lineTo(edge.targetNode.x, edge.targetNode.y);
        ctx.strokeStyle = EDGE_COLORS[edge.edge_type] || EDGE_COLORS.default;
        ctx.globalAlpha = edge.is_cross_server ? 0.6 : 0.25;
        ctx.lineWidth = edge.is_cross_server ? 2 : 1;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Arrow
        const angle = Math.atan2(edge.targetNode.y - edge.sourceNode.y, edge.targetNode.x - edge.sourceNode.x);
        const arrowLen = 8;
        const ax = edge.targetNode.x - Math.cos(angle) * edge.targetNode.radius;
        const ay = edge.targetNode.y - Math.sin(angle) * edge.targetNode.radius;
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - arrowLen * Math.cos(angle - 0.4), ay - arrowLen * Math.sin(angle - 0.4));
        ctx.lineTo(ax - arrowLen * Math.cos(angle + 0.4), ay - arrowLen * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = EDGE_COLORS[edge.edge_type] || EDGE_COLORS.default;
        ctx.globalAlpha = edge.is_cross_server ? 0.6 : 0.25;
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Nodes
      const hovered = hoveredRef.current;
      for (const node of nodes) {
        const isHovered = node === hovered;

        // Glow
        if (isHovered) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 8, 0, Math.PI * 2);
          ctx.fillStyle = node.color + '22';
          ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.color + (isHovered ? 'ff' : 'cc');
        ctx.fill();
        ctx.strokeStyle = node.color;
        ctx.lineWidth = isHovered ? 2.5 : 1;
        ctx.stroke();

        // Label
        ctx.font = `${isHovered ? '600' : '400'} 10px Inter, sans-serif`;
        ctx.fillStyle = isHovered ? '#e8eaf6' : '#9ba3c7';
        ctx.textAlign = 'center';
        ctx.fillText(node.tool_name || node.id, node.x, node.y + node.radius + 14);

        // Server label
        if (isHovered && node.server_name) {
          ctx.font = '400 9px Inter, sans-serif';
          ctx.fillStyle = '#5d6494';
          ctx.fillText(`[${node.server_name}]`, node.x, node.y + node.radius + 26);
        }
      }

      animRef.current = requestAnimationFrame(tick);
    }

    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [graphData, width, height]);

  // Mouse interaction
  const handleMouseMove = useCallback((e) => {
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    mouseRef.current = { x: mx, y: my };

    if (dragRef.current) {
      dragRef.current.x = mx;
      dragRef.current.y = my;
      dragRef.current.vx = 0;
      dragRef.current.vy = 0;
      return;
    }

    // Hit test
    let found = null;
    for (const node of nodesRef.current) {
      const dx = mx - node.x;
      const dy = my - node.y;
      if (dx * dx + dy * dy < (node.radius + 4) * (node.radius + 4)) {
        found = node;
        break;
      }
    }
    hoveredRef.current = found;
    canvasRef.current.style.cursor = found ? 'pointer' : 'grab';
  }, []);

  const handleMouseDown = useCallback((e) => {
    if (hoveredRef.current) {
      dragRef.current = hoveredRef.current;
      canvasRef.current.style.cursor = 'grabbing';
    }
  }, []);

  const handleMouseUp = useCallback(() => {
    dragRef.current = null;
  }, []);

  if (!graphData?.nodes?.length) {
    return (
      <div className="card empty-state" style={{ height }}>
        <div className="empty-state__icon">🕸️</div>
        <div className="empty-state__title">No Graph Data</div>
        <div className="empty-state__description">
          Run a scan to generate the capability graph.
        </div>
      </div>
    );
  }

  return (
    <div className="graph-container" style={{ height }}>
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        onMouseMove={handleMouseMove}
        onMouseDown={handleMouseDown}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        style={{ display: 'block', width: '100%', height: '100%' }}
      />
      <div className="graph-legend">
        {Object.entries(NODE_COLORS).map(([cap, color]) => (
          <div key={cap} className="graph-legend__item">
            <span className="graph-legend__dot" style={{ background: color }} />
            <span>{CAPABILITY_LABELS[cap]?.label || cap}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function getPrimaryColor(capabilities) {
  if (!capabilities?.length) return '#5d6494';
  // Priority: reads > ingests > sends > executes > modifies > credentials
  const priority = [
    'reads_sensitive_data',
    'ingests_untrusted_content',
    'sends_data_out',
    'executes_code',
    'modifies_filesystem',
    'manages_credentials',
  ];
  for (const cap of priority) {
    if (capabilities.includes(cap)) return NODE_COLORS[cap];
  }
  return '#5d6494';
}
