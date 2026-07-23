import React from 'react';
import { riskColor, riskLevel } from '../utils/constants';

/**
 * Animated conic-gradient risk gauge — the centrepiece of the scan overview.
 */
export default function RiskGauge({ score = 0, size = 180 }) {
  const pct = Math.min(score * 10, 100);
  const color = riskColor(score);
  const level = riskLevel(score);
  const innerSize = size - 40;

  return (
    <div className="risk-gauge" style={{ width: size, height: size }}>
      <div
        className="risk-gauge__circle"
        style={{
          '--gauge-pct': pct,
          '--gauge-color': color,
        }}
      >
        <div className="risk-gauge__inner" style={{ width: innerSize, height: innerSize }}>
          <span className="risk-gauge__score" style={{ color }}>
            {score.toFixed(1)}
          </span>
          <span className="risk-gauge__label">{level} risk</span>
        </div>
      </div>
    </div>
  );
}
