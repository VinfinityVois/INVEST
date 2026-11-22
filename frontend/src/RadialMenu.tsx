import { useEffect, useMemo, useState } from "react";

export type RadialItem = {
  type: string;
  title: string;
  category: string;
  description?: string;
};

type Props = {
  x: number;
  y: number;
  items: RadialItem[];
  onPick: (type: string) => void;
  onClose: () => void;
};

const SIZE = 360;
const CENTER = SIZE / 2;
const INNER_RADIUS = 65;
const OUTER_RADIUS = 164;
const LABEL_RADIUS = 116;

const CATEGORY_COLOR: Record<string, string> = {
  Trigger: "#38bdf8",
  Source: "#22d3ee",
  Scanner: "#f59e0b",
  Logic: "#a78bfa",
  AI: "#c084fc",
  Notify: "#34d399",
  Gate: "#f87171",
  Merge: "#94a3b8",
};

function polar(radius: number, angle: number) {
  return {
    x: CENTER + Math.cos(angle) * radius,
    y: CENTER + Math.sin(angle) * radius,
  };
}

function sectorPath(index: number, count: number) {
  const step = (Math.PI * 2) / count;
  const gap = Math.min(0.035, step * 0.08);
  const start = -Math.PI / 2 + index * step + gap;
  const end = -Math.PI / 2 + (index + 1) * step - gap;
  const outerStart = polar(OUTER_RADIUS, start);
  const outerEnd = polar(OUTER_RADIUS, end);
  const innerEnd = polar(INNER_RADIUS, end);
  const innerStart = polar(INNER_RADIUS, start);
  const largeArc = end - start > Math.PI ? 1 : 0;

  return [
    `M ${outerStart.x} ${outerStart.y}`,
    `A ${OUTER_RADIUS} ${OUTER_RADIUS} 0 ${largeArc} 1 ${outerEnd.x} ${outerEnd.y}`,
    `L ${innerEnd.x} ${innerEnd.y}`,
    `A ${INNER_RADIUS} ${INNER_RADIUS} 0 ${largeArc} 0 ${innerStart.x} ${innerStart.y}`,
    "Z",
  ].join(" ");
}

export default function RadialMenu({ x, y, items, onPick, onClose }: Props) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [position, setPosition] = useState({ x, y });

  const wheelItems = useMemo(
    () => items.slice(0, 12).map((item) => ({
      ...item,
      color: CATEGORY_COLOR[item.category] || "#7c9aaa",
    })),
    [items],
  );

  const activeItem = wheelItems[activeIndex] ?? wheelItems[0];

  useEffect(() => {
    const margin = SIZE / 2 + 12;
    setPosition({
      x: Math.max(margin, Math.min(window.innerWidth - margin, x)),
      y: Math.max(margin, Math.min(window.innerHeight - margin, y)),
    });
  }, [x, y]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }

      if (!wheelItems.length) return;

      if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        event.preventDefault();
        setActiveIndex((current) => (current + 1) % wheelItems.length);
      } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        event.preventDefault();
        setActiveIndex((current) => (current - 1 + wheelItems.length) % wheelItems.length);
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const selected = wheelItems[activeIndex];
        if (selected) onPick(selected.type);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [activeIndex, onClose, onPick, wheelItems]);

  if (!wheelItems.length) return null;

  return (
    <div
      className="weapon-wheel-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="weapon-wheel"
        style={{ left: position.x, top: position.y }}
        role="menu"
        aria-label="Быстрое добавление блока"
      >
        <svg className="weapon-wheel-svg" viewBox={`0 0 ${SIZE} ${SIZE}`} aria-hidden="true">
          <circle className="weapon-wheel-track" cx={CENTER} cy={CENTER} r="164" />
          <circle className="weapon-wheel-inner-track" cx={CENTER} cy={CENTER} r="65" />

          {wheelItems.map((item, index) => {
            const step = (Math.PI * 2) / wheelItems.length;
            const middle = -Math.PI / 2 + (index + 0.5) * step;
            const label = polar(LABEL_RADIUS, middle);
            const selected = index === activeIndex;

            return (
              <g
                key={item.type}
                className={`weapon-wheel-sector${selected ? " is-active" : ""}`}
                role="menuitem"
                aria-label={`${item.title}. ${item.description || item.type}`}
                aria-current={selected ? "true" : undefined}
                tabIndex={0}
                onMouseEnter={() => setActiveIndex(index)}
                onFocus={() => setActiveIndex(index)}
                onClick={() => onPick(item.type)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onPick(item.type);
                  }
                }}
                style={{ "--sector-color": item.color } as React.CSSProperties}
              >
                <path className="weapon-wheel-sector-shape" d={sectorPath(index, wheelItems.length)} />
                <path className="weapon-wheel-sector-edge" d={sectorPath(index, wheelItems.length)} />
                <text
                  className="weapon-wheel-sector-index"
                  x={label.x}
                  y={label.y - 9}
                  textAnchor="middle"
                >
                  {String(index + 1).padStart(2, "0")}
                </text>
                <text
                  className="weapon-wheel-sector-label"
                  x={label.x}
                  y={label.y + 10}
                  textAnchor="middle"
                >
                  {item.title.length > 17 ? `${item.title.slice(0, 15)}` : item.title}
                </text>
              </g>
            );
          })}
        </svg>

        <div className="weapon-wheel-core">
          <span className="weapon-wheel-core-caption">WORKFLOW BLOCK</span>
          <b key={activeItem.type} className="weapon-wheel-core-title">
            {activeItem.title}
          </b>
          <span className="weapon-wheel-core-category">{activeItem.category}</span>
          <p>{activeItem.description || activeItem.type}</p>
          <button type="button" onClick={() => onPick(activeItem.type)}>
            ДОБАВИТЬ
          </button>
          <small>ESC  закрыть     выбор</small>
        </div>
      </div>
    </div>
  );
}