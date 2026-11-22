import { useEffect, useMemo } from "react";

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

export default function RadialMenu({ x, y, items, onPick, onClose }: Props) {
  const ring = useMemo(() => {
    const list = items.slice(0, 12);
    const n = list.length || 1;
    const radius = Math.min(132, 82 + n * 3);
    return list.map((item, index) => {
      const angle = (Math.PI * 2 * index) / n - Math.PI / 2;
      return {
        ...item,
        left: Math.cos(angle) * radius,
        top: Math.sin(angle) * radius,
        color: CATEGORY_COLOR[item.category] || "#64748b",
      };
    });
  }, [items]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="radial-menu-root" style={{ left: x, top: y }} role="menu" aria-label="Быстрые действия">
      {ring.map(item => (
        <button
          key={item.type}
          type="button"
          className="radial-menu-item"
          style={{
            transform: `translate(-50%, -50%) translate(${item.left}px, ${item.top}px)`,
            borderColor: item.color,
            boxShadow: `0 0 16px ${item.color}33`,
          }}
          title={`${item.title}\n${item.description || item.type}`}
          onClick={() => onPick(item.type)}
        >
          <b style={{ color: item.color }}>{item.title.split(" ")[0]}</b>
          <small>{item.type.split(".").pop()}</small>
        </button>
      ))}
      <div className="radial-menu-hint">Выбери блок · Esc закрыть</div>
    </div>
  );
}
