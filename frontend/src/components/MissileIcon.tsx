// Fox3 missile icon — pointed nose, body, fins, exhaust trail
export default function MissileIcon({ size = 24, color = 'currentColor', ...props }: { size?: number; color?: string;[key: string]: any }) {
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" {...props}>
            {/* Missile body — nose cone to tail */}
            <path
                d="M20.5 3.5L14 7.5L8 9L5.5 11.5L7 13L4.5 15.5L3 19.5L5 21L8.5 19.5L11 17L12.5 18.5L15 16L16.5 10L20.5 3.5Z"
                fill={color}
                fillOpacity={0.9}
                stroke={color}
                strokeWidth={1}
                strokeLinejoin="round"
            />
            {/* Fin marks */}
            <line x1="5" y1="15" x2="9" y2="11" stroke={color} strokeWidth={0.8} strokeOpacity={0.4} />
            <line x1="9" y1="19" x2="13" y2="15" stroke={color} strokeWidth={0.8} strokeOpacity={0.4} />
            {/* Exhaust flare */}
            <path d="M3.5 20.5L2 22" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeOpacity={0.5} />
            <path d="M5 21.5L4 23" stroke={color} strokeWidth={1} strokeLinecap="round" strokeOpacity={0.3} />
        </svg>
    );
}
