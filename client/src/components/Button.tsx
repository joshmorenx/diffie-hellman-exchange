interface ButtonProps {
    text: string;
    onClick?: () => void;  // ← Agregar esta línea
}

export default function Button({ text, onClick }: ButtonProps) {
    return (
        <button onClick={onClick}>
            {text}
        </button>
    )
}