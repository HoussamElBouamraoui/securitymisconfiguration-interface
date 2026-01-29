import { useState, useRef, useEffect } from 'react';

interface TerminalLine {
  type: 'input' | 'output' | 'error' | 'success' | 'info';
  content: string;
  timestamp: Date;
}

interface TerminalProps {
  onCommand: (command: string) => void;
  lines: TerminalLine[];
  isProcessing?: boolean;
}

export function Terminal({ onCommand, lines, isProcessing = false }: TerminalProps) {
  const [input, setInput] = useState('');
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  // Auto-scroll vers le bas
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !isProcessing) {
      onCommand(input.trim());
      setInput('');
    }
  };
  
  const handleTerminalClick = () => {
    inputRef.current?.focus();
  };
  
  return (
    <div 
      className="bg-[#0d1117] text-[#c9d1d9] font-mono text-sm rounded-lg border border-[#30363d] h-full flex flex-col"
      onClick={handleTerminalClick}
    >
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-[#30363d] bg-[#161b22]">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-[#ff5f56]"></div>
          <div className="w-3 h-3 rounded-full bg-[#ffbd2e]"></div>
          <div className="w-3 h-3 rounded-full bg-[#27c93f]"></div>
        </div>
        <span className="text-xs text-[#7d8590] ml-2">Pentest Assistant Terminal</span>
      </div>
      
      {/* Output */}
      <div className="flex-1 overflow-auto p-4 space-y-1">
        {lines.map((line, index) => (
          <div key={index} className="flex gap-2">
            <span className="text-[#7d8590] select-none text-xs mt-0.5">
              {line.timestamp.toLocaleTimeString()}
            </span>
            <div className="flex-1">
              {line.type === 'input' && (
                <div className="flex gap-2">
                  <span className="text-[#58a6ff]">$</span>
                  <span className="text-[#c9d1d9]">{line.content}</span>
                </div>
              )}
              {line.type === 'output' && (
                <span className="text-[#8b949e]">{line.content}</span>
              )}
              {line.type === 'error' && (
                <span className="text-[#f85149]">✗ {line.content}</span>
              )}
              {line.type === 'success' && (
                <span className="text-[#3fb950]">✓ {line.content}</span>
              )}
              {line.type === 'info' && (
                <span className="text-[#58a6ff]">ℹ {line.content}</span>
              )}
            </div>
          </div>
        ))}
        {isProcessing && (
          <div className="flex gap-2">
            <span className="text-[#7d8590] select-none text-xs mt-0.5">
              {new Date().toLocaleTimeString()}
            </span>
            <div className="flex gap-1">
              <span className="text-[#58a6ff] animate-pulse">●</span>
              <span className="text-[#8b949e]">Scan en cours...</span>
            </div>
          </div>
        )}
        <div ref={terminalEndRef} />
      </div>
      
      {/* Input */}
      <form onSubmit={handleSubmit} className="border-t border-[#30363d] p-4">
        <div className="flex gap-2 items-center">
          <span className="text-[#58a6ff]">$</span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isProcessing}
            className="flex-1 bg-transparent outline-none text-[#c9d1d9] placeholder-[#7d8590] disabled:opacity-50"
            placeholder={isProcessing ? "Scan en cours..." : "Entrez une commande (ex: scan example.com)"}
            autoFocus
          />
        </div>
      </form>
    </div>
  );
}

export type { TerminalLine };
