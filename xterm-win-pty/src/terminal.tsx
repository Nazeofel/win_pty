// src/components/Terminal.tsx
import { invoke } from '@tauri-apps/api/core';
import { useEffect, useRef, useState } from 'react';
import 'xterm/css/xterm.css';

export function TerminalView() {
  const [inputValue, setInputValue] = useState('');
  const myRef = useRef<HTMLInputElement | null>(null);

  const handleInputChange = (event: any) => {   
    setInputValue(event.target.value);
  }



  useEffect(() => {
   invoke('start_terminal');

  }, []);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      console.log('Input value:', inputValue);
      invoke('send_pty_cmd', { cmd: inputValue }).then((response: any) => {  console.log('Response from Rust:', response) });
      setInputValue('');
    }
  };

  return (
    <main>
      <h1>Terminal</h1>
      <input
        ref={myRef}
        type="text"
        value={inputValue}
        id="my_input"
        onChange={handleInputChange}
        onKeyDown={handleKeyDown}
      />
    </main>
  );
}