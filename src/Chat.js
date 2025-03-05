import React, { useState } from "react";

const Chat = () => {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);

  const sendMessage = () => {
    if (message.trim()) {
      setMessages([...messages, { text: message, sender: "You" }]);
      setMessage(""); // Clear input
      // TODO: Implement encryption before sending messages
    }
  };

  return (
    <div className="flex flex-col h-screen p-4">
      <h2 className="text-2xl font-bold">Secure Chat</h2>
      <div className="flex-1 overflow-auto border p-2 mt-2">
        {messages.map((msg, index) => (
          <div key={index} className="my-1">
            <strong>{msg.sender}:</strong> {msg.text}
          </div>
        ))}
      </div>
      <div className="mt-4 flex">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Type a message..."
          className="flex-1 p-2 border rounded"
        />
        <button onClick={sendMessage} className="ml-2 px-4 py-2 bg-blue-500 text-white rounded">
          Send
        </button>
      </div>
    </div>
  );
};

export default Chat;