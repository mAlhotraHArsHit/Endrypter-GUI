import React, { useState } from "react";
import "./App.css";

const operations = [
  { id: "encryption", name: "Encryption" },
  { id: "decryption", name: "Decryption" },
  { id: "hashing", name: "Hashing" },
];

const algorithms = {
  encryption: ["Base64", "Caesar Cipher", "Monoalphabetic Substitution Cipher", "Vigenère Cipher", "DES", "AES", "RSA"],
  decryption: ["Base64", "Caesar Cipher", "Monoalphabetic Substitution Cipher", "Vigenère Cipher", "DES", "AES", "RSA"],
  hashing: ["MD5", "SHA-1", "SHA-256", "SHA-512"],
};

export default function CryptographyTool() {
  const [step, setStep] = useState(1);
  const [operation, setOperation] = useState("");
  const [algorithm, setAlgorithm] = useState("");
  const [input, setInput] = useState("");
  const [key, setKey] = useState("");
  const [result, setResult] = useState("");
  const [shift, setShift] = useState(0);
  const [direction, setDirection] = useState("right");
  const [decryptionMethod, setDecryptionMethod] = useState("shift");
  const [rsaKeyOption, setRsaKeyOption] = useState("new");
  const [rsaPublicKeyFile, setRsaPublicKeyFile] = useState(null);
  const [rsaPrivateKeyFile, setRsaPrivateKeyFile] = useState(null);
  const [rsaInputFile, setRsaInputFile] = useState(null);
  const [aesKeyOption, setAesKeyOption] = useState("new");
  const [aesKeyFile, setAesKeyFile] = useState(null);
  const [aesInputFile, setAesInputFile] = useState(null);

  const handleOperationSelect = (selectedOperation) => {
    setOperation(selectedOperation);
  };

  const handleAlgorithmSelect = (selectedAlgorithm) => {
    setAlgorithm(selectedAlgorithm);
  };

  const handleNext = () => {
    if (step === 1 && operation) {
      setStep(2);
    } else if (step === 2 && algorithm) {
      setStep(3);
    }
  };

  const handleBack = () => {
    if (step > 1) {
      setStep(step - 1);
    }
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
  
    const payload = {
      operation,
      algorithm,
      input,
      ...(algorithm === "Caesar Cipher" && {
        shift,
        direction,
        ...(operation === "decryption" && { decryptionMethod }),
      }),
      ...(algorithm === "Vigenère Cipher" && { key }),
      ...(algorithm === "RSA" && {
        ...(operation === "encryption" && rsaKeyOption === "existing" && {
          rsaPublicKeyFile: rsaPublicKeyFile ? rsaPublicKeyFile.name : null,
        }),
        ...(operation === "decryption" && {
          rsaInputFile: rsaInputFile ? rsaInputFile.name : null,
          rsaPrivateKeyFile: rsaPrivateKeyFile ? rsaPrivateKeyFile.name : null,
        }),
      }),
      ...(algorithm === "AES" && {
        ...(operation === "encryption" && aesKeyOption === "existing" && {
          aesKeyFile: aesKeyFile ? aesKeyFile.name : null,
        }),
        ...(operation === "decryption" && {
          aesInputFile: aesInputFile ? aesInputFile.name : null,
          aesKeyFile: aesKeyFile ? aesKeyFile.name : null,
        }),
      }),
    };
  
    // console.log("Payload:", payload);
  
    try {
      const response = await fetch("http://127.0.0.1:5000/crypto", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
  
      const data = await response.json();
      if (response.ok) {
        setResult(data.result);
      } else {
        console.error("Error:", data.error);
        setResult("An error occurred");
      }
      setStep(4);
    } catch (error) {
      console.error("Error:", error);
      setResult("An error occurred");
      setStep(4);
    }
  };  
  
  
  
  const renderAlgorithmFields = () => {
    switch (algorithm) {
      case "Caesar Cipher":
        return (
          <>
            {operation === "decryption" && decryptionMethod === "all" ? (
              <>
                <p className="note">This option will generate all possible combinations.</p>
              </>
            ) : (
              <>
                <div className="input-group">
                  <label htmlFor="direction">Direction:</label>
                  <select
                    id="direction"
                    value={direction}
                    onChange={(e) => setDirection(e.target.value)}
                    className="input-text"
                    required
                  >
                    {operation === "encryption" ? (
                      <>
                        <option value="right">Right shift</option>
                        <option value="left">Left shift</option>
                      </>
                    ) : (
                      <>
                        <option value="left">Left Shift</option>
                        <option value="right">Right Shift</option>
                      </>
                    )}
                  </select>
                </div>
                <div className="input-group">
                  <label htmlFor="shift">Shift:</label>
                  <input
                    type="number"
                    id="shift"
                    value={shift}
                    onChange={(e) => setShift(Number.parseInt(e.target.value))}
                    className="input-text"
                    required
                  />
                </div>
              </>
            )}

            {operation === "decryption" && (
              <div className="input-group">
                <label htmlFor="decryptionMethod">Decryption Method:</label>
                <select
                  id="decryptionMethod"
                  value={decryptionMethod}
                  onChange={(e) => setDecryptionMethod(e.target.value)}
                  className="input-text"
                  required
                >
                  <option value="shift">By shift</option>
                  <option value="all">All 26 combinations</option>
                </select>
              </div>
            )}
          </>
        );
      case "RSA":
        if (operation === "encryption") {
          return (
            <>
              <div className="input-group">
                <label htmlFor="rsaKeyOption">RSA Key Option:</label>
                <select
                  id="rsaKeyOption"
                  value={rsaKeyOption}
                  onChange={(e) => setRsaKeyOption(e.target.value)}
                  className="input-text"
                  required
                >
                  <option value="new">Create new key</option>
                  <option value="existing">Use existing key</option>
                </select>
              </div>
              {rsaKeyOption === "existing" && (
                <div className="input-group">
                  <label htmlFor="rsaPublicKeyFile">RSA Public Key File:</label>
                  <input
                    type="file"
                    id="rsaPublicKeyFile"
                    onChange={(e) => setRsaPublicKeyFile(e.target.files[0])}
                    className="input-text"
                    required
                  />
                </div>
              )}
            </>
          );
        } else if (operation === "decryption") {
          return (
            <>
              <div className="input-group">
                <label htmlFor="rsaInputFile">Encrypted File:</label>
                <input
                  type="file"
                  id="rsaInputFile"
                  onChange={(e) => setRsaInputFile(e.target.files[0])}
                  className="input-text"
                  required
                />
              </div>
              <div className="input-group">
                <label htmlFor="rsaPrivateKeyFile">RSA Private Key File:</label>
                <input
                  type="file"
                  id="rsaPrivateKeyFile"
                  onChange={(e) => setRsaPrivateKeyFile(e.target.files[0])}
                  className="input-text"
                  required
                />
              </div>
            </>
          );
        }
        break;
      case "AES":
        if (operation === "encryption") {
          return (
            <>
              <div className="input-group">
                <label htmlFor="aesKeyOption">AES Key Option:</label>
                <select
                  id="aesKeyOption"
                  value={aesKeyOption}
                  onChange={(e) => setAesKeyOption(e.target.value)}
                  className="input-text"
                  required
                >
                  <option value="new">Create new key</option>
                  <option value="existing">Use existing key</option>
                </select>
              </div>
              {aesKeyOption === "existing" && (
                <div className="input-group">
                  <label htmlFor="aesKeyFile">AES Key File:</label>
                  <input
                    type="file"
                    id="aesKeyFile"
                    onChange={(e) => setAesKeyFile(e.target.files[0])}
                    className="input-text"
                    required
                  />
                </div>
              )}
            </>
          );
        } else if (operation === "decryption") {
          return (
            <>
              <div className="input-group">
                <label htmlFor="aesInputFile">Encrypted File:</label>
                <input
                  type="file"
                  id="aesInputFile"
                  onChange={(e) => setAesInputFile(e.target.files[0])}
                  className="input-text"
                  required
                />
              </div>
              <div className="input-group">
                <label htmlFor="aesKeyFile">AES Key File:</label>
                <input
                  type="file"
                  id="aesKeyFile"
                  onChange={(e) => setAesKeyFile(e.target.files[0])}
                  className="input-text"
                  required
                />
              </div>
            </>
          );
        }
        break;
      case "Vigenère Cipher":
        return (
          <div className="input-group">
            <label htmlFor="key">Key:</label>
            <input
              type="text"
              id="key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className="input-text"
              required
            />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="cryptography-tool-container">
      <div className="cryptography-card">
        <button onClick={handleBack} className="back-button" style={{ visibility: step === 1 ? "hidden" : "visible" }}>
          Back
        </button>

        <h1 className="tool-title">Cryptography Tool</h1>

        {step === 1 && (
          <div className="step-container">
            <h2 className="step-title">Choose an operation:</h2>
            <div className="radio-group">
              {operations.map((op) => (
                <div key={op.id} className="radio-option">
                  <input
                    type="radio"
                    id={op.id}
                    name="operation"
                    value={op.id}
                    checked={operation === op.id}
                    onChange={() => handleOperationSelect(op.id)}
                    className="radio-input"
                  />
                  <label htmlFor={op.id}>{op.name}</label>
                </div>
              ))}
            </div>
            <button onClick={handleNext} className="next-button" disabled={!operation}>
              Next
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="step-container">
            <h2 className="step-title">Choose an algorithm:</h2>
            <div className="radio-group">
              {algorithms[operation].map((algo) => (
                <div key={algo} className="radio-option">
                  <input
                    type="radio"
                    id={algo}
                    name="algorithm"
                    value={algo}
                    checked={algorithm === algo}
                    onChange={() => handleAlgorithmSelect(algo)}
                    className="radio-input"
                  />
                  <label htmlFor={algo}>{algo}</label>
                </div>
              ))}
            </div>
            <button onClick={handleNext} className="next-button" disabled={!algorithm}>
              Next
            </button>
          </div>
        )}

        {step === 3 && (
          <form onSubmit={handleSubmit}>
            <div className="input-group">
              <label htmlFor="input">Input:</label>
              <textarea
                id="input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="input-text"
                rows="4"
                required
              />
            </div>
            {renderAlgorithmFields()}
            <button type="submit" className="submit-button">
              Submit
            </button>
          </form>
        )}

        {step === 4 && (
          <div className="result-container">
            <h2 className="result-title">Result:</h2>
            <textarea
              className="result-text"
              rows="4"
              value={result}
              readOnly
            />
            <button
              onClick={() => {
                setStep(1);
                setOperation("");
                setAlgorithm("");
                setInput("");
                setKey("");
                setResult("");
                setShift(0);
                setDirection("right");
                setDecryptionMethod("shift");
                setRsaKeyOption("new");
                setAesKeyOption("new");
              }}
              className="reset-button"
            >
              Reset
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
