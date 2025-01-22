import React, { useState } from "react"
import "./App.css"

const operations = [
  { id: "encryption", name: "Encryption" },
  { id: "decryption", name: "Decryption" },
  { id: "hashing", name: "Hashing" },
]

const algorithms = {
  encryption: ["Base64", "Caesar Cipher", "Monoalphabetic Substitution Cipher", "Vigenère Cipher", "DES", "AES", "RSA"],
  decryption: ["Base64", "Caesar Cipher", "Monoalphabetic Substitution Cipher", "Vigenère Cipher", "DES", "AES", "RSA"],
  hashing: ["MD5", "SHA-1", "SHA-256", "SHA-512"],
}

export default function CryptographyTool() {
  const [step, setStep] = useState(1)
  const [operation, setOperation] = useState("")
  const [algorithm, setAlgorithm] = useState("")
  const [input, setInput] = useState("")
  const [key, setKey] = useState("")
  const [result, setResult] = useState("")
  const [shift, setShift] = useState(0)
  const [direction, setDirection] = useState("right")
  const [decryptionMethod, setDecryptionMethod] = useState("shift")
  const [rsaKeyOption, setRsaKeyOption] = useState("new")
  const [rsaPublicKeyFile, setRsaPublicKeyFile] = useState(null)
  const [rsaPrivateKeyFile, setRsaPrivateKeyFile] = useState(null)
  const [rsaInputFile, setRsaInputFile] = useState(null)
  const [aesKeyOption, setAesKeyOption] = useState("new")
  const [aesKeyFile, setAesKeyFile] = useState(null)
  const [aesInputFile, setAesInputFile] = useState(null)

  const handleOperationSelect = (selectedOperation) => {
    setOperation(selectedOperation)
  }

  const handleAlgorithmSelect = (selectedAlgorithm) => {
    setAlgorithm(selectedAlgorithm)
  }

  const handleNext = () => {
    if (step === 1 && operation) {
      setStep(2)
    } else if (step === 2 && algorithm) {
      setStep(3)
    }
  }

  const handleBack = () => {
    if (step > 1) {
      setStep(step - 1)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const formData = new FormData()
    formData.append("operation", operation)
    formData.append("algorithm", algorithm)
    formData.append("input", input)
    formData.append("key", key)
    formData.append("shift", shift)
    formData.append("direction", direction)
    formData.append("decryptionMethod", decryptionMethod)
    formData.append("rsaKeyOption", rsaKeyOption)
    formData.append("aesKeyOption", aesKeyOption)

    if (algorithm === "RSA") {
      if (operation === "encryption") {
        if (rsaKeyOption === "existing") {
          formData.append("rsaPublicKeyFile", rsaPublicKeyFile)
        }
      } else if (operation === "decryption") {
        formData.append("rsaInputFile", rsaInputFile)
        formData.append("rsaPrivateKeyFile", rsaPrivateKeyFile)
      }
    }

    if (algorithm === "AES") {
      if (operation === "encryption") {
        if (aesKeyOption === "existing") {
          formData.append("aesKeyFile", aesKeyFile)
        }
      } else if (operation === "decryption") {
        formData.append("aesInputFile", aesInputFile)
        formData.append("aesKeyFile", aesKeyFile)
      }
    }

    try {
      const response = await fetch("/api/crypto", {
        method: "POST",
        body: formData,
      })
      const data = await response.json()
      setResult(data.result)
      setStep(4)
    } catch (error) {
      console.error("Error:", error)
      setResult("An error occurred")
      setStep(4)
    }
  }

  const renderAlgorithmFields = () => {
    switch (algorithm) {
      case "Caesar Cipher":
        return (
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
        )
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
          )
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
          )
        }
        break
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
          )
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
          )
        }
        break
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
        )
      default:
        return null
    }
  }

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
              {algorithms[operation].map((alg) => (
                <div key={alg} className="radio-option">
                  <input
                    type="radio"
                    id={alg}
                    name="algorithm"
                    value={alg}
                    checked={algorithm === alg}
                    onChange={() => handleAlgorithmSelect(alg)}
                    className="radio-input"
                  />
                  <label htmlFor={alg}>{alg}</label>
                </div>
              ))}
            </div>
            <button onClick={handleNext} className="next-button" disabled={!algorithm}>
              Next
            </button>
          </div>
        )}

        {step === 3 && (
          <form onSubmit={handleSubmit} className="form-container">
            {(algorithm !== "AES" || (algorithm === "AES" && operation === "encryption")) && (
              <textarea
                placeholder={`Enter text to ${operation}`}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="input-textarea"
                required
              />
            )}
            {renderAlgorithmFields()}
            <button type="submit" className="process-button">
              Process
            </button>
          </form>
        )}

        {step === 4 && (
          <div className="result-container">
            <h3 className="result-title">Result:</h3>
            <pre className="result">{result}</pre>
            <button
              onClick={() => {
                setStep(1)
                setOperation("")
                setAlgorithm("")
                setInput("")
                setKey("")
                setResult("")
                setShift(0)
                setDirection("right")
                setDecryptionMethod("shift")
                setRsaKeyOption("new")
                setRsaPublicKeyFile(null)
                setRsaPrivateKeyFile(null)
                setRsaInputFile(null)
                setAesKeyOption("new")
                setAesKeyFile(null)
                setAesInputFile(null)
              }}
              className="start-over-button"
            >
              Start Over
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

