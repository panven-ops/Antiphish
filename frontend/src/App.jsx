import { useState } from "react"


function getVerdictColor(verdict) {

  if (verdict === "safe") {
    return "green"
  }

  if (verdict === "suspicious") {
    return "orange"
  }
  if (verdict === "dangerous"){
    return "red"
  }

  return "gray"
}


function App() {

  const [text, setText] = useState("")
  const [inputType, setInputType] = useState("email")
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")


  async function handleAnalyze() {

    try {

      setLoading(true)

      setError("")

      const response = await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          text: text,
          input_type: inputType
        })
      })

      if (!response.ok) {
        throw new Error("Failed to analyze")
      }

      const data = await response.json()

      setResult(data)

    } catch (err) {

      setError(err.message)

    } finally {

      setLoading(false)

    }
  }


  return (

    <div style={{
      padding: "40px",
      fontFamily: "Arial"
    }}>

      <h1>Phishing Scam Detector</h1>

      <textarea
        rows="10"
        cols="60"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Paste suspicious text..."
      />

      <br /><br />

      <select
        value={inputType}
        onChange={(e) => setInputType(e.target.value)}
      >
        <option value="email">Email</option>
        <option value="phone">Phone</option>
      </select>

      <br /><br />

      <button
        onClick={handleAnalyze}
        disabled={loading}
      >
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {loading && (
        <p>Checking for phishing indicators...</p>
      )}

      {error && (
        <p style={{ color: "red" }}>
          {error}
        </p>
      )}

      {result && (
        <div style={{ marginTop: "30px" }}>

          <h2 style={{
            color: getVerdictColor(result.verdict)
          }}>
            Verdict: {result.verdict}
          </h2>

          <p>Total Score: {result.total_score}</p>

          <h3>Checks</h3>

          {result.checks.map((check, index) => (
            <div
              key={index}
              style={{
                border: "1px solid gray",
                padding: "10px",
                marginBottom: "10px"
              }}
            >
              <p><strong>{check.name}</strong></p>

              <p>
                Passed: {check.passed ? "Yes" : "No"}
              </p>

              <p>Score: {check.score}</p>

              <p>{check.detail}</p>

            </div>
          ))}

        </div>
      )}

    </div>
  )

}

export default App
