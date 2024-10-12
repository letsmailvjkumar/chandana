import { useState } from 'react';
import './App.css';

function App() {
  const [ip, setIp] = useState('');
  const [threatMessage, setThreatMessage] = useState('');
  const [analysisStats, setAnalysisStats] = useState(null);
  const [vendorResults, setVendorResults] = useState([]);
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(''); // Clear any previous errors
    setThreatMessage(''); // Clear previous threat message
    setAnalysisStats(null); // Clear previous analysis stats
    setVendorResults([]); // Clear previous vendor results

    // Basic IP validation
    const ipPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    if (!ipPattern.test(ip)) {
      setError('Please enter a valid IP address.');
      return;
    }

    try {
      const response = await fetch('http://localhost:5000/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });

      if (!response.ok) {
        // Check for specific status codes
        if (response.status === 404) {
          setError('The requested resource was not found. Please check the URL.');
          return;
        }
        throw new Error('Error fetching data');
      }

      const data = await response.json();
      console.log(data); // Log the entire response to inspect its structure

      // Accessing last_analysis_stats correctly
      const lastAnalysisStats = data.details.data.attributes.last_analysis_stats;
      setAnalysisStats(lastAnalysisStats);

      // Constructing the threat message
      const message = `Threat Detected: ${data.details.data.attributes.as_owner || 'N/A'} from ${data.details.data.attributes.continent || 'N/A'}.`;
      setThreatMessage(message);

      const lastAnalysisResults = data.details.data.attributes.last_analysis_results;
      const resultsArray = Object.entries(lastAnalysisResults).map(([vendor, result]) => ({
        vendor,
        result: result.result || 'No result',
      }));
      setVendorResults(resultsArray); // Store vendor results in state

    } catch (err) {
      // Show detailed error message from the backend if available
      if (err instanceof Error) {
        setError('Failed to detect threat, please try again'); // General error message
      } else if (err.response) {
        const errorMessage = await err.response.json();
        setError(errorMessage.error || 'Failed to detect threat, please try again');
      } else {
        setError('Failed to detect threat, please try again');
      }
    }
  };

  return (
    <div className="container">
      <h1>Threat Detection</h1>
      <form onSubmit={handleSubmit}>
        <label htmlFor="ip">Enter IP Address</label>
        <input
          type="text"
          id="ip"
          name="ip"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="e.g., 192.168.1.1"
          style={{ padding: '10px', width: '100%', marginTop: '10px' }}
        />
        <button type="submit" style={{ padding: '10px', width: '100%', marginTop: '10px' }}>
          Detect Threat
        </button>
      </form>

      {error && <div style={{ color: 'red', marginTop: '20px' }}>{error}</div>}
      {threatMessage && <div style={{ marginTop: '20px' }}>{threatMessage}</div>}
      
      {analysisStats && (
        <div style={{ marginTop: '20px' }}>
          <h2>Last Analysis Stats:</h2>
          <ul>
            <li>Harmless: {analysisStats.harmless}</li>
            <li>Malicious: {analysisStats.malicious}</li>
            <li>Suspicious: {analysisStats.suspicious}</li>
            <li>Timeout: {analysisStats.timeout}</li>
            <li>Undetected: {analysisStats.undetected}</li>
          </ul>
        </div>
      )}

      {vendorResults.length > 0 && (
        <div style={{ marginTop: '20px' }}>
          <h2>Security Vendors' Analysis</h2>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ border: '1px solid black', padding: '8px' }}>Vendor</th>
                <th style={{ border: '1px solid black', padding: '8px' }}>Result</th>
              </tr>
            </thead>
            <tbody>
              {vendorResults.map((vendorData, index) => (
                <tr key={index}>
                  <td style={{ border: '1px solid black', padding: '8px' }}>{vendorData.vendor}</td>
                  <td style={{ border: '1px solid black', padding: '8px' }}>{vendorData.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default App;
