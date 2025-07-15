import React, { useState, useEffect } from 'react';

// Main App component for the network sniffer frontend
const App = () => {
  // State to store captured packets. Initially, it contains mock data.
  // Added more detailed mock payload for the detailed view.
  const [packets, setPackets] = useState([
    {
      id: 1,
      timestamp: '2025-07-15 09:30:01',
      srcIp: '192.168.1.100',
      dstIp: '8.8.8.8',
      protocol: 'TCP',
      srcPort: '54321',
      dstPort: '443',
      payloadSummary: 'HTTPS Handshake',
      fullPayload: 'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SimulatedBrowser\r\n\r\n',
      layers: {
        ethernet: { src: 'AA:BB:CC:DD:EE:F0', dst: '11:22:33:44:55:60', type: 'IPv4' },
        ip: { version: 4, headerLen: 20, ttl: 64, id: 12345, flags: 'DF' },
        tcp: { seq: 1000, ack: 2000, window: 65535, urgptr: 0, options: ['MSS', 'SACK_PERM'] }
      }
    },
    {
      id: 2,
      timestamp: '2025-07-15 09:30:02',
      srcIp: '192.168.1.1',
      dstIp: '192.168.1.100',
      protocol: 'UDP',
      srcPort: '53',
      dstPort: '12345',
      payloadSummary: 'DNS Query Response',
      fullPayload: 'DNS Response for example.com A record: 93.184.216.34',
      layers: {
        ethernet: { src: 'AA:BB:CC:DD:EE:F1', dst: '11:22:33:44:55:61', type: 'IPv4' },
        ip: { version: 4, headerLen: 20, ttl: 128, id: 54321, flags: 'DF' },
        udp: { length: 50, checksum: '0xABCD' }
      }
    },
    {
      id: 3,
      timestamp: '2025-07-15 09:30:03',
      srcIp: '10.0.0.5',
      dstIp: '10.0.0.1',
      protocol: 'ICMP',
      srcPort: '-',
      dstPort: '-',
      payloadSummary: 'Echo Request',
      fullPayload: 'ICMP Echo Request (ping)',
      layers: {
        ethernet: { src: 'AA:BB:CC:DD:EE:F2', dst: '11:22:33:44:55:62', type: 'IPv4' },
        ip: { version: 4, headerLen: 20, ttl: 64, id: 67890, flags: 'DF' },
        icmp: { type: 8, code: 0, checksum: '0xEFGH' }
      }
    },
    {
      id: 4,
      timestamp: '2025-07-15 09:30:04',
      srcIp: '192.168.1.100',
      dstIp: '172.217.160.142',
      protocol: 'TCP',
      srcPort: '54322',
      dstPort: '80',
      payloadSummary: 'HTTP GET /index.html',
      fullPayload: 'GET /index.html HTTP/1.1\r\nHost: google.com\r\nConnection: keep-alive\r\n\r\n',
      layers: {
        ethernet: { src: 'AA:BB:CC:DD:EE:F3', dst: '11:22:33:44:55:63', type: 'IPv4' },
        ip: { version: 4, headerLen: 20, ttl: 50, id: 98765, flags: 'DF' },
        tcp: { seq: 3000, ack: 4000, window: 65535, urgptr: 0, options: ['MSS'] }
      }
    },
  ]);

  // State to manage the sniffing status (e.g., 'idle', 'sniffing', 'stopped')
  const [sniffingStatus, setSniffingStatus] = useState('idle');

  // State to hold any messages or errors for the user
  const [message, setMessage] = useState('');

  // State for filtering packets
  const [filterCriteria, setFilterCriteria] = useState({
    srcIp: '',
    dstIp: '',
    protocol: '',
    srcPort: '',
    dstPort: '',
    searchTerm: '' // General search term
  });

  // State for selected packet to show details
  const [selectedPacket, setSelectedPacket] = useState(null);

  // useEffect hook to simulate real-time data fetching or WebSocket connection
  useEffect(() => {
    let intervalId;
    if (sniffingStatus === 'sniffing') {
      setMessage('Sniffing active... (simulated data)');
      intervalId = setInterval(() => {
        const newPacket = {
          id: Date.now() + Math.random(), // Use a more unique ID
          timestamp: new Date().toLocaleString(),
          srcIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
          dstIp: `10.0.0.${Math.floor(Math.random() * 255)}`,
          protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
          srcPort: Math.floor(Math.random() * (65535 - 1024) + 1024).toString(),
          dstPort: Math.floor(Math.random() * (65535 - 1024) + 1024).toString(),
          payloadSummary: `Simulated data ${Math.random().toFixed(2)}`,
          fullPayload: `This is a simulated full payload for packet ID ${Date.now() + Math.random()}. It contains more detailed information.`,
          layers: {
            ethernet: { src: 'XX:YY:ZZ:AA:BB:CC', dst: 'DD:EE:FF:GG:HH:II', type: 'IPv4' },
            ip: { version: 4, headerLen: 20, ttl: Math.floor(Math.random() * 100) + 50, id: Math.floor(Math.random() * 65535), flags: 'DF' },
            // Example for dynamic layer details based on protocol
            ...(['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)] === 'TCP' && { tcp: { seq: Math.floor(Math.random() * 10000), ack: Math.floor(Math.random() * 10000), window: 65535 } }),
            ...(['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)] === 'UDP' && { udp: { length: Math.floor(Math.random() * 100) + 20, checksum: '0x' + Math.random().toString(16).slice(2,6).toUpperCase() } }),
            ...(['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)] === 'ICMP' && { icmp: { type: Math.floor(Math.random() * 10), code: Math.floor(Math.random() * 5) } }),
          }
        };
        setPackets((prevPackets) => [newPacket, ...prevPackets].slice(0, 50)); // Keep only the last 50 packets
      }, 1000); // Add a new simulated packet every 1 second
    } else if (sniffingStatus === 'stopped') {
      setMessage('Sniffing stopped.');
    } else {
      setMessage('Ready to start sniffing.');
    }

    // Cleanup function for the interval
    return () => clearInterval(intervalId);
  }, [sniffingStatus, packets.length]); // Re-run effect when status or packet count changes

  // Function to handle starting the sniffing process
  const handleStartSniffing = () => {
    // In a real application, this would send a request to the Python backend
    // to start the actual packet capture.
    setSniffingStatus('sniffing');
    setSelectedPacket(null); // Clear any selected packet when starting
  };

  // Function to handle stopping the sniffing process
  const handleStopSniffing = () => {
    // In a real application, this would send a request to the Python backend
    // to stop the actual packet capture.
    setSniffingStatus('stopped');
  };

  // Function to handle clearing all displayed packets
  const handleClearPackets = () => {
    setPackets([]);
    setSelectedPacket(null); // Clear any selected packet
    setMessage('All packets cleared.');
  };

  // Function to handle changes in filter input fields
  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilterCriteria((prevCriteria) => ({
      ...prevCriteria,
      [name]: value.toLowerCase(), // Store filter values in lowercase for case-insensitive comparison
    }));
  };

  // Function to handle clicking on a packet row to show details
  const handlePacketClick = (packet) => {
    setSelectedPacket(packet);
  };

  // Function to close the packet details modal
  const handleCloseDetails = () => {
    setSelectedPacket(null);
  };

  // Filter and search packets based on criteria
  const filteredPackets = packets.filter((packet) => {
    const { srcIp, dstIp, protocol, srcPort, dstPort, searchTerm } = filterCriteria;

    // Check individual filters
    const matchesSrcIp = srcIp ? packet.srcIp.toLowerCase().includes(srcIp) : true;
    const matchesDstIp = dstIp ? packet.dstIp.toLowerCase().includes(dstIp) : true;
    const matchesProtocol = protocol ? packet.protocol.toLowerCase().includes(protocol) : true;
    const matchesSrcPort = srcPort ? packet.srcPort.toLowerCase().includes(srcPort) : true;
    const matchesDstPort = dstPort ? packet.dstPort.toLowerCase().includes(dstPort) : true;

    // Check general search term across all relevant fields
    const matchesSearchTerm = searchTerm ?
      Object.values(packet).some(value =>
        String(value).toLowerCase().includes(searchTerm)
      ) : true;

    return matchesSrcIp && matchesDstIp && matchesProtocol && matchesSrcPort && matchesDstPort && matchesSearchTerm;
  });

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center p-4 font-sans antialiased">
      {/* Header Section */}
      <header className="w-full max-w-6xl bg-white shadow-lg rounded-xl p-6 mb-8 mt-4">
        <h1 className="text-4xl font-extrabold text-gray-900 mb-2 text-center">
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-purple-600 to-indigo-600">
            Advanced Network Sniffer
          </span>
        </h1>
        <p className="text-lg text-gray-600 text-center">
          Capture, analyze, and filter network traffic in real-time.
        </p>
      </header>

      {/* Control Panel */}
      <section className="w-full max-w-6xl bg-white shadow-lg rounded-xl p-6 mb-8 flex flex-col sm:flex-row justify-center items-center space-y-4 sm:space-y-0 sm:space-x-6">
        <button
          onClick={handleStartSniffing}
          disabled={sniffingStatus === 'sniffing'}
          className={`px-8 py-3 rounded-full text-white font-semibold text-lg transition-all duration-300 ease-in-out
            ${sniffingStatus === 'sniffing' ? 'bg-gray-400 cursor-not-allowed' : 'bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-4 focus:ring-green-300 active:scale-95'}`}
        >
          Start Sniffing
        </button>
        <button
          onClick={handleStopSniffing}
          disabled={sniffingStatus !== 'sniffing'}
          className={`px-8 py-3 rounded-full text-white font-semibold text-lg transition-all duration-300 ease-in-out
            ${sniffingStatus !== 'sniffing' ? 'bg-gray-400 cursor-not-allowed' : 'bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-4 focus:ring-red-300 active:scale-95'}`}
        >
          Stop Sniffing
        </button>
        <button
          onClick={handleClearPackets}
          className="px-8 py-3 rounded-full bg-blue-600 text-white font-semibold text-lg hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-300 active:scale-95 transition-all duration-300 ease-in-out"
        >
          Clear Packets
        </button>
        <div className="text-lg font-medium text-gray-700">
          Status: <span className={`font-bold ${sniffingStatus === 'sniffing' ? 'text-green-600' : 'text-red-600'}`}>{message}</span>
        </div>
      </section>

      {/* Filtering and Search Section */}
      <section className="w-full max-w-6xl bg-white shadow-lg rounded-xl p-6 mb-8">
        <h2 className="text-2xl font-bold text-gray-800 mb-4">Filter & Search</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <input
            type="text"
            name="srcIp"
            placeholder="Filter Source IP"
            value={filterCriteria.srcIp}
            onChange={handleFilterChange}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition duration-200"
          />
          <input
            type="text"
            name="dstIp"
            placeholder="Filter Destination IP"
            value={filterCriteria.dstIp}
            onChange={handleFilterChange}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition duration-200"
          />
          <input
            type="text"
            name="protocol"
            placeholder="Filter Protocol (e.g., TCP, UDP)"
            value={filterCriteria.protocol}
            onChange={handleFilterChange}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition duration-200"
          />
          <input
            type="text"
            name="srcPort"
            placeholder="Filter Source Port"
            value={filterCriteria.srcPort}
            onChange={handleFilterChange}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition duration-200"
          />
          <input
            type="text"
            name="dstPort"
            placeholder="Filter Destination Port"
            value={filterCriteria.dstPort}
            onChange={handleFilterChange}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition duration-200"
          />
          <input
            type="text"
            name="searchTerm"
            placeholder="Search all fields..."
            value={filterCriteria.searchTerm}
            onChange={handleFilterChange}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200 col-span-full"
          />
        </div>
      </section>

      {/* Packet Display Area */}
      <section className="w-full max-w-6xl bg-white shadow-lg rounded-xl p-6 overflow-hidden">
        <h2 className="text-2xl font-bold text-gray-800 mb-4">Captured Packets ({filteredPackets.length} displayed)</h2>
        <div className="overflow-x-auto rounded-lg border border-gray-200">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Src Port</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Dst Port</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payload Summary</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">
                    No packets match your criteria.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((packet) => (
                  <tr
                    key={packet.id}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => handlePacketClick(packet)}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{packet.timestamp}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{packet.srcIp}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{packet.dstIp}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{packet.protocol}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{packet.srcPort}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{packet.dstPort}</td>
                    <td className="px-6 py-4 text-sm text-gray-700 max-w-xs truncate">{packet.payloadSummary}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Packet Details Modal */}
      {selectedPacket && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-75 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-2xl max-h-[90vh] overflow-y-auto relative">
            <button
              onClick={handleCloseDetails}
              className="absolute top-4 right-4 text-gray-500 hover:text-gray-800 text-2xl font-bold"
            >
              &times;
            </button>
            <h3 className="text-2xl font-bold text-gray-900 mb-4 border-b pb-2">Packet Details (ID: {selectedPacket.id})</h3>

            <div className="space-y-4">
              <div>
                <h4 className="text-lg font-semibold text-gray-800 mb-2">General Information:</h4>
                <p><span className="font-medium">Timestamp:</span> {selectedPacket.timestamp}</p>
                <p><span className="font-medium">Source IP:</span> {selectedPacket.srcIp}</p>
                <p><span className="font-medium">Destination IP:</span> {selectedPacket.dstIp}</p>
                <p><span className="font-medium">Protocol:</span> {selectedPacket.protocol}</p>
                {selectedPacket.srcPort !== '-' && <p><span className="font-medium">Source Port:</span> {selectedPacket.srcPort}</p>}
                {selectedPacket.dstPort !== '-' && <p><span className="font-medium">Destination Port:</span> {selectedPacket.dstPort}</p>}
                <p><span className="font-medium">Payload Summary:</span> {selectedPacket.payloadSummary}</p>
              </div>

              {selectedPacket.layers && (
                <div>
                  <h4 className="text-lg font-semibold text-gray-800 mb-2">Layer Details:</h4>
                  {Object.entries(selectedPacket.layers).map(([layerName, layerData]) => (
                    <div key={layerName} className="mb-3 p-3 bg-gray-50 rounded-lg border border-gray-200">
                      <h5 className="font-bold text-md text-purple-700 capitalize">{layerName} Layer:</h5>
                      {Object.entries(layerData).map(([key, value]) => (
                        <p key={`${layerName}-${key}`} className="text-sm">
                          <span className="font-medium">{key}:</span> {JSON.stringify(value)}
                        </p>
                      ))}
                    </div>
                  ))}
                </div>
              )}

              {selectedPacket.fullPayload && (
                <div>
                  <h4 className="text-lg font-semibold text-gray-800 mb-2">Full Payload:</h4>
                  <pre className="bg-gray-50 p-4 rounded-lg text-sm overflow-x-auto border border-gray-200">
                    {selectedPacket.fullPayload}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
