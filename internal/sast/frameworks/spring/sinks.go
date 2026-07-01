package spring

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

// Sinks are the Spring dangerous APIs that tainted data must not reach.
// These cover SQL injection (JdbcTemplate, EntityManager), SSRF
// (RestTemplate, WebClient), deserialization (ObjectInputStream, XStream),
// XXE (DocumentBuilderFactory), open redirect (sendRedirect), command
// injection (ProcessBuilder, Runtime), and path traversal (File, Paths).
var Sinks = []frameworks.SinkPattern{
	// SQL injection sinks
	{FuncName: "jdbcTemplate.query", ArgIndex: 0},
	{FuncName: "jdbcTemplate.queryForObject", ArgIndex: 0},
	{FuncName: "jdbcTemplate.queryForList", ArgIndex: 0},
	{FuncName: "jdbcTemplate.queryForMap", ArgIndex: 0},
	{FuncName: "jdbcTemplate.update", ArgIndex: 0},
	{FuncName: "jdbcTemplate.execute", ArgIndex: 0},
	{FuncName: "entityManager.createNativeQuery", ArgIndex: 0},
	{FuncName: "createNativeQuery", ArgIndex: 0},

	// SSRF sinks
	{FuncName: "restTemplate.getForObject", ArgIndex: 0},
	{FuncName: "restTemplate.postForObject", ArgIndex: 0},
	{FuncName: "restTemplate.exchange", ArgIndex: 0},
	{FuncName: "webClient.get", ArgIndex: -1},
	{FuncName: "webClient.post", ArgIndex: -1},
	{FuncName: "RestTemplate", ArgIndex: -1},
	{FuncName: "WebClient", ArgIndex: -1},
	{FuncName: "URL.openConnection", ArgIndex: 0},
	{FuncName: "new URL", ArgIndex: 0},

	// Deserialization sinks
	{FuncName: "ObjectInputStream.readObject", ArgIndex: -1},
	{FuncName: "readObject", ArgIndex: -1},
	{FuncName: "XStream.fromXML", ArgIndex: 0},
	{FuncName: "fromXML", ArgIndex: 0},

	// XXE sinks
	{FuncName: "DocumentBuilderFactory.newDocumentBuilder", ArgIndex: -1},
	{FuncName: "DocumentBuilder.parse", ArgIndex: 0},
	{FuncName: "SAXParserFactory.newSAXParser", ArgIndex: -1},
	{FuncName: "SAXParser.parse", ArgIndex: 0},
	{FuncName: "XMLInputFactory.createXMLStreamReader", ArgIndex: 0},

	// Open redirect sinks
	{FuncName: "response.sendRedirect", ArgIndex: 0},
	{FuncName: "sendRedirect", ArgIndex: 0},
	{FuncName: "RedirectView", ArgIndex: 0},
	{FuncName: "ResponseEntity.Location", ArgIndex: -1},

	// Command injection sinks
	{FuncName: "Runtime.getRuntime", ArgIndex: -1},
	{FuncName: "Runtime.exec", ArgIndex: 0},
	{FuncName: "ProcessBuilder", ArgIndex: -1},
	{FuncName: "ProcessBuilder.start", ArgIndex: -1},

	// Path traversal sinks
	{FuncName: "new File", ArgIndex: 0},
	{FuncName: "Paths.get", ArgIndex: 0},
	{FuncName: "FileInputStream", ArgIndex: 0},
	{FuncName: "Files.readAllBytes", ArgIndex: 0},
	{FuncName: "Files.newInputStream", ArgIndex: 0},
}
