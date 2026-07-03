package express

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "query", ArgIndex: 0},
	{FuncName: "knex.raw", ArgIndex: 0},
	{FuncName: "sequelize.query", ArgIndex: 0},
	{FuncName: "db.query", ArgIndex: 0},
	{FuncName: "res.redirect", ArgIndex: 0},
	{FuncName: "res.send", ArgIndex: 0},
	{FuncName: "res.render", ArgIndex: 1},
	{FuncName: "child_process.exec", ArgIndex: 0},
	{FuncName: "exec", ArgIndex: 0},
	{FuncName: "execSync", ArgIndex: 0},
	{FuncName: "spawn", ArgIndex: 0},
	{FuncName: "axios.get", ArgIndex: 0},
	{FuncName: "fetch", ArgIndex: 0},
	{FuncName: "fs.readFile", ArgIndex: 0},
	{FuncName: "fs.createReadStream", ArgIndex: 0},
}
