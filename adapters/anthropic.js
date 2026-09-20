'use strict';
// Anthropic / Claude adapter: same guard shape, action names like "claude.tool:web_search".
const { guardedTools } = require('./openai');
module.exports = { guardedTools };
