const tldts = require('tldts')
const Trackers = require('./privacy-grade.js')
const utils = require('./utils')
module.exports = new Trackers({ tldjs: tldts, utils })