'use strict';

const application = require('./src/application');

if (require.main === module) {
  application.startWebUI();
}

module.exports = application;
