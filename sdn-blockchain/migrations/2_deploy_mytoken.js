// migrations/2_deploy_mytoken.js
const MyToken = artifacts.require("MyToken");

module.exports = function (deployer) {
  deployer.deploy(MyToken);
};
