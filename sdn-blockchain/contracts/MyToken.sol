// contracts/MyToken.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract MyToken {
    string public name = "MyToken";
    string public symbol = "MTK";
    uint8 public decimals = 0; // if you don't need fractional tokens
    address public owner;

    // Each address => token balance
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender; // whoever deploys the contract is owner
    }

    // Only the owner can create (mint) tokens
    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner!");
        _;
    }

    // Mint tokens for a given address
    function mint(address _to, uint256 _amount) public onlyOwner {
        balanceOf[_to] += _amount;
    }
}
