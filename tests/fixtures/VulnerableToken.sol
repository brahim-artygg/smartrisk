// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Deliberately vulnerable fixture for SmartRisk detector regression tests.
contract VulnerableToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public blacklist;
    address public owner;
    address public implementation;
    uint256 public totalSupply;
    uint256 public feeBps;
    bool public paused;

    constructor() {
        owner = msg.sender;
        balanceOf[msg.sender] = 1_000_000 ether;
        totalSupply = 1_000_000 ether;
    }

    // Vulnerable: arbitrary caller can replace the implementation.
    function upgradeTo(address next) external {
        implementation = next;
    }

    // Vulnerable: arbitrary caller can mint unlimited supply.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // Vulnerable: arbitrary caller can burn from any account.
    function burn(address from, uint256 amount) external {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    // Vulnerable: arbitrary caller can blacklist any account.
    function setBlacklist(address account, bool value) external {
        blacklist[account] = value;
    }

    // Vulnerable: arbitrary caller can pause transfers.
    function setPaused(bool value) external {
        paused = value;
    }

    // Vulnerable: arbitrary caller can set an unbounded fee.
    function setFeeBps(uint256 nextFeeBps) external {
        feeBps = nextFeeBps;
    }

    // Vulnerable: arbitrary caller can seize ownership.
    function setOwner(address nextOwner) external {
        owner = nextOwner;
    }
}
