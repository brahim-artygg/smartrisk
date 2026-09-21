// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Protected fixture: sensitive writes are guarded and fees are bounded.
contract ProtectedToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public blacklist;
    address public owner;
    address public implementation;
    uint256 public totalSupply;
    uint256 public feeBps;
    bool public paused;
    uint256 public constant MAX_FEE_BPS = 1_000;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyRole(bytes32 role) {
        require(msg.sender == owner || role == keccak256("ADMIN"), "not authorized");
        _;
    }

    function upgradeTo(address next) external onlyOwner {
        implementation = next;
    }

    function mint(address to, uint256 amount) external onlyRole(keccak256("MINTER")) {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external onlyRole(keccak256("BURNER")) {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    function setBlacklist(address account, bool value) external onlyOwner {
        blacklist[account] = value;
    }

    function setPaused(bool value) external onlyOwner {
        paused = value;
    }

    function setFeeBps(uint256 nextFeeBps) external onlyOwner {
        require(nextFeeBps <= MAX_FEE_BPS, "fee too high");
        feeBps = nextFeeBps;
    }

    function setOwner(address nextOwner) external onlyOwner {
        owner = nextOwner;
    }
}
