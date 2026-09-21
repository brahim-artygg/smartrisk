// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Minimal {
    uint256 public value;

    function setValue(uint256 next) external {
        value = next;
    }
}
