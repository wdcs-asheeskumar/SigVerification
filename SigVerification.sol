// SPDX-License-Identifier:MIT
pragma solidity ^0.8.20;

contract SigVerification {
    function getMessageHash(string memory _message)
        public
        pure
        returns (bytes32)
    {
        bytes32 data = keccak256(abi.encodePacked(_message));
        return (data);
    }

    function getMessageHashPrefix(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        bytes32 data = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
        );
        return data;
    }

    function recover(bytes32 _ethSignedMessageHash, bytes memory _sig)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = _split(_sig);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function _split(bytes memory _sig)
        internal
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(_sig.length == 65, "Invalid signature");

        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
    }

    function verify(
        address _signer,
        string memory _message,
        bytes memory _sig
    ) public pure returns (bool, address) {
        bytes32 messageHash = getMessageHash(_message);
        bytes32 ethSignedMessageHash = getMessageHashPrefix(messageHash);
        return (
            recover(ethSignedMessageHash, _sig) == _signer,
            recover(ethSignedMessageHash, _sig)
        );
    }
}
