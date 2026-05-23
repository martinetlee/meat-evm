"""Unit tests for decoding — no API calls needed."""
from __future__ import annotations
from meat.decode import (
    compute_selector, decode_erc20_transfer, decode_approval,
    decode_weth_event, format_value, TRANSFER_TOPIC, APPROVAL_TOPIC,
    WETH_DEPOSIT_TOPIC, WETH_WITHDRAWAL_TOPIC,
)


def test_compute_selector_transfer():
    sel = compute_selector("transfer(address,uint256)")
    assert sel == "0xa9059cbb"


def test_compute_selector_approve():
    sel = compute_selector("approve(address,uint256)")
    assert sel == "0x095ea7b3"


def test_transfer_topic_correct():
    assert TRANSFER_TOPIC.startswith("0xddf252ad")


def test_approval_topic_correct():
    assert APPROVAL_TOPIC.startswith("0x8c5be1e5")


def test_decode_erc20_transfer():
    log = {
        "topics": [
            TRANSFER_TOPIC,
            "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "address": "0x6b175474e89094c44da98b954eedeac495271d0f",
    }
    result = decode_erc20_transfer(log)
    assert result is not None
    assert result["type"] == "transfer"
    assert result["from"] == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert result["to"] == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert result["amount_raw"] == "1000000000000000000"
    assert result["token_address"] == "0x6b175474e89094c44da98b954eedeac495271d0f"


def test_decode_approval():
    log = {
        "topics": [
            APPROVAL_TOPIC,
            "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        "data": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "address": "0x6b175474e89094c44da98b954eedeac495271d0f",
    }
    result = decode_approval(log)
    assert result is not None
    assert result["type"] == "approval"
    assert result["owner"] == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert result["spender"] == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_decode_weth_deposit():
    log = {
        "topics": [
            WETH_DEPOSIT_TOPIC,
            "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    }
    result = decode_weth_event(log)
    assert result is not None
    assert result["type"] == "weth_deposit"
    assert result["note"] == "ETH wrapped to WETH"


def test_decode_weth_withdrawal():
    log = {
        "topics": [
            WETH_WITHDRAWAL_TOPIC,
            "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    }
    result = decode_weth_event(log)
    assert result is not None
    assert result["type"] == "weth_withdrawal"


def test_format_value_18_decimals():
    assert format_value(1000000000000000000, 18) == "1.0"
    assert format_value(30000000000000000000000000, 18) == "30000000.0"


def test_format_value_6_decimals():
    assert format_value(1000000, 6) == "1.0"
    assert format_value(2300000000000, 6) == "2300000.0"


def test_format_value_zero():
    assert format_value(0, 18) == "0.0"


def test_non_transfer_log_returns_none():
    log = {
        "topics": ["0x0000000000000000000000000000000000000000000000000000000000000000"],
        "data": "0x",
        "address": "0x0000000000000000000000000000000000000000",
    }
    assert decode_erc20_transfer(log) is None
    assert decode_approval(log) is None
    assert decode_weth_event(log) is None
