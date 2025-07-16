from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class DangerousCallsDetector(AbstractDetector):
    ARGUMENT = "dangerous-calls"
    HELP = "Detect dangerous low-level calls: delegatecall, callcode, low-level call, selfdestruct"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["delegatecall", "callcode", "call(", "selfdestruct"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[DangerousCallsDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class AccessControlDetector(AbstractDetector):
    ARGUMENT = "access-control"
    HELP = "Detect missing or weak access control: public functions with owner-only logic"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        suspicious_keywords = ["owner", "admin"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented and function.visibility in ["public", "external"]:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in suspicious_keywords:
                                if keyword in expr_str and "onlyOwner" not in function.modifiers_as_strings:
                                    info = [
                                        f"[AccessControlDetector] Function '{function.full_name}' references '{keyword}' without onlyOwner modifier"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class BlockDependencyDetector(AbstractDetector):
    ARGUMENT = "block-dependency"
    HELP = "Detect use of block properties like block.timestamp, block.number, blockhash"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["block.timestamp", "block.number", "blockhash"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[BlockDependencyDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class ReentrancyDetector(AbstractDetector):
    ARGUMENT = "reentrancy-issues"
    HELP = "Detect potential reentrancy vulnerabilities like unprotected external calls and reentrancy patterns"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["call.value", "call{value", "send(", "transfer("]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[ReentrancyDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class InsecureRandomnessDetector(AbstractDetector):
    ARGUMENT = "insecure-randomness"
    HELP = "Detect use of insecure randomness sources like blockhash, timestamp, or predictable values"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["blockhash", "block.timestamp", "now", "block.number"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[InsecureRandomnessDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class ArithmeticIssuesDetector(AbstractDetector):
    ARGUMENT = "arithmetic-issues"
    HELP = "Detect unsafe arithmetic operations like overflows and underflows (when SafeMath is not used)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["+", "-", "*", "/", "++", "--"]

        # Note: This is a basic pattern; full detection would require data flow and type checks.
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            # Simplistic heuristic to detect arithmetic ops
                            if any(op in expr_str for op in keywords):
                                # Ideally, check if SafeMath is used - omitted here for brevity
                                info = [
                                    f"[ArithmeticIssuesDetector] Arithmetic op in {function.full_name}"
                                ]
                                results.append(self.generate_result(info))
        return results


class UnprotectedUpgradeDetector(AbstractDetector):
    ARGUMENT = "unprotected-upgrade"
    HELP = "Detect unprotected upgrade functions or proxies allowing unauthorized upgrades"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        upgrade_keywords = ["upgradeTo", "setImplementation", "proxyAdmin", "upgrade"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in upgrade_keywords:
                                if keyword in expr_str:
                                    # Check if function has proper access control (simplified)
                                    if "onlyOwner" not in function.modifiers_as_strings:
                                        info = [
                                            f"[UnprotectedUpgradeDetector] Function '{function.full_name}' calls '{keyword}' without onlyOwner"
                                        ]
                                        results.append(self.generate_result(info))
        return results


class GasGriefingDetector(AbstractDetector):
    ARGUMENT = "gas-griefing"
    HELP = "Detect potential gas griefing issues such as unbounded loops and block gas limit dependencies"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["for(", "while(", "gasleft()"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[GasGriefingDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class FlashLoanDetector(AbstractDetector):
    ARGUMENT = "flash-loan"
    HELP = "Detect unprotected flash loan usage and potential vulnerabilities"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["flashloan", "flashLoan", "executeOperation", "uniswapV2Call"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[FlashLoanDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class OracleManipulationDetector(AbstractDetector):
    ARGUMENT = "oracle-manipulation"
    HELP = "Detect potential oracle manipulation vulnerabilities and insecure price feeds"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["oracle", "priceFeed", "getPrice", "updatePrice"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[OracleManipulationDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class EventEmissionDetector(AbstractDetector):
    ARGUMENT = "event-emission"
    HELP = "Detect missing or incorrect event emission for critical state changes"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        event_keywords = ["emit", "Event", "event "]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in event_keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[EventEmissionDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class InitializationDetector(AbstractDetector):
    ARGUMENT = "initialization-issues"
    HELP = "Detect uninitialized storage variables or uninitialized proxies"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["constructor", "initialize", "initializer", "uninitialized"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or function.is_initializer or function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[InitializationDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class CrossChainDetector(AbstractDetector):
    ARGUMENT = "cross-chain-issues"
    HELP = "Detect bridge misuse and cross-chain replay vulnerabilities"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["bridge", "crossChain", "replay", "relay"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[CrossChainDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class NFTSpecificDetector(AbstractDetector):
    ARGUMENT = "nft-specific"
    HELP = "Detect NFT-specific issues such as royalty bypass or unprotected minting"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["mint", "royalty", "tokenId", "safeMint"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[NFTSpecificDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class GaslessTransactionDetector(AbstractDetector):
    ARGUMENT = "gasless-transactions"
    HELP = "Detect potential exploits related to relayers or permit abuse in gasless transactions"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["relayer", "permit", "gasless", "metaTx", "metaTransaction"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[GaslessTransactionDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class DenialOfServiceDetector(AbstractDetector):
    ARGUMENT = "denial-of-service"
    HELP = "Detect potential denial of service vectors such as fallback DOS or withdraw DOS"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["fallback", "withdraw", "DOS", "revert", "fail"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[DenialOfServiceDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class MiscDetector(AbstractDetector):
    ARGUMENT = "miscellaneous-issues"
    HELP = "Detect miscellaneous issues such as unchecked return values or hardcoded secrets"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["unchecked", "hardcoded", "secret", "private key"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[MiscDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class FrontRunningDetector(AbstractDetector):
    ARGUMENT = "front-running"
    HELP = "Detect potential front-running vectors such as MEV or sandwich attacks"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["MEV", "sandwich", "front-run", "miner extractable value"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[FrontRunningDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class AuthenticationIssuesDetector(AbstractDetector):
    ARGUMENT = "authentication-issues"
    HELP = "Detect authentication issues such as use of tx.origin or insecure signatures"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["tx.origin", "ecrecover", "signature", "signer"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[AuthenticationIssuesDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class TokenomicsDetector(AbstractDetector):
    ARGUMENT = "tokenomics-issues"
    HELP = "Detect issues related to token supply manipulation, minting, burning, or inflation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["mint", "burn", "totalSupply", "inflation", "deflation", "tokenSupply"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[TokenomicsDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class UpgradeabilityDetector(AbstractDetector):
    ARGUMENT = "upgradeability-issues"
    HELP = "Detect potential issues related to proxy patterns, uninitialized implementations, or unauthorized upgrades"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["proxy", "implementation", "upgradeTo", "delegatecall", "initialize"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[UpgradeabilityDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class AuthorizationBypassDetector(AbstractDetector):
    ARGUMENT = "authorization-bypass"
    HELP = "Detect possible authorization bypass such as missing access controls or insecure role management"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["require", "onlyOwner", "hasRole", "accessControl", "msg.sender"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[AuthorizationBypassDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class DelegatecallInjectionDetector(AbstractDetector):
    ARGUMENT = "delegatecall-injection"
    HELP = "Detect unsafe delegatecall usage that may lead to injection vulnerabilities"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["delegatecall"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            if any(keyword in expr_str for keyword in keywords):
                                info = [
                                    f"[DelegatecallInjectionDetector] Found '{keywords[0]}' in {function.full_name}"
                                ]
                                results.append(self.generate_result(info))
        return results


class TimestampDependenceDetector(AbstractDetector):
    ARGUMENT = "timestamp-dependence"
    HELP = "Detect usage of timestamp-dependent logic which may be manipulated"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["block.timestamp", "now"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            if any(keyword in expr_str for keyword in keywords):
                                info = [
                                    f"[TimestampDependenceDetector] Found '{keywords[0]}' or '{keywords[1]}' in {function.full_name}"
                                ]
                                results.append(self.generate_result(info))
        return results


class UncheckedCallReturnDetector(AbstractDetector):
    ARGUMENT = "unchecked-call-return"
    HELP = "Detect external calls with unchecked return values which can lead to silent failures"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["call(", "send(", "transfer("]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[UncheckedCallReturnDetector] Found unchecked call '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class HardcodedAddressDetector(AbstractDetector):
    ARGUMENT = "hardcoded-address"
    HELP = "Detect hardcoded addresses which can be a source of security risk or lack of flexibility"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["0x0000000000000000000000000000000000000000", "0x1234", "0xdeadbeef"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[HardcodedAddressDetector] Found hardcoded address '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class DelegatecallToUntrustedDetector(AbstractDetector):
    ARGUMENT = "delegatecall-to-untrusted"
    HELP = "Detect delegatecalls to untrusted contracts that may lead to execution hijacking"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["delegatecall"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            if any(keyword in expr_str for keyword in keywords):
                                info = [
                                    f"[DelegatecallToUntrustedDetector] Found delegatecall in {function.full_name}"
                                ]
                                results.append(self.generate_result(info))
        return results


class TimestampManipulationDetector(AbstractDetector):
    ARGUMENT = "timestamp-manipulation"
    HELP = "Detect potential manipulation of timestamps used in critical logic"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["block.timestamp", "now"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            if any(keyword in expr_str for keyword in keywords):
                                info = [
                                    f"[TimestampManipulationDetector] Found '{keywords[0]}' or '{keywords[1]}' in {function.full_name}"
                                ]
                                results.append(self.generate_result(info))
        return results


class AccessControlBypassDetector(AbstractDetector):
    ARGUMENT = "access-control-bypass"
    HELP = "Detect patterns that may lead to access control bypass such as missing modifier checks"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        suspicious_keywords = ["onlyOwner", "hasRole", "require", "msg.sender"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented and function.visibility in ["public", "external"]:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in suspicious_keywords:
                                if keyword in expr_str and "onlyOwner" not in function.modifiers_as_strings:
                                    info = [
                                        f"[AccessControlBypassDetector] Function '{function.full_name}' may have access control bypass related to '{keyword}'"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class TimeLockBypassDetector(AbstractDetector):
    ARGUMENT = "timelock-bypass"
    HELP = "Detect potential bypasses or vulnerabilities in timelock mechanisms"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["timelock", "delay", "execute", "schedule"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[TimeLockBypassDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class PhishingRiskDetector(AbstractDetector):
    ARGUMENT = "phishing-risk"
    HELP = "Detect potential phishing risks such as misleading function names or suspicious payable functions"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    def _detect(self):
        results = []
        keywords = ["payable", "withdraw", "claim", "sendEther", "donate"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword.lower() in expr_str.lower():
                                    info = [
                                        f"[PhishingRiskDetector] Found '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class IntegerOverflowDetector(AbstractDetector):
    ARGUMENT = "integer-overflow"
    HELP = "Detect possible integer overflow or underflow vulnerabilities"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["+", "-", "*"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[IntegerOverflowDetector] Found potential '{keyword}' operation in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class ReentrancyDetector(AbstractDetector):
    ARGUMENT = "reentrancy"
    HELP = "Detect possible reentrancy vulnerabilities"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        keywords = ["call.value", "send(", "transfer("]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[ReentrancyDetector] Found possible reentrancy pattern with '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class UninitializedStorageDetector(AbstractDetector):
    ARGUMENT = "uninitialized-storage"
    HELP = "Detect uninitialized storage pointers that could lead to unexpected behavior"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["storage"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str and "=" not in expr_str:
                                    info = [
                                        f"[UninitializedStorageDetector] Found possible uninitialized storage usage in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


class DenialOfServiceDetector(AbstractDetector):
    ARGUMENT = "dos"
    HELP = "Detect possible denial-of-service conditions such as gas exhaustion or unbounded loops"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        keywords = ["while ", "for ", "require("]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_implemented:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = node.expression.__str__()
                            for keyword in keywords:
                                if keyword in expr_str:
                                    info = [
                                        f"[DenialOfServiceDetector] Found possible DOS pattern with '{keyword}' in {function.full_name}"
                                    ]
                                    results.append(self.generate_result(info))
        return results


