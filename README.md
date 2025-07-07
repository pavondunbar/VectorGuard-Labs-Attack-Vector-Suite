
![vguard](https://github.com/user-attachments/assets/c73f23fb-1d63-42ed-b922-26b67ddd6488)

# Comprehensive Attack Vector Inventory (Updated July 2025)

## NOTE: The Attack Suite will cover all 96 core attack vectors and those attack vectors that are unique to the your unique type of contract.

## Core Vulnerabilities

### **Reentrancy Attack Vectors**
1. Basic Reentrancy Attack
2. Cross-Contract Reentrancy Attack
3. Recursive Reentrancy Attack
4. Advanced Reentrancy with Flash Loans
5. Cross-Function Reentrancy
6. State-Dependent Reentrancy
7. View Function Reentrancy
8. Delegated Call Reentrancy
9. Flash Loan Reentrancy
10. ERC721 Reentrancy Attack
11. Cross-Chain Reentrancy Attack

### **Arithmetic/Mathematical Attack Vectors**
12. Division by Zero Attack
13. Integer Overflow Attack
14. Integer Underflow Attack
15. Multiplication Overflow Attack
16. Enhanced Overflow Attack
17. Precision Loss Attack
18. Modulo Bias Attack
19. Enhanced Arithmetic Attack
20. Share Price Calculation Manipulation

### **Access Control Attack Vectors**
21. Role Escalation Attack
22. Role Renounce Attack
23. Role Hierarchy Attack
24. Role Check Bypass Attack
25. Multi-Signature Bypass Attack
26. Admin Takeover Scheduling Attack
27. Backdoor Role Escalation Attack
28. Timelock Bypass Attack
29. Front-Run Role Change Attack
30. Role Rotation Attack
31. Time-Based Admin Takeover Attack
32. Access Control Bypass via Delegate Call
33. Access Control Bypass via Low-Level Call
34. Impersonation Attack
35. tx.origin vs msg.sender Attack
36. Backdoor Access Attack
37. Signature-Based Bypass Attack

### **External Calls Attack Vectors**
38. Unprotected Function Attack
39. Unchecked External Call Attack
40. Low-Level Call Manipulation
41. Delegatecall Storage Attack
42. Enhanced Delegatecall Attack
43. External Call Reentrancy
44. Callback Function Exploitation
45. Cross-Contract State Corruption

### **MEV Attack Vectors**
46. MEV Arbitrage Attack
47. Sandwich Detection Attack
48. Front-Running Bot Attack
49. Arbitrage Bot Exploit
50. AI-Evading Sandwich Attack
51. Protocol-Specific Uniswap V4 Attack
52. AI-Evading Enhanced Sandwich
53. Cross-Chain MEV Attack

### **Storage & State Variables Attack Vectors**
54. Storage Slot Manipulation
55. State Desynchronization
56. Variable Corruption
57. Stack Overflow Attack
58. Memory Manipulation Attack
59. State Corruption via Delegatecall
60. Cross-Chain State Desynchronization
61. L2 Bridge State Manipulation

### **Gas Attack Vectors**
62. Gas Limit Attack
63. Enhanced Gas Griefing Attack
64. Gas Griefing Attack
65. Gas Limit Manipulation
66. Stealth Gas Attack
67. Gas Usage Optimization Exploitation

### **Randomness & Predictability Attack Vectors**
68. Randomness Manipulation Attack
69. Enhanced Randomness Attack
70. Block Hash Attack
71. Block Hash Manipulation
72. Timestamp Manipulation
73. Time Manipulation Attack
74. Enhanced Time Attack
75. Time-Lock Attack
76. Enhanced Time Manipulation with Admin Features

### **Logic Attack Vectors**
77. Constructor Initialization Attack
78. Enhanced Initialization Attack
79. Function Selector Attack
80. Enhanced Function Selector Attack
81. CREATE2 Deployment Attack
82. Enhanced CREATE2 Attack
83. CREATE2 Self-Destruct Attack
84. Enhanced CREATE2 Self-Destruct
85. Calldata Manipulation Attack
86. Enhanced Calldata Attack
87. Calldata Length Attack
88. Enhanced Length Attack
89. Bytecode Injection Attack
90. Enhanced Bytecode Injection
91. Bytecode Hash Attack
92. Enhanced Hash Attack
93. Opcode Manipulation Attack
94. Enhanced Opcode Attack
95. Self-Destruct Attack
96. Enhanced Self-Destruct Attack

## Cross-Chain Attack Vectors
97. Cross-Chain Message Replay Attack
98. Chain ID Confusion Attack
99. Bridge Double-Spending Attack
100. Finality Attack
101. Cross-Chain State Desynchronization
102. L2 Withdrawal Blocking
103. Cross-Chain Message Manipulation
104. Bridge State Manipulation
105. Cross-Chain Balance Manipulation

## Bridge Exploitation Vectors
106. Validator Compromise Attack
107. Mint/Burn Imbalance Attack
108. Cross-Chain MEV Attack
109. Wormhole Bridge Attack
110. Multichain Bridge Attack
111. Hop Protocol Attack
112. Synapse Protocol Attack
113. Across Bridge Attack

## Liquidity Manipulation Vectors
114. Liquidity Sandwich Attack
115. Impermanent Loss Exploit
116. Liquidity Lock Attack
117. Slippage Manipulation Attack
118. Advanced Liquidity Manipulation
119. Liquidity Drain Attack
120. AMM Pool Manipulation
121. Curve Pool Manipulation
122. Balancer Vault Attack
123. Uniswap V2 Flash Swap Attack
124. Uniswap V3 Flash Attack
125. SushiSwap Kashi Attack
126. Curve Meta Pool Attack

## Flash Loan Attack Vectors
127. Flash Loan Price Manipulation
128. Governance Token Flash Loan Attack
129. Advanced Flash Loan Attack
130. Multi-Step Flash Loan Governance Attack
131. Flash Loan Oracle Manipulation
132. Recursive Flash Loan Attack
133. Flash Loan Reentrancy Attack
134. Aave Flash Loan Attack

## Token Swap Attack Vectors
135. Price Manipulation Swap
136. Malicious Token Swap
137. Slippage Front-Running Attack
138. Swap Path Manipulation Attack

## Governance Attack Vectors
139. Governance Function Attack
140. Timelock Bypass
141. Enhanced Governance Attack with Flash Loans
142. Compound Governance Attack
143. Aragon Voting Attack
144. DAOstack Proposal Attack
145. Moloch Ragequit Attack
146. Snapshot Off-Chain Attack

## Signature/Cryptographic Attack Vectors
147. Signature Replay Attack
148. Enhanced Signature Manipulation
149. EIP-1559 Chain ID Manipulation
150. Advanced Cryptographic Attack
151. Hash Collision Exploit
152. Nonce Manipulation Attack
153. EIP-712 Signature Forgery
154. Signature Verification Bypass
155. Merkle Proof Manipulation

## Implementation/Proxy Attack Vectors
156. Malicious Implementation Attack
157. Enhanced Implementation Attack
158. Proxy Upgrade Attack
159. Enhanced Proxy Attack
160. Unauthorized Upgrade Attack

## Oracle Manipulation Vectors
161. Direct Price Manipulation
162. Flash Loan Oracle Attack
163. Advanced Oracle Manipulation
164. Chainlink Oracle Attack
165. Uniswap TWAP Attack
166. Tellor Oracle Attack
167. Band Protocol Attack
168. DIA DATA Attack
169. Oracle Price Setting

## Event/History Manipulation Vectors
170. Fake Transaction History Creation
171. Advanced Event Manipulation
172. Event Emission Attack
173. Enhanced Event Manipulation Attack

## Layer 2 Specific Vectors
174. Optimism Fraud Proof Attack
175. Arbitrum Delayed Inbox Attack
176. Polygon Checkpoint Attack
177. StarkNet L1-L2 Message Attack
178. zkSync Commit Block Attack
179. Rollup Fraud Proof Manipulation
180. Enhanced Fraud Proof Attack

## DeFi Protocol Specific Vectors
181. Compound Borrow Attack
182. Yearn Vault Attack
183. Synthetix Debt Pool Attack
184. Convex Reward Attack
185. MakerDAO CDP Attack
186. Liquity Trove Attack
187. Reflexer SAFE Attack
188. Alpaca Finance Attack

## NFT Attack Vectors
189. ERC1155 Batch Attack
190. NFT Royalty Bypass Attack
191. OpenSea Wyvern Attack
192. Rarible Royalty Attack

## Staking Attack Vectors
193. ETH2 Validator Attack
194. Lido Staking Attack
195. RocketPool Node Attack
196. StakeWise Pool Attack
197. Frax ETH Minting Attack

## Yield Farming Vectors
198. MasterChef Attack
199. PancakeSwap Farm Attack
200. SpiritSwap Farm Attack
201. QuickSwap Farm Attack
202. Tomb Finance Attack

## Insurance Protocol Vectors
203. Nexus Mutual Attack
204. Cover Protocol Attack
205. InsurAce Attack
206. Unslashed Finance Attack
207. Bright Union Attack

## Options Protocol Vectors
208. Hegic Options Attack
209. Opyn Gamma Attack
210. Premia 2.0 Attack
211. Dopex Options Attack
212. Lyra Options Attack

## Mining Pool Vectors
213. EtherMine Attack
214. F2Pool Attack
215. SparkPool Attack
216. FlexPool Attack
217. NanoPool Attack

## Token Vesting Vectors
218. Linear Vesting Attack
219. Merkle Vesting Attack
220. Time-Locked Vesting Attack
221. Sablier Stream Attack
222. LlamaPay Stream Attack

## Perpetual Protocol Vectors
223. Perpetual V1 Attack
224. Perpetual V2 Attack
225. dYdX Perpetual Attack
226. GMX Perpetual Attack
227. Gains Perpetual Attack

## Identity/Naming Vectors
228. ENS Attack
229. Unstoppable Domains Attack
230. BrightID Attack
231. Civic Identity Attack
232. Proof of Humanity Attack

## Advanced/Compound Vectors
233. Multi-Vector Simultaneous Attack
234. Cascading Failure Attack
235. System-Wide Corruption Attack
236. Emergency Drain Attack
237. Governance Emergency Attack
238. Randomized Attack Pattern
239. Phased Attack Execution
240. Targeted Attack Sequences
241. Complete Attack Suite Execution

## Honeypot Mechanism Vectors
242. Honeypot Activation Trigger
243. Sell Blocking Attack
244. Liquidity Trap Attack
245. Progressive Tax Attack
246. Exit Prevention Attack

## Specialized Token Vectors
247. Fee-on-Transfer Token Manipulation
248. Rebasing Token Manipulation
249. Pausable Token Attack
250. Blacklist Token Attack
251. Deflationary Token Attack
252. Non-Standard Token Attack

## Poison/Vanity Contract Vectors
253. Poison Contract Fake History
254. Vanity Address Manipulation
255. Advanced Vanity Contract Attack

## VM/ZK Proof Vectors
256. ZK Proof Manipulation
257. Enhanced ZK Proof Manipulation
258. Prover Compromise Attack
259. Enhanced Prover Compromise
260. VM Instruction Exploitation
261. Enhanced VM Exploit
262. State Transition Manipulation
263. Enhanced State Transition Attack

## Asset Lock/Bridge Vectors
264. Asset Lock Exploit
265. Enhanced Asset Lock Exploit
266. Bridge Exploit
267. Enhanced Bridge Exploit

## Distraction/Stealth Vectors
268. Distraction Attack
269. Complex Distraction Attack
270. Enhanced Distraction Attack

## Emergency/Orchestration Vectors
271. Ultimate Attack Orchestration
272. Complete Attack Suite
273. Emergency Vector Execution
274. Comprehensive Attack Framework

## NEWLY ADDED: Lending & Borrowing Vulnerability Vectors

### **Category Overview**
These attacks target lending and borrowing protocols, exploiting vulnerabilities in loan management, collateral handling, and debt operations. They can lead to loss of funds, unfair liquidations, and protocol insolvency.

### **Attack Vectors**
275. **Liquidation Before Default Attack** - Force liquidation before payment is due, causing premature loss of collateral
276. **Prevent Borrower Liquidation by Zeroing Collateral** - Overwrite collateral amounts to 0, preventing legitimate liquidations
277. **Close Debt Without Repayment** - Call close() with non-existent ID to decrement counter without actual repayment
278. **Exploit Paused Repayments While Liquidations Enabled** - Pause repayments but keep liquidations active, trapping borrowers
279. **Disallow Tokens to Stop Existing Operations** - Disallow tokens to halt ongoing operations without proper handling
280. **No Grace Period After Unpause** - Resume repayments and immediately liquidate without giving users time to react
281. **Liquidator Takes Collateral with Insufficient Repayment** - Liquidate with minimal repayment, taking excessive collateral
282. **Repayment Sent to Zero Address** - Delete loan data and send repayment to address(0), losing funds
283. **Force Loan Assignment** - Force assign loan to unwilling lender without consent
284. **Loan State Manipulation via Refinancing** - Cancel auction via refinancing to extend loan indefinitely
285. **Double Debt Subtraction** - Refinancing incorrectly subtracts debt twice, corrupting state
286. **Griefing with Dust Loans** - Bypass minLoanSize checks to force small loans that waste gas

## NEWLY ADDED: Liquidation Incentive Vulnerability Vectors

### **Category Overview**
These attacks exploit weaknesses in liquidation incentive mechanisms, making liquidations unprofitable or impossible. This can lead to protocol insolvency and accumulation of bad debt.

### **Attack Vectors**
287. **No Liquidation Incentive Attack** - Liquidate without sufficient rewards, making liquidation unprofitable
288. **No Incentive for Small Positions** - Create small position below gas cost threshold, preventing liquidation
289. **Profitable User Withdraws All Collateral** - User with positive PNL withdraws all collateral, leaving no incentive
290. **No Mechanism for Bad Debt** - Create insolvent position with no insurance fund to cover losses
291. **Partial Liquidation Bypasses Bad Debt** - Avoid covering bad debt via partial liquidation
292. **No Partial Liquidation Prevents Whale Liquidation** - Large position exceeds individual liquidator capacity

## NEWLY ADDED: Liquidation Denial of Service Vulnerability Vectors

### **Category Overview**
These attacks prevent liquidations from occurring through various DoS techniques and state manipulation. They can make the protocol unusable and allow unhealthy positions to remain active.

### **Attack Vectors**
293. **Many Small Positions DoS Attack** - Create many small positions to cause OOG revert during liquidation
294. **Multiple Positions Corruption** - Corrupt EnumerableSet ordering to prevent liquidation
295. **Front-Run Prevention Attack** - Change nonce or perform small self-liquidation to block liquidation
296. **Pending Action Prevention** - Pending withdrawals equal to balance force liquidation reverts
297. **Malicious Callback Prevention** - onERC721Received or ERC20 hooks revert during liquidation
298. **Yield Vault Collateral Hiding** - Hide collateral in external vaults during liquidation
299. **Insurance Fund Insufficient** - Bad debt exceeding insurance fund prevents liquidation
300. **Fixed Bonus Insufficient Collateral** - 110% bonus fails when collateral ratio < 110%
301. **Non-18 Decimal Reverts** - Incorrect decimal handling causes liquidation failure
302. **Multiple NonReentrant Modifiers** - Complex liquidation paths hit multiple reentrancy guards
303. **Zero Value Transfer Reverts** - Missing zero checks with tokens that revert on zero transfer
304. **Token Deny List Reverts** - USDC-style blocklists prevent liquidation token transfers
305. **Single Borrower Edge Case** - Protocol incorrectly assumes > 1 borrower for liquidation

## NEWLY ADDED: Liquidation Calculation Vulnerability Vectors

### **Category Overview**
These attacks exploit mathematical errors and precision issues in liquidation calculations. They can lead to incorrect rewards, unfair fees, and economic inefficiencies.

### **Attack Vectors**
306. **Incorrect Liquidator Reward** - Decimal precision errors make rewards too small/large
307. **Unprioritized Liquidator Reward** - Other fees paid first, removing liquidation incentive
308. **Excessive Protocol Fee** - 30%+ fees on seized collateral make liquidation unprofitable
309. **Missing Liquidation Fees in Requirements** - Minimum collateral doesn't account for liquidation costs
310. **Unaccounted Yield/PNL** - Earned yield or positive PNL not included in collateral value
311. **No Swap Fee During Liquidation** - Protocol loses fees when liquidation involves swaps
312. **Oracle Sandwich Self-Liquidation** - Users trigger price updates for profitable self-liquidation

## NEWLY ADDED: Unfair Liquidation Vulnerability Vectors

### **Category Overview**
These attacks create unfair liquidation scenarios that harm users or benefit attackers. They exploit timing issues, state inconsistencies, and protocol design flaws.

### **Attack Vectors**
313. **Missing L2 Sequencer Grace Period** - Users liquidated immediately when sequencer restarts
314. **Interest Accumulates While Paused** - Users liquidated for interest accrued during pause
315. **Repayment Paused, Liquidation Active** - Users prevented from avoiding liquidation
316. **Late Interest/Fee Updates** - isLiquidatable checks stale values
317. **Lost Positive PNL/Yield** - Profitable positions lose gains during liquidation
318. **Unhealthier Post-Liquidation State** - Liquidator cherry-picks stable collateral
319. **Corrupted Collateral Priority** - Liquidation order doesn't match risk profile
320. **Borrower Replacement Misattribution** - Original borrower repays new owner's debt
321. **No LTV Gap** - Users liquidatable immediately after borrowing
322. **Interest During Auction** - Borrowers accrue interest while being auctioned
323. **No Liquidation Slippage Protection** - Liquidators can't specify minimum acceptable rewards

## NEWLY ADDED: Staking & Reward Vulnerability Vectors

### **Category Overview**
These attacks target staking protocols and reward distribution mechanisms. They can lead to unfair reward distribution, precision loss, and economic manipulation.

### **Attack Vectors**
324. **Front-Running First Deposit** - Attacker steals initial WETH rewards via sandwich attack
325. **Reward Dilution via Direct Transfer** - Sending tokens directly increases totalSupply without staking
326. **Precision Loss in Reward Calculation** - Small stakes or frequent updates cause rewards to round to zero
327. **Flash Deposit/Withdraw Griefing** - Large instant deposits dilute rewards for existing stakers
328. **Update Not Called After Reward Distribution** - Stale index causes incorrect reward calculations
329. **Balance Caching Issues** - Claiming updates cached balance incorrectly

## NEWLY ADDED: Auction Manipulation Vulnerability Vectors

### **Category Overview**
These attacks manipulate auction mechanisms for unfair advantage. They can lead to auction manipulation, unfair timing, and protocol exploitation.

### **Attack Vectors**
330. **Self-Bidding to Reset Auction** - Buying own loan to restart auction timer
331. **Auction Start During Sequencer Downtime** - L2 sequencer issues affect auction timing
332. **Insufficient Auction Length Validation** - Very short auctions (1 second) allow immediate seizure
333. **Auction Can Be Seized During Active Period** - Off-by-one error in timestamp check

## NEWLY ADDED: Concentrated Liquidity Manager Vulnerability Vectors

### **Category Overview**
These attacks target concentrated liquidity protocols and TWAP mechanisms. They can lead to unfavorable liquidity deployment, rug pulls, and token loss.

### **Attack Vectors**
334. **Forced Unfavorable Liquidity Deployment** - Missing TWAP checks allow draining via sandwich attacks
335. **Owner Rug-Pull via TWAP Parameters** - Setting ineffective maxDeviation/twapInterval disables protection
336. **Tokens Permanently Stuck** - Rounding errors accumulate tokens that can never be withdrawn
337. **Stale Token Approvals** - Router updates don't revoke previous approvals
338. **Retrospective Fee Application** - Updated fees apply to previously earned rewards
