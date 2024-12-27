# Secure Multi-Party Computation for General Adversary Structures (Simulated Network)

WHAT:
This project contains the implementation of MPC protocols protecting against passive and actively corrupted parties, MPCProtocolPassive and MPCProtocolActive, respectively. The code is divided into code detailing the Active protocol, the Passive protocol and code used for both protocols in Active.go, Passive.go and Common.go respectively. These all have corresponding test files. The Adversary.go is a duplication of MPCProtocolActive, where we change the behaviour of some parties, to simulate the different kinds of attacks an adversary with active corruption capabilities may use. As such, the file is used within Active_test.go to ensure the robustness of the protocol. Additionally, a benchmark file can be found, which test the performance of the two main protocols and the effect on computation time for different variables. 

HOW:
Network => Parties:
To run an MPC, one needs to start the simulated network by providing the number of parties for the protocol, a secrecy structure, an adversary structure and the range of the domain, given as *big.Int. For an explanation of the structures see "https://crypto.ethz.ch/publications/files/Maurer02b.pdf" by Ueli Maurer. The network will return a slice of pointers to the now initialized parties, the number of pointers matching the number of parties parameter.  

Instructions: 
One then needs to provide the expression to be computed, in the form of a list of instructions. An instruction is either an addition or a multiplication, as these two operations can express any computation. An instruction needs a type, denoting the operation, the location of the two operands for the given operation and the number of instruction, starting from 0 up to the number of provided instructions. 

MPCProtocol: 
The parties and the instructions are then provided to the chosen MPC protocol and the result of the computation can be found in each party's "MPCResult" field.