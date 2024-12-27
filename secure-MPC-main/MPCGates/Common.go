/*
This file containts functions used by both the passive and the active MPC protocol,
as well as functions for setting up the parties and the simulated network
*/

package Gates

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// A simulation of a network
type Network struct {
	partyChannels   map[int]chan Message // The network has an incoming channel for each participating party
	outgoingChannel chan Message         // The outgoing channel is shared among all participating parties
}

// Term matrices are used in the active multiplication protocol
type TermMatrix = [][]Shares

// Shares are represented as slices
type Shares = []*big.Int

// Struct used to model secrecy and adversary structures
type Structure = [][]int

// The model of the participants of the protocol
type Party struct {
	partyNumber        int         // Number from 0 to n-1
	totalNoOfParties   int         // n
	Domain             *big.Int    // All parties agree upon this value
	secret             *big.Int    // The party's input to the protocol
	shares             []Shares    // n x k matrix, where n is the number of parties and k is the number of shares
	intermediaries     []Shares    // For holding intermediary result values
	distributionSet    Structure   // Contains the complements of all the sets in the secrecy structure
	adversaryStructure Structure   // The structure containing the potential corruptible subsets of the parties
	partitionSubset    []IndexPair // Used in the passive protocol to assign terms to the different parties
	resultBuffer       Shares
	MPCResult          *big.Int     // The result of an MPC is stored here
	incomingMessages   chan Message // Incoming messages in the network
	outgoingMessages   chan Message // Outgoing messages in the network. This channel is shared between all parties
	complaints         []Message    // Slice used to contain complaints raised in the VSS Share protocol
	termMatrices       []TermMatrix // Used to store all the shares in the multiplication protocol. Stores n term matrices of size k x k x k
	differenceSlices   []Shares     // Used to store the differences between different version of a term in the multiplication protocol
	exitCode           int          // Used for signalling various events
}

// Pair of indices for use with multiplication protocols
type IndexPair struct {
	i int
	j int
}

// Messages are passed in the network
type Message struct {
	messageType string // The type / purpose of the message
	sender      int
	receiver    int
	payload     Payload // The actual content of the message
}

type Payload struct {
	shares       Shares       // Used when sending a single slice of shares. If a single share is sent it is put at index 0 in the slice
	termMatrices []TermMatrix // Used when sending a matrix of terms for multiplication. If single matrix is sent it is put at index 0 in the slice
	shareIndex   int          // Used for indicating which share is sent when complaining or sending out verifications
	termIndex    IndexPair    // Used to indicate which term is disputed when complaining in the multiplication protocol
	accusedParty int          // Used to indicate which party is accused of sending out wrong shares
}

type Instruction struct {
	instructionType InstructionType // An instruction is either an Add or a Mult instruction
	operand1        int             // Operand 1 specifies where the first operand is located
	operand2        int             // Operand 2 specifies where the second operand is located
	instructionNo   int             // An index into the intermediaries. Is used to store the result of the instruction
}

// Returns the shares of the operand, which index is given as input.
// If the index is smaller than n, the operand is a secret share. Otherwise it is a intermediary result of another instruction than the current
func (p *Party) getOperand(index int) Shares {
	n := p.totalNoOfParties
	if index < n {
		return p.shares[index]
	} else {
		return p.intermediaries[index-n]
	}
}

// Returns the address of a factor, s_i or t_j
func (p *Party) getAddressOfFactor(indexOfShares int, indexInShares int) **big.Int {
	n := p.totalNoOfParties
	if indexOfShares < n {
		return &p.shares[indexOfShares][indexInShares]
	} else {
		return &p.intermediaries[indexOfShares-n][indexInShares]
	}
}

// Constants used in Instructions

type InstructionType int

const (
	Add InstructionType = iota
	Mult
)

const (
	InitShare            = "initShare"         // Shares of party secrets
	ResultShare          = "resultShare"       // Shares of the result of the MPC in the passive protocol
	MultShare            = "multShare"         // Shares sent in the multiplication protocol
	VerifyInit           = "verifyInit"        // Shares sent as part of the verification phase of the initial VSS share sending in the active protocol
	VerifyMult           = "verifyMult"        // Shares sent as part of the verification phase of the VSS share sending in the active multiplication protocol
	InitComplaint        = "initComplaint"     // Complaint in the complaining phase of the initial VSS share sending in the active protocol
	MultComplaint        = "multComplaint"     // Complaint in the complaining phase of the VSS share sending in the active multiplication protocol
	DisputedInitShare    = "disputedInitShare" // Response to a complaint in the initial VSS share sending in the active protocol
	DisputedMultShare    = "disputedMultShare" // Response to a complaint in the VSS share sending in the active multiplication protocol
	Reconstruct          = "reconstruct"       // A party's version of a share slice that is to be reconstructed
	ReconstructFactor    = "reconstructFactor" // A party's version of a factor that is to be reconstructed in the multiplication protocol
	Refuse               = "refuse"            // A message sent to model that an accused party ignores a complaint
	S_i                  = "s_i"               // Signals to the reconstructFactor function that s_i is to be reconstructed
	T_j                  = "t_j"               // Signals to the reconstructFactor function that t_j is to be reconstructed
	Success              = 0                   // Exit code signalling protocol succes
	Abort                = 1                   // Exit code signalling that the protocol needs to be aborted
	ReconstructNeeded    = 2                   // Exit code signalling that a reconstruction of the current term is needed
	ReconstructNotNeeded = 3                   // Exit code signalling that a reconstruction of the current term is not needed
)

// Starts a goroutine that runs the network and creates and returns the parties participating in the protocol
func startNetwork(noOfParties int, secrecyStructure Structure, adversaryStructure Structure, domain *big.Int) []*Party {
	// Check whether condition 1, the Q^2 condition, holds. Abort otherwise
	if !qSquaredConditionHolds(noOfParties, secrecyStructure) {
		panic("Error: Provided secrecy structure violates condition Q^2")
	}

	// The passive protocol does not use the adversary structure, so it can be set to nil in the passive case
	if adversaryStructure != nil {
		// Check if various conditions on the adversary structure holds. Abort otherwise
		holds, errorMsg := adversaryConditionsHold(noOfParties, secrecyStructure, adversaryStructure)
		if !holds {
			panic(errorMsg)
		}
	}

	partyChannels := make(map[int]chan Message)
	outgoingChannel := make(chan Message)
	network := Network{partyChannels: partyChannels, outgoingChannel: outgoingChannel}

	parties := make([]*Party, 0, noOfParties)
	distributionSet := createDistributionSet(noOfParties, secrecyStructure)
	partition := createPartition(noOfParties, distributionSet)

	for i := 0; i < noOfParties; i++ {
		network.addParty(&parties, i, noOfParties, distributionSet, adversaryStructure, partition[i], domain)
	}

	go network.handleTraffic()

	return parties
}

// Return true if condition 1, the Q^2 condition, holds. Returns false otherwise
func qSquaredConditionHolds(noOfParties int, secrecyStructure [][]int) bool {
	setOfParties := createSetOfParties(noOfParties)

	// compare all different unions of sets from the secrecy structure with the set of parties
	for i := range secrecyStructure {
		for j := range secrecyStructure {
			if i != j {
				union := computeUnion(secrecyStructure[i], secrecyStructure[j])
				// if the sets are equal, condition 1 does not hold
				if setsAreEqual(union, setOfParties) {
					return false
				}
			}
		}
	}
	return true
}

// Checks if an adversary structure satisfies the conditions required for correctness and secrecy
func adversaryConditionsHold(noOfParties int, ss, as Structure) (holds bool, errorMsg string) {
	// Test if adversary structure is subset of secrecy structure
	for _, aset := range as {
		aSetInSs := false
		for _, sset := range ss {
			if isSubset(aset, sset) {
				aSetInSs = true
				break
			}
		}
		if !aSetInSs {
			holds = false
			errorMsg = fmt.Sprintf("adversary structure is not subset of secrecy structure. Adversary structure has set %v which is not a subset of any set in secrecy structure", aset)
			return
		}
	}

	setOfParties := createSetOfParties(noOfParties)

	// Test condition (2) from Maurer text
	for i := range as {
		for j := range as {
			if i != j {
				for k := range ss {
					union1 := computeUnion(as[i], as[j])
					union2 := computeUnion(union1, ss[k])
					if setsAreEqual(union2, setOfParties) {
						holds = false
						errorMsg = fmt.Sprintf("adversary structure and secrecy structure does not enforce condition (2). The union of the sets %v and %v from the adversary structure together with the set %v from the secrecy structure includes all parties",
							as[i], as[j], ss[k])
						return
					}
				}
			}
		}
	}

	// Test condition (3) from Maurer text
	for i := range as {
		for j := range ss {
			for k := range ss {
				if j != k {
					union1 := computeUnion(as[i], ss[j])
					union2 := computeUnion(union1, ss[k])
					if setsAreEqual(union2, setOfParties) {
						holds = false
						errorMsg = fmt.Sprintf("adversary structure and secrecy structure does not enforce condition (3). The union of the set %v from the adversary structure together with the sets %v and %v from the secrecy structure includes all parties",
							as[i], ss[j], ss[k])
						return
					}
				}
			}
		}
	}
	holds = true
	return
}

// Checks if the first input set is a subset of the second input set
func isSubset(sub, super []int) bool {
	for _, e1 := range sub {
		ise1InSuperSet := false
		for _, e2 := range super {
			if e1 == e2 {
				ise1InSuperSet = true
				break
			}
		}
		if !ise1InSuperSet {
			return false
		}
	}
	return true
}

// Returns the union of the two input sets
func computeUnion(set1, set2 []int) (union []int) {
	setMap := make(map[int]bool)
	for _, partyIndex := range set1 {
		setMap[partyIndex] = true
	}
	for _, partyIndex := range set2 {
		setMap[partyIndex] = true
	}
	for key := range setMap {
		union = append(union, key)
	}
	return
}

// Returns the intersection of the two input sets
func computeIntersection(set1, set2 []int) (intersection []int) {
	m := make(map[int]bool)

	for _, item := range set1 {
		m[item] = true
	}

	for _, item := range set2 {
		if _, ok := m[item]; ok {
			intersection = append(intersection, item)
		}
	}
	return
}

// Checks if the two input sets contain the same elements
func setsAreEqual(a, b []int) bool {
	// Tests that the size of the sets is equal
	if len(a) != len(b) {
		return false
	}

	// Tests that all elements of a exists in b. Due to the above test, this is sufficient
	for i := range a {
		foundI := false
		for j := range b {
			if a[i] == b[j] {
				foundI = true // i exists in both sets
				break
			}
		}
		if !foundI {
			return false // i does not exist in set b
		}
	}
	return true
}

// Creates the distribution set from the secrecy structure
func createDistributionSet(noOfParties int, secrecyStructure [][]int) (distributionSet [][]int) {
	setOfParties := createSetOfParties(noOfParties)

	// Create distribution set form secrecy structure
	for _, v := range secrecyStructure {
		distributionSet = append(distributionSet, computeCompliment(setOfParties, v))
	}

	return
}

// Creates a set containing all party numbers
func createSetOfParties(noOfParties int) (setOfParties []int) {
	setOfParties = make([]int, noOfParties)
	for i := range setOfParties {
		setOfParties[i] = i
	}
	return
}

// Takes the set difference of arg a and arg b
func computeCompliment(a, b []int) (diff []int) {
	m := make(map[int]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return
}

// Creates the partition that is used for distributing the terms between the parties
func createPartition(noOfParties int, distributionSet [][]int) [][]IndexPair {

	partition := make([][]IndexPair, noOfParties)
	for i, elem1 := range distributionSet {
		for j, elem2 := range distributionSet {
			intersection := computeIntersection(elem1, elem2)
			partyIndex := intersection[0] // Take the first element. Greedy.
			partition[partyIndex] = append(partition[partyIndex], IndexPair{i: i, j: j})
		}
	}
	return partition
}

// Creates a new party and adds it to the network
func (n *Network) addParty(parties *[]*Party, partyNumber int, noOfParties int, distributionSet Structure, adversaryStructure Structure, subset []IndexPair, domain *big.Int) {
	incomingChannel := make(chan Message)
	complaints := make([]Message, 0)
	n.partyChannels[partyNumber] = incomingChannel

	party := Party{
		partyNumber:        partyNumber,
		totalNoOfParties:   noOfParties,
		Domain:             domain,
		distributionSet:    distributionSet,
		adversaryStructure: adversaryStructure,
		partitionSubset:    subset,
		incomingMessages:   incomingChannel,
		outgoingMessages:   n.outgoingChannel,
		complaints:         complaints}
	party.chooseSecret(domain) // Chooses a random value for the party's secret
	party.shares = party.createEmptyShareMatrix()
	party.clearResultBuffer()
	party.termMatrices = party.createTermMatrices()

	*parties = append(*parties, &party)

}

// Resets the all parties, such that a new MPC protocol can be run
func resetFields(parties []*Party, noOfIns int) {
	for _, p := range parties {
		p.resetFields(noOfIns)
	}
}

// Resets the party, such that a new MPC protocol can be run
func (p *Party) resetFields(noOfIns int) {
	p.shares = p.createEmptyShareMatrix()
	p.createIntermediaries(noOfIns)
	p.MPCResult = nil
}

// Resets all the term matrices of all parties such that a new multiplication instruction can be executed
func resetTermMatrices(parties []*Party) {
	for _, p := range parties {
		p.resetTermMatrices()
	}
}

// Resets the party's term matrices such that a new multiplication instruction can be executed
func (p *Party) resetTermMatrices() {
	p.termMatrices = p.createTermMatrices()
}

// Creates an empty n x k matrix for shares to be stored in
func (p *Party) createEmptyShareMatrix() (matrix []Shares) {
	noOfParties := p.totalNoOfParties
	matrix = make([]Shares, noOfParties)
	noOfShares := p.computeNumberOfShares()
	for i := range matrix {
		matrix[i] = make(Shares, noOfShares)
	}
	return
}

// Create the array of intermediary values used in the MPCProtocol
func (p *Party) createIntermediaries(noOfIns int) {
	k := p.computeNumberOfShares()
	noOfIntermediaries := noOfIns
	intermediaries := make([]Shares, noOfIntermediaries)
	for i := 0; i < noOfIntermediaries; i++ {
		intermediaries[i] = make(Shares, k)
	}
	p.intermediaries = intermediaries
}

// Creates n empty k x k x k matrices
func (p *Party) createTermMatrices() (termMatrices []TermMatrix) {
	n := p.totalNoOfParties
	termMatrices = make([]TermMatrix, n)
	for i := 0; i < n; i++ {
		termMatrices[i] = p.createTermMatrix()
	}
	return
}

// Creates an empty k x k x k matrix
func (p *Party) createTermMatrix() (termMatrix TermMatrix) {
	k := p.computeNumberOfShares()
	termMatrix = make([][]Shares, k)
	for i := 0; i < k; i++ {
		sliceOfShares := make([]Shares, k)
		for j := 0; j < k; j++ {
			sliceOfShares[j] = make(Shares, k)
		}
		termMatrix[i] = sliceOfShares
	}
	return
}

// Send shares of the party's secret to all other parties
func (p *Party) sendShares(secret *big.Int, messageType string) {
	// Prepare share-messages in accordance with protocol
	shares := p.createShares(secret)

	// Creates the n x k share matrix
	sharesToSend := p.createEmptyShareMatrix()

	// Iterate through the created shares
	for i, s := range shares {
		// Iterate through the parties that should receive this share
		for _, party := range p.distributionSet[i] {
			sharesToSend[party][i] = big.NewInt(0).Set(s) // Creates a new big int and sets it to the value of s
		}
	}

	// Send out the share over the network
	for i := 0; i < p.totalNoOfParties; i++ {
		p.outgoingMessages <- Message{messageType: messageType, sender: p.partyNumber, receiver: i, payload: Payload{shares: sharesToSend[i]}}
	}
}

// Create and returns shares of the input secret
func (p *Party) createShares(secret *big.Int) Shares {
	noOfShares := p.computeNumberOfShares()

	sumOfShares := big.NewInt(0) // sum of all shares except the final share
	shares := make(Shares, noOfShares)

	for i := 0; i < noOfShares-1; i++ {
		shareI := chooseRandomlyFromDomain(p.Domain)
		sumOfShares = sumOfShares.Add(sumOfShares, shareI)

		shares[i] = shareI
	}

	// Add final share
	differenceOfShares := big.NewInt(0).Sub(secret, sumOfShares)
	shares[noOfShares-1] = big.NewInt(0).Mod(differenceOfShares, p.Domain)

	return shares
}

// Takes messages from the common outgoing channel and sends it to the right input channel
func (n *Network) handleTraffic() {
	for {
		message := <-n.outgoingChannel
		receiver := message.receiver
		n.sendMessageToChannel(receiver, message)
	}
}

// Sends the input message to the input receiver, if that receiver exists
func (n *Network) sendMessageToChannel(receiver int, message Message) {
	if channel, ok := n.partyChannels[receiver]; ok {
		channel <- message
	} else {
		fmt.Printf("receiver %d not part of network \n", message.receiver)
	}
}

// Simulates a broadcast simply by sending the message to each player
func (p *Party) broadcast(message Message) {
	for i := 0; i < p.totalNoOfParties; i++ {
		messageToSend := message // We do not want to overwrite the receiver field of the original message
		messageToSend.receiver = i
		p.outgoingMessages <- messageToSend
	}
}

// Chooses a random number from the domain
func chooseRandomlyFromDomain(domainSize *big.Int) *big.Int {
	randomInt, _ := rand.Int(rand.Reader, domainSize)
	return randomInt
}

// Sets the party's secret to a random number from the domain
func (p *Party) chooseSecret(domain *big.Int) {
	p.secret = chooseRandomlyFromDomain(domain)
}

// Computed the number k which determines the number of shares that a secret is split up into.
// The number k is exactly the number of sets in the secrecy structure
func (p *Party) computeNumberOfShares() int {
	return len(p.distributionSet)
}

// Removes a message from a slice of messages
func removeMessageFromSlice(s []Message, i int) []Message {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

// Checks if the input element is part of the input set
func setContains(set []int, element int) bool {
	for _, e := range set {
		if e == element {
			return true
		}
	}
	return false
}

// Adds two big int rows / share slices together
func addShareSlices(op1 Shares, op2 Shares) (res Shares) {
	if len(op1) != len(op2) {
		panic(fmt.Sprintf("Input rows are not of equal length. op1 row had length: %d \n op2 row had length: %d \n", len(op1), len(op2)))
	}
	res = make(Shares, len(op1))
	for i := range op1 {
		if op1[i] == nil {
			if op2[i] == nil {
				res[i] = nil
			} else {
				res[i] = copyBigInt(op2[i])
			}
		} else {
			if op2[i] == nil {
				res[i] = copyBigInt(op1[i])
			} else {
				copy1 := copyBigInt(op1[i])
				copy2 := copyBigInt(op2[i]) // Not strictly needed, but more readable
				res[i] = big.NewInt(0).Add(copy1, copy2)
			}
		}
	}
	return res
}

// Subtracts two big int rows / share slices from each other
func subtractShareSlices(op1 Shares, op2 Shares) (res Shares) {
	if len(op1) != len(op2) {
		panic(fmt.Sprintf("Input rows are not of equal length. op1 row had length: %d \n op2 row had length: %d \n", len(op1), len(op2)))
	}
	res = make(Shares, len(op1))
	for i := range op1 {
		if op1[i] == nil {
			if op2[i] == nil {
				res[i] = nil
			} else {
				res[i] = big.NewInt(0).Neg(op2[i]) // to get the value 0 - op2
			}
		} else {
			if op2[i] == nil {
				res[i] = copyBigInt(op1[i])
			} else {
				copy1 := copyBigInt(op1[i])
				copy2 := copyBigInt(op2[i]) // Not strictly needed, but more readable
				res[i] = big.NewInt(0).Sub(copy1, copy2)
			}
		}
	}
	return res
}

// Copies a big int row / share slice into another slice
func copyBigIntRows(dest []*big.Int, src []*big.Int) {
	for i := range dest {
		if src[i] != nil {
			dest[i] = copyBigInt(src[i])
		}
	}
}

// Makes a deep copy of a big int
func copyBigInt(toCopy *big.Int) *big.Int {
	return big.NewInt(0).Set(toCopy)
}

// Returns the result of the input function
func (p *Party) computeResult() (res *big.Int) {
	resultShares := p.getResultShares()
	res = p.computeSumOfShares(resultShares)
	return
}

// Returns the sharing of the result of the input function
func (p *Party) getResultShares() Shares {
	indexOfResultShares := len(p.intermediaries) - 1 // The sharing of the result is located in the last intermediary
	return p.intermediaries[indexOfResultShares]
}

// Computes the sum of a share slice
func (p *Party) computeSumOfShares(shares Shares) *big.Int {
	sumOfSlice := big.NewInt(0)
	for _, share := range shares {
		if share != nil {
			sumOfSlice.Add(sumOfSlice, share)
		}
	}
	return sumOfSlice.Mod(sumOfSlice, p.Domain)
}

// Prints the values of a share slice
func sharesToString(shares []*big.Int) (s string) {
	for _, share := range shares {
		s = s + share.String() + " "
	}
	return
}

// Computes a share slice of all zeroes
// TODO: Rename
func makeZeroShares(sliceSize int) Shares {
	zeroShares := make(Shares, sliceSize)
	for i := 0; i < sliceSize; i++ {
		zeroShares[i] = big.NewInt(0)
	}
	return zeroShares
}

// Print a party's term matrices for debugging
func (p *Party) printTermMatrices() {
	k := p.computeNumberOfShares()
	for q := 0; q < p.totalNoOfParties; q++ {
		for i := 0; i < k; i++ {
			row := "["
			for j := 0; j < k-1; j++ {
				row = row + sharesToString(p.termMatrices[q][i][j]) + ", "
			}
			row = row + sharesToString(p.termMatrices[q][i][k-1]) + "]"
			fmt.Println(row)
		}
		fmt.Println()
	}
}
