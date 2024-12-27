/*
This file contains the functions of the active MPC protocol
*/

package Gates

import (
	"fmt"
	"math/big"
	"sync"
)

// Main protocol function
func MPCProtocolActive(instructions []Instruction, parties []*Party) (exitCode int) {
	// Reset each party
	resetFields(parties, len(instructions))

	// VSS SHARE of secrets
	exitCode = VSSShareInit(parties)
	if exitCode == Abort {
		return
	}

	// Execute the instructions of MPC function
	exitCode = executeInstructionsActive(parties, instructions)
	if exitCode == Abort {
		return
	}

	// All computations are finished. Reconstruct the result of the input function.
	reconstructResult(parties)

	exitCode = Success
	return
}

// High level methods

// Distributes the secrets of each party using VSS
func VSSShareInit(parties []*Party) (exitCode int) {
	// Send secret shares between parties
	shareInit(parties)

	// Send out each party's version of their shares for verification
	verifyInitShares(parties)

	// Broadcast any complaints that have arisen in the above step
	broadcastComplaints(parties)

	// Resolve any complaints broadcasted in the above step
	resolveComplaints(parties)

	// Check if any party aborted in the above step
	partiesAborted := checkForAborts(parties)
	if partiesAborted {
		exitCode = Abort
	} else {
		exitCode = Success
	}
	return
}

// Executes each instruction in the list of instructions.
// At the end of this function, each party has shares of the result stored in their intermediary results
func executeInstructionsActive(parties []*Party, instructions []Instruction) (exitCode int) {
	for _, ins := range instructions {
		if ins.instructionType == Add {
			// Run add protocol
			addition(parties, ins)
		} else if ins.instructionType == Mult {
			// Run mult protocol
			exitCodeMult := activeMultiplication(parties, ins)
			if exitCodeMult == Abort {
				exitCode = Abort
				return
			}
		} else {
			panic(fmt.Sprintf("Error: illegal instruction type id %d \n", ins.instructionType))
		}
	}

	exitCode = Success
	return
}

// Executes a multiplication instruction
func activeMultiplication(parties []*Party, ins Instruction) (exitCode int) {
	resetTermMatrices(parties)

	// Step 1: compute and send out all terms using VSS
	VSSShareMult(parties, ins)

	partiesAborted := checkForAborts(parties)
	if partiesAborted {
		exitCode = Abort
		return
	}

	// Step 2+3+4
	handleTerms(parties, ins)

	exitCode = Success
	return
}

// Reconstruct the result of the MPC after all instructions have been executed
func reconstructResult(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.reconstructResult(&wg)
	}
	wg.Wait()
	// Sum all reconstructed shares, yielding a single final value
	for _, p := range parties {
		p.MPCResult = p.computeResult()
	}
}

// Methods for VSSShareInit

// Spawns and waits for the goroutines for sending and receiving verifications of shares
func verifyInitShares(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.receiveVerifications(&wg)
		go p.verifyShares()
	}
	wg.Wait()
}

// Receives verifications of shares from the qualified sets that the party is part of
func (p *Party) receiveVerifications(wg *sync.WaitGroup) {
	defer wg.Done()
	verificationsReceived := 0
	for {
		if verificationsReceived == p.countDistributionSetGroupMembers() {
			// Return when the party has received messages from all other parties in each of the qualified sets that the party is part of
			return
		}
		message := <-p.incomingMessages

		if message.messageType == VerifyInit || message.messageType == VerifyMult {
			// Check that the sender of the share is part of the qualified set for that share
			qualifiedSetForShare := p.distributionSet[message.payload.shareIndex]
			if setContains(qualifiedSetForShare, message.sender) {
				p.checkSharesMatch(message)
				verificationsReceived++
			}
		} else {
			panic(fmt.Sprintf("expected only verify messages at this stage at party %d: %s", p.partyNumber, message.messageType))
		}
	}
}

// Verifies the received message by checking that the party has the same value of the shares
func (p *Party) checkSharesMatch(message Message) {
	shareIndex := message.payload.shareIndex
	if message.messageType == VerifyInit {
		// Check that party has the same values in his share matrix
		for partyIndex, share := range message.payload.shares {
			if p.shares[partyIndex][shareIndex].Cmp(share) != 0 {
				// Complain
				payload := Payload{shareIndex: shareIndex, accusedParty: partyIndex}
				message := Message{messageType: InitComplaint, sender: p.partyNumber, payload: payload}
				p.addUniqueComplaint(message)
			}
		}
	}
	if message.messageType == VerifyMult {
		// Check that party has the same values in his term matrices
		for partyIndex, termMatrix := range message.payload.termMatrices {
			for i := 0; i < p.computeNumberOfShares(); i++ {
				for j := 0; j < p.computeNumberOfShares(); j++ {
					if p.termMatrices[partyIndex][i][j][shareIndex].Cmp(termMatrix[i][j][shareIndex]) != 0 {
						// Complain
						payload := Payload{shareIndex: shareIndex, termIndex: IndexPair{i: i, j: j}, accusedParty: partyIndex}
						message := Message{messageType: MultComplaint, sender: p.partyNumber, payload: payload}
						p.addUniqueComplaint(message)
					}
				}
			}
		}
	}
}

// Adds a complaint to the party's list of complaints unless the party already has that complaint
func (p *Party) addUniqueComplaint(complaint Message) {
	isUnique := true
	if complaint.messageType == InitComplaint {
		// For complaints in the initial share sending, two complaints are equal if they are about the same share index and the same accused party
		for _, c := range p.complaints {
			if c.payload.shareIndex == complaint.payload.shareIndex && c.payload.accusedParty == complaint.payload.accusedParty {
				isUnique = false
			}
		}
	} else if complaint.messageType == MultComplaint {
		// For complaints in the multiplication protocol, two complaints are equal if they are about the same share index, the same term and the same accused party
		for _, c := range p.complaints {
			if c.payload.shareIndex == complaint.payload.shareIndex &&
				c.payload.accusedParty == complaint.payload.accusedParty &&
				c.payload.termIndex.i == complaint.payload.termIndex.i &&
				c.payload.termIndex.j == complaint.payload.termIndex.j {
				isUnique = false
				break
			}
		}
	} else {
		panic(fmt.Sprintf("received illegal complaint type at party %d: %s", p.partyNumber, complaint.messageType))
	}

	if isUnique {
		p.complaints = append(p.complaints, complaint)
	}
}

// Removes a complaint from the party's list of complaints
func (p *Party) removeFromComplaints(response Message) {
	responseShareIndex := response.payload.shareIndex
	responseSender := response.sender
	responseTermI := response.payload.termIndex.i
	responseTermJ := response.payload.termIndex.j
	for i, complaint := range p.complaints {
		// Check for equality. If the complaint is an init complaint, responseTermI and responseTermJ are nil
		if complaint.payload.shareIndex == responseShareIndex &&
			complaint.payload.accusedParty == responseSender &&
			complaint.payload.termIndex.i == responseTermI &&
			complaint.payload.termIndex.j == responseTermJ {
			p.complaints = removeMessageFromSlice(p.complaints, i)
			return
		}
	}
}

// Sends out the party's shares for verification
func (p *Party) verifyShares() {
	// Iterate over the qualified sets in the distribution set
	for shareIndex, qset := range p.distributionSet {
		// The party has to be part of the given set in the distribution set to have the share
		if setContains(qset, p.partyNumber) {
			// Add all of the shares with index given by shareIndex to a slice
			payloadShares := make([]*big.Int, 0)
			for _, shareSlice := range p.shares {
				payloadShares = append(payloadShares, shareSlice[shareIndex])
			}
			payload := Payload{shareIndex: shareIndex, shares: payloadShares}

			// Send to everyone but the party itself in the set
			for _, partyIndex := range qset {
				if p.partyNumber != partyIndex {
					p.outgoingMessages <- Message{messageType: VerifyInit, sender: p.partyNumber, receiver: partyIndex, payload: payload}
				}
			}
		}
	}
}

// Spawns and waits for the goroutines for sending and receiving complaints
func broadcastComplaints(parties []*Party) {
	var wg sync.WaitGroup
	sumOfComplaints := countAllComplaints(parties)

	for _, p := range parties {
		wg.Add(1)
		// Copy the complaints array since receiveComplaints() adds new complaints to this array
		copyOfComplaints := make([]Message, len(p.complaints))
		copy(copyOfComplaints, p.complaints)
		go p.broadcastComplaints(copyOfComplaints)
		go p.receiveComplaints(&wg, sumOfComplaints)
	}

	wg.Wait()
}

// Broadcasts all the complaints raised by the party
func (p *Party) broadcastComplaints(complaints []Message) {
	for _, complaint := range complaints {
		p.broadcast(complaint)
	}
}

// Receive broadcasted complaints from all parties
func (p *Party) receiveComplaints(wg *sync.WaitGroup, sumOfComplaints int) {
	defer wg.Done()
	complaintsReceived := 0
	for {
		if complaintsReceived == sumOfComplaints {
			return
		}
		message := <-p.incomingMessages
		if message.messageType == InitComplaint || message.messageType == MultComplaint {
			complaintsReceived++

			// Find out if the sender of the complaint is qualified to know the share he complains about
			qualifiedSet := p.distributionSet[message.payload.shareIndex]
			if setContains(qualifiedSet, message.sender) {
				p.addUniqueComplaint(message)
			}
		} else {
			panic(fmt.Sprintf("expected only complaints messages during complaints phase of protocol, instead received %s", message.messageType))
		}
	}
}

// Spawns and waits for the goroutines for sending and receiving responses to complaints
func resolveComplaints(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)

		// Copy the complaints array since receiveDisputes() removes complaints from this array
		copyOfComplaints := make([]Message, len(p.complaints))
		copy(copyOfComplaints, p.complaints)
		go p.handleAccusations(copyOfComplaints)
		go p.receiveDisputes(&wg)
	}
	wg.Wait()
}

// Answers all accusations raised against the party
func (p *Party) handleAccusations(complaints []Message) {
	for _, c := range complaints {
		// InitComplaints and MultComplaints requires accessing different field of the party
		if c.payload.accusedParty == p.partyNumber && c.messageType == InitComplaint {
			shareToSend := []*big.Int{p.shares[p.partyNumber][c.payload.shareIndex]}
			payload := Payload{shares: shareToSend, shareIndex: c.payload.shareIndex}
			messageToBroadcast := Message{messageType: DisputedInitShare, sender: p.partyNumber, payload: payload}
			p.broadcast(messageToBroadcast)
		} else if c.payload.accusedParty == p.partyNumber && c.messageType == MultComplaint {
			i := c.payload.termIndex.i
			j := c.payload.termIndex.j
			shareIndex := c.payload.shareIndex
			shareToSend := []*big.Int{p.termMatrices[p.partyNumber][i][j][shareIndex]}
			payload := Payload{shares: shareToSend, shareIndex: shareIndex, termIndex: IndexPair{i: i, j: j}}
			messageToBroadcast := Message{messageType: DisputedMultShare, sender: p.partyNumber, payload: payload}
			p.broadcast(messageToBroadcast)
		}
	}
}

// Receives answers to complaints
func (p *Party) receiveDisputes(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		if len(p.complaints) == 0 {
			p.exitCode = Success
			return
		}
		message := <-p.incomingMessages
		if message.messageType == Refuse {
			// The accused party refuses to broadcast, and the protocol must be aborted
			p.exitCode = Abort
			return
		}
		if message.messageType == DisputedInitShare {
			// Overwrite the party's version of the share
			disputedShare := message.payload.shares[0]
			p.shares[message.sender][message.payload.shareIndex] = disputedShare

			// Remove the complaint from the list of complaints
			p.removeFromComplaints(message)

		} else if message.messageType == DisputedMultShare {
			// Overwrite the party's version of the share
			disputedShare := message.payload.shares[0]
			i := message.payload.termIndex.i
			j := message.payload.termIndex.j
			shareIndex := message.payload.shareIndex
			p.termMatrices[message.sender][i][j][shareIndex] = disputedShare

			// Remove the complaint from the list of complaints
			p.removeFromComplaints(message)
		} else {
			panic(fmt.Sprintf("expected only responses to complaints during response phase of protocol, instead received %s", message.messageType))
		}
	}
}

// Checks if any party aborted during the Resolve Complaints phase
func checkForAborts(parties []*Party) (didAbort bool) {
	for _, p := range parties {
		if p.exitCode == Abort {
			didAbort = true
			return
		}
	}
	didAbort = false
	return
}

// Methods for active multiplication

// Handles the VSS sharing of all the terms of all the parties
func VSSShareMult(parties []*Party, ins Instruction) {
	distributeMultShares(parties, ins)
	verifyMultShares(parties)
	broadcastComplaints(parties)
	resolveComplaints(parties)
}

// Spawns and waits for the goroutines for sending and receiving mult shares in the form of term matrices
func distributeMultShares(parties []*Party, ins Instruction) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.receiveMultShares(&wg)
		go p.initializeMultSharesActive(ins)
	}
	// Wait for all parties to receive all shares
	wg.Wait()
}

// Receives shares of terms that all parties have computed, in the form of term matrices
func (p *Party) receiveMultShares(wg *sync.WaitGroup) {
	defer wg.Done()
	sharesReceived := 0
	for {
		message := <-p.incomingMessages

		if message.messageType == MultShare {
			//Store received term matrix
			p.termMatrices[message.sender] = message.payload.termMatrices[0]
			sharesReceived++
			// n term matrices are to be received
			if sharesReceived == p.totalNoOfParties {
				return
			}
		}
	}
}

// Creates an initial, temporary term matrix, then splits it up to n term matrices to send to the n parties
func (p *Party) initializeMultSharesActive(ins Instruction) {
	// Compute initial, temporary term matrix
	ownTermMatrix := p.computeTermMatrix(ins)

	// Create n empty term matrices
	termMatricesToSend := p.createTermMatrices()
	k := p.computeNumberOfShares()
	// Iterate through all possible terms
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			// Find out if the party computed (is qualified to) this term
			if ownTermMatrix[i][j] != nil {
				// Iterate through the distribution set
				for shareIndex, qset := range p.distributionSet {
					// Add the share of the computed term to the term matrices of the parties that are qualified to know this share
					for _, partyNumber := range qset {
						termMatricesToSend[partyNumber][i][j][shareIndex] = ownTermMatrix[i][j][shareIndex]
					}
				}
			}
		}
	}

	// Send out the term matrices. The party sends to itself
	for i := 0; i < p.totalNoOfParties; i++ {
		termMatrices := []TermMatrix{termMatricesToSend[i]} // store the term matrix in the first entry of the slice of term matrices
		p.outgoingMessages <- Message{messageType: MultShare, sender: p.partyNumber, receiver: i, payload: Payload{termMatrices: termMatrices}}
	}
}

// Computes shares of all terms that the party is qualified to know, and enters them into a new term matrix
func (p *Party) computeTermMatrix(ins Instruction) TermMatrix {
	// Collect the shares of s and t
	sShares := p.getOperand(ins.operand1)
	tShares := p.getOperand(ins.operand2)

	// Create an empty term matrix
	termMatrix := p.createTermMatrix()

	// Iterate through the shares of s
	for i, sShare := range sShares {
		// If the party is not qualified to know this share, skip this iteration
		if !setContains(p.distributionSet[i], p.partyNumber) {
			continue
		}
		// Iterate through the shares of t
		for j, tShare := range tShares {
			// If the party is not qualified to know this share, skip this iteration
			if !setContains(p.distributionSet[j], p.partyNumber) {
				continue
			}
			// Create shares of this term since the player is qualified to know both s_i and t_j
			termMatrix[i][j] = p.createShares(big.NewInt(0).Mul(sShare, tShare))
		}
	}
	return termMatrix
}

// Spawns and waits for the goroutines for sending and receiving verifications of mult shares
func verifyMultShares(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.receiveVerifications(&wg)
		go p.verifyTermShares()
	}
	wg.Wait()
}

// Sends out the party's versions of the shares for verification
func (p *Party) verifyTermShares() {
	// Iterate over the distribution set
	k := p.computeNumberOfShares()
	for shareIndex, qset := range p.distributionSet {
		// Check if the party is qualified to know the share
		if setContains(qset, p.partyNumber) {
			// Add all of the shares with index given by shareIndex to a term matrix
			termMatrixPayload := p.createTermMatrices()

			for partyNumber, termMatrix := range p.termMatrices {
				for i := 0; i < k; i++ {
					for j := 0; j < k; j++ {
						if termMatrix[i][j][shareIndex] != nil {
							termMatrixPayload[partyNumber][i][j][shareIndex] = termMatrix[i][j][shareIndex]
						}
					}
				}
			}
			payload := Payload{shareIndex: shareIndex, termMatrices: termMatrixPayload}

			// Send to everyone but the party itself in the accessElement
			for _, partyIndex := range qset {
				if p.partyNumber != partyIndex {
					p.outgoingMessages <- Message{messageType: VerifyMult, sender: p.partyNumber, receiver: partyIndex, payload: payload}
				}
			}
		}
	}
}

// Executes step 2+3+4 of the multiplication protocol
func handleTerms(parties []*Party, ins Instruction) {
	// Create all termCombinations
	numberOfShares := parties[0].computeNumberOfShares()
	termCombinations := createTermCombinations(numberOfShares)

	// Iterate over the terms
	for _, term := range termCombinations {
		// Compute differences of the terms
		computeDifferences(parties, term)

		// Check the differences to see if reconstruction is necessary
		reconstructNeeded := checkForReconstruct(parties)
		if reconstructNeeded {
			// Reconstruct the two factors that make up the term
			fmt.Println("reconstruct needed for term", term.i, term.j)
			reconstructFactors(parties, term, ins)
		}
		// Add the term to the parties' resultBuffers
		addTermToResults(parties, reconstructNeeded, term, ins)
	}

	// Move the content of the resultbuffers into the intermediary results
	for _, p := range parties {
		p.moveProductFromBuffer(ins)
	}
}

// Creates all pairs (i,j) for 0 <= i < k and 0 <= j < k
func createTermCombinations(numberOfShares int) []IndexPair {
	termCombinations := make([]IndexPair, 0)
	for i := 0; i < numberOfShares; i++ {
		for j := 0; j < numberOfShares; j++ {
			termCombinations = append(termCombinations, IndexPair{i: i, j: j})
		}
	}
	return termCombinations
}

// Computes the difference slices for the given term for all parties
func computeDifferences(parties []*Party, term IndexPair) {
	var wg sync.WaitGroup

	// For each party, compute the shares of the difference slices that the party is qualified to know
	for _, p := range parties {
		p.createDifferenceSlices(term)
	}

	numberOfDifferences := len(parties[0].differenceSlices)

	// Reconstruct the difference slices such that all parties have complete difference slices
	for i := 0; i < numberOfDifferences; i++ {
		for _, p := range parties {
			wg.Add(1)
			go p.reconstruct(&p.differenceSlices[i], &wg)
		}
		wg.Wait()
	}
}

// Computes the shares that the party is qualified to know of each difference slice for the input term
func (p *Party) createDifferenceSlices(term IndexPair) {
	// Find the parties that are qualified to know the input term, and add their versions of the term to a slice
	versionsOfTerm := make([]Shares, 0)
	for partyNo, termMatrix := range p.termMatrices {
		partyIsQualified := setContains(p.distributionSet[term.i], partyNo) && setContains(p.distributionSet[term.j], partyNo)
		if partyIsQualified {
			versionsOfTerm = append(versionsOfTerm, termMatrix[term.i][term.j])
		}
	}
	r := len(versionsOfTerm)

	// From the first version of the term, subtract each other version to create the r-1 difference slices
	differenceSlices := make([]Shares, 0)
	for i := 1; i < r; i++ {
		differenceSlice := make(Shares, p.computeNumberOfShares())
		copyBigIntRows(differenceSlice, versionsOfTerm[0])
		differenceSlice = subtractShareSlices(differenceSlice, versionsOfTerm[i])
		differenceSlices = append(differenceSlices, differenceSlice)
	}

	p.differenceSlices = differenceSlices
}

// Reconstructs the two factors that make up the input term, at each party
func reconstructFactors(parties []*Party, term IndexPair, ins Instruction) {
	var wg sync.WaitGroup

	// reconstruct s_i
	for _, p := range parties {
		wg.Add(1)
		go p.reconstructFactor(term, ins, &wg, S_i)
	}
	wg.Wait()

	// reconstruct t_j
	for _, p := range parties {
		wg.Add(1)
		go p.reconstructFactor(term, ins, &wg, T_j)
	}
	wg.Wait()
}

// Reconstructs one of the factors (specified by the input factorToReconstruct) of the input term
func (p *Party) reconstructFactor(term IndexPair, ins Instruction, wg *sync.WaitGroup, factorToReconstruct string) {
	defer wg.Done()

	var occurencesOfFactor int
	var addressOfFactor **big.Int
	var factorValue *big.Int
	var qualifiedSetForFactor []int

	if factorToReconstruct == S_i {
		// Count how many parties knows s_i
		qualifiedSetForFactor = p.distributionSet[term.i]
		occurencesOfFactor = len(qualifiedSetForFactor)
		addressOfFactor = p.getAddressOfFactor(ins.operand1, term.i) // Find the address of s_i

	} else if factorToReconstruct == T_j {
		// Count how many parties knows t_j
		qualifiedSetForFactor = p.distributionSet[term.j]
		occurencesOfFactor = len(qualifiedSetForFactor)
		addressOfFactor = p.getAddressOfFactor(ins.operand2, term.j) // Find the address of t_j

	} else {
		panic(fmt.Sprintf("Provided illegal factor type: %s", factorToReconstruct))
	}

	// Check if the party knows the value of factor to reconstruct and should therefore broadcast
	shouldBroadcast := setContains(qualifiedSetForFactor, p.partyNumber)
	if shouldBroadcast {
		factorValue = *addressOfFactor
		payload := Payload{shares: Shares{factorValue}}
		messageToBroadcast := Message{messageType: ReconstructFactor, sender: p.partyNumber, payload: payload}
		go p.broadcast(messageToBroadcast)
	}
	// Receive broadcasted versions of the factor and find the unique correct value
	p.receiveReconstructFactor(occurencesOfFactor, addressOfFactor)
}

// Receives broadcasted versions of the a factor and finds the unique correct value of the factor
// The correct value is then stored at the input address
func (p *Party) receiveReconstructFactor(occurencesOfFactor int, addressOfFactor **big.Int) {
	messagesReceived := 0
	receivedValues := make([]Shares, 0)
	for {
		message := <-p.incomingMessages
		if message.messageType == ReconstructFactor {
			messagesReceived++
			// We only receive a single share in the first entry of message.payload.shares
			receivedValues = append(receivedValues, message.payload.shares)
			if messagesReceived == occurencesOfFactor {
				// completeShareSlice takes entire slices as input
				// In this case only the first entry is reconstructed, so only the first entry of the output is needed.
				correctFactorValue := p.completeShareSlice(receivedValues)[0]
				*addressOfFactor = correctFactorValue
				return
			}
		} else {
			panic(fmt.Sprintf("expected only reconstructFactor messages in this part of the protocol, instead received %s", message.messageType))
		}
	}
}

// Reconstructs the share slice, which address is given as input
func (p *Party) reconstruct(shares *Shares, wg *sync.WaitGroup) {
	defer wg.Done()

	// Send the party's version of the share slice to all parties
	sharesCopy := make(Shares, len(*shares))
	copy(sharesCopy, *shares)
	payload := Payload{shares: sharesCopy}
	messageToBroadcast := Message{messageType: Reconstruct, sender: p.partyNumber, payload: payload}

	go p.broadcast(messageToBroadcast)

	// Receive different versions of the shares and find the unique correct share slice
	p.receiveReconstructMessages(shares)
}

func (p *Party) reconstructResult(wg *sync.WaitGroup) {
	indexOfResultShares := len(p.intermediaries) - 1
	p.reconstruct(&p.intermediaries[indexOfResultShares], wg)
}

// Receives different versions of the shares and find the unique correct share slice
// The correct share slice is then stored at the input address
func (p *Party) receiveReconstructMessages(shares *Shares) {
	messagesReceived := 0
	receivedSlices := make([]Shares, p.totalNoOfParties)
	for {
		message := <-p.incomingMessages
		if message.messageType == Reconstruct {
			messagesReceived++
			sender := message.sender
			receivedSlices[sender] = message.payload.shares
			if messagesReceived == p.totalNoOfParties {
				*shares = p.completeShareSlice(receivedSlices)
				return
			}
		} else {
			panic(fmt.Sprintf("party %d expected only reconstruct messages in this part of the protocol, instead received %s", p.partyNumber, message.messageType))
		}
	}
}

// Takes n incomplete share slices as input and constructs the complete and correct share slice from them
func (p *Party) completeShareSlice(receivedSlices []Shares) (correctShareValues Shares) {

	// Iterate through the entries in the slices
	for i := 0; i < len(receivedSlices[0]); i++ {
		// Add the different version of this share to a map
		shareValueMap := make(map[int]string)
		for sender, receivedSlice := range receivedSlices {
			// We want to compare the values of our pointers, so convert to string, which is an accepted map type
			if receivedSlice[i] != nil {
				shareValueMap[sender] = receivedSlice[i].String()
			}
		}
		foundExplanation := false
		lastValueOfMap := ""
		// Iterate over the adversary structure
		for _, adversarySubset := range p.adversaryStructure {
			// Copy map, ensuring safe delete after
			copyOfShareValueMap := make(map[int]string)
			for k, v := range shareValueMap {
				copyOfShareValueMap[k] = v
			}
			// Delete entries of the copied map that correspond to corrupted parties
			for _, adversary := range adversarySubset {
				delete(copyOfShareValueMap, adversary)
			}
			// Save one of the entries in the map for comparison with the rest of the entries
			for _, shareValueString := range copyOfShareValueMap {
				lastValueOfMap = shareValueString
			}
			// Compare the entries of the map with the lastValueOfMap
			numberOfTotalEntries := len(copyOfShareValueMap)
			numberOfEvaluatedEntries := 0
			for _, shareValueString := range copyOfShareValueMap {
				if lastValueOfMap != shareValueString {
					// Found mismatch, so move on to next adversarySubset
					numberOfEvaluatedEntries++
					break
				} else {
					numberOfEvaluatedEntries++
				}
				if numberOfEvaluatedEntries == numberOfTotalEntries {
					// Went through all share values without breaking, so didn't find a mismatch, therefore found an explanation
					foundExplanation = true
				}
			}
			if foundExplanation {
				break
			}
		}
		if foundExplanation {
			// Convert back to *big.Int
			shareValue := big.NewInt(0)
			shareValue.SetString(lastValueOfMap, 10)

			correctShareValues = append(correctShareValues, shareValue)
		}
	}

	return
}

// Checks if any party calls for a reconstruction of the current term
func checkForReconstruct(parties []*Party) bool {
	for _, p := range parties {
		p.checkForReconstruct()
		if p.exitCode == ReconstructNeeded {
			return true
		}
	}
	return false
}

// Checks if the sum of any of the party's difference slices is not zero
// If that is the case, set the party's exit code to ReconstructNeeded, else to ReconstructNotNeeded
func (p *Party) checkForReconstruct() {
	reconstructNeeded := false
	for _, slice := range p.differenceSlices {

		sumOfSlice := p.computeSumOfShares(slice)
		if sumOfSlice.Cmp(big.NewInt(0)) != 0 {
			reconstructNeeded = true
		}
	}
	if reconstructNeeded {
		p.exitCode = ReconstructNeeded
	} else {
		p.exitCode = ReconstructNotNeeded
	}
}

// For each party adds the shares of the input term to the intermediary result
func addTermToResults(parties []*Party, wasReconstructed bool, term IndexPair, ins Instruction) {
	for _, p := range parties {
		p.addTermToResult(wasReconstructed, term, ins)
	}
}

// Adds the shares of the input term to the intermediary result
func (p *Party) addTermToResult(wasReconstructed bool, term IndexPair, ins Instruction) {
	if wasReconstructed {
		// If the term was reconstructed, only the parties in the first distribution set should add the term
		if setContains(p.distributionSet[0], p.partyNumber) {
			// Find the value of s_i and t_j
			s_i := p.getOperand(ins.operand1)[term.i]
			t_j := p.getOperand(ins.operand2)[term.j]

			// s_it_j is added as the first entry of the share slice, while the rest of the entries get value 0
			s_it_j := big.NewInt(0).Mul(s_i, t_j)
			sharesToAdd := makeZeroShares(p.computeNumberOfShares())
			sharesToAdd[0].Mod(s_it_j, p.Domain) // Take modulo to stay within domain
			p.resultBuffer = addShareSlices(p.resultBuffer, sharesToAdd)
		}
	} else {
		// Find the first party qualified to know the term and add that party's sharing of the term to the intermediary result
		for partyNo, termMatrix := range p.termMatrices {
			partyIsQualified := setContains(p.distributionSet[term.i], partyNo) && setContains(p.distributionSet[term.j], partyNo)
			if partyIsQualified {
				termEntry := termMatrix[term.i][term.j]
				// Copy the sharing of the term and add it to the result
				sharesToAdd := make(Shares, p.computeNumberOfShares())
				for i, s := range termEntry {
					if setContains(p.distributionSet[i], p.partyNumber) {
						sharesToAdd[i] = big.NewInt(0).Set(s)
					}
				}
				p.resultBuffer = addShareSlices(p.resultBuffer, sharesToAdd)
				break
			}
		}
	}
}

// Helper methods

// Counts the complaints of all parties
func countAllComplaints(parties []*Party) (sumOfComplaints int) {
	for _, p := range parties {
		sumOfComplaints += len(p.complaints)
	}
	return
}

// Returns the number of members, besides this party, in the sets in the distribution set where this party is included
func (p *Party) countDistributionSetGroupMembers() (noOfMembers int) {
	for _, s := range p.distributionSet {
		if setContains(s, p.partyNumber) {
			noOfMembers += len(s) - 1 // Minus 1 since the party itself is not counted
		}
	}
	return
}
