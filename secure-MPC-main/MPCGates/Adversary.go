/*
The functions in this file is used to model an adversary.
It containts functions mimicing the functions in Active.go but injects illegal messages in the system.
*/

package Gates

import (
	"fmt"
	"math/big"
	"sync"
)

// Used to contain various metrics for testing
type TestResults struct {
	sumOfComplaintsShare int
	exitCodeShare        int
	sumOfComplaintsMult  int
	exitCodeMult         int
	reconstructions      int
	sharedMultValue      *big.Int
}

// Contains all tests where the VSS sharing step of the multiplication protocol is needed
func multTests() []string {
	return []string{
		"TestShareMismatchStep1Mult",
		"TestAcceptBroadcastStep1Mult",
		"TestRefuseBroadcastStep1Mult",
		"TestWellBehavedStep2Mult",
		"TestWrongTermValue",
		"TestReconstructionOfValueAfterMultShareSending",
		"TestMultipleAdversaryAttacks"}
}

// Contains all tests where the entire multiplication protocol is needed
func multStep2Tests() []string {
	return []string{
		"TestWellBehavedStep2Mult",
		"TestWrongTermValue",
		"TestMultipleAdversaryAttacks"}
}

// The active MPC protocol with adversary
func MPCProtocolForTests(instructions []Instruction, parties []*Party, test string) (results TestResults) {
	resetFields(parties, len(instructions))

	VSSShareForTests(parties, test, &results)

	if sliceContainsString(multTests(), test) {
		for _, ins := range instructions {
			if ins.instructionType == Add {
				// Run add protocol
				addition(parties, ins)
			} else if ins.instructionType == Mult {
				// First step of mult protocol
				resetTermMatrices(parties)
				VSSShareMultForTests(parties, ins, test, &results)
				// Rest of mult protocol
				if sliceContainsString(multStep2Tests(), test) {
					handleTermsForTest(parties, ins, &results)
				}
			} else {
				panic(fmt.Sprintf("Error: illegal instruction type id %d \n", ins.instructionType))
			}
		}
	}

	reconstructResult(parties)

	return
}

// Checks if the input string is contained in the input string slice
func sliceContainsString(slice []string, s string) bool {
	for _, e := range slice {
		if e == s {
			return true
		}
	}
	return false
}

// First step of active multiplication protocol, with adversary
func VSSShareMultForTests(parties []*Party, ins Instruction, test string, results *TestResults) {
	if test == "TestWrongTermValue" {
		// Give a wrong value of s_2 to party 1 in order to make him send out a wrong value of term (2,1), (2,2) and (2,3)
		parties[1].shares[0][2].Sub(parties[1].shares[0][2], big.NewInt(1))
	}

	distributeMultShares(parties, ins)
	if test == "TestShareMismatchStep1Mult" ||
		test == "TestRefuseBroadcastStep1Mult" ||
		test == "TestAcceptBroadcastStep1Mult" {
		// Simulate party 1 sending wrong share
		parties[0].termMatrices[1][1][1][4] = big.NewInt(0).Sub(parties[0].termMatrices[1][1][1][4], big.NewInt(1))
	}
	if test == "TestMultipleAdversaryAttacks" {
		// Simulate party 0 and 1 sending out multiple wrong shares
		parties[0].termMatrices[2][3][3][1] = big.NewInt(0).Sub(parties[0].termMatrices[2][3][3][1], big.NewInt(1))
		parties[0].termMatrices[2][3][3][2] = big.NewInt(0).Sub(parties[0].termMatrices[2][3][3][2], big.NewInt(1))
		parties[0].termMatrices[2][3][3][3] = big.NewInt(0).Sub(parties[0].termMatrices[2][3][3][3], big.NewInt(1))
		parties[0].termMatrices[3][1][1][1] = big.NewInt(0).Sub(parties[0].termMatrices[3][1][1][1], big.NewInt(1))

		parties[1].termMatrices[4][2][2][1] = big.NewInt(0).Sub(parties[1].termMatrices[4][2][2][1], big.NewInt(1))
		parties[1].termMatrices[4][1][1][1] = big.NewInt(0).Sub(parties[1].termMatrices[4][1][1][1], big.NewInt(1))
		parties[1].termMatrices[4][2][2][2] = big.NewInt(0).Sub(parties[1].termMatrices[4][2][2][2], big.NewInt(1))
		parties[1].termMatrices[4][2][2][3] = big.NewInt(0).Sub(parties[1].termMatrices[4][2][2][3], big.NewInt(1))
		parties[1].termMatrices[2][3][3][1] = big.NewInt(0).Sub(parties[1].termMatrices[2][3][3][1], big.NewInt(1))
	}

	verifyMultShares(parties)
	if test == "TestShareMismatchStep1Mult" {
		results.sumOfComplaintsMult = countAllComplaints(parties)
	}

	broadcastComplaints(parties)
	if test == "TestRefuseBroadcastStep1Mult" {
		ignoreAccusationsMult(parties)
	} else {
		resolveComplaints(parties)
	}

	if test == "TestReconstructionOfValueAfterMultShareSending" {
		sum := big.NewInt(0)
		k := parties[0].computeNumberOfShares()
		for i := 0; i < k; i++ {
			for j := 0; j < k; j++ {
				qualifiedPlayer := computeIntersection(parties[0].distributionSet[i], parties[0].distributionSet[j])[0]

				sumOfTermShares := big.NewInt(0)
				sumOfTermShares.Add(sumOfTermShares, parties[2].termMatrices[qualifiedPlayer][i][j][0])
				sumOfTermShares.Add(sumOfTermShares, parties[0].termMatrices[qualifiedPlayer][i][j][1])
				sumOfTermShares.Add(sumOfTermShares, parties[0].termMatrices[qualifiedPlayer][i][j][2])
				sumOfTermShares.Add(sumOfTermShares, parties[0].termMatrices[qualifiedPlayer][i][j][3])

				sum.Add(sum, sumOfTermShares)
			}
		}
		sum.Mod(sum, parties[0].Domain)
		results.sharedMultValue = sum
	}

	// check if any party aborted in the above step
	partiesAborted := checkForAborts(parties)
	if partiesAborted {
		results.exitCodeMult = Abort
	}
}

// Step 2+3+4 of active multiplication protocol with adversary
func handleTermsForTest(parties []*Party, ins Instruction, results *TestResults) {
	// Create all termCombinations
	numberOfShares := parties[0].computeNumberOfShares()
	termCombinations := createTermCombinations(numberOfShares)

	// Iterate over termCombinations for each party
	for _, term := range termCombinations {
		computeDifferences(parties, term)
		reconstructNeeded := checkForReconstruct(parties)
		if reconstructNeeded {
			// fmt.Printf("reconstruction needed for term (%d,%d)\n", term.i, term.j)
			reconstructFactors(parties, term, ins)
			results.reconstructions++
		}
		addTermToResults(parties, reconstructNeeded, term, ins)
	}

	for _, p := range parties {
		p.moveProductFromBuffer(ins)
	}
}

// Initial VSS sharing with adversary
func VSSShareForTests(parties []*Party, test string, results *TestResults) {
	var wg sync.WaitGroup

	// Send secret shares between parties
	shareInit(parties)
	if test == "TestShareMismatch" ||
		test == "TestRefuseBroadcast" ||
		test == "TestAcceptBroadcast" {
		// We decrease party 0'es share 4 from party 1 by one, to test that the other parties will complain about mismatch.
		// Party 0 receives shares with index 4-9
		// For this test we say that the adversary is party 1
		parties[0].shares[1][4].Sub(parties[0].shares[1][4], big.NewInt(1))
	}

	for _, p := range parties {
		go p.receiveVerifications(&wg)
	}
	for _, p := range parties {
		wg.Add(1)
		go p.verifyShares()

		if test == "TestIllegalVerificationSending" && p.partyNumber == 1 {
			// Send illegal verifications
			// Party 1 is not part of access structure set 0
			// Access structure set 0 contains parties 2, 3 and 4

			for _, partyNumber := range p.distributionSet[0] {
				shares := makeZeroShares(p.totalNoOfParties)
				payload := Payload{shares: shares, shareIndex: 0}
				message := Message{messageType: VerifyInit, sender: p.partyNumber, receiver: partyNumber, payload: payload}
				p.outgoingMessages <- message
			}
		}
	}
	wg.Wait()
	if test == "TestIllegalComplaints" {
		// inject illegal complaint into party 1's complaints

		// party 1 is not in qualified set 0. Attempt to get party 2 to broadcast its share 0
		payload := Payload{shareIndex: 0, accusedParty: 2}
		complaint := Message{messageType: InitComplaint, sender: 1, receiver: 2, payload: payload}
		parties[1].complaints = append(parties[1].complaints, complaint)
	}

	sumOfComplaints := countAllComplaints(parties)
	broadcastComplaints(parties)
	if test == "TestIllegalComplaints" {
		// remove the complaint from the party since the protocol cannot proceed otherwise
		parties[1].complaints = make([]Message, 0)
		// Count number of complaints again and see that they are unchanged
		sumOfComplaints = countAllComplaints(parties)
	}

	for _, p := range parties {
		wg.Add(1)
		copyOfComplaints := make([]Message, len(p.complaints))
		copy(copyOfComplaints, p.complaints)
		if test == "TestRefuseBroadcast" && p.partyNumber == 1 {
			go p.ignoreAccusations(copyOfComplaints)
		} else {
			go p.handleAccusations(copyOfComplaints)
		}
		go p.receiveDisputes(&wg)
	}
	wg.Wait()

	partiesAborted := checkForAborts(parties)
	if partiesAborted {
		results.exitCodeShare = Abort
		return
	}

	// create results
	results.sumOfComplaintsShare = sumOfComplaints
	results.exitCodeShare = Success
}

// Models and adversary ignoring an accusation in the initial VSS share of the active MPC protocol
func (p *Party) ignoreAccusations(complaints []Message) {
	for _, c := range complaints {
		if c.payload.accusedParty == p.partyNumber {
			shareToSend := []*big.Int{p.shares[p.partyNumber][c.payload.shareIndex]}
			payload := Payload{shares: shareToSend, shareIndex: c.payload.shareIndex}
			for i := 0; i < p.totalNoOfParties; i++ {
				if i == 3 {
					p.outgoingMessages <- Message{messageType: Refuse, receiver: 3}
				} else {
					messageToBroadcast := Message{messageType: DisputedInitShare, receiver: i, sender: p.partyNumber, payload: payload}
					p.outgoingMessages <- messageToBroadcast
				}
			}
		}
	}
}

// Models the Resolve Complaints phase of the active multiplication protocol with adversary
func ignoreAccusationsMult(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		copyOfComplaints := make([]Message, len(p.complaints))
		copy(copyOfComplaints, p.complaints)
		// Let party 1 be corrupt
		if p.partyNumber == 1 {
			go p.ignoreAccusationsMult(copyOfComplaints)
		} else {

			go p.handleAccusations(copyOfComplaints)
		}
		go p.receiveDisputes(&wg)
	}
	wg.Wait()
}

// Models a corrupt party ignoring an accusation in step 1 of the active multiplication protocol
func (p *Party) ignoreAccusationsMult(complaints []Message) {
	for _, c := range complaints {
		if c.payload.accusedParty == p.partyNumber {
			i := c.payload.termIndex.i
			j := c.payload.termIndex.j
			shareIndex := c.payload.shareIndex
			shareToSend := []*big.Int{p.termMatrices[p.partyNumber][i][j][shareIndex]}
			payload := Payload{shares: shareToSend, shareIndex: shareIndex, termIndex: IndexPair{i: i, j: j}}
			for i := 0; i < p.totalNoOfParties; i++ {
				// Let the party ignore a complaint
				if i == 3 {
					p.outgoingMessages <- Message{messageType: Refuse, receiver: 3}
				} else {
					messageToBroadcast := Message{messageType: DisputedMultShare, receiver: i, sender: p.partyNumber, payload: payload}
					p.outgoingMessages <- messageToBroadcast
				}
			}
		}
	}
}
