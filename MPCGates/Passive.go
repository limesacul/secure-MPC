/*
This file contains the functions of the passive MPC protocol
*/

package Gates

import (
	"fmt"
	"math/big"
	"sync"
)

// The passive MPC protocol taking as input a list of instructions and a set of participating parties
func MPCProtocolPassive(instructions []Instruction, parties []*Party) {
	// Reset each party
	resetFields(parties, len(instructions))

	// First phase of protocol: Send secret shares between parties
	shareInit(parties)

	// Second phase of protocol: Execute the instructions of MPC function
	executeInstructionsPassive(parties, instructions)

	// Third phase of the protocol: Reconstruct the function of the secrets
	reconstructResultPassive(parties)
}

// Spawns and waits for the goroutines that sends and receives shares the parties' secrets
func shareInit(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.receiveInitShares(&wg)
		go p.sendInitShares()
	}
	// Wait for all parties to receive all shares
	wg.Wait()
}

// Executes each instruction in the list of instructions.
// At the end of this function, each party has shares of the result stored in their intermediary results
func executeInstructionsPassive(parties []*Party, instructions []Instruction) {
	for _, ins := range instructions {
		if ins.instructionType == Add {
			// Run add protocol
			addition(parties, ins)

		} else if ins.instructionType == Mult {
			// Run mult protocol
			passiveMultiplication(parties, ins)
		} else {
			panic(fmt.Sprintf("Error: illegal instruction type id %d \n", ins.instructionType))
		}
	}
}

// Locally computes the addition of the two operands at each party
func addition(parties []*Party, instruction Instruction) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.beginAddition(&wg, instruction)
	}
	wg.Wait()
}

// Multiplication procol in the passive case.
// Each party has the partition as well as the operands needed to execute the input multiplication instruction
func passiveMultiplication(parties []*Party, ins Instruction) {
	// Spawn and wait for the goroutines that sends and receives mult shares
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.sendMultShares(ins)
		go p.receiveMultSharesPassive(&wg)
	}
	wg.Wait()

	for _, p := range parties {
		p.moveProductFromBuffer(ins)
	}
}

// Spawns and waits for the goroutines that sends and receives shares of the result
func reconstructResultPassive(parties []*Party) {
	var wg sync.WaitGroup
	for _, p := range parties {
		wg.Add(1)
		go p.sendResultShares()
		go p.receiveResultShares(&wg)
	}
	wg.Wait()
}

// Computes the addition of the two operands specified by the instruction
// All shares have been distributed beforehand so no communication is needed with other parties
func (p *Party) beginAddition(wg *sync.WaitGroup, ins Instruction) {
	defer wg.Done()

	operand1 := p.getOperand(ins.operand1)
	operand2 := p.getOperand(ins.operand2)

	p.intermediaries[ins.instructionNo] = addShareSlices(operand1, operand2)
}

// Sends shares of the party's secret
func (p *Party) sendInitShares() {
	messageType := InitShare
	p.sendShares(p.secret, messageType)
}

// Receives shares of the secrets of all other parties
func (p *Party) receiveInitShares(wg *sync.WaitGroup) {
	defer wg.Done()
	sharesReceived := 0
	for {
		message := <-p.incomingMessages

		if message.messageType == InitShare {
			//store received shares
			p.shares[message.sender] = message.payload.shares
			sharesReceived++
			if sharesReceived == p.totalNoOfParties {
				// return when shares has been received from all parties
				return
			}
		} else {
			panic(fmt.Sprintf("expected only init share messages during initial sharing phase of protocol, instead received %s", message.messageType))
		}
	}
}

// Sends shares of the sum of the terms in the party's subset of the partition
func (p *Party) sendMultShares(ins Instruction) {
	sumOfSubset := p.computeSumOfSubset(ins)
	messageType := MultShare
	p.sendShares(sumOfSubset, messageType)
}

// Receives shares of the sum of subsets from all parties
func (p *Party) receiveMultSharesPassive(wg *sync.WaitGroup) {
	defer wg.Done()
	multSharesReceived := 0
	for {
		message := <-p.incomingMessages

		if message.messageType == MultShare {
			// Add the received shares to a the temporary result buffer
			p.resultBuffer = addShareSlices(p.resultBuffer, message.payload.shares)
			multSharesReceived++
			if multSharesReceived == p.totalNoOfParties {
				// return when shares has been received from all parties
				return
			}
		} else {
			panic(fmt.Sprintf("expected only mult share messages during multiplication protocol, instead received %s", message.messageType))
		}
	}
}

// Sends out the party's shares of the result to all parties
// TODO: Rename
func (p *Party) sendResultShares() {
	for i := 0; i < p.totalNoOfParties; i++ {
		resultShares := p.getResultShares()
		p.outgoingMessages <- Message{messageType: ResultShare, sender: p.partyNumber, receiver: i, payload: Payload{shares: resultShares}}
	}
}

// Receives shares of the result from all parties in order to complete the result share slice
func (p *Party) receiveResultShares(wg *sync.WaitGroup) {
	defer wg.Done()
	sharesReceived := 0
	for {
		message := <-p.incomingMessages

		if message.messageType == ResultShare {
			p.collectUniqueResultShares(message.payload.shares) // Adds any shares that have not been seen to the result
			sharesReceived++
			if sharesReceived == p.totalNoOfParties {
				// Compute the result and return when shares has been received from all parties
				p.MPCResult = p.computeResult()
				return
			}
		} else {
			panic(fmt.Sprintf("expected only result shares during reconstruction phase of protocol, instead received %s", message.messageType))
		}
	}
}

// Moves the result of a multiplication instruction from the result buffer into the intermediaries
func (p *Party) moveProductFromBuffer(ins Instruction) {
	copy(p.intermediaries[ins.instructionNo], p.resultBuffer)
	p.clearResultBuffer()
}

// UTILITY FUNCTIONS

// Computes the sum of the terms in the party's subset of the partition
func (p *Party) computeSumOfSubset(ins Instruction) *big.Int {
	// Collect the shares of s and t
	sShares := p.getOperand(ins.operand1)
	tShares := p.getOperand(ins.operand2)

	// Iterate over the partition subset of the party and sum up the products of shares from the two slices
	sum := big.NewInt(0)
	for _, pair := range p.partitionSubset {
		sShare := sShares[pair.i]
		tShare := tShares[pair.j]
		product := big.NewInt(0)
		product.Mul(sShare, tShare)
		sum.Add(sum, product)
	}

	return sum
}

// Collect any shares of the result that the party does not currently have
func (p *Party) collectUniqueResultShares(receivedShares Shares) {
	resultShares := p.getResultShares() // resultShares is a shallow copy so we can change its value to change the copied value too
	for i, f := range receivedShares {
		if f == nil {
			// The result share is nil so nothing needs to be done
			continue
		} else if resultShares[i] == nil {
			// The party does not have this result share, so it is added
			resultShares[i] = f
		} else if resultShares[i].Cmp(f) != 0 {
			// The party disagrees with the value of the received result share
			// Should not happen in the passive case
			panic(fmt.Sprintf("party %d received result share with wrong value at index %d. Party had value %s, received %s \n",
				p.partyNumber, i, resultShares[i].String(), f.String()))
		}

		// The party agrees with the received share so nothing needs to be done
	}
}

// Clears the result buffer in preparation for a new multiplication instruction
func (p *Party) clearResultBuffer() {
	k := p.computeNumberOfShares()
	p.resultBuffer = make(Shares, k)
}
