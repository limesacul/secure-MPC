/*
This file containts tests for Passive.go
*/

package Gates

import (
	"math/big"
	"testing"
)

func (p *Party) computeNumberOfSharesReceived() int {
	noOfSharesReceived := 0
	for _, slice := range p.shares {
		for _, share := range slice {
			if share != nil {
				noOfSharesReceived++
			}
		}
	}
	return noOfSharesReceived
}

func addInstructionForTest() []Instruction {
	ins1 := Instruction{instructionType: Add, operand1: 0, operand2: 1, instructionNo: 0}
	return []Instruction{ins1}
}

func TestSharesReceived3Parties(t *testing.T) {
	ss := createSecrecyStructureForTests(3)
	parties := startNetwork(3, ss, nil, testDomain())

	instructions := addInstructionForTest()

	MPCProtocolPassive(instructions, parties)

	if parties[0].computeNumberOfSharesReceived() != 6 {
		t.Errorf("Expected party 0 to have received 6 shares, instead received: %d \n", parties[0].computeNumberOfSharesReceived())
	}
	if parties[1].computeNumberOfSharesReceived() != 6 {
		t.Errorf("Expected party 1 to have received 6 shares, instead received: %d \n", parties[1].computeNumberOfSharesReceived())
	}
	if parties[2].computeNumberOfSharesReceived() != 6 {
		t.Errorf("Expected party 2 to have received 6 shares, instead received: %d \n", parties[2].computeNumberOfSharesReceived())
	}
}

func TestSharesReceived5Parties(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())

	ins := addInstructionForTest()

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.computeNumberOfSharesReceived() != 30 {
			t.Errorf("Expected party %d to have received 30 shares, instead received: %d  \n", i, p.computeNumberOfSharesReceived())
		}
	}
}

func TestSingleAddition(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	parties[1].secret = big.NewInt(21)
	parties[2].secret = big.NewInt(21)

	i1 := Instruction{instructionType: Add, operand1: 1, operand2: 2, instructionNo: 0}
	ins := []Instruction{i1}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(42)) != 0 {
			t.Errorf("Expected party %d to have result 42, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestAdditionCustomSecrecyStructure(t *testing.T) {
	ss := [][]int{{1, 2, 3}, {1, 4}, {2, 4}, {3, 4}, {5}}
	parties := startNetwork(5, ss, nil, testDomain())
	parties[0].secret = big.NewInt(42)
	parties[1].secret = big.NewInt(21)

	i1 := Instruction{instructionType: Add, operand1: 0, operand2: 1, instructionNo: 0}
	ins := []Instruction{i1}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(63)) != 0 {
			t.Errorf("Expected party %d to have result 63, instead %s \n", i, p.MPCResult.String())
		}
	}
}

//Addition for (a+b)+(c+d)
func TestAdditionWithIntermediaries(t *testing.T) {
	n := 5
	ss := createSecrecyStructureForTests(n)
	parties := startNetwork(n, ss, nil, testDomain())
	parties[0].secret = big.NewInt(42)
	parties[1].secret = big.NewInt(21)
	parties[2].secret = big.NewInt(8)
	parties[3].secret = big.NewInt(28)

	i1 := Instruction{instructionType: Add, operand1: 0, operand2: 1, instructionNo: 0}
	i2 := Instruction{instructionType: Add, operand1: 2, operand2: 3, instructionNo: 1}
	// intermediary values produced by earlier instructions get operand with index n plus the instruction number
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2}

	ins := []Instruction{i1, i2, i3}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(99)) != 0 {
			t.Errorf("Expected party %d to have result 99, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestMultiplicationOfTwoShares(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	parties[0].secret = big.NewInt(5)
	parties[1].secret = big.NewInt(3)

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}

	ins := []Instruction{i1}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(15)) != 0 {
			t.Errorf("Expected party %d to have result 15, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestIntermediaries(t *testing.T) {
	// testing the MPC of (a * b) + (c * d)
	n := 5
	ss := createSecrecyStructureForTests(n)
	parties := startNetwork(n, ss, nil, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}        // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 1}        // multiplies c and d
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2} // adds together i1 and i2

	ins := []Instruction{i1, i2, i3}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(23)) != 0 {
			t.Errorf("Expected party %d to have result 23, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestLargeCircuit(t *testing.T) {
	// testing the MPC of ((a * b) + (b * c)) * ((c * d) + (d * e))
	n := 5
	ss := createSecrecyStructureForTests(n)
	parties := startNetwork(n, ss, nil, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d
	parties[4].secret = big.NewInt(6) // e

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}         // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 1, operand2: 2, instructionNo: 1}         // multiplies b and c
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2}  // adds together i1 and i2
	i4 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 3}         // multiplies c and d
	i5 := Instruction{instructionType: Mult, operand1: 3, operand2: 4, instructionNo: 4}         // multiplies d and e
	i6 := Instruction{instructionType: Add, operand1: n + 3, operand2: n + 4, instructionNo: 5}  // adds together i4 and i5
	i7 := Instruction{instructionType: Mult, operand1: n + 2, operand2: n + 5, instructionNo: 6} // multiplies i3 and i6

	ins := []Instruction{i1, i2, i3, i4, i5, i6, i7}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(672)) != 0 { // (5*3 + 3*2) * (2*4 + 4*6) = 672
			t.Errorf("Expected party %d to have result 672, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestMultipleMPCs(t *testing.T) {
	n := 5
	ss := createSecrecyStructureForTests(n)
	parties := startNetwork(n, ss, nil, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}

	ins := []Instruction{i1}
	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(15)) != 0 {
			t.Errorf("Expected party %d to have result 15, instead %s \n", i, p.MPCResult.String())
		}
	}

	i1 = Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}         // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 1}        // multiplies c and d
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2} // add together result of the two earlier instructions

	ins = []Instruction{i1, i2, i3}

	MPCProtocolPassive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(23)) != 0 {
			t.Errorf("Expected party %d to have result 23, instead %s \n", i, p.MPCResult.String())
		}
	}

}
