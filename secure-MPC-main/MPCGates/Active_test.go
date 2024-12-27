/*
This file containts tests for Active.go
*/

package Gates

import (
	"fmt"
	"math/big"
	"testing"
)

func multInstructionForTest() []Instruction {
	ins1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}
	return []Instruction{ins1}
}

func createSecrecyStructureForActiveTests() Structure {
	return Structure{[]int{0, 1}, []int{2}, []int{3}, []int{4}}
}

func createAdversaryStructureForActiveTests() Structure {
	return createSecrecyStructureForActiveTests()
}

func TestWellBehavedShareSending(t *testing.T) {
	ss := createSecrecyStructureForTests(3)
	parties := startNetwork(3, ss, nil, testDomain())

	instructions := addInstructionForTest()

	exitCode := MPCProtocolActive(instructions, parties)

	if exitCode != Success {
		t.Errorf("expected the protocol to terminate succesfully with well-behaved parties")
	}
}

func TestShareMismatch(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	instructions := addInstructionForTest()

	test := "TestShareMismatch"
	results := MPCProtocolForTests(instructions, parties, test)
	if results.sumOfComplaintsShare != 3 {
		t.Errorf("expected the number of complaints to be 3, instead %d", results.sumOfComplaintsShare)
	}
}

func TestAcceptBroadcast(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	instructions := addInstructionForTest()

	test := "TestAcceptBroadcast"
	results := MPCProtocolForTests(instructions, parties, test)
	if results.exitCodeShare != Success {
		t.Errorf("expected protocol to terminate succesfully if the dealer accepts broadcast")
	}
}

func TestRefuseBroadcast(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	instructions := addInstructionForTest()

	test := "TestRefuseBroadcast"
	results := MPCProtocolForTests(instructions, parties, test)
	if results.exitCodeShare != Abort {
		t.Errorf("Expected honest parties to abort the protocol upon refusal to broadcast, instead exitcode was %d", results.exitCodeShare)
	}
}

func TestIllegalVerificationSending(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	instructions := addInstructionForTest()

	test := "TestIllegalVerificationSending"
	results := MPCProtocolForTests(instructions, parties, test)
	if results.exitCodeShare != Success || results.sumOfComplaintsShare != 0 {
		t.Errorf("expected the number of complaints to be 0 and exitCode to be %d, instead number of complaints was %d and exitCode was %d",
			Success, results.sumOfComplaintsShare, results.exitCodeShare)
	}
}

func TestIllegalComplaints(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	instructions := addInstructionForTest()

	test := "TestIllegalComplaints"
	results := MPCProtocolForTests(instructions, parties, test)
	if results.sumOfComplaintsShare != 0 || results.exitCodeShare != Success {
		t.Errorf("expected the number of complaints to be 0 and exitCode to be %d, instead number of complaints was %d and exitCode was %d",
			Success, results.sumOfComplaintsShare, results.exitCodeShare)
	}
}

func TestMultShareSending(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())

	MPCProtocolActive(multInstructionForTest(), parties)
	p0 := parties[0]
	k := p0.computeNumberOfShares()
	// iterate over all termmatrices
	for n := 0; n < 5; n++ {
		// iterate over all s values
		for i := 0; i < k; i++ {
			// iterate over all t values
			for j := 0; j < k; j++ {
				// check if party n should have sent shares of this term
				if setContains(p0.distributionSet[i], n) && setContains(p0.distributionSet[j], n) {
					// iterate over the shares that party 0 should receive
					for s := 1; s < 4; s++ {
						// check if the party received the share
						if p0.termMatrices[n][i][j][s] == nil {
							t.Errorf("expected party 0 to receive shares of term (%d, %d) from party %d, did not receive share %d", i, j, n, s)
						}
					}
				} else {
					// check if party 0 has received any shares of term s_it_j from party n
					for s := 0; s < 4; s++ {
						shareValue := p0.termMatrices[n][i][j][s]
						if shareValue != nil {
							t.Errorf("did not expect party 0 to receive any shares of term (%d, %d) from party %d, received share %d with value %d", i, j, n, s, shareValue)
						}
					}
				}

			}
		}
	}

}

func TestShareMismatchStep1Mult(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())

	test := "TestShareMismatchStep1Mult"
	results := MPCProtocolForTests(multInstructionForTest(), parties, test)
	if results.sumOfComplaintsMult != 3 {
		t.Errorf("Expected 3 complaints, instead had %d", results.sumOfComplaintsMult)
	}
}

func TestAcceptBroadcastStep1Mult(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())

	test := "TestAcceptBroadcastStep1Mult"
	results := MPCProtocolForTests(multInstructionForTest(), parties, test)
	if results.exitCodeMult != Success {
		t.Errorf("expected protocol to terminate succesfully if the dealer accepts broadcast")
	}
	if parties[0].termMatrices[1][1][1][4].Cmp(parties[1].termMatrices[1][1][1][4]) != 0 {
		t.Errorf("Expected party 0 to have received party 1's broadcast and to have taken this broadcasted value. Party 0's share is %s \n while party 1's share is %s \n", parties[0].termMatrices[1][1][1][4].String(), parties[1].termMatrices[1][1][1][4].String())
	}
}

func TestRefuseBroadcastStep1Mult(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())

	test := "TestRefuseBroadcastStep1Mult"
	results := MPCProtocolForTests(multInstructionForTest(), parties, test)
	if results.exitCodeMult != Abort {
		t.Errorf("Expected honest parties to abort the protocol upon refusal to broadcast, instead exitcode was %d", results.exitCodeShare)
	}
}

func TestReconstructionOfValueAfterMultShareSending(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	parties := startNetwork(5, ss, nil, testDomain())
	parties[0].secret = big.NewInt(6)
	parties[1].secret = big.NewInt(5)

	test := "TestReconstructionOfValueAfterMultShareSending"
	results := MPCProtocolForTests(multInstructionForTest(), parties, test)
	if results.sharedMultValue.Cmp(big.NewInt(30)) != 0 {
		t.Errorf("expected the value shared in mult to be 30, instead %s", results.sharedMultValue.String())
	}
}

func TestWellBehavedStep2Mult(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())

	test := "TestWellBehavedStep2Mult"
	results := MPCProtocolForTests(multInstructionForTest(), parties, test)
	if results.reconstructions != 0 {
		t.Errorf("did not expect any reconstructions, instead %d", results.reconstructions)
	}
}

func TestWrongTermValue(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())

	test := "TestWrongTermValue"
	results := MPCProtocolForTests(multInstructionForTest(), parties, test)
	if results.reconstructions != 3 {
		t.Errorf("Expected 3 reconstructions to happen, instead had %d reconstructions happen", results.reconstructions)
	}

	p0Result := parties[0].MPCResult
	for partyNumber, p := range parties {
		if p0Result.Cmp(p.MPCResult) != 0 {
			t.Errorf("Expected party %d to have same result as party 0 \n instead party %d result: %s \n party 0 result: %s", partyNumber, partyNumber, p.MPCResult.String(), p0Result)
		}
	}
}

func TestCompleteShareSlice(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	adversaryStructure := [][]int{{0}, {1}, {2}}
	parties := startNetwork(5, ss, adversaryStructure, testDomain())

	p := parties[0]
	// Number of shares does not match number of parties, but it's not necessary
	receivedSlice1 := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(6)}
	receivedSlice2 := []*big.Int{big.NewInt(10), big.NewInt(5), nil, big.NewInt(6)}
	receivedSlice3 := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(6)}
	receivedSlices := [][]*big.Int{receivedSlice1, receivedSlice2, receivedSlice3}
	supposedCorrectShareValues := p.completeShareSlice(receivedSlices)
	actualCorrectShareValues := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(6)}
	for i, correctValue := range actualCorrectShareValues {
		if supposedCorrectShareValues[i].Cmp(correctValue) != 0 {
			fmt.Println("Returned length of 'correct' slice is", len(supposedCorrectShareValues))
			t.Errorf("Expected value %d to be %s. Instead was %s", i, correctValue.String(), supposedCorrectShareValues[i].String())
		}
	}
}

func TestSameResultForInputFunction(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())

	MPCProtocolActive(multInstructionForTest(), parties)
	locationOfResult := len(parties[0].intermediaries) - 1
	p0Result := parties[0].intermediaries[locationOfResult]
	k := len(p0Result)
	for _, p := range parties {
		for i := 0; i < k; i++ {
			if p.intermediaries[locationOfResult][i] == nil {
				t.Errorf("expected party %d to have all shares of the result, instead share %d was missing", p.partyNumber, i)
			}

			if p.intermediaries[locationOfResult][i].Cmp(p0Result[i]) != 0 {
				t.Errorf("expected party %d and party 0 to have same values in intermediaries, instead: \n %s \n %s",
					p.partyNumber, sharesToString(p.intermediaries[locationOfResult]), sharesToString(p0Result))
			}
		}
	}
}

func TestSingleAdditionActive(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())
	parties[1].secret = big.NewInt(21)
	parties[2].secret = big.NewInt(21)

	i1 := Instruction{instructionType: Add, operand1: 1, operand2: 2, instructionNo: 0}
	ins := []Instruction{i1}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(42)) != 0 {
			t.Errorf("Expected party %d to have result 42, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestAdditionCustomSecrecyStructureActive(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())
	parties[0].secret = big.NewInt(42)
	parties[1].secret = big.NewInt(21)

	i1 := Instruction{instructionType: Add, operand1: 0, operand2: 1, instructionNo: 0}
	ins := []Instruction{i1}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(63)) != 0 {
			t.Errorf("Expected party %d to have result 63, instead %s \n", i, p.MPCResult.String())
		}
	}
}

//Addition for a+b+c+d
func TestAdditionWithIntermediariesActive(t *testing.T) {
	n := 5
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(n, ss, as, testDomain())
	parties[0].secret = big.NewInt(42)
	parties[1].secret = big.NewInt(21)
	parties[2].secret = big.NewInt(8)
	parties[3].secret = big.NewInt(28)

	i1 := Instruction{instructionType: Add, operand1: 0, operand2: 1, instructionNo: 0}
	i2 := Instruction{instructionType: Add, operand1: 2, operand2: 3, instructionNo: 1}
	// intermediary values produced by earlier instructions get operand index n plus the instruction number
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2}

	ins := []Instruction{i1, i2, i3}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(99)) != 0 {
			t.Errorf("Expected party %d to have result 00, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestMultiplicationOfTwoSharesActive(t *testing.T) {
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(5, ss, as, testDomain())
	parties[0].secret = big.NewInt(5)
	parties[1].secret = big.NewInt(3)

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}

	ins := []Instruction{i1}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(15)) != 0 {
			t.Errorf("Expected party %d to have result 15, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestIntermediariesActive(t *testing.T) {
	// testing the MPC of (a * b) + (c * d)
	n := 5
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(n, ss, as, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}        // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 1}        // multiplies c and d
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2} // add together result of the two earlier instructions

	ins := []Instruction{i1, i2, i3}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(23)) != 0 {
			t.Errorf("Expected party %d to have result 23, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestLargeCircuitActive(t *testing.T) {
	// testing the MPC of ((a * b) + (b * c)) * ((c * d) + (d * e))
	n := 5
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(n, ss, as, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d
	parties[4].secret = big.NewInt(6) // e

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}         // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 1, operand2: 2, instructionNo: 1}         // multiplies b and c
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2}  // add together i1 and i2
	i4 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 3}         // multiplies c and d
	i5 := Instruction{instructionType: Mult, operand1: 3, operand2: 4, instructionNo: 4}         // multiplies d and e
	i6 := Instruction{instructionType: Add, operand1: n + 3, operand2: n + 4, instructionNo: 5}  // add together i4 and i5
	i7 := Instruction{instructionType: Mult, operand1: n + 2, operand2: n + 5, instructionNo: 6} // multiplies i3 and i6

	ins := []Instruction{i1, i2, i3, i4, i5, i6, i7}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(672)) != 0 { // (5*3 + 3*2) * (2*4 + 4*6) = 672
			t.Errorf("Expected party %d to have result 672, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestMultipleMPCsActive(t *testing.T) {
	n := 5
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(n, ss, as, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}

	ins := []Instruction{i1}
	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(15)) != 0 {
			t.Errorf("Expected party %d to have result 15, instead %s \n", i, p.MPCResult.String())
		}
	}

	i1 = Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}         // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 1}        // multiplies c and d
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2} // add together result of the two earlier instructions

	ins = []Instruction{i1, i2, i3}

	MPCProtocolActive(ins, parties)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(23)) != 0 {
			t.Errorf("Expected party %d to have result 23, instead %s \n", i, p.MPCResult.String())
		}
	}
}

func TestMultipleAdversaryAttacks(t *testing.T) {
	n := 5
	ss := createSecrecyStructureForActiveTests()
	as := createAdversaryStructureForActiveTests()
	parties := startNetwork(n, ss, as, testDomain())
	parties[0].secret = big.NewInt(5) // a
	parties[1].secret = big.NewInt(3) // b
	parties[2].secret = big.NewInt(2) // c
	parties[3].secret = big.NewInt(4) // d

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}        // multiplies a and b
	i2 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 1}        // multiplies c and d
	i3 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2} // add together result of the two earlier instructions

	ins := []Instruction{i1, i2, i3}

	test := "TestMultipleAdversaryAttacks"
	MPCProtocolForTests(ins, parties, test)

	for i, p := range parties {
		if p.MPCResult.Cmp(big.NewInt(23)) != 0 {
			t.Errorf("Expected party %d to have result 23, instead %s \n", i, p.MPCResult.String())
		}
	}

}
