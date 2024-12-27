/*
This file containts tests for Common.go
*/

package Gates

import (
	"math"
	"math/big"
	"reflect"
	"testing"
)

func testDomain() *big.Int {
	return big.NewInt(1000)
}

func createSecrecyStructureForTests(noOfParties int) [][]int {
	setOfParties := make([]int, noOfParties)
	threshold := computeCorruptionThreshold(noOfParties)
	secrecyStructure := make([][]int, 0)
	tmp := make([]int, threshold)

	for i := range setOfParties {
		setOfParties[i] = i
	}

	createCombinations(&secrecyStructure, setOfParties, tmp, 0, len(setOfParties)-1, 0, threshold)

	return secrecyStructure
}

// inspiration drawn from
// https://www.geeksforgeeks.org/print-subsets-given-size-set/
func createCombinations(secrecyStructure *[][]int, arr []int, data []int, start int, end int, index int, r int) {

	// Current combination is ready to be printed, add it to secrecy structure
	if index == r {
		combination := make([]int, len(data))
		copy(combination, data)
		*secrecyStructure = append(*secrecyStructure, combination)
		return
	}

	// replace index with all possible elements. The condition
	// "end-i+1 >= r-index" makes sure that including one element
	// at index will make a combination with remaining elements
	// at remaining positions
	for i := start; i <= end && end-i+1 >= r-index; i++ {
		data[index] = arr[i]
		createCombinations(secrecyStructure, arr, data, i+1, end, index+1, r)
	}
}

func computeNumberOfSharesForTest(noOfParties int) int {
	t := computeCorruptionThreshold(noOfParties)
	return binomialCoefficient(noOfParties, t)
}

func computeCorruptionThreshold(noOfParties int) int {
	return int(math.Ceil(float64(noOfParties)/2 - 1))
}

func binomialCoefficient(n int, choose int) int {
	return factorial(n) / (factorial(choose) * factorial(n-choose))
}

func factorial(n int) int {
	if n == 0 {
		return 1
	}
	return n * factorial(n-1)
}
func computeIntersectionOfIndexPairs(a, b []IndexPair) (c []IndexPair) {
	m := make(map[IndexPair]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			c = append(c, item)
		}
	}
	return
}

func TestSetup3Clients(t *testing.T) {
	ss := createSecrecyStructureForTests(3)
	domain := testDomain()
	parties := startNetwork(3, ss, nil, domain)
	if len(parties) != 3 {
		t.Errorf("Expected number of parties in 'parties' to be 3, instead was: %d", len(parties))
	}

	if (parties[0].outgoingMessages != parties[1].outgoingMessages) || (parties[0].outgoingMessages != parties[2].outgoingMessages) {
		t.Errorf("Expected the outgoing message channel of the parties to be the same for each party")
	}
}

func TestSecrecyStructure(t *testing.T) {
	ss1 := createSecrecyStructureForTests(3)
	goal1 := [][]int{{0}, {1}, {2}}

	if !reflect.DeepEqual(ss1, goal1) {
		t.Errorf("Secrecy structure was not created correctly for 3 parties \n secret structure is: %v \n target is: %v \n", ss1, goal1)
	}

	ss2 := createSecrecyStructureForTests(5)

	goal2 := [][]int{{0, 1}, {0, 2}, {0, 3}, {0, 4}, {1, 2}, {1, 3}, {1, 4}, {2, 3}, {2, 4}, {3, 4}}

	if !reflect.DeepEqual(ss2, goal2) {
		t.Errorf("Secrecy structure was not created correctly for 5 parties \n secret structure is: %v \n target is: %v \n", ss2, goal2)
	}

	ss3 := createSecrecyStructureForTests(10)

	if len(ss3) != 210 {
		t.Errorf("expected secrecy structure to have size 210 for 10 parties, instead %d", len(ss2))
	}
}

func TestAccessStructure(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	as := createDistributionSet(5, ss)

	goal := [][]int{{2, 3, 4}, {1, 3, 4}, {1, 2, 4}, {1, 2, 3}, {0, 3, 4}, {0, 2, 4}, {0, 2, 3}, {0, 1, 4}, {0, 1, 3}, {0, 1, 2}}

	if !reflect.DeepEqual(as, goal) {
		t.Errorf("Access structure was not created correctly for 5 parties \n access structure is: %v \n target is: %v \n", as, goal)
	}
}

func TestIntersectionOfPartitionSubsetsIsEmpty(t *testing.T) {
	noOfParties := 3
	ss := createSecrecyStructureForTests(noOfParties)
	accessStructure := createDistributionSet(noOfParties, ss)
	partition := createPartition(noOfParties, accessStructure)

	for i, u := range partition {
		for j, v := range partition {
			if i != j {
				intersection := computeIntersectionOfIndexPairs(u, v)
				if len(intersection) != 0 {
					t.Errorf("Intersection of subsets and U should be empty, instead had elements: %v", intersection)
				}
			}
		}
	}
}

func TestPartitionContainsAllPairs3Parties(t *testing.T) {
	noOfParties := 3
	ss := createSecrecyStructureForTests(noOfParties)
	accessStructure := createDistributionSet(noOfParties, ss)
	partition := createPartition(noOfParties, accessStructure)
	k := computeNumberOfSharesForTest(noOfParties)
	for i := 0; i < k; i++ { // iterate through all values i, where 0<=i<=k
		for j := 0; j < k; j++ { // iterate through all values j, where 0<=j<=k
			pair := IndexPair{i: i, j: j}
			foundPair := false
			for _, ss := range partition { // iterate through all partition subsets of U
				if foundPair {
					break
				}
				for _, p := range ss { // iterate through all elements in subset partition
					if p == pair {
						// found pair (i,j) in U
						foundPair = true
						break
					}
				}
			}
			if !foundPair {
				t.Errorf("did not find pair %v in U", pair)
			}
		}
	}
}

func TestPartitionContainsAllPairs5Parties(t *testing.T) {
	noOfParties := 5
	ss := createSecrecyStructureForTests(noOfParties)
	accessStructure := createDistributionSet(noOfParties, ss)
	partition := createPartition(noOfParties, accessStructure)
	k := computeNumberOfSharesForTest(noOfParties)
	for i := 0; i < k; i++ { // iterate through all values i, where 0<=i<=k
		for j := 0; j < k; j++ { // iterate through all values j, where 0<=j<=k
			pair := IndexPair{i: i, j: j}
			foundPair := false
			for _, ss := range partition { // iterate through all partition subsets of U
				if foundPair {
					break
				}
				for _, p := range ss { // iterate through all elements in subset partition
					if p == pair {
						// found pair (i,j) in U
						foundPair = true
						break
					}
				}
			}
			if !foundPair {
				t.Errorf("did not find pair %v in U", pair)
			}
		}
	}
}

func Test3PartiesHaveSharesInPartitionSubset(t *testing.T) {
	ss := createSecrecyStructureForTests(3)
	parties := startNetwork(3, ss, nil, testDomain())
	iParty := 1
	jParty := 2
	parties[0].secret = big.NewInt(5)
	parties[1].secret = big.NewInt(3)

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}

	ins := []Instruction{i1}
	MPCProtocolPassive(ins, parties)

	for partyNo, p := range parties {
		for _, pair := range p.partitionSubset {
			foundi := p.shares[iParty][pair.i] != nil // tests if the party has share i
			foundj := p.shares[jParty][pair.j] != nil // tests if the party has share j

			if !foundi {
				t.Errorf("party %d did not receive share with index %d from party %d, but pair %v was in party's subset", partyNo, pair.i, iParty, pair)
			}
			if !foundj {
				t.Errorf("party %d did not receive share with index %d from party %d, but pair %v was in party's subset", partyNo, pair.j, jParty, pair)
			}
		}
	}
}

func Test5PartiesHaveSharesInPartitionSubset(t *testing.T) {
	ss := createSecrecyStructureForTests(5)
	parties := startNetwork(5, ss, nil, testDomain())
	iParty := 1
	jParty := 2
	parties[0].secret = big.NewInt(5)
	parties[1].secret = big.NewInt(3)

	i1 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}

	ins := []Instruction{i1}
	MPCProtocolPassive(ins, parties)

	for partyNo, p := range parties {
		for _, pair := range p.partitionSubset {
			foundi := p.shares[iParty][pair.i] != nil // tests if the party has share i
			foundj := p.shares[jParty][pair.j] != nil // tests if the party has share j

			if !foundi {
				t.Errorf("party %d did not receive share with index %d from party %d, but pair %v was in party's subset", partyNo, pair.i, iParty, pair)
			}
			if !foundj {
				t.Errorf("party %d did not receive share with index %d from party %d, but pair %v was in party's subset", partyNo, pair.j, jParty, pair)
			}
		}
	}
}

func TestPartitionLengths(t *testing.T) {
	ss1 := createSecrecyStructureForTests(3)
	p1 := createPartition(3, createDistributionSet(3, ss1))

	totalLength := func(p [][]IndexPair) int {
		sum := 0
		for _, u := range p {
			sum += len(u)
		}
		return sum
	}

	if len(p1) != 3 {
		t.Errorf("U should have length 3 but had %d", len(p1))
	}
	if totalLength(p1) != 9 {
		t.Errorf("The total length of subsets should be 9, but was %d", totalLength(p1))
	}

	ss2 := createSecrecyStructureForTests(5)
	p2 := createPartition(5, createDistributionSet(5, ss2))

	if len(p2) != 5 {
		t.Errorf("U should have length 5 but had %d", len(p2))
	}
	if totalLength(p2) != 100 {
		t.Errorf("The total length of subsets should be 100, but was %d", totalLength(p1))
	}

	ss3 := createSecrecyStructureForTests(10)
	p3 := createPartition(10, createDistributionSet(10, ss3))

	if len(p3) != 10 {
		t.Errorf("U should have length 10 but had %d", len(p2))
	}
	if totalLength(p3) != 44100 {
		t.Errorf("The total length of subsets should be 44100, but was %d", totalLength(p1))
	}
}

func TestQSquaredCondition(t *testing.T) {
	correctSs := [][]int{{0, 1, 2}, {0, 3}, {1, 3}, {2, 3}, {4}}
	wrongSs := [][]int{{0, 1, 2}, {3, 4}}

	if !qSquaredConditionHolds(5, correctSs) {
		t.Errorf("Expected Q^2 condition to hold for this ss: \n %v \n", correctSs)
	}
	if qSquaredConditionHolds(5, wrongSs) {
		t.Errorf("Did not expect Q^2 condition to hold for this ss: \n %v \n", wrongSs)
	}
}

func TestAdversaryAndSecrecyStructureConditions(t *testing.T) {
	noOfParties := 7
	correctSs := [][]int{{0, 1, 2, 3}, {4}, {5}, {6}}
	notSubset := [][]int{{0}, {1, 2, 3, 4}, {5}, {6}}

	holds, _ := adversaryConditionsHold(noOfParties, correctSs, notSubset)
	if holds {
		t.Errorf("Did not expect adversary condition to hold for adversary structure %v that is not subset of secrecy structure %v", notSubset, correctSs)
	}

	incorrectSs := [][]int{{0, 1, 2, 3}, {3, 4, 5, 6}}
	incorrectAs := [][]int{{0, 1, 2}, {3}, {4}, {5}, {6}}
	holds, _ = adversaryConditionsHold(noOfParties, incorrectSs, incorrectAs)

	if holds {
		t.Errorf("Did not expect adversary condition to hold for illegal secrecy structure / adversary structure %v %v", incorrectSs, incorrectAs)
	}

	correctAs := [][]int{{0, 1, 3}, {2}, {4}, {5}, {6}}
	holds, errorMsg := adversaryConditionsHold(noOfParties, correctSs, correctAs)

	if !holds {
		t.Errorf("Expected conditions to hold for correct advesary structure %v and secrecy structure %v. \n Error message: %s", correctAs, correctSs, errorMsg)
	}

}
