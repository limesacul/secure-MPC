package Gates

import (
	"fmt"
	"math"
	"math/big"
	"testing"
)

const (
	standardPartyNumber = 5
)

var numberOfPartiesTable = []struct {
	numberOfParties int
}{
	{numberOfParties: 4},
	{numberOfParties: 5},
	{numberOfParties: 6},
	{numberOfParties: 7},
	{numberOfParties: 8},
	{numberOfParties: 9},
	{numberOfParties: 10},
}

var domainSizeTable = []struct {
	size *big.Int
}{
	{size: big.NewInt(2)},
	{size: big.NewInt(101)},
	{size: big.NewInt(1001)},
	{size: big.NewInt(10001)},
	{size: big.NewInt(100001)},
	{size: big.NewInt(1000001)},
	{size: big.NewInt(10000001)},
	{size: big.NewInt(100000001)},
}

// Can be used for varying secrecy structure with subsets size 1
func createMinimalSecrecyStructure(numberOfParties int) [][]int {
	secrecyStructure := make([][]int, numberOfParties)
	for i := 0; i < numberOfParties; i++ {
		secrecyStructure[i] = append(secrecyStructure[i], i)
	}
	return secrecyStructure
}

func createIncreasingSecrecyStructuresSubsetSize3Parties10() [][][]int {
	secrecyStructures := make([][][]int, 0)

	sizeThreeInput := []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, input := range sizeThreeInput {
		secrecyStructures = append(secrecyStructures, createSecrecyStructureForTestsActive(10)[:input])
	}

	return secrecyStructures
}

// Excludes the final addition in each sub-list
func createIncreasingInstructionsMixed(n int) [][]Instruction {
	// Initialize the return list and add a*b to first entry
	instructions := make([][]Instruction, 0)
	i0 := []Instruction{{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}}
	instructions = append(instructions, i0)

	for i := 0; i < 10; i++ {
		tempList := make([]Instruction, 0)
		tempList = append(tempList, i0...)
		instructionCounter := 1
		for j := 0; j < i+1; j++ {
			for k := 0; k < 5; k++ {
				multInstruction := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: instructionCounter}
				addInstruction := Instruction{instructionType: Add, operand1: n + instructionCounter - 1, operand2: n + instructionCounter, instructionNo: instructionCounter + 1}
				tempList = append(tempList, multInstruction, addInstruction)
				instructionCounter += 2
			}
		}
		instructions = append(instructions, tempList[:len(tempList)-1])
	}
	return instructions
}

// Excludes the final multiplication in each sub-list
func createIncreasingInstructionsSame(instructionType InstructionType, n int) [][]Instruction {
	// Initialize the return list and add 'a (operand) b' to first entry
	instructions := make([][]Instruction, 0)
	aAndBOperation := []Instruction{{instructionType: instructionType, operand1: 0, operand2: 1, instructionNo: 0}}
	instructions = append(instructions, aAndBOperation)

	for i := 1; i < 10; i++ {
		tempList := make([]Instruction, 0)
		tempList = append(tempList, aAndBOperation...)
		instructionCounter := 1
		for j := 0; j < i+1; j++ {
			for k := 0; k < 10; k++ {
				resultAndBOperation := []Instruction{{instructionType: instructionType, operand1: n + instructionCounter - 1, operand2: 0, instructionNo: instructionCounter}}
				tempList = append(tempList, resultAndBOperation...)
				instructionCounter++
			}
		}
		instructions = append(instructions, tempList[:len(tempList)-1])
	}
	return instructions
}

//(a*b)+(c*d)
func createStandardInstructions(n int) []Instruction {
	i0 := Instruction{instructionType: Mult, operand1: 0, operand2: 1, instructionNo: 0}        // Multiply a*b
	i1 := Instruction{instructionType: Mult, operand1: 2, operand2: 3, instructionNo: 1}        // Multiply c*d
	i2 := Instruction{instructionType: Add, operand1: n + 0, operand2: n + 1, instructionNo: 2} // Add (a*b)+(c*d) to intermediaries

	ins := []Instruction{i0, i1, i2}

	return ins
}

func createStandardDomainSize() *big.Int {
	return big.NewInt(100)
}

func createSecrecyStructureForTestsActive(noOfParties int) [][]int {
	setOfParties := make([]int, noOfParties)
	threshold := computeCorruptionThresholdActive(noOfParties)
	secrecyStructure := make([][]int, 0)
	tmp := make([]int, threshold)

	for i := range setOfParties {
		setOfParties[i] = i
	}

	createCombinations(&secrecyStructure, setOfParties, tmp, 0, len(setOfParties)-1, 0, threshold)

	return secrecyStructure
}

func computeCorruptionThresholdActive(noOfParties int) int {
	return int(math.Ceil(float64(noOfParties)/3 - 1))
}

func BenchmarkPassive(b *testing.B) {
	for _, v := range numberOfPartiesTable {
		parties := startNetwork(v.numberOfParties, createSecrecyStructureForTestsActive(v.numberOfParties), nil, createStandardDomainSize())
		ins := createStandardInstructions(v.numberOfParties)
		b.Run(fmt.Sprintf("Number of parties (maximal): %d", v.numberOfParties), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolPassive(ins, parties)
			}
		})
	}

	for _, v := range numberOfPartiesTable {
		parties := startNetwork(v.numberOfParties, createMinimalSecrecyStructure(v.numberOfParties), nil, createStandardDomainSize())
		ins := createStandardInstructions(v.numberOfParties)
		b.Run(fmt.Sprintf("Number of parties (minimal): %d", v.numberOfParties), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolPassive(ins, parties)
			}
		})
	}

	// Increases the size of the secret by a factor 10 each iteration, ending in 100000000
	secret := big.NewInt(1)
	for _, v := range domainSizeTable {
		parties := startNetwork(standardPartyNumber,
			createSecrecyStructureForTestsActive(standardPartyNumber), nil, v.size)
		for _, p := range parties {
			p.secret.Set(secret)
		}
		ins := createStandardInstructions(standardPartyNumber)
		b.Run(fmt.Sprintf("Secret is: %s", secret.String()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolPassive(ins, parties)
			}
		})
		secret.Mul(secret, big.NewInt(10))
	}

	for _, instructionList := range createIncreasingInstructionsMixed(standardPartyNumber) {
		parties := startNetwork(standardPartyNumber, createSecrecyStructureForTestsActive(standardPartyNumber), nil, createStandardDomainSize())
		b.Run(fmt.Sprintf("Number of instructions: %d", len(instructionList)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolPassive(instructionList, parties)
			}
		})
	}
}

// NOTE: Adversary Structure == Secrecy Structure for all benchmarks here
func BenchmarkActive(b *testing.B) {
	for _, v := range numberOfPartiesTable {
		parties := startNetwork(v.numberOfParties, createSecrecyStructureForTestsActive(v.numberOfParties), createSecrecyStructureForTestsActive(v.numberOfParties), createStandardDomainSize())
		ins := createStandardInstructions(v.numberOfParties)
		b.Run(fmt.Sprintf("Number of parties (maximal): %d", v.numberOfParties), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(ins, parties)
			}
		})
	}

	for _, v := range numberOfPartiesTable {
		parties := startNetwork(v.numberOfParties, createMinimalSecrecyStructure(v.numberOfParties), createMinimalSecrecyStructure(v.numberOfParties), createStandardDomainSize())
		ins := createStandardInstructions(v.numberOfParties)
		b.Run(fmt.Sprintf("Number of parties (minimal): %d", v.numberOfParties), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(ins, parties)
			}
		})
	}

	// Increases the size of the secret by a factor 10 each iteration, ending in 100000000
	secret := big.NewInt(1)
	for _, v := range domainSizeTable {
		parties := startNetwork(standardPartyNumber,
			createSecrecyStructureForTestsActive(standardPartyNumber), createSecrecyStructureForTestsActive(standardPartyNumber), v.size)
		for _, p := range parties {
			p.secret.Set(secret)
		}
		ins := createStandardInstructions(standardPartyNumber)
		b.Run(fmt.Sprintf("Secret is: %s", secret.String()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(ins, parties)
			}
		})
		secret.Mul(secret, big.NewInt(10))
	}

	// Both add and mult instructions
	for _, instructionList := range createIncreasingInstructionsMixed(standardPartyNumber) {
		parties := startNetwork(standardPartyNumber, createSecrecyStructureForTestsActive(standardPartyNumber), createSecrecyStructureForTestsActive(standardPartyNumber), createStandardDomainSize())
		b.Run(fmt.Sprintf("Number of instructions: %d", len(instructionList)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(instructionList, parties)
			}
		})
	}

	// Only add instructions
	for _, instructionList := range createIncreasingInstructionsSame(Add, standardPartyNumber) {
		parties := startNetwork(standardPartyNumber, createSecrecyStructureForTestsActive(standardPartyNumber), createSecrecyStructureForTestsActive(standardPartyNumber), createStandardDomainSize())
		b.Run(fmt.Sprintf("Number of add instructions: %d", len(instructionList)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(instructionList, parties)
			}
		})
	}

	// Only mult instructions
	for _, instructionList := range createIncreasingInstructionsSame(Mult, standardPartyNumber) {
		parties := startNetwork(standardPartyNumber, createSecrecyStructureForTestsActive(standardPartyNumber), createSecrecyStructureForTestsActive(standardPartyNumber), createStandardDomainSize())
		b.Run(fmt.Sprintf("Number of mult instructions: %d", len(instructionList)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(instructionList, parties)
			}
		})
	}

	for _, secrecyStructure := range createIncreasingSecrecyStructuresSubsetSize3Parties10() {
		parties := startNetwork(10, secrecyStructure, secrecyStructure, createStandardDomainSize())
		b.Run(fmt.Sprintf("Secrecy Structure has %d subsets", len(secrecyStructure)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MPCProtocolActive(createStandardInstructions(10), parties)
			}
		})
	}
}
