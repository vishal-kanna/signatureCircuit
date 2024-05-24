package main

import (
	"fmt"
	"log"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	ed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func prove() {

	// here we are generating the eddsa keys and signing the msg with keys
	hFunc := hash.MIMC_BN254.New()
	randSrc := rand.NewSource(1)

	privkey, err := ed.GenerateKey(rand.New(randSrc))
	HandleError(err)
	publickey := (*privkey).PublicKey
	msg := []byte{0xde, 0xad, 0xf0, 0x0d}
	signbytes, err := privkey.Sign(msg, hFunc)
	fmt.Println("The signbytes length is", len(signbytes))
	HandleError(err)

	// provide the fields to the circuit such that they produce the witness and proof
	// and then the verifier verifies the proofs
	var assignment eddsaCircuit
	assignment.Message = msg
	assignment.Signature.Assign(twistededwards.ID(ecc.BN254), signbytes)
	assignment.PublicKey.Assign(twistededwards.ID(ecc.BN254), publickey.Bytes())

	var circuit eddsaCircuit
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(cs)

	// now create the witness
	fullwitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	HandleError(err)
	proof, err := groth16.Prove(cs, pk, fullwitness)
	HandleError(err)
	// generate random signature and publickey as
	// this values doesn't need to public to the verifier
	randSrc = rand.NewSource(1)

	privkey1, err := ed.GenerateKey(rand.New(randSrc))
	HandleError(err)
	publickey1 := (*privkey1).PublicKey
	publicAssignment := eddsaCircuit{
		Message: msg,
	}
	eg := make([]byte, 64)
	publicAssignment.Signature.Assign(twistededwards.ID(ecc.BN254), eg)
	publicAssignment.PublicKey.Assign(twistededwards.ID(ecc.BN254), publickey1.Bytes())

	publicwitness, err := frontend.NewWitness(&publicAssignment, ecc.BN254.ScalarField())
	HandleError(err)
	pubwit, err := publicwitness.Public()
	HandleError(err)
	err = groth16.Verify(proof, vk, pubwit)
	HandleError(err)
}

func HandleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
