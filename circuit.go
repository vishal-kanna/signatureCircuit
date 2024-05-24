package main

import (
	twards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type eddsaCircuit struct {
	PublicKey eddsa.PublicKey
	Signature eddsa.Signature
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, twards.BN254)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}
