package main

import (
	"math/big"
)

// #############################################################################

func BlindWorker(a WorkerCtx, b interface{}) interface{} {
	var output DHOutput
	var h DHElement
	var m big.Int
	ctx, ok := a.(BlindCtx)
	Assert(ok)
	arg, ok := b.(BlindInput)
	Assert(ok)

	HashToCurve_13(arg.w, &h, ctx.ctx.ecc.Curve)
	ctx.ctx.ecc.EC_Multiply(ctx.alpha, h, &output.S)
	m = *big.NewInt(int64(arg.v))
	ctx.ctx.EG_Encrypt(&ctx.pk, &m, &output.Ct)
	// var mPrime big.Int
	// ctx.ctx.EG_Decrypt(ctx.sk, &mPrime, &output.Ct)
	// Assert(mPrime.Cmp(&m) == 0)
	return output
}

func RandomizeWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(DHCtx)
	Assert(ok)
	var output DHOutput
	ctx.ctx.RandomElement(&output.Q)
	ctx.ctx.RandomElement(&output.S)
	return output
}

func RandomizeDelegateWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtx)
	Assert(ok)
	var output DHOutput
	ctx.ctx.ecc.RandomElement(&output.Q)
	ctx.ctx.ecc.RandomElement(&output.S)
	// var mPrime big.Int
	ctx.ctx.EG_RandomCt(&ctx.pk, &output.Ct)
	// ctx.ctx.EG_Decrypt(ctx.sk, &mPrime, &output.Ct)
	// Assert(mPrime.Cmp(&zero) == 0)
	return output
}

func ReduceWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(DHCtx)
	Assert(ok)
	arg, ok := b.(ReduceInput)
	Assert(ok)
	var output DHOutput
	output.Q, output.S = ctx.ctx.DH_Reduce(ctx.L, arg.H, arg.P)
	return output
}

func UnblindWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtx)
	Assert(ok)
	arg, ok := b.(UnblindInput)
	Assert(ok)
	var S DHElement
	zero := new(big.Int)
	Assert(zero.Cmp(arg.Q.x) != 0)
	ctx.ctx.ecc.EC_Multiply(ctx.alpha, arg.Q, &S)
	key := SHA256(S.Serialize())
	ctBytes, err := AEAD_Decrypt(arg.AES, key)
	if err == nil {
		// var mPrime big.Int
		ct := ctx.ctx.EG_Deserialize(ctBytes)
		// ctx.ctx.EG_Decrypt(ctx.sk, &mPrime, &ct)
		// if mPrime.Int64() < 1000 && mPrime.Cmp(zero) != 0 {
		// fmt.Println("mPrime:", mPrime.Text(10))
		// }

		return &ct
	}
	return nil
}

// #############################################################################
