package main

import (
	"math/big"
)

// #############################################################################

func BlindEGWorker(a WorkerCtx, b interface{}) interface{} {
	var output DHOutput
	var h DHElement
	var m big.Int
	ctx, ok := a.(BlindCtxSum)
	Assert(ok)
	arg, ok := b.(BlindInput)
	Assert(ok)

	HashToCurve_13(arg.w, &h, ctx.ctx.ecc.Curve)
	ctx.ctx.ecc.EC_Multiply(ctx.alpha, h, &output.S)
	m = *big.NewInt(int64(arg.v))
	ctx.ctx.EG_Encrypt(&ctx.pk, &m, &output.Ct.EG)
	// var mPrime big.Int
	// ctx.ctx.EG_Decrypt(ctx.sk, &mPrime, &output.Ct)
	// Assert(mPrime.Cmp(&m) == 0)
	return output
}

func BlindAESWorker(a WorkerCtx, b interface{}) interface{} {
	var output DHOutput
	var h DHElement
	ctx, ok := a.(BlindCtxInt)
	Assert(ok)
	arg, ok := b.(BlindInput)
	Assert(ok)

	HashToCurve_13(arg.w, &h, ctx.ctx.Curve)
	ctx.ctx.EC_Multiply(ctx.alpha, h, &output.S)
	output.Ct.AES = AEAD_Encrypt([]byte(arg.w), ctx.sk)
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

func RandomizeEGDelegateWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtxSum)
	Assert(ok)
	var output DHOutput
	ctx.ctx.ecc.RandomElement(&output.Q)
	ctx.ctx.ecc.RandomElement(&output.S)
	// var mPrime big.Int
	ctx.ctx.EG_EncryptZero(&ctx.pk, &output.Ct.EG)
	// ctx.ctx.EG_Decrypt(ctx.sk, &mPrime, &output.Ct)
	// Assert(mPrime.Cmp(&zero) == 0)
	return output
}

func RandomizeAESDelegateWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtxInt)
	Assert(ok)
	var output DHOutput
	ctx.ctx.RandomElement(&output.Q)
	ctx.ctx.RandomElement(&output.S)
	output.Ct.AES = RandomBytes(12)
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

func HashAndReduceWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(DHCtx)
	Assert(ok)
	arg, ok := b.(HashAndReduceInput)
	Assert(ok)
	var output DHOutput
	var H DHElement
	HashToCurve_13(string(arg.w), &H, ctx.ctx.Curve)
	output.Q, output.S = ctx.ctx.DH_Reduce(ctx.L, H, arg.P)
	return output
}

func UnblindEGWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtxSum)
	Assert(ok)
	arg, ok := b.(UnblindInput)
	Assert(ok)
	var S DHElement
	// zero := new(big.Int)
	Assert(zero.Cmp(arg.Q.x) != 0)
	ctx.ctx.ecc.EC_Multiply(ctx.alpha, arg.Q, &S)
	ctBytes, err := AEAD_Decrypt(arg.AES, AES_KDF(S.Serialize()))
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

func UnblindAESWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtxInt)
	Assert(ok)
	arg, ok := b.(UnblindInput)
	Assert(ok)

	var S DHElement
	ctx.ctx.EC_Multiply(ctx.alpha, arg.Q, &S)
	ctBytes, err := AEAD_Decrypt(arg.AES, AES_KDF(S.Serialize()))
	if err == nil {
		return string(ctBytes)
	}
	return ""
}

func EncryptEGWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, _ := a.(EncryptCtx)
	arg, _ := b.(EncryptInput)

	ctx.ctx.EG_Rerandomize(ctx.apk, &arg.ct.EG)
	return EncryptOutput(AEAD_Encrypt(ctx.ctx.EG_Serialize(&arg.ct.EG), AES_KDF(arg.S.Serialize())))
}

func EncryptAESWorker(a WorkerCtx, b interface{}) interface{} {
	arg, _ := b.(EncryptInput)

	return EncryptOutput(AEAD_Encrypt(arg.ct.AES, AES_KDF(arg.S.Serialize())))
}

func H2CWorker(a WorkerCtx, b interface{}) interface{} {
	var Q DHElement
	curve, ok := a.(H2CCtx)
	Assert(ok)
	arg, ok := b.(H2CInput)
	Assert(ok)

	HashToCurve_13(string(arg), &Q, curve)
	return H2COutput(Q)
}

// #############################################################################
