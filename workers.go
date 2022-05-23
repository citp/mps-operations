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

	HashToCurve_13(arg.w, &h, ctx.ctx.ecc.Curve, ctx.h2c)
	ctx.ctx.ecc.EC_Multiply(ctx.alpha, h, &output.S)
	m.SetInt64(int64(arg.v))
	// fmt.Println(m.String(), int64(arg.v))
	// fmt.Println(ctx.pk)
	ctx.ctx.EG_Encrypt(&ctx.pk, &m, &output.Ct.EG)
	return output
}

func BlindAESWorker(a WorkerCtx, b interface{}) interface{} {
	var output DHOutput
	var h DHElement
	ctx, ok := a.(BlindCtxInt)
	Assert(ok)
	arg, ok := b.(BlindInput)
	Assert(ok)

	HashToCurve_13(arg.w, &h, ctx.ctx.Curve, ctx.h2c)
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
	ctx.ctx.ecc.RandomElement(&output.S)
	ctx.ctx.EG_EncryptZero(&ctx.pk, &output.Ct.EG)
	return output
}

func RandomizeAESDelegateWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtxInt)
	Assert(ok)
	var output DHOutput
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
	HashToCurve_13(string(arg.w), &H, ctx.ctx.Curve, ctx.h2c)
	output.Q, output.S = ctx.ctx.DH_Reduce(ctx.L, H, arg.P)
	return output
}

func MPSIReduceWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(DHCtx)
	Assert(ok)
	arg, ok := b.(MPSIReduceInput)
	Assert(ok)
	var output DHOutput
	var H DHElement
	HashToCurve_13(string(arg.w), &H, ctx.ctx.Curve, ctx.h2c)
	output.Q, output.S = ctx.ctx.DH_Reduce(ctx.L, H, arg.Mj)
	if !ctx.isP1 {
		ctx.ctx.EC_Add(output.Q, arg.Rj0, &output.Q)
		ctx.ctx.EC_Add(output.S, arg.Rj1, &output.S)
	}
	return output
}

func UnblindEGWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtxSum)
	Assert(ok)
	arg, ok := b.(UnblindInput)
	Assert(ok)
	var S DHElement
	Assert(zero.Cmp(arg.Q.x) != 0)
	ctx.ctx.ecc.EC_Multiply(ctx.alpha, arg.Q, &S)
	ctBytes, err := AEAD_Decrypt(arg.AES, AES_KDF(S.Serialize()))
	if err == nil {
		ct := ctx.ctx.EG_Deserialize(ctBytes)
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

// #############################################################################
