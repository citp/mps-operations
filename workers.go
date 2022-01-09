package main

import "math/big"

// #############################################################################

func BlindWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtx)
	Assert(ok)
	arg, ok := b.(BlindInput)
	Assert(ok)
	var output DHOutput
	var h DHElement
	HashToCurve_13(arg.x, &h, ctx.ctx.Curve)
	// output.Q = ctx.ctx.HashToCurve(arg.x)
	ctx.ctx.EC_Multiply(ctx.sk, h, &output.S)
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
	var SComp DHElement
	zero := new(big.Int)
	nonZero := (zero.Cmp(arg.Q.x) != 0 && zero.Cmp(arg.S.x) != 0)
	Assert(nonZero)
	ctx.ctx.EC_Multiply(ctx.sk, arg.Q, &SComp)
	if arg.S.x.Cmp(SComp.x) == 0 && arg.S.y.Cmp(SComp.y) == 0 {
		return 1
	}
	return 0
}

// #############################################################################
