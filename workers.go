package main

// #############################################################################

func BlindWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtx)
	Assert(ok)
	arg, ok := b.(BlindInput)
	Assert(ok)
	var output DHOutput
	output.Q = ctx.ctx.HashToCurve(arg.x)
	ctx.ctx.EC_Multiply(ctx.sk, output.Q, &output.S)
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
	var beta, gamma DHScalar
	ctx.ctx.DH_Reduce(arg.P, ctx.L, arg.H, &beta, &gamma, &output.Q, &output.S)
	return output
}

func UnblindWorker(a WorkerCtx, b interface{}) interface{} {
	ctx, ok := a.(BlindCtx)
	Assert(ok)
	arg, ok := b.(UnblindInput)
	Assert(ok)
	var SComp DHElement
	ctx.ctx.EC_Multiply(ctx.sk, arg.Q, &SComp)
	res := (arg.S.x.Cmp(SComp.x) == 0 && arg.S.y.Cmp(SComp.y) == 0)
	if res {
		return 1
	}
	return 0
}

// #############################################################################
