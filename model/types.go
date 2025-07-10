package model

// StateEvent は状態遷移CSVの1行を表します。
type StateEvent struct {
	Timestamp float64
	State     int
}

// Result は最終的な出力結果の1行を表します。
type Result struct {
	Sequence        uint32
	TimeDifferenceT float64 // 変更点: FirstTxTime (t) から TimeDifferenceT (T) へ
	Time            float64
	Timef           float64
}
