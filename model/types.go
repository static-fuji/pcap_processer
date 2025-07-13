package model

// SrttEvent はSRTTのCSVの1行を表します。
type SrttEvent struct {
	Timestamp float64
	Srtt      float64
}

// StateEvent は状態遷移CSVの1行を表します。
type StateEvent struct {
	Timestamp float64
	State     int
}

// Result は最終的な出力結果の1行を表します。
type Result struct {
	Sequence        uint32
	TimeDifferenceT float64
	Srtt            float64 // 変更点: SRTTの値を格納するフィールドを追加
}
