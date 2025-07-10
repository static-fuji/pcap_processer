package csvio

import (
	"encoding/csv"
	"fmt"
	"os"
	"pcap_processor/model"
	"strconv"
)

// WriteResultsCSV は処理結果をCSVファイルに書き込みます。
func WriteResultsCSV(path string, results []model.Result) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("出力ファイルを作成できませんでした: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 変更点: ヘッダーを "t" から "T" へ
	if err := writer.Write([]string{"seq", "T", "t", "f"}); err != nil {
		return fmt.Errorf("CSVヘッダーの書き込みに失敗しました: %w", err)
	}

	for _, res := range results {
		record := []string{
			strconv.FormatUint(uint64(res.Sequence), 10),
			// 変更点: res.FirstTxTime から res.TimeDifferenceT へ
			strconv.FormatFloat(res.TimeDifferenceT, 'f', -1, 64),
			strconv.FormatFloat(res.Time, 'f', -1, 64),
			strconv.FormatFloat(res.Timef, 'f', -1, 64),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("CSVレコードの書き込みに失敗しました: %w", err)
		}
	}

	return writer.Error()
}
