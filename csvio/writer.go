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

	// 変更点: ヘッダーに "srtt" を追加
	if err := writer.Write([]string{"seq", "T", "srtt"}); err != nil {
		return fmt.Errorf("CSVヘッダーの書き込みに失敗しました: %w", err)
	}

	for _, res := range results {
		record := []string{
			strconv.FormatUint(uint64(res.Sequence), 10),
			strconv.FormatFloat(res.TimeDifferenceT, 'f', -1, 64),
			strconv.FormatFloat(res.Srtt, 'f', -1, 64), // 変更点: SRTTの値を追加
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("CSVレコードの書き込みに失敗しました: %w", err)
		}
	}

	return writer.Error()
}
