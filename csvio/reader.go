package csvio

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"pcap_processor/model" // 変更
	"strconv"
)

// ReadStateCSV は状態遷移が記録されたCSVファイルを読み込みます。
func ReadStateCSV(path string) ([]model.StateEvent, error) { // 変更: []StateEvent -> []model.StateEvent
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("CSVファイルを開けませんでした: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("CSVヘッダーの読み込みに失敗しました: %w", err)
	}

	var events []model.StateEvent // 変更
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("CSVレコードの読み込みに失敗しました: %w", err)
		}

		ts, err := strconv.ParseFloat(record[0], 64)
		if err != nil {
			continue
		}

		st, err := strconv.Atoi(record[1])
		if err != nil {
			continue
		}

		events = append(events, model.StateEvent{Timestamp: ts, State: st}) // 変更
	}
	return events, nil
}
