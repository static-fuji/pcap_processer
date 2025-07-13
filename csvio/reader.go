package csvio

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"pcap_processor/model"
	"strconv"
)

// ReadSrttCSV はSRTTが記録されたCSVファイルを読み込みます。
func ReadSrttCSV(path string) ([]model.SrttEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("SRTT CSVファイルを開けませんでした: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// ヘッダー行を読み飛ばす
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("SRTT CSVヘッダーの読み込みに失敗しました: %w", err)
	}

	var events []model.SrttEvent
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("SRTT CSVレコードの読み込みに失敗しました: %w", err)
		}
		if len(record) < 2 {
			continue // カラム数が足りない行はスキップ
		}

		ts, err := strconv.ParseFloat(record[0], 64)
		if err != nil {
			continue // パース失敗した行はスキップ
		}

		srtt, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			continue // パース失敗した行はスキップ
		}

		events = append(events, model.SrttEvent{Timestamp: ts, Srtt: srtt})
	}
	return events, nil
}

// ReadStateCSV は変更ありません (省略)
func ReadStateCSV(path string) ([]model.StateEvent, error) {
	// (元のコードのまま)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("CSVファイルを開けませんでした: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// ヘッダー行を読み飛ばす
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("CSVヘッダーの読み込みに失敗しました: %w", err)
	}

	var events []model.StateEvent
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
			continue // パース失敗した行はスキップ
		}

		st, err := strconv.Atoi(record[1])
		if err != nil {
			continue // パース失敗した行はスキップ
		}

		events = append(events, model.StateEvent{Timestamp: ts, State: st})
	}
	return events, nil
}
