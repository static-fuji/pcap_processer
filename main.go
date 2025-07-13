package main

import (
	"log"
	"os"
	"pcap_processor/csvio"
	"pcap_processor/pcapio"
	"pcap_processor/processor"
)

func main() {
	// 1. コマンドライン引数を検証 (引数を5つに)
	if len(os.Args) != 5 {
		log.Fatalf("使用方法: %s <pcapファイル> <状態遷移csv> <srtt csv> <出力csv>", os.Args[0])
	}
	pcapPath := os.Args[1]
	stateCSVPath := os.Args[2]
	srttCSVPath := os.Args[3] // 変更点: SRTTファイルのパスを追加
	outputCSVPath := os.Args[4]

	log.Println("処理を開始します...")

	// 2. 状態遷移CSVファイルを読み込み
	log.Printf("状態遷移CSVを読み込み中: %s", stateCSVPath)
	states, err := csvio.ReadStateCSV(stateCSVPath)
	if err != nil {
		log.Fatalf("状態遷移CSVの読み込みに失敗しました: %v", err)
	}

	// 変更点: SRTTのCSVファイルを読み込む処理を追加
	log.Printf("SRTT CSVを読み込み中: %s", srttCSVPath)
	srttData, err := csvio.ReadSrttCSV(srttCSVPath)
	if err != nil {
		log.Fatalf("SRTT CSVの読み込みに失敗しました: %v", err)
	}

	// 3. pcapファイルを読み込み、データを整理
	log.Printf("pcapファイルを読み込み中: %s", pcapPath)
	pcapData, err := pcapio.ReadPcapFile(pcapPath)
	if err != nil {
		log.Fatalf("pcapファイルの読み込みに失敗しました: %v", err)
	}

	// 4. メインの処理を実行 (引数にsrttDataを追加)
	log.Println("データの処理を実行中...")
	results := processor.ProcessData(states, pcapData, srttData)

	// 5. 結果をCSVファイルに出力
	log.Printf("結果を出力中: %s", outputCSVPath)
	err = csvio.WriteResultsCSV(outputCSVPath, results)
	if err != nil {
		log.Fatalf("結果のCSV出力に失敗しました: %v", err)
	}

	log.Printf("処理が正常に完了しました。%d件のデータが出力されました。", len(results))
}
