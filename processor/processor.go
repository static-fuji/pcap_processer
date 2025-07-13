package processor

import (
	"log"
	"math"
	"pcap_processor/model"
	"pcap_processor/pcapio"
	"sort"
)

// findClosestTimestamp は変更ありません (省略)
func findClosestTimestamp(target float64, sortedTimestamps []float64) (float64, bool) {
	// (元のコードのまま)
	if len(sortedTimestamps) == 0 {
		return 0, false
	}
	i := sort.SearchFloat64s(sortedTimestamps, target)
	if i == len(sortedTimestamps) {
		return sortedTimestamps[i-1], true
	}
	if i == 0 {
		return sortedTimestamps[0], true
	}
	if (target - sortedTimestamps[i-1]) < (sortedTimestamps[i] - target) {
		return sortedTimestamps[i-1], true
	}
	return sortedTimestamps[i], true
}

// findLastSrttBefore は、targetTimeの直前のSRTTイベントを探します。
// SRTTデータは時刻でソートされている必要があります。
func findLastSrttBefore(targetTime float64, srttData []model.SrttEvent) (float64, bool) {
	if len(srttData) == 0 {
		return 0, false
	}

	// targetTimeを超える最初の要素のインデックスを探す
	i := sort.Search(len(srttData), func(i int) bool {
		return srttData[i].Timestamp >= targetTime
	})

	// iが0の場合、targetTimeより前の時刻のデータは存在しない
	if i == 0 {
		return 0, false
	}

	// 探しているのはインデックス i の1つ前の要素
	return srttData[i-1].Srtt, true
}

// ProcessData のシグネチャを変更し、srttDataを受け取るようにします。
func ProcessData(states []model.StateEvent, pcapData *pcapio.PcapData, srttData []model.SrttEvent) []model.Result {
	resultsMap := make(map[uint32]model.Result)

	for _, event := range states {
		if event.State != 3 {
			continue
		}

		fFromCSV := event.Timestamp
		f, found := findClosestTimestamp(fFromCSV, pcapData.SortedTimestamps)
		if !found {
			continue
		}

		if math.Abs(f-fFromCSV) > 0.1 {
			log.Printf("警告: CSV時刻 %.6f に最も近いpcap時刻 %.6f は差分が大きいです。", fFromCSV, f)
		}

		// 変更点: fを基準に直前のSRTTを探す
		srttValue, srttFound := findLastSrttBefore(f, srttData)
		if !srttFound {
			log.Printf("警告: 時刻 %.6f の直前のSRTTが見つかりませんでした。", f)
			srttValue = 0 // 見つからない場合は0を設定
		}

		segments := pcapData.PacketsByTimestamp[f]
		for _, segment := range segments {
			s := segment.Seq
			if s == 0 || s == 1 {
				continue
			}

			t, ok := pcapData.FirstSeen[s]
			if !ok {
				log.Printf("警告: シーケンス番号 %d の初回送信時刻が見つかりません。", s)
				continue
			}

			T := f - t
			T = math.Round(T*10000000) / 10000000

			// 変更点: 結果にsrttValueを追加
			resultsMap[s] = model.Result{Sequence: s, TimeDifferenceT: T, Srtt: srttValue}
		}
	}

	finalResults := make([]model.Result, 0, len(resultsMap))
	for _, res := range resultsMap {
		finalResults = append(finalResults, res)
	}

	return finalResults
}
