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

// ProcessData は状態遷移とpcapデータから最終結果を導出します。
func ProcessData(states []model.StateEvent, pcapData *pcapio.PcapData) []model.Result {
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

		segments := pcapData.PacketsByTimestamp[f]

		for _, segment := range segments {
			s := segment.Seq
			if s == 0 || s == 1 {
				continue
			}

			// t: sが初めて送信された時刻
			t, ok := pcapData.FirstSeen[s]
			if !ok {
				log.Printf("警告: シーケンス番号 %d の初回送信時刻が見つかりません。", s)
				continue
			}

			// 変更点: T = f - t を計算する
			T := f - t

			// 変更点: 結果としてtの代わりにTを格納する
			resultsMap[s] = model.Result{Sequence: s, TimeDifferenceT: T, Time: t, Timef: f}
		}
	}

	finalResults := make([]model.Result, 0, len(resultsMap))
	for _, res := range resultsMap {
		finalResults = append(finalResults, res)
	}

	return finalResults
}
