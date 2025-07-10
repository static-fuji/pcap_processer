package pcapio

import (
	"fmt"
	"sort" // sortパッケージをインポート

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PcapData はpcapファイルから抽出したデータを格納します。
type PcapData struct {
	// FirstSeen: シーケンス番号が最初に現れた時刻を記録
	FirstSeen map[uint32]float64

	// PacketsByTimestamp: 時刻ごとに送信されたTCPセグメントを記録 (キーは生のタイムスタンプ)
	PacketsByTimestamp map[float64][]*layers.TCP

	// SortedTimestamps: PacketsByTimestampのキーをソートしたもの。最近傍探索を高速化する。
	SortedTimestamps []float64
}

// ReadPcapFile はpcapファイルを読み込み、PcapData構造体に整理して返します。
func ReadPcapFile(path string) (*PcapData, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("pcapファイルを開けませんでした: %w", err)
	}
	defer handle.Close()

	data := &PcapData{
		FirstSeen:          make(map[uint32]float64),
		PacketsByTimestamp: make(map[float64][]*layers.TCP),
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer == nil {
			continue
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		// 生の(四捨五入されていない)高精度な時刻を使用
		timestamp := packet.Metadata().Timestamp
		tsFloat := float64(timestamp.UnixNano()) / 1e9

		// PacketsByTimestampマップを更新
		data.PacketsByTimestamp[tsFloat] = append(data.PacketsByTimestamp[tsFloat], tcp)

		// FirstSeenマップを更新
		seq := tcp.Seq
		if _, exists := data.FirstSeen[seq]; !exists {
			data.FirstSeen[seq] = tsFloat
		}
	}

	// PacketsByTimestampのキー(ユニークなタイムスタンプ)をスライスに抽出し、ソートする
	// これにより、後で二分探索が可能になる
	data.SortedTimestamps = make([]float64, 0, len(data.PacketsByTimestamp))
	for ts := range data.PacketsByTimestamp {
		data.SortedTimestamps = append(data.SortedTimestamps, ts)
	}
	sort.Float64s(data.SortedTimestamps) // スライスを昇順にソート

	return data, nil
}
