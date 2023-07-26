package stats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gizak/termui/v3"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

type datarec struct {
	rxPackets uint64 // packets received
	rxBytes   uint64 // bytes received
}

func (d *datarec) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	err := binary.Read(r, binary.LittleEndian, &d.rxPackets)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.LittleEndian, &d.rxBytes)
	if err != nil {
		return err
	}

	return nil
}

type record struct {
	timestamp time.Time
	total     datarec
}

type StatsRecord struct {
	Records [5]record
}

func (rec *StatsRecord) collectStats(sMap *ebpf.Map) error {
	var action uint32

	for action = 0; action < 5; action++ {
		if err := getMapVal(action, sMap, rec /* Stats record */); err != nil {
			return err
		}
	}

	return nil
}

// getMapVal collects the total sum of values per key across all the CPUs
func getMapVal(key uint32, m *ebpf.Map, stat *StatsRecord) error {
	var (
		perCpuValues []datarec
		valueSum     datarec
	)

	stat.Records[key].timestamp = time.Now()

	err := m.Lookup(&key, &perCpuValues)
	if err != nil {
		return err
	}

	// Collecting data for every cpu and sum them up
	for _, d := range perCpuValues {
		valueSum.rxPackets += d.rxPackets
		valueSum.rxBytes += d.rxBytes
	}

	stat.Records[key].total.rxBytes = valueSum.rxBytes
	stat.Records[key].total.rxPackets = valueSum.rxPackets

	return nil
}

func action2str(act uint) string {
	switch act {
	case 0:
		return "XDP_ABORT"
	case 1:
		return "XDP_DROP"
	case 2:
		return "XDP_PASS"
	case 3:
		return "XDP_TX"
	case 4:
		return "XDP_REDIRECT"
	default:
		log.Panic("invalid input")
	}

	return ""
}

type stats struct {
	Packets string
	PPs     string
	Bytes   string
	BPs     string
	Period  string
}

func calculateSpeed(bytes, period float64) string {
	kbps := (bytes * 8) / period / 1000

	if kbps < 1000 {
		return fmt.Sprintf("%6.0f Kbits/s", kbps)
	} else {
		mbps := kbps / 1000
		return fmt.Sprintf("%6.0f Mbits/s", mbps)
	}
}

func formatBytes(bytes uint64) string {
	kbs := bytes / 1024

	if kbs < 1024 {
		return fmt.Sprintf("%d KBs", kbs)
	} else {
		mbs := kbs / 1024
		return fmt.Sprintf("%d MBs", mbs)
	}
}

func calcStats(prev, recv StatsRecord) [5]*stats {
	var (
		pps float64
	)

	s := [5]*stats{}

	for i := 0; i < 5; i++ {
		rec := recv.Records[i]
		prev := prev.Records[i]

		period := rec.timestamp.Sub(prev.timestamp).Seconds()

		pps = float64(rec.total.rxPackets-prev.total.rxPackets) / period

		bytes := float64(rec.total.rxBytes - prev.total.rxBytes)
		speed := calculateSpeed(bytes, period)

		stat := &stats{
			Packets: fmt.Sprintf("%d", rec.total.rxPackets),
			PPs:     fmt.Sprintf("%10.0f pps", pps),
			Bytes:   formatBytes(rec.total.rxBytes),
			BPs:     speed,
			Period:  fmt.Sprintf("%f", period),
		}

		s[i] = stat
	}

	return s
}

func RenderStats(statsMap *ebpf.Map) error {
	if err := ui.Init(); err != nil {
		return err
	}
	defer ui.Close()

	table := widgets.NewTable()
	table.Rows = [][]string{
		[]string{"Action", "Total Packets", "Packets Per Sec", "Total Bytes", "Speed (Mbps)", "Period"},
		[]string{"", "", "", "", "", ""},
		[]string{"", "", "", "", "", ""},
		[]string{"", "", "", "", "", ""},
		[]string{"", "", "", "", "", ""},
		[]string{"", "", "", "", "", ""},
	}

	table.TextStyle = ui.NewStyle(ui.ColorWhite)
	table.SetRect(0, 0, 120, 13)
	table.BorderStyle = ui.NewStyle(ui.ColorCyan)
	table.RowSeparator = true
	table.FillRow = true
	table.TextAlignment = termui.AlignCenter

	uiEvents := ui.PollEvents()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		var (
			recv StatsRecord
			prev StatsRecord
		)

		if err := recv.collectStats(statsMap); err != nil {
			return fmt.Errorf("error collecting stats: %w", err)
		}

		select {
		case <-ticker.C:
			copy(prev.Records[:], recv.Records[:])

			if err := recv.collectStats(statsMap); err != nil {
				return fmt.Errorf("error collecting stats: %w", err)
			}

			stats := calcStats(prev, recv)
			table = updateTable(stats, table)

			ui.Render(table)

		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return nil
			}
		}
	}
}

func updateTable(stats [5]*stats, table *widgets.Table) *widgets.Table {
	for i := 0; i < len(stats); i++ {
		s := stats[i]
		table.Rows[i+1][0] = action2str(uint(i))
		table.Rows[i+1][1] = s.Packets
		table.Rows[i+1][2] = s.PPs
		table.Rows[i+1][3] = s.Bytes
		table.Rows[i+1][4] = s.BPs
		table.Rows[i+1][5] = s.Period
	}

	return table
}
