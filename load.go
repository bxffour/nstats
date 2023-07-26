package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/urfave/cli/v2"
)

var pinPath = "/sys/fs/bpf/xdp_stats"

var startCommand = cli.Command{
	Name: "load",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "dev",
			Required: true,
			Usage:    "<ifname> of interface to attach program to",
		},
		&cli.StringFlag{
			Name:    "sec",
			Aliases: []string{"S"},
			Value:   "xdp.pass",
			Usage:   "choose what section to load. (xdp.pass|xdp.drop|xdp.aborted)",
		},
	},
	Before: func(ctx *cli.Context) error {
		if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
			return err
		}
		return nil
	},

	Action: func(ctx *cli.Context) error {
		ifaceName := ctx.String("dev")

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}

		var objs bpfObjects
		if err := loadBpfObjects(&objs, nil); err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer objs.Close()

		path := path.Join(pinPath, "xdp_stats_map")
		if err := objs.XdpStatsMap.Pin(path); err != nil {
			return err
		}
		defer objs.XdpStatsMap.Unpin()

		section := ctx.String("sec")
		prog := sec2prog(section, objs)

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})

		if err != nil {
			return fmt.Errorf("link: %w", err)
		}

		defer l.Close()

		log.Printf("Attached XDP program (SEC %s) to iface %q (index %d)\n", section, ifaceName, iface.Index)
		log.Println("Press CTRL-C to exit the program")

		ctrlC := make(chan os.Signal, 1)
		signal.Notify(ctrlC, os.Interrupt)

		<-ctrlC
		return nil
	},
}

func sec2prog(section string, objs bpfObjects) *ebpf.Program {
	switch section {
	case "xdp.pass":
		return objs.XdpPass
	case "xdp.drop":
		return objs.XdpDrop
	case "xdp.aborted":
		return objs.XdpAborted
	default:
		log.Fatal("invalid input")
	}

	return nil
}
