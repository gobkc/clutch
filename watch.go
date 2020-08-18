package clutch

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
)

//Watch 抓包封装库
type Watch struct {
	dev         string
	snapshotLen int32
	promiscuous bool
	timeout     time.Duration
	handle      *pcap.Handle
	filter      string
}

//NewWatch 初始化
func NewWatch() *Watch {
	return &Watch{
		dev:         "eth0",
		snapshotLen: 1024,
		promiscuous: true,
		timeout:     30 * time.Second,
		filter:      "",
	}
}

//SetFilter 设置过滤器 例："tcp and port 80"
func (b *Watch) SetFilter(filter string) *Watch {
	b.filter = filter
	return b
}

//SetTimeout 设置超时时间
func (b *Watch) SetTimeout(timeout time.Duration) *Watch {
	b.timeout = timeout
	return b
}

//SetPromiscuous 设置混杂模式
func (b *Watch) SetPromiscuous(promiscuous bool) *Watch {
	b.promiscuous = promiscuous
	return b
}

//SetSnapshotLen 设置快照长度（每次抓的包）
func (b *Watch) SetSnapshotLen(snapshotLen int32) *Watch {
	b.snapshotLen = snapshotLen
	return b
}

//SetDev 设置设备 网卡
func (b *Watch) SetDev(dev string) *Watch {
	b.dev = dev
	return b
}

//Watch 监控网卡
func (b *Watch) Watch(f func(src string, dst string)) error {
	var err error
	if b.handle, err = pcap.OpenLive(b.dev, b.snapshotLen, b.promiscuous, b.timeout); err != nil {
		return err
	}

	//设置过滤器
	if err = b.handle.SetBPFFilter(b.filter); err != nil {
		return err
	}

	defer b.handle.Close()
	//获取数据源头包
	packetSource := gopacket.NewPacketSource(b.handle, b.handle.LinkType())
	for packet := range packetSource.Packets() {
		netLayer := packet.NetworkLayer()
		if netLayer != nil {
			src := netLayer.NetworkFlow().Src().Raw()
			dst := netLayer.NetworkFlow().Dst().Raw()
			if src != nil && dst != nil {
				srcIP := netLayer.NetworkFlow().Src().String()
				dstIP := netLayer.NetworkFlow().Dst().String()
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					f(fmt.Sprintf("%s:%v", srcIP, tcp.SrcPort), fmt.Sprintf("%s:%v", dstIP, tcp.DstPort))
				}
			}
		}
	}
	return nil
}
