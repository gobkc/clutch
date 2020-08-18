###一个gopacket的封装包

>example

    package main
    
    import (
        "log"
        "github.com/gobkc/clutch"
    )
    
    func main() {
        watcher := clutch.NewWatch().
            SetDev("ppp0").
            SetPromiscuous(false).
            SetFilter("tcp and src port 5001")
        err:=watcher.Watch(func(src string, dst string) {
            log.Println("来源：",src,"目标：", dst)
        })
        if err!=nil{
            log.Println(err.Error())
        }
    }