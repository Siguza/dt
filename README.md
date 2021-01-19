# DeviceTree

Minimal code to deal with Apple's DeviceTree format.

The `Makefile` builds `dt` and `pmgr` binaries, but you should also be able to use `dt.c` + `dt.h` as a library of sorts.

### Usage

```
dt ./DeviceTree                     # Print all properties of all nodes
dt ./DeviceTree cpu0                # Print all properties of node "cpu0"
dt ./DeviceTree cpu0 reg-private    # Print property "reg-private" of node "cpu0"
dt ./DeviceTree +cpus               # Print all properties of node "cpus" and all its child nodes
dt ./DeviceTree +cpus reg-private   # Print property "reg-private" of node "cpus" and all its child nodes
dt ./DeviceTree -4                  # Do hexdumps as uint32
dt ./DeviceTree cpu0 reg-private -8 # Do hexdumps as uint64
dt ./DeviceTree /device-tree/arm-io # Filter by absolute path
```
```
pmgr ./DeviceTree                   # Print MMIO addresses of all devices in the power manager
```

### Notes

1. The addresses given by `pmgr` can be used to turn on various SoC components and possibly more.  
   Bits `0xf` are the "wanted mode" and can be used to turn on or off with value `0x0` being off and `0xf` being on. There seem to be exceptions to this though, e.g. cpu0 doesn't let itself be turned off at boot. States between `0x0` and `0xf` supposedly control clocking or smth like that.  
   Bits `0xf0` are the "actual mode" of the component.  
   Higher bits exist, but for most their meaning is unknown and might change between chip generations.

2. The `reg-private` property of `cpu<N>` nodes in the DeviceTree gives you their CoreSight debugbase address. Relative to those are other potentially interesting things:

   ```
   +0x00000 DBG - CoreSight / External debug interface
   +0x10000 CTI - Cross-Trigger Interface
   +0x20000 PMU - Performance monitors
   +0x30000 TRC - Custom Apple "trace" registers
   +0x40000 SYS - Custom Apple "implementation specific" registers
   ```

   The first three should be roughly as in the [ARM spec](https://developer.arm.com/docs/ddi0487/latest).  
   `TRC` has a register at `0x0` that can halt, resume, catch-on-reset, etc.  
   `SYS` has IORVBAR at `0x0`.

### License

[MPL2](https://github.com/Siguza/iometa/blob/master/LICENSE) with Exhibit B.
