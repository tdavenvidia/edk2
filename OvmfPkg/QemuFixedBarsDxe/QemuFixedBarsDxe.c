/** @file
  Produce EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL for fixed-BAR
  (GPA=HPA) passthrough devices described by QEMU's etc/fixed-bars fw_cfg blob.

  QEMU writes one blob entry per (device, BAR) carrying vendor_id/device_id
  (used to match CheckDevice() calls), a topology path devfn chain (carried
  for future location-based matching), and the host-physical address/size.

  For each CheckDevice() match this driver returns an ACPI QWORD descriptor
  with _MIF|_MAF (GenFlag BIT2|BIT3) set and AddrRangeMin = HPA.  A companion
  change in PciBusDxe UpdatePciInfo() reads AddrRangeMin when _MIF|_MAF are
  both set and stores it as FixedBaseAddress; ProgramBar() then uses it
  instead of the GCD-allocated Base+Offset.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/Pci.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/QemuFwCfgLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Protocol/IncompatiblePciDeviceSupport.h>
#include <Protocol/PciEnumerationComplete.h>
#include <Protocol/PciIo.h>

/* -----------------------------------------------------------------------
 * On-wire structures: must be byte-for-byte identical to QEMU's structs
 * in hw/pci/pci-fixed-bar.h (little-endian, packed).
 * ----------------------------------------------------------------------- */
#pragma pack (1)

typedef struct {
  UINT32    Version;
  UINT32    NumEntries;
  UINT64    WindowBase;
  UINT64    WindowSize;
  UINT8     Reserved[8];
} QEMU_FIXED_BARS_HDR;                       /* 32 bytes */

typedef struct {
  UINT8    Dev;
  UINT8    Fn;
} QEMU_FIXED_BARS_PATH_ENTRY;

#define QEMU_FIXED_BARS_MAX_PATH  8

typedef struct {
  UINT16                      Segment;
  UINT8                       PathLen;
  UINT8                       Bar;
  UINT32                      Flags;
  UINT64                      Address;       /* HPA; 0 = emulated */
  UINT64                      Size;
  UINT16                      VendorId;
  UINT16                      DeviceId;
  UINT8                       Reserved[4];
  QEMU_FIXED_BARS_PATH_ENTRY  Path[QEMU_FIXED_BARS_MAX_PATH];
} QEMU_FIXED_BARS_ENTRY;                     /* 48 bytes */

#pragma pack ()

#define QEMU_FIXED_BARS_VERSION  2
#define QEMU_FIXED_BAR_F_MEM64  BIT0
#define QEMU_FIXED_BAR_F_PREF   BIT1

/*
 * ACPI general-flag bits (ACPI 6.x 6.4.3.5.1):
 *   BIT2 = _MIF (minimum address fixed)
 *   BIT3 = _MAF (maximum address fixed)
 * Both set means AddrRangeMin carries the exact required base address.
 */
#define ACPI_ADDR_FLAG_FIXED  (BIT2 | BIT3)

STATIC QEMU_FIXED_BARS_HDR    mHdr;
STATIC QEMU_FIXED_BARS_ENTRY  *mEntries;

/*
 * Reserve the fixed-bar window in GCD and assign addresses to any BAR that
 * has no HPA (address == 0 in the blob, e.g. the GPU C2C BAR).
 *
 * The blob header carries WindowBase/WindowSize already sized by QEMU to
 * cover all real HPAs plus room for zero-HPA BARs.  EDK2 claims the entire
 * window as one GCD block so no non-fixed device can be allocated there.
 * Zero-HPA BARs are assigned addresses sequentially after the last real HPA,
 * aligned to their natural (power-of-2) size — all within the owned window.
 *
 * Must run after PciHostBridgeDxe has registered the full MMIO64 window in
 * GCD (ensured by DEPEX on gEfiPciHostBridgeResourceAllocationProtocolGuid).
 */
STATIC VOID
ReserveHpaRanges (VOID)
{
  UINTN       Idx;
  UINT64      Next;
  UINT64      Addr;
  EFI_STATUS  Status;

  /* Pass 1: find the end address of the highest real HPA. */
  Next = mHdr.WindowBase;
  for (Idx = 0; Idx < mHdr.NumEntries; Idx++) {
    QEMU_FIXED_BARS_ENTRY  *E = &mEntries[Idx];
    if ((E->Address != 0) && (E->Size != 0)) {
      UINT64  End = E->Address + E->Size;
      if (End > Next) {
        Next = End;
      }
    }
  }

  /* Pass 2: assign addresses to zero-HPA BARs sequentially after real HPAs. */
  for (Idx = 0; Idx < mHdr.NumEntries; Idx++) {
    QEMU_FIXED_BARS_ENTRY  *E = &mEntries[Idx];

    if ((E->Address != 0) || (E->Size == 0)) {
      continue;
    }

    Next = (Next + E->Size - 1) & ~(E->Size - 1);

    if (Next + E->Size > mHdr.WindowBase + mHdr.WindowSize) {
      DEBUG ((DEBUG_ERROR,
              "QFBD: BAR%u (no HPA) size 0x%Lx overflows window\n",
              (UINT32)E->Bar, E->Size));
      continue;
    }

    E->Address = Next;
    Next      += E->Size;

    DEBUG ((DEBUG_INFO,
            "QFBD: BAR%u (no HPA) assigned 0x%016Lx size 0x%016Lx\n",
            (UINT32)E->Bar, E->Address, E->Size));
  }

  /* Claim the entire window as one GCD block. */
  Addr   = mHdr.WindowBase;
  Status = gDS->AllocateMemorySpace (
                  EfiGcdAllocateAddress,
                  EfiGcdMemoryTypeMemoryMappedIo,
                  0,
                  mHdr.WindowSize,
                  &Addr,
                  gImageHandle,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR,
            "QFBD: reserve window 0x%016Lx+0x%016Lx failed: %r\n",
            mHdr.WindowBase, mHdr.WindowSize, Status));
  } else {
    DEBUG ((DEBUG_INFO,
            "QFBD: reserved HPA window 0x%016Lx+0x%016Lx in GCD\n",
            mHdr.WindowBase, mHdr.WindowSize));
  }
}

STATIC
EFI_STATUS
BuildFixedBarConfiguration (
  IN  UINT16  VendorId,
  IN  UINT16  DeviceId,
  OUT VOID    **Configuration
  )
{
  UINTN                              Idx;
  UINTN                              Count;
  UINT8                              *Buffer;
  EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR  *Desc;
  EFI_ACPI_END_TAG_DESCRIPTOR        *End;

  *Configuration = NULL;

  Count = 0;
  for (Idx = 0; Idx < mHdr.NumEntries; Idx++) {
    if ((mEntries[Idx].VendorId == VendorId) &&
        (mEntries[Idx].DeviceId == DeviceId) &&
        (mEntries[Idx].Size     != 0))
    {
      Count++;
    }
  }

  if (Count == 0) {
    return EFI_SUCCESS;
  }

  Buffer = AllocateZeroPool (Count * sizeof (*Desc) + sizeof (*End));
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Desc = (EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *)Buffer;

  for (Idx = 0; Idx < mHdr.NumEntries; Idx++) {
    QEMU_FIXED_BARS_ENTRY  *E = &mEntries[Idx];

    if ((E->VendorId != VendorId) || (E->DeviceId != DeviceId) ||
        (E->Size == 0))
    {
      continue;
    }

    Desc->Desc                  = ACPI_ADDRESS_SPACE_DESCRIPTOR;
    Desc->Len                   = (UINT16)(sizeof (*Desc) - 3);
    Desc->ResType               = ACPI_ADDRESS_SPACE_TYPE_MEM;
    Desc->GenFlag               = ACPI_ADDR_FLAG_FIXED;
    Desc->SpecificFlag          = 0;
    Desc->AddrSpaceGranularity  = (E->Flags & QEMU_FIXED_BAR_F_MEM64) ? 64 : 32;
    Desc->AddrRangeMin          = E->Address;
    Desc->AddrRangeMax          = E->Size - 1;  /* alignment = Size-1 (power-of-2 BAR) */
    /*
     * EDK2's UpdatePciInfo() matches AddrTranslationOffset against its
     * internal sequential BarIndex (0, 1, 2 ...).  The blob stores
     * physical BAR register numbers (0, 2, 4 for three 64-bit BARs).
     * Compute the sequential index as the count of same-device entries
     * with a lower physical bar number — i.e., position in sorted order.
     */
    {
      UINTN  SeqIdx = 0, K;
      for (K = 0; K < mHdr.NumEntries; K++) {
        if ((mEntries[K].VendorId == VendorId) &&
            (mEntries[K].DeviceId == DeviceId) &&
            (mEntries[K].Size     != 0) &&
            (mEntries[K].Bar      <  E->Bar))
        {
          SeqIdx++;
        }
      }
      Desc->AddrTranslationOffset = SeqIdx;
    }
    Desc->AddrLen               = E->Size;

    DEBUG ((
      DEBUG_INFO,
      "QFBD: %04x:%04x BAR%u -> HPA 0x%016Lx size 0x%016Lx\n",
      VendorId, DeviceId, (UINT32)E->Bar, E->Address, E->Size
      ));

    Desc++;
  }

  End           = (EFI_ACPI_END_TAG_DESCRIPTOR *)Desc;
  End->Desc     = ACPI_END_TAG_DESCRIPTOR;
  End->Checksum = 0;

  *Configuration = Buffer;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
FixedBarCheckDevice (
  IN  EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL  *This,
  IN  UINTN                                          VendorId,
  IN  UINTN                                          DeviceId,
  IN  UINTN                                          RevisionId,
  IN  UINTN                                          SubsystemVendorId,
  IN  UINTN                                          SubsystemDeviceId,
  OUT VOID                                           **Configuration
  )
{
  if (Configuration == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return BuildFixedBarConfiguration (
           (UINT16)VendorId,
           (UINT16)DeviceId,
           Configuration
           );
}

STATIC EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL  mFixedBarSupport = {
  FixedBarCheckDevice
};

/*
 * After PciBusDxe programs all bridges using its GCD-allocated base, the
 * prefetchable windows on bridges above the fixed-bar GPU will not cover the
 * HPA region.  This callback fires on gEfiPciEnumerationCompleteProtocolGuid
 * and reprograms every bridge whose secondary bus range contains the GPU to
 * span [WindowBase, WindowBase+WindowSize).
 *
 * No changes to default EDK2 PCI code — all fixup is in our own driver.
 */
STATIC VOID
EFIAPI
FixBridgeWindows (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS           Status;
  UINTN                HandleCount;
  EFI_HANDLE           *Handles;
  UINTN                Idx;
  UINTN                GpuSeg, GpuBus, GpuDev, GpuFn;
  BOOLEAN              GpuFound;
  UINT64               WinBase, WinEnd;
  UINT16               PrefBase16, PrefLimit16;
  UINT32               PrefBaseHi, PrefLimitHi;
  UINT16               Cmd;

  gBS->CloseEvent (Event);

  /* Find the GPU by VendorId/DeviceId to get its bus number. */
  GpuFound = FALSE;
  GpuBus   = 0;
  GpuSeg   = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol, &gEfiPciIoProtocolGuid,
                  NULL, &HandleCount, &Handles
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  for (Idx = 0; Idx < HandleCount && !GpuFound; Idx++) {
    EFI_PCI_IO_PROTOCOL  *PciIo;
    UINT16                VendorId, DeviceId;

    if (EFI_ERROR (gBS->HandleProtocol (
                          Handles[Idx], &gEfiPciIoProtocolGuid,
                          (VOID **)&PciIo)))
    {
      continue;
    }

    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, PCI_VENDOR_ID_OFFSET, 1, &VendorId);
    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, PCI_DEVICE_ID_OFFSET, 1, &DeviceId);

    /* Check if this is one of our fixed-bar devices. */
    for (UINTN E = 0; E < mHdr.NumEntries; E++) {
      if ((mEntries[E].VendorId == VendorId) &&
          (mEntries[E].DeviceId == DeviceId))
      {
        PciIo->GetLocation (PciIo, &GpuSeg, &GpuBus, &GpuDev, &GpuFn);
        GpuFound = TRUE;
        break;
      }
    }
  }

  if (!GpuFound) {
    DEBUG ((DEBUG_WARN, "QFBD: bridge fixup: GPU not found\n"));
    FreePool (Handles);
    return;
  }

  DEBUG ((DEBUG_INFO,
          "QFBD: bridge fixup: GPU at %04Lx:%02Lx, "
          "programming prefetch window 0x%016Lx+0x%016Lx\n",
          (UINT64)GpuSeg, (UINT64)GpuBus,
          mHdr.WindowBase, mHdr.WindowSize));

  WinBase = mHdr.WindowBase;
  WinEnd  = mHdr.WindowBase + mHdr.WindowSize - 1;

  /* Prefetchable 64-bit window register values. */
  PrefBase16  = (UINT16)(((WinBase >> 20) & 0xFFF) << 4) | 0x1;
  PrefLimit16 = (UINT16)(((WinEnd  >> 20) & 0xFFF) << 4) | 0x1;
  PrefBaseHi  = (UINT32)(WinBase >> 32);
  PrefLimitHi = (UINT32)(WinEnd  >> 32);

  /* Reprogram every bridge whose secondary bus range contains the GPU. */
  for (Idx = 0; Idx < HandleCount; Idx++) {
    EFI_PCI_IO_PROTOCOL  *PciIo;
    UINT8                 HeaderType, SecBus, SubBus;
    UINTN                 Seg, Bus, Dev, Fn;

    if (EFI_ERROR (gBS->HandleProtocol (
                          Handles[Idx], &gEfiPciIoProtocolGuid,
                          (VOID **)&PciIo)))
    {
      continue;
    }

    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                     PCI_HEADER_TYPE_OFFSET, 1, &HeaderType);
    if ((HeaderType & 0x7F) != HEADER_TYPE_PCI_TO_PCI_BRIDGE) {
      continue;
    }

    PciIo->GetLocation (PciIo, &Seg, &Bus, &Dev, &Fn);
    if (Seg != GpuSeg) {
      continue;
    }

    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x19, 1, &SecBus);
    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x1A, 1, &SubBus);

    if ((GpuBus < SecBus) || (GpuBus > SubBus)) {
      continue;
    }

    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, 0x24, 1, &PrefBase16);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, 0x26, 1, &PrefLimit16);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32, 0x28, 1, &PrefBaseHi);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32, 0x2C, 1, &PrefLimitHi);

    PciIo->Pci.Read  (PciIo, EfiPciIoWidthUint16,
                      PCI_COMMAND_OFFSET, 1, &Cmd);
    Cmd |= EFI_PCI_COMMAND_MEMORY_SPACE | EFI_PCI_COMMAND_BUS_MASTER;
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16,
                      PCI_COMMAND_OFFSET, 1, &Cmd);

    DEBUG ((DEBUG_INFO,
            "QFBD: bridge %02Lx:%02Lx.%Lx prefetch window -> "
            "[0x%016Lx, 0x%016Lx]\n",
            (UINT64)Bus, (UINT64)Dev, (UINT64)Fn, WinBase, WinEnd));
  }

  FreePool (Handles);
}

EFI_STATUS
EFIAPI
QemuFixedBarsDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  FIRMWARE_CONFIG_ITEM  FwCfgItem;
  UINTN                 FwCfgSize;
  EFI_STATUS            Status;
  EFI_HANDLE            Handle;
  EFI_EVENT             Event;
  VOID                  *Registration;

  Status = QemuFwCfgFindFile ("etc/fixed-bars", &FwCfgItem, &FwCfgSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "QFBD: etc/fixed-bars absent, nothing to do\n"));
    return EFI_SUCCESS;
  }

  if (FwCfgSize < sizeof (mHdr)) {
    DEBUG ((DEBUG_ERROR, "QFBD: blob too small (%Lu bytes)\n", (UINT64)FwCfgSize));
    return EFI_UNSUPPORTED;
  }

  QemuFwCfgSelectItem (FwCfgItem);
  QemuFwCfgReadBytes (sizeof (mHdr), &mHdr);

  if (mHdr.Version != QEMU_FIXED_BARS_VERSION) {
    DEBUG ((
      DEBUG_ERROR,
      "QFBD: unsupported blob version %u (expected %u)\n",
      mHdr.Version, QEMU_FIXED_BARS_VERSION
      ));
    return EFI_UNSUPPORTED;
  }

  if (mHdr.NumEntries == 0) {
    DEBUG ((DEBUG_INFO, "QFBD: zero entries, nothing to do\n"));
    return EFI_SUCCESS;
  }

  if (FwCfgSize < sizeof (mHdr) + (UINTN)mHdr.NumEntries * sizeof (QEMU_FIXED_BARS_ENTRY)) {
    DEBUG ((DEBUG_ERROR, "QFBD: blob truncated\n"));
    return EFI_UNSUPPORTED;
  }

  mEntries = AllocatePool ((UINTN)mHdr.NumEntries * sizeof (QEMU_FIXED_BARS_ENTRY));
  if (mEntries == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  QemuFwCfgReadBytes (
    (UINTN)mHdr.NumEntries * sizeof (QEMU_FIXED_BARS_ENTRY),
    mEntries
    );

  DEBUG ((
    DEBUG_INFO,
    "QFBD: window 0x%016Lx+0x%016Lx  %u fixed BAR entries\n",
    mHdr.WindowBase, mHdr.WindowSize, mHdr.NumEntries
    ));

  ReserveHpaRanges ();

  Handle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gEfiIncompatiblePciDeviceSupportProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mFixedBarSupport
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "QFBD: install protocol failed: %r\n", Status));
    FreePool (mEntries);
    mEntries = NULL;
    return Status;
  }

  /* Register bridge window fixup for after PCI enumeration completes. */
  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL, TPL_CALLBACK,
                  FixBridgeWindows, NULL, &Event
                  );
  if (!EFI_ERROR (Status)) {
    gBS->RegisterProtocolNotify (
           &gEfiPciEnumerationCompleteProtocolGuid,
           Event, &Registration
           );
  }

  return EFI_SUCCESS;
}
