/** @file
  QemuFixedBarsDxe implements EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL
  to place PCI BAR addresses at their host-physical addresses (GPA=HPA)
  using the etc/fixed-bars fw_cfg blob provided by QEMU.

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
  UINT32    NumDevices;
  UINT32    NumBars;
  UINT8     Reserved[4];
  UINT64    WindowBase;
  UINT64    WindowSize;
} QEMU_FIXED_BARS_HDR;                       /* 32 bytes */

typedef struct {
  UINT8    Dev;
  UINT8    Fn;
} QEMU_FIXED_BARS_PATH_ENTRY;

typedef struct {
  UINT16    VendorId;
  UINT16    DeviceId;
  UINT16    Segment;
  UINT8     PathLen;
  UINT8     NumBars;
} QEMU_FIXED_BARS_DEVICE;                    /* 8 bytes */

typedef struct {
  UINT8     Bar;
  UINT8     Reserved[3];
  UINT32    Flags;
  UINT64    Address;
  UINT64    Size;
} QEMU_FIXED_BARS_BAR;                       /* 24 bytes */

#pragma pack ()

#define QEMU_FIXED_BARS_VERSION  1
#define QEMU_FIXED_BAR_F_MEM64  BIT0
#define QEMU_FIXED_BAR_F_PREF   BIT1

/*
 * ACPI general-flag bits (ACPI 6.x 6.4.3.5.1):
 *   BIT2 = _MIF (minimum address fixed)
 *   BIT3 = _MAF (maximum address fixed)
 * Both set means AddrRangeMin carries the exact required base address.
 */
#define ACPI_ADDR_FLAG_FIXED  (BIT2 | BIT3)

/*
 * P2P bridge prefetchable memory window register offsets.
 * PCI Local Bus Specification 2.2, Section 3.2.5.6.
 */
#define PPB_PREF_MEM_BASE_OFFSET    0x24
#define PPB_PREF_MEM_LIMIT_OFFSET   0x26
#define PPB_PREF_BASE_HI32_OFFSET   0x28
#define PPB_PREF_LIMIT_HI32_OFFSET  0x2C

/* Raw blob kept in memory; device entries point into it. */
STATIC UINT8              *mBlobData;
STATIC QEMU_FIXED_BARS_HDR mHdr;

/* Pre-parsed per-device index built from the blob at startup. */
typedef struct {
  UINT16                 VendorId;
  UINT16                 DeviceId;
  UINT8                  NumBars;
  QEMU_FIXED_BARS_BAR   *Bars;    /* pointer into mBlobData */
} QFBD_DEVICE;

/*
 * Per-(VendorId, DeviceId) class.  CheckDevice() is called once per PCI
 * function and once per scan pass.  Different VID:DID classes must advance
 * their counters independently so that one class (e.g. CX8) cannot disturb
 * the position of another (e.g. GPU) across scan passes.
 *
 * Assumptions:
 *   - QEMU emits blob entries in the same order PciBusDxe discovers devices.
 *   - For identical VID:DID devices, discovery order is stable across passes.
 *   - The counter is maintained per VID:DID class, not globally.
 */
typedef struct {
  UINT16    VendorId;
  UINT16    DeviceId;
  UINTN     Count;       /* number of devices with this VID:DID in the blob */
  UINTN     CurrentIdx;  /* next entry to serve; wraps at Count */
} QFBD_DEVICE_CLASS;

STATIC QFBD_DEVICE        *mDevices;
STATIC UINTN               mNumDevices;
STATIC QFBD_DEVICE_CLASS  *mClasses;   /* heap-allocated; mNumDevices entries max */
STATIC UINTN               mNumClasses;

/*
 * Claim the fixed-bar address window in GCD so PciBusDxe cannot place
 * other devices into it.
 */
STATIC VOID
ReserveHpaRanges (VOID)
{
  UINTN       DevIdx, BarIdx;
  UINT64      DeviceNext;
  UINT64      Addr;
  EFI_STATUS  Status;

  /*
   * Some BARs carry no host-physical address — for example, a GPU BAR used
   * for C2C mapping has no mapping on the host side.  Assign those BARs a
   * GPA within the window, immediately after the device's own real BARs.
   */
  for (DevIdx = 0; DevIdx < mNumDevices; DevIdx++) {
    QFBD_DEVICE  *Dev = &mDevices[DevIdx];

    DeviceNext = 0;

    for (BarIdx = 0; BarIdx < Dev->NumBars; BarIdx++) {
      QEMU_FIXED_BARS_BAR  *Bar = &Dev->Bars[BarIdx];

      if (Bar->Address != 0) {
        UINT64  End = Bar->Address + Bar->Size;
        if (End > DeviceNext) {
          DeviceNext = End;
        }
        continue;
      }

      if (Bar->Size == 0) {
        continue;
      }

      DeviceNext = (DeviceNext + Bar->Size - 1) & ~(Bar->Size - 1);

      if (DeviceNext + Bar->Size > mHdr.WindowBase + mHdr.WindowSize) {
        DEBUG ((DEBUG_ERROR,
                "QFBD: BAR%u size 0x%Lx overflows window\n",
                (UINT32)Bar->Bar, Bar->Size));
        continue;
      }

      Bar->Address  = DeviceNext;
      DeviceNext   += Bar->Size;

      DEBUG ((DEBUG_INFO,
              "QFBD: BAR%u assigned 0x%016Lx size 0x%016Lx\n",
              (UINT32)Bar->Bar, Bar->Address, Bar->Size));
    }
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

/* Walk the blob once, build the mDevices[] index and the mClasses[] table. */
STATIC VOID
InitDevices (
  IN UINTN  BlobSize
  )
{
  UINT8  *Ptr = mBlobData + sizeof (QEMU_FIXED_BARS_HDR);
  UINT8  *End = mBlobData + BlobSize;
  UINTN   D, C;

  for (D = 0; D < mHdr.NumDevices; D++) {
    QEMU_FIXED_BARS_DEVICE  *Dev;
    UINT8                   *Next;

    if (Ptr + sizeof (QEMU_FIXED_BARS_DEVICE) > End) {
      DEBUG ((DEBUG_ERROR, "QFBD: blob truncated at device %u\n", (UINT32)D));
      break;
    }

    Dev  = (QEMU_FIXED_BARS_DEVICE *)Ptr;
    Next = Ptr
         + sizeof (QEMU_FIXED_BARS_DEVICE)
         + Dev->PathLen * sizeof (QEMU_FIXED_BARS_PATH_ENTRY)
         + Dev->NumBars * sizeof (QEMU_FIXED_BARS_BAR);

    if (Next > End) {
      DEBUG ((DEBUG_ERROR, "QFBD: blob truncated at device %u\n", (UINT32)D));
      break;
    }

    mDevices[mNumDevices].VendorId = Dev->VendorId;
    mDevices[mNumDevices].DeviceId = Dev->DeviceId;
    mDevices[mNumDevices].NumBars  = Dev->NumBars;
    mDevices[mNumDevices].Bars     = (QEMU_FIXED_BARS_BAR *)(
      Ptr
      + sizeof (QEMU_FIXED_BARS_DEVICE)
      + Dev->PathLen * sizeof (QEMU_FIXED_BARS_PATH_ENTRY)
      );
    mNumDevices++;

    /* Find or create the class entry for this VID:DID. */
    for (C = 0; C < mNumClasses; C++) {
      if (mClasses[C].VendorId == Dev->VendorId &&
          mClasses[C].DeviceId == Dev->DeviceId)
      {
        mClasses[C].Count++;
        break;
      }
    }
    if (C == mNumClasses) {
      mClasses[mNumClasses].VendorId   = Dev->VendorId;
      mClasses[mNumClasses].DeviceId   = Dev->DeviceId;
      mClasses[mNumClasses].Count      = 1;
      mClasses[mNumClasses].CurrentIdx = 0;
      mNumClasses++;
    }

    DEBUG ((DEBUG_INFO,
            "QFBD: device %04x:%04x num_bars=%u\n",
            Dev->VendorId, Dev->DeviceId, Dev->NumBars));

    Ptr = Next;
  }

  for (C = 0; C < mNumClasses; C++) {
    DEBUG ((DEBUG_INFO,
            "QFBD: class %04x:%04x count=%u\n",
            mClasses[C].VendorId, mClasses[C].DeviceId,
            (UINT32)mClasses[C].Count));
  }
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
  QFBD_DEVICE_CLASS                  *Class;
  QFBD_DEVICE                        *Dev;
  UINTN                               BarIdx, DevIdx, MatchCount, C;
  UINT8                              *Buffer;
  EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR  *Desc;
  EFI_ACPI_END_TAG_DESCRIPTOR        *End;

  (VOID)RevisionId;
  (VOID)SubsystemVendorId;
  (VOID)SubsystemDeviceId;

  if (Configuration == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Configuration = NULL;

  if (mNumClasses == 0) {
    return EFI_SUCCESS;
  }

  /* Look up the per-VID:DID class. */
  Class = NULL;
  for (C = 0; C < mNumClasses; C++) {
    if (mClasses[C].VendorId == (UINT16)VendorId &&
        mClasses[C].DeviceId == (UINT16)DeviceId)
    {
      Class = &mClasses[C];
      break;
    }
  }
  if (Class == NULL) {
    return EFI_SUCCESS;  /* not a fixed-bar device */
  }

  /* Find the CurrentIdx-th device in mDevices[] matching this VID:DID. */
  Dev        = NULL;
  MatchCount = 0;
  for (DevIdx = 0; DevIdx < mNumDevices; DevIdx++) {
    if (mDevices[DevIdx].VendorId == (UINT16)VendorId &&
        mDevices[DevIdx].DeviceId == (UINT16)DeviceId)
    {
      if (MatchCount == Class->CurrentIdx) {
        Dev = &mDevices[DevIdx];
        break;
      }
      MatchCount++;
    }
  }
  if (Dev == NULL) {
    return EFI_SUCCESS;
  }

  Buffer = AllocateZeroPool (Dev->NumBars * sizeof (*Desc) + sizeof (*End));
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Desc = (EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *)Buffer;

  for (BarIdx = 0; BarIdx < Dev->NumBars; BarIdx++) {
    QEMU_FIXED_BARS_BAR  *Bar = &Dev->Bars[BarIdx];

    Desc->Desc                  = ACPI_ADDRESS_SPACE_DESCRIPTOR;
    Desc->Len                   = (UINT16)(sizeof (*Desc) - 3);
    Desc->ResType               = ACPI_ADDRESS_SPACE_TYPE_MEM;
    Desc->GenFlag               = ACPI_ADDR_FLAG_FIXED;
    Desc->SpecificFlag          = 0;
    Desc->AddrSpaceGranularity  = (Bar->Flags & QEMU_FIXED_BAR_F_MEM64) ? 64 : 32;
    Desc->AddrRangeMin          = Bar->Address;
    Desc->AddrRangeMax          = Bar->Size - 1;
    Desc->AddrTranslationOffset = BarIdx;
    Desc->AddrLen               = Bar->Size;

    DEBUG ((DEBUG_INFO,
            "QFBD: %04x:%04x BAR%u -> 0x%016Lx size 0x%016Lx\n",
            Dev->VendorId, Dev->DeviceId,
            (UINT32)Bar->Bar, Bar->Address, Bar->Size));

    Desc++;
  }

  End           = (EFI_ACPI_END_TAG_DESCRIPTOR *)Desc;
  End->Desc     = ACPI_END_TAG_DESCRIPTOR;
  End->Checksum = 0;

  *Configuration = Buffer;

  /* Advance this class's counter, wrapping after all instances are served. */
  Class->CurrentIdx++;
  if (Class->CurrentIdx >= Class->Count) {
    Class->CurrentIdx = 0;
  }

  return EFI_SUCCESS;
}

STATIC EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL  mFixedBarSupport = {
  FixedBarCheckDevice
};

/*
 * Range of prefetchable memory (PMem) addresses covered by a PCI subtree.
 * Min is inclusive, Max is exclusive (base + size).
 */
typedef struct {
  UINT64   Min;
  UINT64   Max;
  BOOLEAN  Valid;
} QFBD_RANGE;

/* Return the size of BAR BarNum for the given (VendorId, DeviceId). */
STATIC UINT64
BlobBarSize (
  UINT16  VendorId,
  UINT16  DeviceId,
  UINT8   BarNum
  )
{
  UINTN  DevIdx, BarIdx;

  for (DevIdx = 0; DevIdx < mNumDevices; DevIdx++) {
    if ((mDevices[DevIdx].VendorId != VendorId) ||
        (mDevices[DevIdx].DeviceId != DeviceId))
    {
      continue;
    }
    for (BarIdx = 0; BarIdx < mDevices[DevIdx].NumBars; BarIdx++) {
      if (mDevices[DevIdx].Bars[BarIdx].Bar == BarNum) {
        return mDevices[DevIdx].Bars[BarIdx].Size;
      }
    }
  }
  return 0;
}

/*
 * Recursively walk all devices on (Seg, Bus).
 *
 * For each P2P bridge: recurse into its secondary bus, then program its
 * PMem window to cover the child range.
 *
 * For each endpoint: read PMem BAR base addresses from config space
 * (already programmed by PciBusDxe / ProgramBar) and look up sizes from the
 * blob.  Accumulate the covered range and return it to the caller.
 */
STATIC QFBD_RANGE
ReprogramPMemWindows (
  UINTN       Seg,
  UINT8       Bus,
  UINTN       HandleCount,
  EFI_HANDLE  *Handles
  )
{
  QFBD_RANGE  R = { MAX_UINT64, 0, FALSE };
  UINTN       Idx;

  for (Idx = 0; Idx < HandleCount; Idx++) {
    EFI_PCI_IO_PROTOCOL  *PciIo;
    UINTN                 S, B, D, F;
    UINT8                 HeaderType;

    if (EFI_ERROR (gBS->HandleProtocol (
                          Handles[Idx], &gEfiPciIoProtocolGuid,
                          (VOID **)&PciIo)))
    {
      continue;
    }

    PciIo->GetLocation (PciIo, &S, &B, &D, &F);
    if ((S != Seg) || ((UINT8)B != Bus)) {
      continue;
    }

    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                     PCI_HEADER_TYPE_OFFSET, 1, &HeaderType);

    if ((HeaderType & 0x7F) == HEADER_TYPE_PCI_TO_PCI_BRIDGE) {
      UINT8       SecBus;
      QFBD_RANGE  Child;
      UINT64      WinBase, WinEnd;
      UINT16      PMemBase16, PMemLimit16;
      UINT32      PMemBaseHi, PMemLimitHi;
      UINT16      Cmd;

      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                       PCI_BRIDGE_SECONDARY_BUS_REGISTER_OFFSET, 1, &SecBus);
      Child = ReprogramPMemWindows (Seg, SecBus, HandleCount, Handles);

      if (!Child.Valid) {
        continue;
      }

      WinBase      = Child.Min;
      WinEnd       = Child.Max - 1;
      PMemBase16   = (UINT16)(((UINT32)(WinBase)) >> 16);
      PMemLimit16  = (UINT16)(((UINT32)(WinEnd))  >> 16);
      PMemBaseHi   = (UINT32)RShiftU64 (WinBase, 32);
      PMemLimitHi  = (UINT32)RShiftU64 (WinEnd,  32);

      PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16,
                        PPB_PREF_MEM_BASE_OFFSET,   1, &PMemBase16);
      PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16,
                        PPB_PREF_MEM_LIMIT_OFFSET,  1, &PMemLimit16);
      PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32,
                        PPB_PREF_BASE_HI32_OFFSET,  1, &PMemBaseHi);
      PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32,
                        PPB_PREF_LIMIT_HI32_OFFSET, 1, &PMemLimitHi);

      PciIo->Pci.Read  (PciIo, EfiPciIoWidthUint16,
                        PCI_COMMAND_OFFSET, 1, &Cmd);
      Cmd |= EFI_PCI_COMMAND_MEMORY_SPACE | EFI_PCI_COMMAND_BUS_MASTER;
      PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16,
                        PCI_COMMAND_OFFSET, 1, &Cmd);

      DEBUG ((DEBUG_INFO,
              "QFBD: bridge %02Lx:%02Lx.%Lx PMem window -> "
              "[0x%016Lx, 0x%016Lx]\n",
              (UINT64)B, (UINT64)D, (UINT64)F, WinBase, WinEnd));

      if (Child.Min < R.Min) R.Min = Child.Min;
      if (Child.Max > R.Max) R.Max = Child.Max;
      R.Valid = TRUE;

    } else {
      /* Endpoint: read PMem BAR base addresses from config space. */
      UINT16  VendorId, DeviceId;
      UINT8   BarNum;

      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16,
                       PCI_VENDOR_ID_OFFSET, 1, &VendorId);
      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16,
                       PCI_DEVICE_ID_OFFSET, 1, &DeviceId);

      for (BarNum = 0; BarNum < 6; ) {
        UINT32   Lo;
        UINT64   Base, Size;
        BOOLEAN  Is64;

        PciIo->Pci.Read (PciIo, EfiPciIoWidthUint32,
                         PCI_BASE_ADDRESSREG_OFFSET + BarNum * 4, 1, &Lo);

        if ((Lo & 0x1) != 0) { BarNum++; continue; }     /* IO BAR */

        Is64 = (((Lo >> 1) & 0x3) == 0x2);

        if ((Lo & 0x8) == 0) {                            /* non-prefetchable */
          BarNum += Is64 ? 2 : 1;
          continue;
        }

        Base = (UINT64)(Lo & ~0xFU);
        if (Is64) {
          UINT32  Hi;
          PciIo->Pci.Read (PciIo, EfiPciIoWidthUint32,
                           PCI_BASE_ADDRESSREG_OFFSET + (BarNum + 1) * 4,
                           1, &Hi);
          Base |= ((UINT64)Hi << 32);
        }

        Size = BlobBarSize (VendorId, DeviceId, BarNum);

        if ((Base != 0) && (Size != 0)) {
          if (Base        < R.Min) R.Min = Base;
          if (Base + Size > R.Max) R.Max = Base + Size;
          R.Valid = TRUE;
        }

        BarNum += Is64 ? 2 : 1;
      }
    }
  }

  return R;
}

STATIC VOID
EFIAPI
FixBridgeWindows (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  UINTN       HandleCount;
  EFI_HANDLE  *Handles;
  UINT8       SecBusList[256];
  UINTN       NSecBus;
  UINT8       DoneBus[256];
  UINTN       NDone;
  UINTN       Idx, J;

  (VOID)Context;

  gBS->CloseEvent (Event);

  Status = gBS->LocateHandleBuffer (
                  ByProtocol, &gEfiPciIoProtocolGuid,
                  NULL, &HandleCount, &Handles
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  /* Collect secondary bus numbers so we can identify root buses. */
  NSecBus = 0;
  for (Idx = 0; Idx < HandleCount; Idx++) {
    EFI_PCI_IO_PROTOCOL  *PciIo;
    UINT8                 HeaderType, SecBus;
    UINTN                 S, B, D, F;

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
    PciIo->GetLocation (PciIo, &S, &B, &D, &F);
    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                     PCI_BRIDGE_SECONDARY_BUS_REGISTER_OFFSET, 1, &SecBus);
    if (NSecBus < ARRAY_SIZE (SecBusList)) {
      SecBusList[NSecBus++] = SecBus;
    }
  }

  /* Trigger recursion once per root bus. */
  NDone = 0;
  for (Idx = 0; Idx < HandleCount; Idx++) {
    EFI_PCI_IO_PROTOCOL  *PciIo;
    UINTN                 Seg, Bus, Dev, Fn;
    BOOLEAN               IsSecondary, AlreadyDone;

    if (EFI_ERROR (gBS->HandleProtocol (
                          Handles[Idx], &gEfiPciIoProtocolGuid,
                          (VOID **)&PciIo)))
    {
      continue;
    }
    PciIo->GetLocation (PciIo, &Seg, &Bus, &Dev, &Fn);

    IsSecondary = FALSE;
    for (J = 0; J < NSecBus; J++) {
      if (SecBusList[J] == (UINT8)Bus) { IsSecondary = TRUE; break; }
    }
    if (IsSecondary) {
      continue;
    }

    AlreadyDone = FALSE;
    for (J = 0; J < NDone; J++) {
      if (DoneBus[J] == (UINT8)Bus) { AlreadyDone = TRUE; break; }
    }
    if (AlreadyDone) {
      continue;
    }

    if (NDone < ARRAY_SIZE (DoneBus)) {
      DoneBus[NDone++] = (UINT8)Bus;
    }

    ReprogramPMemWindows (Seg, (UINT8)Bus, HandleCount, Handles);
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
    DEBUG ((DEBUG_ERROR, "QFBD: blob too small (%Lu bytes)\n",
            (UINT64)FwCfgSize));
    return EFI_UNSUPPORTED;
  }

  QemuFwCfgSelectItem (FwCfgItem);
  QemuFwCfgReadBytes (sizeof (mHdr), &mHdr);

  if (mHdr.Version != QEMU_FIXED_BARS_VERSION) {
    DEBUG ((DEBUG_ERROR,
            "QFBD: unsupported blob version %u (expected %u)\n",
            mHdr.Version, QEMU_FIXED_BARS_VERSION));
    return EFI_UNSUPPORTED;
  }

  if (mHdr.NumDevices == 0) {
    DEBUG ((DEBUG_INFO, "QFBD: zero devices, nothing to do\n"));
    return EFI_SUCCESS;
  }

  /* Read the full blob into a persistent buffer; device entries point into it. */
  mBlobData = AllocatePool (FwCfgSize);
  if (mBlobData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  QemuFwCfgSelectItem (FwCfgItem);
  QemuFwCfgReadBytes (FwCfgSize, mBlobData);
  CopyMem (&mHdr, mBlobData, sizeof (mHdr));

  mDevices = AllocateZeroPool (mHdr.NumDevices * sizeof (QFBD_DEVICE));
  if (mDevices == NULL) {
    FreePool (mBlobData);
    return EFI_OUT_OF_RESOURCES;
  }

  /* Worst case: every device has a unique VID:DID — allocate mNumDevices slots. */
  mClasses = AllocateZeroPool (mHdr.NumDevices * sizeof (QFBD_DEVICE_CLASS));
  if (mClasses == NULL) {
    FreePool (mDevices);
    FreePool (mBlobData);
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((DEBUG_INFO,
          "QFBD: window 0x%016Lx+0x%016Lx  %u device(s) %u BAR(s)\n",
          mHdr.WindowBase, mHdr.WindowSize,
          mHdr.NumDevices, mHdr.NumBars));

  mNumDevices = 0;
  mNumClasses = 0;
  InitDevices (FwCfgSize);
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
    FreePool (mDevices);
    FreePool (mBlobData);
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
