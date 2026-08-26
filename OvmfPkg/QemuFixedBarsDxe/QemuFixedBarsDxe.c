/** @file
  QemuFixedBarsDxe implements EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL
  to place PCI BAR addresses at fixed addresses using the
  etc/fixed-bars fw_cfg blob provided by QEMU.

  Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.<BR>

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

/* byte-for-byte identical to QEMU's structs in hw/pci/pci-fixed-bar.h */
#pragma pack (1)

typedef struct {
  UINT32    Version;
  UINT32    NumDevices;
} QEMU_FIXED_BARS_HDR;                       /* 8 bytes */

typedef struct {
  UINT16    VendorId;
  UINT16    DeviceId;
  UINT8     DevFlags;
  UINT8     RpBus;
  UINT8     NumBars;
  UINT8     Reserved;
} QEMU_FIXED_BARS_DEVICE;                    /* 8 bytes */

typedef struct {
  UINT8     Bar;
  UINT8     Reserved[3];
  UINT32    Flags;
  UINT64    Address;
  UINT64    Size;
} QEMU_FIXED_BARS_BAR;                       /* 24 bytes */

#pragma pack ()

#define QEMU_FIXED_BARS_VERSION      1
#define QEMU_FIXED_BAR_F_MEM64       BIT0
#define QEMU_FIXED_BAR_F_PREF        BIT1
#define QEMU_FIXED_BARS_DEV_F_FIXED  BIT0

/*
 * ACPI general-flag bits (ACPI 6.x 6.4.3.5.1):
 *   BIT2 = _MIF (minimum address fixed)
 *   BIT3 = _MAF (maximum address fixed)
 * Both set means AddrRangeMin carries the exact required base address.
 */
#define ACPI_ADDR_FLAG_FIXED  (BIT2 | BIT3)

/*
 * P2P bridge memory window register offsets.
 * PCI Local Bus Specification 2.2, Section 3.2.5.6.
 */
#define PPB_MEM32_BASE_OFFSET       OFFSET_OF (PCI_TYPE01, Bridge.MemoryBase)
#define PPB_MEM32_LIMIT_OFFSET      OFFSET_OF (PCI_TYPE01, Bridge.MemoryLimit)
#define PPB_PREF_MEM_BASE_OFFSET    OFFSET_OF (PCI_TYPE01, Bridge.PrefetchableMemoryBase)
#define PPB_PREF_MEM_LIMIT_OFFSET   OFFSET_OF (PCI_TYPE01, Bridge.PrefetchableMemoryLimit)
#define PPB_PREF_BASE_HI32_OFFSET   OFFSET_OF (PCI_TYPE01, Bridge.PrefetchableBaseUpper32)
#define PPB_PREF_LIMIT_HI32_OFFSET  OFFSET_OF (PCI_TYPE01, Bridge.PrefetchableLimitUpper32)

/* QFBD = Qemu Fixed Bars Dxe; used as the tag in this file's DEBUG() messages. */
/* Raw blob kept in memory; device entries point into it. */
STATIC UINT8              *mBlobData;
STATIC QEMU_FIXED_BARS_HDR mHdr;

/* Pre-parsed per-device index built from the blob at startup. */
typedef struct {
  UINT16                VendorId;
  UINT16                DeviceId;
  UINT8                 DevFlags;
  UINT8                 RpBus;    /* primary bus of the root port */
  UINT8                 NumBars;
  QEMU_FIXED_BARS_BAR  *Bars;    /* pointer into mBlobData */
} QFBD_DEVICE;

/*
 * Per-(VendorId, DeviceId) class. CheckDevice() is called once per PCI
 * function and once per scan pass. Different VID:DID classes must advance
 * their counters independently so that one class cannot disturb the
 * position of another across scan passes.
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

STATIC VOID
ReserveHpaRanges (VOID)
{
  UINTN       DevIdx;
  UINTN       BarIdx;
  UINT64      Min64;
  UINT64      Max64;
  UINT64      Min32;
  UINT64      Max32;
  UINT64      Gran;
  UINT64      Base;
  UINT64      Size;
  EFI_STATUS  Status;

  Min64 = MAX_UINT64;
  Max64 = 0;
  Min32 = MAX_UINT64;
  Max32 = 0;
  Gran  = SIZE_1MB;

  for (DevIdx = 0; DevIdx < mNumDevices; DevIdx++) {
    QFBD_DEVICE  *Dev = &mDevices[DevIdx];

    if (!(Dev->DevFlags & QEMU_FIXED_BARS_DEV_F_FIXED)) {
      continue;
    }
    for (BarIdx = 0; BarIdx < Dev->NumBars; BarIdx++) {
      QEMU_FIXED_BARS_BAR  *Bar = &Dev->Bars[BarIdx];

      if (Bar->Flags & QEMU_FIXED_BAR_F_MEM64) {
        if (Bar->Address < Min64) {
          Min64 = Bar->Address;
        }
        if (Bar->Address + Bar->Size > Max64) {
          Max64 = Bar->Address + Bar->Size;
        }
      } else {
        if (Bar->Address < Min32) {
          Min32 = Bar->Address;
        }
        if (Bar->Address + Bar->Size > Max32) {
          Max32 = Bar->Address + Bar->Size;
        }
      }
    }
  }

  if (Min64 < Max64) {
    Base   = Min64 & ~(Gran - 1);
    Size   = ALIGN_VALUE (Max64 - Base, Gran);
    Status = gDS->AllocateMemorySpace (
                    EfiGcdAllocateAddress,
                    EfiGcdMemoryTypeMemoryMappedIo,
                    0, Size, &Base, gImageHandle, NULL
                    );
    DEBUG ((EFI_ERROR (Status) ? DEBUG_ERROR : DEBUG_INFO,
            "QFBD: reserve 64-bit 0x%016Lx+0x%016Lx: %r\n",
            Base, Size, Status));
  }

  if (Min32 < Max32) {
    Base   = Min32 & ~(Gran - 1);
    Size   = ALIGN_VALUE (Max32 - Base, Gran);
    Status = gDS->AllocateMemorySpace (
                    EfiGcdAllocateAddress,
                    EfiGcdMemoryTypeMemoryMappedIo,
                    0, Size, &Base, gImageHandle, NULL
                    );
    DEBUG ((EFI_ERROR (Status) ? DEBUG_ERROR : DEBUG_INFO,
            "QFBD: reserve 32-bit 0x%016Lx+0x%016Lx: %r\n",
            Base, Size, Status));
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
  UINTN   DevIdx, ClassIdx;

  for (DevIdx = 0; DevIdx < mHdr.NumDevices; DevIdx++) {
    QEMU_FIXED_BARS_DEVICE  *Dev;
    UINT8                   *Next;

    if (Ptr + sizeof (QEMU_FIXED_BARS_DEVICE) > End) {
      DEBUG ((DEBUG_ERROR, "QFBD: blob truncated at device %u\n", (UINT32)DevIdx));
      break;
    }

    Dev  = (QEMU_FIXED_BARS_DEVICE *)Ptr;
    Next = Ptr
         + sizeof (QEMU_FIXED_BARS_DEVICE)
         + Dev->NumBars * sizeof (QEMU_FIXED_BARS_BAR);

    if (Next > End) {
      DEBUG ((DEBUG_ERROR, "QFBD: blob truncated at device %u\n", (UINT32)DevIdx));
      break;
    }

    mDevices[mNumDevices].VendorId  = Dev->VendorId;
    mDevices[mNumDevices].DeviceId  = Dev->DeviceId;
    mDevices[mNumDevices].DevFlags  = Dev->DevFlags;
    mDevices[mNumDevices].RpBus     = Dev->RpBus;
    mDevices[mNumDevices].NumBars   = Dev->NumBars;
    mDevices[mNumDevices].Bars      = (QEMU_FIXED_BARS_BAR *)(
      Ptr + sizeof (QEMU_FIXED_BARS_DEVICE)
      );
    mNumDevices++;

    /* Find or create the class entry for this VID:DID. */
    for (ClassIdx = 0; ClassIdx < mNumClasses; ClassIdx++) {
      if (mClasses[ClassIdx].VendorId == Dev->VendorId &&
          mClasses[ClassIdx].DeviceId == Dev->DeviceId)
      {
        mClasses[ClassIdx].Count++;
        break;
      }
    }
    if (ClassIdx == mNumClasses) {
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

  for (ClassIdx = 0; ClassIdx < mNumClasses; ClassIdx++) {
    DEBUG ((DEBUG_INFO,
            "QFBD: class %04x:%04x count=%u\n",
            mClasses[ClassIdx].VendorId, mClasses[ClassIdx].DeviceId,
            (UINT32)mClasses[ClassIdx].Count));
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
  UINTN                               BarIdx, DevIdx, MatchCount, ClassIdx;
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
  for (ClassIdx = 0; ClassIdx < mNumClasses; ClassIdx++) {
    if (mClasses[ClassIdx].VendorId == (UINT16)VendorId &&
        mClasses[ClassIdx].DeviceId == (UINT16)DeviceId)
    {
      Class = &mClasses[ClassIdx];
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

  /* Always advance the counter so ordering stays in sync with the blob. */
  Class->CurrentIdx++;
  if (Class->CurrentIdx >= Class->Count) {
    Class->CurrentIdx = 0;
  }

  if (!(Dev->DevFlags & QEMU_FIXED_BARS_DEV_F_FIXED)) {
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

  return EFI_SUCCESS;
}

STATIC EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL  mFixedBarSupport = {
  FixedBarCheckDevice
};

/*
 * Range type: Min inclusive, Max exclusive (base + size).
 */
typedef struct {
  UINT64   Min;
  UINT64   Max;
  BOOLEAN  Valid;
} QFBD_RANGE;

typedef struct {
  QFBD_RANGE  Pref;
  QFBD_RANGE  NonPref;
} QFBD_BRIDGE_RANGES;

STATIC VOID
RangeUnion (
  QFBD_RANGE  *R,
  UINT64       Addr,
  UINT64       Size
  )
{
  if (Addr     < R->Min) R->Min = Addr;
  if (Addr + Size > R->Max) R->Max = Addr + Size;
  R->Valid = TRUE;
}

/*
 * Write PMem and Mem32 window registers on one bridge.
 */
STATIC VOID
SetBridgeWindow (
  IN EFI_PCI_IO_PROTOCOL  *PciIo,
  IN UINTN                 B,
  IN UINTN                 D,
  IN UINTN                 F,
  IN QFBD_BRIDGE_RANGES    R
  )
{
  UINT16  Cmd;

  if (R.Pref.Valid) {
    UINT64  Base  = R.Pref.Min;
    UINT64  End   = R.Pref.Max - 1;
    UINT16  B16   = (UINT16)(((UINT32)Base) >> 16);
    UINT16  L16   = (UINT16)(((UINT32)End)  >> 16);
    UINT32  BHi   = (UINT32)RShiftU64 (Base, 32);
    UINT32  LHi   = (UINT32)RShiftU64 (End,  32);

    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, PPB_PREF_MEM_BASE_OFFSET,  1, &B16);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, PPB_PREF_MEM_LIMIT_OFFSET, 1, &L16);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32, PPB_PREF_BASE_HI32_OFFSET, 1, &BHi);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32, PPB_PREF_LIMIT_HI32_OFFSET, 1, &LHi);

    DEBUG ((DEBUG_INFO, "QFBD: bridge %02Lx:%02Lx.%Lx PMem [0x%Lx, 0x%Lx]\n",
            (UINT64)B, (UINT64)D, (UINT64)F, Base, End));
  }

  if (R.NonPref.Valid) {
    UINT64  Base = R.NonPref.Min;
    UINT64  End  = R.NonPref.Max - 1;
    UINT16  B16  = (UINT16)(Base >> 16);
    UINT16  L16  = (UINT16)(End  >> 16);

    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, PPB_MEM32_BASE_OFFSET,  1, &B16);
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, PPB_MEM32_LIMIT_OFFSET, 1, &L16);

    DEBUG ((DEBUG_INFO, "QFBD: bridge %02Lx:%02Lx.%Lx Mem32 [0x%Lx, 0x%Lx]\n",
            (UINT64)B, (UINT64)D, (UINT64)F, Base, End));
  }

  if (R.Pref.Valid || R.NonPref.Valid) {
    PciIo->Pci.Read  (PciIo, EfiPciIoWidthUint16, PCI_COMMAND_OFFSET, 1, &Cmd);
    Cmd |= EFI_PCI_COMMAND_MEMORY_SPACE | EFI_PCI_COMMAND_BUS_MASTER;
    PciIo->Pci.Write (PciIo, EfiPciIoWidthUint16, PCI_COMMAND_OFFSET, 1, &Cmd);
  }
}

/*
 * Read the BAR ranges (prefetchable and non-prefetchable) from an endpoint
 * by looking up its programmed BAR addresses in the blob.  Every device
 * with the FIXED devflag bit set is guaranteed to have blob-provided BAR
 * entries covering all its BARs, so a match is always found.
 */
STATIC VOID
ClassifyBar (
  IN OUT QFBD_BRIDGE_RANGES  *R,
  IN     UINT64              Addr
  )
{
  UINTN  DevIdx, BarIdx;

  for (DevIdx = 0; DevIdx < mNumDevices; DevIdx++) {
    for (BarIdx = 0; BarIdx < mDevices[DevIdx].NumBars; BarIdx++) {
      QEMU_FIXED_BARS_BAR  *Bar = &mDevices[DevIdx].Bars[BarIdx];

      if (Bar->Address == Addr && Addr != 0) {
        if (Bar->Flags & QEMU_FIXED_BAR_F_PREF) {
          RangeUnion (&R->Pref, Addr, Bar->Size);
        } else {
          RangeUnion (&R->NonPref, Addr, Bar->Size);
        }
      }
    }
  }
}

STATIC QFBD_BRIDGE_RANGES
EndpointRanges (
  IN EFI_PCI_IO_PROTOCOL  *PciIo
  )
{
  QFBD_BRIDGE_RANGES  R = { { MAX_UINT64, 0, FALSE }, { MAX_UINT64, 0, FALSE } };
  UINTN               Off;

  for (Off = PCI_BASE_ADDRESSREG_OFFSET; Off <= 0x24; ) {
    UINT32  Lo;

    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint32, Off, 1, &Lo);

    if ((Lo & 0x1) == 1) {          /* IO BAR */
      Off += 4;
      continue;
    }
    if ((Lo & 0x6) == 0x4) {        /* 64-bit memory BAR */
      UINT32  Hi;
      UINT64  Addr;

      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint32, Off + 4, 1, &Hi);
      Addr = ((UINT64)Hi << 32) | (Lo & ~(UINT32)0xF);
      ClassifyBar (&R, Addr);
      Off += 8;
    } else {                         /* 32-bit memory BAR */
      ClassifyBar (&R, (UINT64)(Lo & ~(UINT32)0xF));
      Off += 4;
    }
  }
  return R;
}

/*
 * Recursively walk bridges starting at SecBus.  For each bridge, collect
 * ranges (prefetchable and non-prefetchable) from all endpoints below it
 * (bottom-up), program the bridge window, and return the union to the
 * caller.
 *
 * Because every device with the FIXED devflag bit set is guaranteed to have
 * blob-provided BAR entries, EndpointRanges() only returns non-empty
 * results for fixed devices.  Branches leading to endpoints with no fixed
 * BARs naturally produce empty ranges and are not programmed.
 */
STATIC QFBD_BRIDGE_RANGES
WalkAndProgram (
  IN UINTN    Seg,
  IN UINT8    Bus,
  IN UINTN    HandleCount,
  IN EFI_HANDLE  *Handles
  )
{
  QFBD_BRIDGE_RANGES  Total = { { MAX_UINT64, 0, FALSE }, { MAX_UINT64, 0, FALSE } };
  UINTN               Idx;

  for (Idx = 0; Idx < HandleCount; Idx++) {
    EFI_PCI_IO_PROTOCOL  *PciIo;
    UINTN                 S, B, D, F;
    UINT8                 HeaderType, SecBus;
    QFBD_BRIDGE_RANGES    Sub;

    if (EFI_ERROR (gBS->HandleProtocol (
                          Handles[Idx], &gEfiPciIoProtocolGuid,
                          (VOID **)&PciIo)))
    {
      continue;
    }

    PciIo->GetLocation (PciIo, &S, &B, &D, &F);
    if (S != Seg || (UINT8)B != Bus) {
      continue;
    }

    PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, PCI_HEADER_TYPE_OFFSET, 1, &HeaderType);

    if ((HeaderType & 0x7F) == HEADER_TYPE_PCI_TO_PCI_BRIDGE) {
      /* Bridge: recurse first, then program with the subtree's range. */
      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                       PCI_BRIDGE_SECONDARY_BUS_REGISTER_OFFSET, 1, &SecBus);
      Sub = WalkAndProgram (Seg, SecBus, HandleCount, Handles);
      if (Sub.Pref.Valid || Sub.NonPref.Valid) {
        SetBridgeWindow (PciIo, B, D, F, Sub);
      }
    } else {
      /* Endpoint: collect its fixed BAR ranges. */
      Sub = EndpointRanges (PciIo);
    }

    if (Sub.Pref.Valid) {
      RangeUnion (&Total.Pref, Sub.Pref.Min, Sub.Pref.Max - Sub.Pref.Min);
    }
    if (Sub.NonPref.Valid) {
      RangeUnion (&Total.NonPref, Sub.NonPref.Min, Sub.NonPref.Max - Sub.NonPref.Min);
    }
  }

  return Total;
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
  UINTN       DevIdx, Idx;

  (VOID)Context;

  gBS->CloseEvent (Event);

  Status = gBS->LocateHandleBuffer (
                  ByProtocol, &gEfiPciIoProtocolGuid,
                  NULL, &HandleCount, &Handles
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  /*
   * For each unique rp_bus that has at least one FIXED device, find the
   * bridge on that bus and walk its subtree bottom-up to set windows.
   */
  for (DevIdx = 0; DevIdx < mNumDevices; DevIdx++) {
    UINT8  RpBus;

    if (!(mDevices[DevIdx].DevFlags & QEMU_FIXED_BARS_DEV_F_FIXED)) {
      continue;
    }
    RpBus = mDevices[DevIdx].RpBus;

    /* Skip if we already processed this rp_bus. */
    {
      UINTN  Di;
      BOOLEAN Already = FALSE;
      for (Di = 0; Di < DevIdx; Di++) {
        if ((mDevices[Di].DevFlags & QEMU_FIXED_BARS_DEV_F_FIXED) &&
            mDevices[Di].RpBus == RpBus)
        {
          Already = TRUE;
          break;
        }
      }
      if (Already) continue;
    }

    /* Find the RP bridge handle: bridge on Bus == RpBus. */
    for (Idx = 0; Idx < HandleCount; Idx++) {
      EFI_PCI_IO_PROTOCOL  *PciIo;
      UINTN                 S, B, D, F;
      UINT8                 HeaderType, SecBus;
      QFBD_BRIDGE_RANGES    Sub;

      if (EFI_ERROR (gBS->HandleProtocol (
                            Handles[Idx], &gEfiPciIoProtocolGuid,
                            (VOID **)&PciIo)))
      {
        continue;
      }

      PciIo->GetLocation (PciIo, &S, &B, &D, &F);
      if ((UINT8)B != RpBus) {
        continue;
      }

      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                       PCI_HEADER_TYPE_OFFSET, 1, &HeaderType);
      if ((HeaderType & 0x7F) != HEADER_TYPE_PCI_TO_PCI_BRIDGE) {
        continue;
      }

      PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8,
                       PCI_BRIDGE_SECONDARY_BUS_REGISTER_OFFSET, 1, &SecBus);

      Sub = WalkAndProgram (S, SecBus, HandleCount, Handles);
      if (Sub.Pref.Valid || Sub.NonPref.Valid) {
        SetBridgeWindow (PciIo, B, D, F, Sub);
        DEBUG ((DEBUG_INFO, "QFBD: RP %02Lx:%02Lx.%Lx programmed\n",
                (UINT64)B, (UINT64)D, (UINT64)F));
      }
    }
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

  DEBUG ((DEBUG_INFO, "QFBD: %u device(s)\n", mHdr.NumDevices));

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
