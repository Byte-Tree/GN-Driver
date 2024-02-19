#include "mx64.h"


NTSTATUS CurrentProcessVaToPa(VA Va, PPA Pa)
{
    __try
    {
        CR3 Cr3 = { NULL };
        Cr3.Value = __readcr3();

        PA L1ptPa = { L1ptPa.Fields4KB.PPN = Cr3.Fields.PPN };
        PL1PTE L1pt = (PL1PTE)MmGetVirtualForPhysical(L1ptPa.AsLargeInteger);
        L1PTE L1pte = L1pt[Va.Fields.VPN1];
        if (!L1pte.Fields.P) return STATUS_INVALID_ADDRESS;

        PA L2ptPa = { L2ptPa.Fields4KB.PPN = L1pte.Fields.PPN };
        PL2PTE L2pt = (PL2PTE)MmGetVirtualForPhysical(L2ptPa.AsLargeInteger);
        L2PTE L2pte = L2pt[Va.Fields.VPN2];
        if (!L2pte.Fields.P) return STATUS_INVALID_ADDRESS;

        if (L2pte.Fields1GB.PS)
        {
            //*Pa = (PA){ .Fields1GB = {
            //    .PPN = L2pte.Fields1GB.PPN,
            //    .PPO = Va.Fields1GB.VPO
            //} };
            Pa->Fields1GB.PPN = L2pte.Fields1GB.PPN;
            Pa->Fields1GB.PPO = Va.Fields1GB.VPO;
            return STATUS_SUCCESS;
        }

        PA L3ptPa = { L3ptPa.Fields4KB.PPN = L2pte.Fields.PPN };
        PL3PTE L3pt = (PL3PTE)MmGetVirtualForPhysical(L3ptPa.AsLargeInteger);
        L3PTE L3pte = L3pt[Va.Fields.VPN3];
        if (!L3pte.Fields.P) return STATUS_INVALID_ADDRESS;

        if (L3pte.Fields2MB.PS)
        {
            //*Pa = (PA){ .Fields2MB = {
            //    .PPN = L3pte.Fields2MB.PPN,
            //    .PPO = Va.Fields2MB.VPO
            //} };
            Pa->Fields2MB.PPN = L3pte.Fields2MB.PPN;
            Pa->Fields2MB.PPO = Va.Fields2MB.VPO;
            return STATUS_SUCCESS;
        }

        PA L4ptPa = { L4ptPa.Fields4KB.PPN = L3pte.Fields.PPN };
        PL4PTE L4pt = (PL4PTE)MmGetVirtualForPhysical(L4ptPa.AsLargeInteger);
        L4PTE L4pte = L4pt[Va.Fields.VPN4];
        if (!L4pte.Fields.P) return STATUS_INVALID_ADDRESS;

        //*Pa = (PA){ .Fields4KB = {
        //    .PPN = L4pte.Fields.PPN,
        //    .PPO = Va.Fields4KB.VPO
        //} };
        Pa->Fields4KB.PPN = L4pte.Fields.PPN;
        Pa->Fields4KB.PPO = Va.Fields4KB.VPO;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error!", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS VaToPa(PEPROCESS Process, VA Va, PPA Pa)
{
    if (PsGetCurrentProcess() == Process)
    {
        DbgPrint("[GN]:ÎÞAttach...");
        return CurrentProcessVaToPa(Va, Pa);
    }
    else
    {
        DbgPrint("[GN]:Attach¶ÁÐ´");
        NTSTATUS Status;
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        Status = CurrentProcessVaToPa(Va, Pa);
        KeUnstackDetachProcess(&ApcState);
        return Status;
    }
}
