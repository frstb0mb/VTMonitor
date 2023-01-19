#include "common.h"
#include <wdm.h>
#include "vmm.h"

NTSTATUS DefaultDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_VTMONITOR_START:
        {
            auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
            if (!size || size > sizeof(vtmif)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            StartVirtualization((vtmif*)(Irp->AssociatedIrp.SystemBuffer));
            Irp->IoStatus.Information = sizeof(vtmif);
            break;
        }
        case IOCTL_VTMONITOR_END:
            Irp->IoStatus.Information = 0;
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

UNICODE_STRING lnkname = RTL_CONSTANT_STRING(L"\\??\\VTMonitor");
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    IoDeleteSymbolicLink(&lnkname);
    IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DefaultDispatcher;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

    PDEVICE_OBJECT devobj = nullptr;
    UNICODE_STRING devname = RTL_CONSTANT_STRING(L"\\Device\\VTMonitor");
    auto status = IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devobj);
    if (!NT_SUCCESS(status))
        return status;
    devobj->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&lnkname, &devname);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devobj);
        return status;
    }

    return STATUS_SUCCESS;
}