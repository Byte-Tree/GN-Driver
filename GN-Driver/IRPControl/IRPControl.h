#pragma once
#include "../pch.h"
#include "IRPControlCode.h"
#include "MyStruct.h"
#include "../MainFunction/MainFunction.h"


NTSTATUS GN_DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp);
BOOLEAN HackDispatchRoutine(IN _FILE_OBJECT* file_object, IN BOOLEAN wait, IN PVOID input_buffer, IN ULONG input_buffer_length, OUT PVOID output_buffer, IN ULONG output_buffer_length, IN ULONG io_control_code, OUT PIO_STATUS_BLOCK io_status, IN _DEVICE_OBJECT* device_object);

