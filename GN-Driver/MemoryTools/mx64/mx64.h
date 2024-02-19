#pragma once
#include "../../pch.h"
#include <intrin.h>

// _CR3 是一个联合体，它的 Value 成员是一个 64 位无符号整数，而 Fields
// 成员是一个结构体，包含了 Value 的各个位的含义。下面是每个位的作用：
// - Ignored1：忽略的位，不使用。
// - PWT：Page-Level
// Write-Through，指示是否启用页面级别的写穿透缓存。如果启用，则写入页面时会将数据写入缓存和内存，否则只写入内存。
// - PCD：Page-Level Cache
// Disable，指示是否禁用页面级别的缓存。如果启用，则不会将页面缓存在高速缓存中。
// - Ignored2：忽略的位，不使用。
// - PPN：Page-Frame
// Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
// - Reserved1：保留的位，不使用。
typedef union _CR3 {
	UINT64 Value;
	struct {
		UINT64 Ignored1 : 3; // 忽略的位，不使用。
		UINT64 PWT : 1; // Page-Level Write-Through，指示是否启用页面级别的写穿透缓存。如果启用，则写入页面时会将数据写入缓存和内存，否则只写入内存。
		UINT64 PCD : 1; // Page-Level Cache Disable，指示是否禁用页面级别的缓存。如果启用，则不会将页面缓存在高速缓存中。
		UINT64 Ignored2 : 7; // 忽略的位，不使用。
		UINT64 PPN : 40; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
		UINT64 Reserved1 : 12; // 保留的位，不使用。
	} Fields;
} CR3, * PCR3;
static_assert(sizeof(CR3) == 8, "sizeof CR3");

//  _PA 是一个联合体，它的 Value 成员是一个 64 位无符号整数，而 AsLargeInteger
//  成员是一个 LARGE_INTEGER 结构体， 用于将 _PA 转换为 LARGE_INTEGER。
//  Fields4KB、Fields2MB 和 Fields1GB 分别是 _PA 的三个结构体成员，用于表示
//  4KB、2MB 和 1GB 三种大小的物理地址。 下面是每个结构体成员的各个位的含义：
// - Fields4KB：
// - PPO：Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
// - PPN：Page-Frame
// Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
// - Reserved1：保留的位，不使用。
// - Fields2MB：
// - PPO：Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
// - PPN：Page-Frame
// Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
// - Reserved1：保留的位，不使用。
// - Fields1GB：
// - PPO：Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
// - PPN：Page-Frame
// Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
// - Reserved1：保留的位，不使用。
//typedef union _PA {
//	UINT64 Value;
//	LARGE_INTEGER AsLargeInteger;
//	struct {
//		UINT64 PPO : 12; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
//		UINT64 PPN : 40; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
//		UINT64 Reserved1 : 12; // 保留的位，不使用。
//	} Fields4KB;
//	struct {
//		UINT64 PPO : 21; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
//		UINT64 PPN : 31; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
//		UINT64 Reserved1 : 12; // 保留的位，不使用。
//	} Fields2MB;
//	struct {
//		UINT64 PPO : 30; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
//		UINT64 PPN : 22; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
//		UINT64 Reserved1 : 12; // 保留的位，不使用。
//	} Fields1GB;
//} PA, * PPA;
//typedef union _PA {
//	UINT64 Value;
//	LARGE_INTEGER AsLargeInteger;
//	struct {
//		UINT64 PPO : 12; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
//		UINT64 PPN : 40; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
//		UINT64 Reserved1 : 12; // 保留的位，不使用。
//	} Fields4KB;
//	struct {
//		UINT64 PPO : 21; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
//		UINT64 PPN : 31; // Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
//		UINT64 Reserved1 : 12; // 保留的位，不使用。
//	} Fields2MB;
//	struct {
//		UINT64 PPO : 30; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
//		UINT64 PPN : 22; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
//		UINT64 Reserved1 : 12; // 保留的位，不使用。
//	} Fields1GB;
//} PA, * PPA;
typedef union _PA {
	UINT64 Value;
	LARGE_INTEGER AsLargeInteger;
	struct {
		UINT64 PPO : 12; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
		UINT64 PPN : 40; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
		UINT64 Reserved1 : 12; // 保留的位，不使用。
	} Fields4KB;
	struct {
		UINT64 PPO : 21; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
		UINT64 PPN : 31; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
		UINT64 Reserved1 : 12; // 保留的位，不使用。
	} Fields2MB;
	struct {
		UINT64 PPO : 30; // Page-Offset，指示页内偏移量。这个值的大小取决于页面大小。
		UINT64 PPN : 22; //  Page-Frame-Number，指示页表的物理地址。这个值的大小取决于系统的物理内存大小和页表的大小。
		UINT64 Reserved1 : 12; // 保留的位，不使用。
	} Fields1GB;
} PA, * PPA;

// 以下是L1PTE结构体中每个字段的含义：
// - P：存在位，指示该页表项是否有效。
// - RW：读写位，指示该页表项是否可读写。
// - US：用户/超级用户位，指示该页表项是否可由用户模式访问。
// - PWT：页面写入类型位，指示该页表项是否支持高速缓存写入。
// - PCD：页面缓存禁用位，指示该页表项是否禁用高速缓存。
// - A：访问位，指示该页表项是否已被访问。
// - Ingored1：保留的位，不使用。
// - Reserved1：保留的位，不使用。
// - Ignored2：保留的位，不使用。
// - R：已读位，指示该页表项是否已被读取。
// - PPN：页帧号，指示该页表项对应的物理页帧号。
// - Ignored3：保留的位，不使用。
// - XD：执行禁止位，指示该页表项是否禁止执行。
typedef union _L1PTE {
	UINT64 Value;
	struct {
		UINT64 P : 1;   // 存在位，指示该页表项是否有效。
		UINT64 R_W : 1; // 读写位，指示该页表项是否可读写。
		UINT64 U_S : 1; // 用户/超级用户位，指示该页表项是否可由用户模式访问。
		UINT64 PWT : 1; // 页面写入类型位，指示该页表项是否支持高速缓存写入。
		UINT64 PCD : 1; // 页面缓存禁用位，指示该页表项是否禁用高速缓存。
		UINT64 A : 1;         // 访问位，指示该页表项是否已被访问。
		UINT64 Ingored1 : 1;  // 保留的位，不使用。
		UINT64 Reserved1 : 1; // 保留的位，不使用。
		UINT64 Ignored2 : 3;  // 保留的位，不使用。
		UINT64 R : 1;         // 已读位，指示该页表项是否已被读取。
		UINT64 PPN : 40; // 页帧号，指示该页表项对应的物理页帧号。
		UINT64 Ignored3 : 11; // 保留的位，不使用。
		UINT64 XD : 1; // 执行禁止位，指示该页表项是否禁止执行。
	} Fields;
} L1PTE, * PL1PTE;
static_assert(sizeof(L1PTE) == 8, "sizeof L1PTE");

typedef union _L2PTE {
	UINT64 Value;
	struct {
		UINT64 P : 1;   // 存在位，指示该页表项是否有效。
		UINT64 R_W : 1; // 读写位，指示该页表项是否可读写。
		UINT64 U_S : 1; // 用户/超级用户位，指示该页表项是否可由用户模式访问。
		UINT64 PWT : 1; // 页面写入类型位，指示该页表项是否支持高速缓存写入。
		UINT64 PCD : 1; // 页面缓存禁用位，指示该页表项是否禁用高速缓存。
		UINT64 A : 1; // 访问位，指示该页表项是否已被访问。
		UINT64 D : 1; // 脏位，指示该页表项是否已被写入。
		UINT64 PS : 1; // 页面大小位，指示该页表项对应的页面大小。
		UINT64 G : 1;        // 全局位，指示该页表项是否全局有效。
		UINT64 Ignored1 : 2; // 保留的位，不使用。
		UINT64 R : 1;        // 已读位，指示该页表项是否已被读取。
		UINT64 PAT : 1; // 页面属性位，指示该页表项对应的页面属性。
		UINT64 Reserved1 : 17; // 保留的位，不使用。
		UINT64 PPN : 22; // 页帧号，指示该页表项对应的物理页帧号。
		UINT64 Ignored2 : 7; // 保留的位，不使用。
		UINT64 ProtKey : 4; // 保护键位，指示该页表项对应的保护键。
		UINT64 XD : 1; // 执行禁止位，指示该页表项是否禁止执行。
	} Fields1GB;

	struct {
		UINT64 P : 1;   // 存在位，指示该页表项是否有效。
		UINT64 R_W : 1; // 读写位，指示该页表项是否可读写。
		UINT64 U_S : 1; // 用户/超级用户位，指示该页表项是否可由用户模式访问。
		UINT64 PWT : 1; // 页面写入类型位，指示该页表项是否支持高速缓存写入。
		UINT64 PCD : 1; // 页面缓存禁用位，指示该页表项是否禁用高速缓存。
		UINT64 A : 1;        // 访问位，指示该页表项是否已被访问。
		UINT64 Ignored1 : 1; // 保留的位，不使用。
		UINT64 PS : 1; // 页面大小位，指示该页表项对应的页面大小。
		UINT64 Ignored2 : 3; // 保留的位，不使用。
		UINT64 R : 1;        // 已读位，指示该页表项是否已被读取。
		UINT64 PPN : 40; // 页帧号，指示该页表项对应的物理页帧号。
		UINT64 Ignored3 : 11; // 保留的位，不使用。
		UINT64 XD : 1; // 执行禁止位，指示该页表项是否禁止执行。
	} Fields;

} L2PTE, * PL2PTE;
static_assert(sizeof(L2PTE) == 8, "sizeof L2PTE");

typedef union _L3PTE {
	UINT64 Value;

	struct {
		UINT64 P : 1;   // 存在位，指示该页表项是否有效。
		UINT64 R_W : 1; // 读写位，指示该页表项是否可读写。
		UINT64 U_S : 1; // 用户/超级用户位，指示该页表项是否可由用户模式访问。
		UINT64 PWT : 1; // 页面写入类型位，指示该页表项是否支持高速缓存写入。
		UINT64 PCD : 1; // 页面缓存禁用位，指示该页表项是否禁用高速缓存。
		UINT64 A : 1; // 访问位，指示该页表项是否已被访问。
		UINT64 D : 1; // 脏位，指示该页表项是否已被写入。
		UINT64 PS : 1; // 页面大小位，指示该页表项对应的页面大小。
		UINT64 G : 1;        // 全局位，指示该页表项是否全局有效。
		UINT64 Ignored1 : 2; // 保留的位，不使用。
		UINT64 R : 1;        // 已读位，指示该页表项是否已被读取。
		UINT64 PAT : 1; // 页面属性位，指示该页表项对应的页面属性。
		UINT64 Reserved1 : 8; // 保留的位，不使用。
		UINT64 PPN : 31; // 页帧号，指示该页表项对应的物理页帧号。
		UINT64 Ignored2 : 7; // 保留的位，不使用。
		UINT64 ProtKey : 4; // 保护键位，指示该页表项对应的保护键。
		UINT64 XD : 1; // 执行禁止位，指示该页表项是否禁止执行。
	} Fields2MB;

	struct {
		UINT64 P : 1;   // 存在位，指示该页表项是否有效。
		UINT64 R_W : 1; // 读写位，指示该页表项是否可读写。
		UINT64 U_S : 1; // 用户/超级用户位，指示该页表项是否可由用户模式访问。
		UINT64 PWT : 1; // 页面写入类型位，指示该页表项是否支持高速缓存写入。
		UINT64 PCD : 1; // 页面缓存禁用位，指示该页表项是否禁用高速缓存。
		UINT64 A : 1;        // 访问位，指示该页表项是否已被访问。
		UINT64 Ingored1 : 1; // 保留的位，不使用。
		UINT64 PS : 1; // 页面大小位，指示该页表项对应的页面大小。
		UINT64 Ignored2 : 3; // 保留的位，不使用。
		UINT64 R : 1;        // 已读位，指示该页表项是否已被读取。
		UINT64 PPN : 40; // 页帧号，指示该页表项对应的物理页帧号。
		UINT64 Ignored3 : 11; // 保留的位，不使用。
		UINT64 XD : 1; // 执行禁止位，指示该页表项是否禁止执行。
	} Fields;

} L3PTE, * PL3PTE;
static_assert(sizeof(L3PTE) == 8, "sizeof L3PTE");

typedef union _L4PTE {
	UINT64 Value;
	struct {
		UINT64 P : 1;   // 存在位，指示该页表项是否有效。
		UINT64 R_W : 1; // 读写位，指示该页表项是否可读写。
		UINT64 U_S : 1; // 用户/超级用户位，指示该页表项是否可由用户模式访问。
		UINT64 PWT : 1; // 页面写入类型位，指示该页表项是否支持高速缓存写入。
		UINT64 PCD : 1; // 页面缓存禁用位，指示该页表项是否禁用高速缓存。
		UINT64 A : 1; // 访问位，指示该页表项是否已被访问。
		UINT64 D : 1; // 脏位，指示该页表项是否已被写入。
		UINT64 PAT : 1; // 页面属性位，指示该页表项对应的页面属性。
		UINT64 G : 1;        // 全局位，指示该页表项是否全局有效。
		UINT64 Ignored1 : 2; // 保留的位，不使用。
		UINT64 R : 1;        // 已读位，指示该页表项是否已被读取。
		UINT64 PPN : 40; // 页帧号，指示该页表项对应的物理页帧号。
		UINT64 Ignored2 : 7; // 保留的位，不使用。
		UINT64 ProtKey : 4; // 保护键位，指示该页表项对应的保护键。
		UINT64 XD : 1; // 执行禁止位，指示该页表项是否禁止执行。
	} Fields;
} L4PTE, * PL4PTE;

typedef union _VA
{
	UINT64 Value;
	struct
	{
		UINT64 VPO : 12; // 页内偏移量
		UINT64 VPN4 : 9; // 一级页表索引
		UINT64 VPN3 : 9; // 二级页表索引
		UINT64 VPN2 : 9; // 三级页表索引
		UINT64 VPN1 : 9; // 四级页表索引
		UINT64 SEXT : 16; // 符号扩展位
	} Fields4KB;
	struct
	{
		UINT64 VPO : 21; // 页内偏移量
		UINT64 VPN3 : 9; // 二级页表索引
		UINT64 VPN2 : 9; // 三级页表索引
		UINT64 VPN1 : 9; // 四级页表索引
		UINT64 SEXT : 16; // 符号扩展位
	} Fields2MB;
	struct
	{
		UINT64 VPO : 30; // 页内偏移量
		UINT64 VPN2 : 9; // 三级页表索引
		UINT64 VPN1 : 9; // 四级页表索引
		UINT64 SEXT : 16; // 符号扩展位
	} Fields1GB;
	struct
	{
		UINT64 Ignored1 : 12; // 保留位
		UINT64 VPN4 : 9; // 一级页表索引
		UINT64 VPN3 : 9; // 二级页表索引
		UINT64 VPN2 : 9; // 三级页表索引
		UINT64 VPN1 : 9; // 四级页表索引
		UINT64 Ignored2 : 16; // 保留位
	} Fields;
} VA, * PVA;

static_assert(sizeof(VA) == 8, "sizeof VA");

NTSTATUS VaToPa(PEPROCESS Process, VA Va, PPA Pa);

