//! supervisor call dispatch.

use zakuro_common::memory_map::*;
use zakuro_common::result::errors;
use zakuro_common::VAddr;
use zakuro_cpu::Bus;

use super::object::{KObject, ObjectId, CURRENT_PROCESS, CURRENT_THREAD};
use super::sync::{self, ArbitrationType, ResetType};
use super::thread::{nanos_to_ticks, ThreadStatus, WaitResult, WaitSyscall, THREAD_EXIT_MAGIC};
use crate::memory::{MemoryState, Permission};
use crate::System;

// MemOp, as libctru defines it.
const MEMOP_FREE: u32 = 1;
const MEMOP_RESERVE: u32 = 2;
const MEMOP_ALLOC: u32 = 3;
const MEMOP_MAP: u32 = 4;
const MEMOP_UNMAP: u32 = 5;
const MEMOP_PROTECT: u32 = 6;
const MEMOP_OP_MASK: u32 = 0xFF;
const MEMOP_LINEAR_FLAG: u32 = 0x1_0000;

/// Luma's extended process-memory mapping SVC, including its v2 call marker.
const MAP_PROCESS_MEMORY_EX_V2_MAGIC: u32 = 0xFFFF_FFF2;
const MAP_PROCESS_MEMORY_EX_PRIVATE: u32 = 1;
/// Citra/Luma OS error 0xD9001818 from svcOpenProcess for an unknown PID.
const PROCESS_NOT_FOUND: u32 = 0xD900_1818;

/// reports a handle a syscall could not resolve.
fn invalid_handle(system: &mut System, handle: u32, what: &str) -> u32 {
    log::warn!(
        "{what}: handle 0x{handle:X} does not exist (called from 0x{:08X})",
        system.cpu.current_pc()
    );
    errors::INVALID_HANDLE.0
}

/// whether recompiled code can have an svc run in place, from inside the
/// code. the ones that map memory, start or end threads or the process,
/// reach services, which load code, or that nothing implements stop the
/// code, and the step runs them.
pub fn in_place(number: u32) -> bool {
    matches!(number, 0x02 | 0x0A..=0x0C | 0x11 | 0x13..=0x1D | 0x21..=0x25 | 0x27 | 0x28 | 0x2A | 0x2B | 0x35 | 0x37..=0x3A | 0x3D | 0x54..=0x56 | 0x7C | 0x94 | 0xB3)
}

/// runs one supervisor call.
pub fn dispatch(system: &mut System, number: u32) {
    if log::log_enabled!(log::Level::Trace) {
        let thread = system
            .kernel
            .current()
            .map_or("?".to_owned(), |t| t.name.clone());
        log::trace!(
            "[{thread}] svc 0x{number:02X} r0={:08X} r1={:08X} r2={:08X} r3={:08X} @0x{:08X} lr 0x{:08X}",
            system.cpu.regs[0],
            system.cpu.regs[1],
            system.cpu.regs[2],
            system.cpu.regs[3],
            system.cpu.current_pc(),
            system.cpu.regs[14],
        );
    }
    match number {
        0x01 => control_memory(system),
        0x02 => query_memory(system),
        0x03 => exit_process(system),
        0x08 => create_thread(system),
        0x09 => exit_thread(system),
        0x0A => sleep_thread(system),
        0x0B => get_thread_priority(system),
        0x0C => set_thread_priority(system),
        0x11 => system.cpu.regs[0] = 0, // GetCurrentProcessorNumber
        0x13 => create_mutex(system),
        0x14 => release_mutex(system),
        0x15 => create_semaphore(system),
        0x16 => release_semaphore(system),
        0x17 => create_event(system),
        0x18 => signal_event(system),
        0x19 => clear_event(system),
        0x1A => create_timer(system),
        0x1B => set_timer(system),
        0x1C => cancel_timer(system),
        0x1D => clear_timer(system),
        0x1E => create_memory_block(system),
        0x1F => map_memory_block(system),
        0x20 => unmap_memory_block(system),
        0x21 => create_address_arbiter(system),
        0x22 => arbitrate_address(system),
        0x23 => close_handle(system),
        0x24 => wait_synchronization1(system),
        0x25 => wait_synchronization_n(system),
        0x27 => duplicate_handle(system),
        0x28 => get_system_tick(system),
        0x2A => get_system_info(system),
        0x2B => get_process_info(system),
        0x2D => connect_to_port(system),
        0x32 => send_sync_request(system),
        0x33 => open_process(system),
        0x35 => get_process_id(system),
        0x37 => get_thread_id(system),
        0x38 => get_resource_limit(system),
        0x39 => get_resource_limit_limit_values(system),
        0x3A => get_resource_limit_current_values(system),
        0x3C => svc_break(system),
        0x3D => output_debug_string(system),
        0x7C => kernel_set_state(system),
        // cache maintenance.
        0x54..=0x56 | 0x94 => {
            // Data and instruction caches are coherent in this emulator.
            system.cpu.regs[0] = 0;
        }
        0xA0 => map_process_memory_ex(system),
        0xA1 => unmap_process_memory_ex(system),
        0xB3 => control_process(system),
        _ => {
            log::warn!(
                "unimplemented svc 0x{number:02X} at 0x{:08X} (r0={:08X} r1={:08X} r2={:08X} r3={:08X})",
                system.cpu.current_pc(),
                system.cpu.regs[0],
                system.cpu.regs[1],
                system.cpu.regs[2],
                system.cpu.regs[3],
            );
            system.unimplemented_svcs.insert(number);
            system.cpu.regs[0] = errors::UNIMPLEMENTED.0;
        }
    }
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// svcControlMemory, r0 = operation, r1 = addr0, r2 = addr1, r3 = size,
/// r4 = permission. Returns the mapped address in r1.
fn control_memory(system: &mut System) {
    let operation = system.cpu.regs[0];
    let addr0 = system.cpu.regs[1];
    let addr1 = system.cpu.regs[2];
    let size = system.cpu.regs[3];
    let permission = system.cpu.regs[4];

    let op = operation & MEMOP_OP_MASK;
    let linear = operation & MEMOP_LINEAR_FLAG != 0;

    if size & PAGE_MASK != 0 {
        log::warn!("svcControlMemory with unaligned size 0x{size:X}");
        system.cpu.regs[0] = errors::MISALIGNED_SIZE.0;
        return;
    }

    let perm = Permission::from_bits_truncate(permission & 0x7);

    match op {
        MEMOP_ALLOC if linear => {
            let region = system.kernel.memory_region;
            let Some(block) = system.memory.phys.allocate(region, size) else {
                log::error!("out of linear memory allocating 0x{size:X}");
                system.cpu.regs[0] = errors::OUT_OF_MEMORY.0;
                return;
            };
            // the whole point of the linear heap is that the guest can derive
            // a physical address from a virtual one, so the mapping offset
            // must match exactly.
            let vaddr = system.kernel.linear_base + (block.addr - FCRAM_PADDR);
            system.memory.map(
                vaddr,
                block.addr,
                block.size,
                perm | Permission::READ,
                MemoryState::Continuous,
            );
            system.kernel.linear_top = system.kernel.linear_top.max(vaddr + block.size);
            log::debug!(
                "linear alloc 0x{size:X} -> va 0x{vaddr:08X} pa 0x{:08X}",
                block.addr
            );
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = vaddr;
        }
        MEMOP_ALLOC => {
            let base = if addr0 == 0 {
                system.kernel.heap_top
            } else {
                addr0
            };
            let region = system.kernel.memory_region;
            let Some(block) = system.memory.phys.allocate_top(region, size) else {
                log::error!("out of heap memory allocating 0x{size:X}");
                system.cpu.regs[0] = errors::OUT_OF_MEMORY.0;
                return;
            };
            system.memory.map(
                base,
                block.addr,
                block.size,
                perm | Permission::READ,
                MemoryState::Private,
            );
            system.kernel.heap_top = system.kernel.heap_top.max(base + block.size);
            log::debug!("heap alloc 0x{size:X} at 0x{base:08X}");
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = base;
        }
        MEMOP_FREE => {
            // the pages behind the range go back, from where it starts in each
            // heap or linear mapping it covers, a heap shrunk from its end
            // gives back its end
            let end = addr0 as u64 + size as u64;
            let freed: Vec<crate::memory::PhysicalBlock> = system
                .memory
                .mappings()
                .filter(|m| matches!(m.state, MemoryState::Private | MemoryState::Continuous))
                .filter(|m| (m.base as u64) < end && (addr0 as u64) < m.base as u64 + m.size as u64)
                .map(|m| {
                    let start = m.base.max(addr0);
                    let stop = (m.base as u64 + m.size as u64).min(end);
                    crate::memory::PhysicalBlock {
                        addr: m.paddr + (start - m.base),
                        size: (stop - start as u64) as u32,
                    }
                })
                .collect();
            for block in freed {
                system.memory.phys.free(block);
            }
            system.memory.unmap(addr0, size);
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = addr0;
        }
        MEMOP_MAP => {
            // mirror the pages backing addr1 at addr0.
            if let Some(mapping) = system.memory.mapping_at(addr1).copied() {
                let offset = addr1 - mapping.base;
                system.memory.map(
                    addr0,
                    mapping.paddr + offset,
                    size,
                    perm | Permission::RW,
                    MemoryState::Aliased,
                );
                system.cpu.regs[0] = 0;
            } else {
                log::warn!("svcControlMemory MAP of unmapped source 0x{addr1:08X}");
                system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
            }
            system.cpu.regs[1] = addr0;
        }
        MEMOP_UNMAP => {
            system.memory.unmap(addr0, size);
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = addr0;
        }
        MEMOP_PROTECT | MEMOP_RESERVE => {
            // nothing enforces permissions yet, so these are accepted as-is.
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = addr0;
        }
        _ => {
            log::warn!("svcControlMemory with unknown operation 0x{operation:X}");
            system.cpu.regs[0] = errors::INVALID_ENUM_VALUE.0;
        }
    }
}

/// svcQueryMemory, r2 = address.
fn query_memory(system: &mut System) {
    let addr = system.cpu.regs[2];
    let info = system.memory.query(addr);
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = info.base;
    system.cpu.regs[2] = info.size;
    system.cpu.regs[3] = info.permission;
    system.cpu.regs[4] = info.state;
    system.cpu.regs[5] = 0;
}

/// svcCreateMemoryBlock, r0 = other permission, r1 = address, r2 = size,
/// r3 = own permission. Returns the handle in r1.
fn create_memory_block(system: &mut System) {
    let addr = system.cpu.regs[1];
    let size = system.cpu.regs[2];

    // an address of zero asks the kernel to take the pages from the BASE
    // region instead of the caller's address space, or from the bottom of
    // the caller's own region, where its linear heap is, when its exheader
    // says shared device memory
    let region = if system.kernel.shared_device_memory {
        system.kernel.memory_region
    } else {
        crate::memory::MemoryRegion::Base
    };
    let paddr = if addr == 0 {
        match system.memory.phys.allocate(region, size) {
            Some(block) => {
                system.memory.zero_physical(block.addr, block.size);
                block.addr
            }
            None => {
                system.cpu.regs[0] = errors::OUT_OF_MEMORY.0;
                return;
            }
        }
    } else {
        match system.memory.mapping_at(addr) {
            Some(mapping) => mapping.paddr + (addr - mapping.base),
            None => {
                system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
                return;
            }
        }
    };

    let object = system
        .kernel
        .objects
        .insert(KObject::SharedMemory(super::object::SharedMemory {
            name: format!("MemoryBlock@{addr:08X}"),
            address: addr,
            size,
            paddr,
            mapped_at: None,
        }));
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "MemoryBlock");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

/// svcMapMemoryBlock, r0 = handle, r1 = address, r2 = own permission,
/// r3 = other permission.
fn map_memory_block(system: &mut System) {
    let handle = system.cpu.regs[0];
    let addr = system.cpu.regs[1];
    let permission = system.cpu.regs[2];

    let Some(object) = system.kernel.resolve(handle) else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcMapMemoryBlock");
        return;
    };
    let Some(KObject::SharedMemory(block)) = system.kernel.objects.get(object) else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcMapMemoryBlock");
        return;
    };

    let (paddr, size, own) = (block.paddr, block.size, block.address);
    let addr = if addr == 0 && own != 0 {
        // a block the system keeps somewhere, as the shared font, goes where
        // it already is, the address the title was told
        own
    } else if addr == 0 {
        // let the kernel choose, the first place in the shared memory region
        // the whole block fits, a big one mapped over the next block along
        // would hide it
        let pages = size.div_ceil(PAGE_SIZE);
        let free = |at: u32| (0..pages).all(|page| system.memory.mapping_at(at + page * PAGE_SIZE).is_none());
        let mut candidate = SHARED_MEMORY_VADDR;
        while !free(candidate) {
            candidate += PAGE_SIZE;
        }
        candidate
    } else {
        addr
    };

    let perm = Permission::from_bits_truncate(permission & 0x7) | Permission::READ;
    system
        .memory
        .map(addr, paddr, size, perm, MemoryState::Shared);

    let name = if let Some(KObject::SharedMemory(block)) = system.kernel.objects.get_mut(object) {
        block.mapped_at = Some(addr);
        block.name.clone()
    } else {
        String::new()
    };

    // the services that publish a shared block need to know where the guest
    // put it, because that is where they write their state each frame.
    match name.as_str() {
        "GSP" => system.services.gsp.shared_memory_address = addr,
        "HID" => {
            system.services.hid.shared_memory_address = addr;
            system.services.hid.shared_memory_paddr = paddr;
        }
        // a font's internal pointers are absolute, so they only mean
        // anything once the guest has chosen where the block lives.
        "SharedFont" => crate::services::shared_font::relocate(&mut system.memory, addr, paddr),
        _ => {}
    }

    log::debug!("mapped {name} block handle 0x{handle:X} at 0x{addr:08X} (0x{size:X} bytes)");
    system.cpu.regs[0] = 0;
}

fn unmap_memory_block(system: &mut System) {
    let handle = system.cpu.regs[0];
    let addr = system.cpu.regs[1];
    if let Some(object) = system.kernel.resolve(handle) {
        if let Some(KObject::SharedMemory(block)) = system.kernel.objects.get(object) {
            let size = block.size;
            system.memory.unmap(addr, size);
        }
    }
    system.cpu.regs[0] = 0;
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

/// svcCreateThread, r0 = priority, r1 = entry, r2 = argument,
/// r3 = stack top, r4 = processor id. Returns the handle in r1.
fn create_thread(system: &mut System) {
    let priority = system.cpu.regs[0];
    let entry = system.cpu.regs[1];
    let arg = system.cpu.regs[2];
    let stack_top = system.cpu.regs[3];
    let processor_id = system.cpu.regs[4] as i32;

    let id = system.kernel.create_thread(
        format!("thread{}", system.kernel.next_guest_id),
        entry,
        stack_top,
        arg,
        priority,
        processor_id,
    );
    // the new thread's TLS page has to exist before it runs.
    system.map_tls_page(id);

    let handle = system.kernel.thread_handle(id);
    log::debug!(
        "svcCreateThread: {} handle 0x{handle:X} priority {priority} core {processor_id} entry 0x{entry:08X} arg 0x{arg:08X} stack 0x{stack_top:08X}",
        system.kernel.thread(id).name
    );
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

fn exit_thread(system: &mut System) {
    if let Some(id) = system.kernel.current_thread {
        log::debug!("thread {} exited", system.kernel.thread(id).name);
        system.kernel.end_thread(id);
    }
}

fn exit_process(system: &mut System) {
    log::info!("guest called svcExitProcess");
    crate::plugin_3gx_loader::unload(system);
    crate::services::csnd::shutdown_all(system);
    for thread in &mut system.kernel.threads {
        thread.status = ThreadStatus::Dead;
    }
    system.kernel.current_thread = None;
    system.kernel.reschedule_pending = true;
    system.exited = true;
}

/// how long a yielding thread steps aside when others are ready, about a
/// scheduler time slice.
const YIELD_TICKS: u64 = 20_000;

/// svcSleepThread, r0:r1 = nanoseconds as a signed 64-bit value.
fn sleep_thread(system: &mut System) {
    let nanos = (system.cpu.regs[0] as u64) | ((system.cpu.regs[1] as u64) << 32);
    let tick = system.cpu.cycles;
    // a zero sleep is a yield, and while other threads are ready the
    // kernel runs them for a while even when their priority is lower,
    // titles polling a worker thread that way would spin forever otherwise
    let ticks = if nanos != 0 {
        nanos_to_ticks(nanos)
    } else if system.kernel.others_ready() {
        YIELD_TICKS
    } else if system.kernel.next_event().is_some_and(|at| at <= tick) {
        // a thread or a timer is due, and the pass at the yield wakes it on
        // time
        0
    } else {
        // nobody else can take the core, so a zero yield is a no-op: the
        // thread keeps it, and no scheduling pass is due. titles that poll
        // this way in a tight loop were paying a full pass per iteration.
        // it still let the core go, as the pass would have counted it
        if let Some(thread) = system.kernel.current_mut() {
            thread.running_since = tick;
        }
        system.cpu.regs[0] = 0;
        return;
    };
    system.kernel.sleep_current(ticks, tick);
    system.cpu.regs[0] = 0;
}

fn get_thread_priority(system: &mut System) {
    let handle = system.cpu.regs[1];
    match resolve_thread(system, handle) {
        Some(id) => {
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = system.kernel.thread(id).priority;
        }
        None => system.cpu.regs[0] = invalid_handle(system, handle, "svcGetThreadPriority"),
    }
}

fn set_thread_priority(system: &mut System) {
    let handle = system.cpu.regs[0];
    let priority = system.cpu.regs[1];
    match resolve_thread(system, handle) {
        Some(id) => {
            system.kernel.thread_mut(id).priority = priority.min(super::LOWEST_PRIORITY);
            system.kernel.reschedule_pending = true;
            system.cpu.regs[0] = 0;
        }
        None => system.cpu.regs[0] = invalid_handle(system, handle, "svcSetThreadPriority"),
    }
}

fn get_thread_id(system: &mut System) {
    let handle = system.cpu.regs[1];
    match resolve_thread(system, handle) {
        Some(id) => {
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = system.kernel.thread(id).guest_id;
        }
        None => system.cpu.regs[0] = invalid_handle(system, handle, "svcGetThreadId"),
    }
}

fn resolve_thread(system: &mut System, handle: u32) -> Option<super::thread::ThreadId> {
    if handle == CURRENT_THREAD {
        return system.kernel.current_thread;
    }
    match system.kernel.objects.get(system.kernel.handles.resolve(handle)?) {
        Some(KObject::Thread(id)) => Some(*id),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Synchronisation
// ---------------------------------------------------------------------------

/// svcCreateMutex, r1 = initially locked. Returns the handle in r1.
fn create_mutex(system: &mut System) {
    let initially_locked = system.cpu.regs[1] != 0;
    let mut mutex = sync::Mutex::new("Mutex");
    if initially_locked {
        mutex.owner = system.kernel.current_thread;
        mutex.lock_count = 1;
    }
    let object = system.kernel.objects.insert(KObject::Mutex(mutex));
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "Mutex");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

fn release_mutex(system: &mut System) {
    let handle = system.cpu.regs[0];
    let Some(object) = system.kernel.resolve(handle) else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcReleaseMutex");
        return;
    };
    if let Some(KObject::Mutex(mutex)) = system.kernel.objects.get_mut(object) {
        mutex.lock_count = mutex.lock_count.saturating_sub(1);
        if mutex.lock_count == 0 {
            mutex.owner = None;
            system.kernel.reschedule_pending = true;
        }
        system.cpu.regs[0] = 0;
    } else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcReleaseMutex");
    }
}

/// svcCreateSemaphore, r1 = initial count, r2 = maximum count.
fn create_semaphore(system: &mut System) {
    let initial = system.cpu.regs[1] as i32;
    let max = system.cpu.regs[2] as i32;
    let object = system
        .kernel
        .objects
        .insert(KObject::Semaphore(sync::Semaphore {
            name: "Semaphore".into(),
            count: initial,
            max_count: max,
        }));
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "Semaphore");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

/// svcReleaseSemaphore, r1 = handle, r2 = release count.
fn release_semaphore(system: &mut System) {
    let handle = system.cpu.regs[1];
    let count = system.cpu.regs[2] as i32;
    let Some(object) = system.kernel.resolve(handle) else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcReleaseSemaphore");
        return;
    };
    if let Some(KObject::Semaphore(semaphore)) = system.kernel.objects.get_mut(object) {
        let previous = semaphore.count;
        semaphore.count = (semaphore.count + count).min(semaphore.max_count);
        system.kernel.reschedule_pending = true;
        system.cpu.regs[0] = 0;
        system.cpu.regs[1] = previous as u32;
    } else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcReleaseSemaphore");
    }
}

/// svcCreateEvent, r1 = reset type. Returns the handle in r1.
fn create_event(system: &mut System) {
    let reset_type = ResetType::from_raw(system.cpu.regs[1]);
    let (_, handle) = system.kernel.create_event(reset_type, "Event");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

fn signal_event(system: &mut System) {
    let handle = system.cpu.regs[0];
    match system.kernel.resolve(handle) {
        Some(object) => {
            system.kernel.signal_event(object);
            system.cpu.regs[0] = 0;
        }
        None => system.cpu.regs[0] = invalid_handle(system, handle, "svcSignalEvent"),
    }
}

fn clear_event(system: &mut System) {
    let handle = system.cpu.regs[0];
    match system.kernel.resolve(handle) {
        Some(object) => {
            system.kernel.clear_event(object);
            system.cpu.regs[0] = 0;
        }
        None => system.cpu.regs[0] = invalid_handle(system, handle, "svcClearEvent"),
    }
}

/// svcCreateTimer, r1 = reset type.
fn create_timer(system: &mut System) {
    let reset_type = ResetType::from_raw(system.cpu.regs[1]);
    let object = system.kernel.objects.insert(KObject::Timer(sync::Timer {
        name: "Timer".into(),
        reset_type,
        signaled: false,
        fire_at: None,
        interval: 0,
    }));
    system.kernel.timers.push(object);
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "Timer");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

/// svcSetTimer, r0 = handle, r2:r3 = initial delay, r1:r4 = interval, both
/// in nanoseconds, a negative one taken as zero.
fn set_timer(system: &mut System) {
    let handle = system.cpu.regs[0];
    let nanos = |low: u32, high: u32| ((low as u64) | ((high as u64) << 32)) as i64;
    let initial = nanos(system.cpu.regs[2], system.cpu.regs[3]).max(0) as u64;
    let interval = nanos(system.cpu.regs[1], system.cpu.regs[4]).max(0) as u64;
    let now = system.cpu.cycles;
    system.kernel.catch_up_timers(now);

    let Some(object) = system.kernel.resolve(handle) else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcSetTimer");
        return;
    };
    if let Some(KObject::Timer(timer)) = system.kernel.objects.get_mut(object) {
        timer.fire_at = Some(now.saturating_add(nanos_to_ticks(initial)));
        timer.interval = nanos_to_ticks(interval);
        timer.signaled = false;
        system.cpu.regs[0] = 0;
    } else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcSetTimer");
    }
}

fn cancel_timer(system: &mut System) {
    let handle = system.cpu.regs[0];
    system.kernel.catch_up_timers(system.cpu.cycles);
    if let Some(object) = system.kernel.resolve(handle) {
        if let Some(KObject::Timer(timer)) = system.kernel.objects.get_mut(object) {
            timer.fire_at = None;
        }
    }
    system.cpu.regs[0] = 0;
}

fn clear_timer(system: &mut System) {
    let handle = system.cpu.regs[0];
    system.kernel.catch_up_timers(system.cpu.cycles);
    if let Some(object) = system.kernel.resolve(handle) {
        if let Some(KObject::Timer(timer)) = system.kernel.objects.get_mut(object) {
            timer.signaled = false;
        }
    }
    system.cpu.regs[0] = 0;
}

fn create_address_arbiter(system: &mut System) {
    let object = system
        .kernel
        .objects
        .insert(KObject::AddressArbiter(sync::AddressArbiter::default()));
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "AddressArbiter");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

/// svcArbitrateAddress, r0 = handle, r1 = address, r2 = type, r3 = value,
/// r4:r5 = timeout in nanoseconds, a negative one waiting for good.
fn arbitrate_address(system: &mut System) {
    let handle = system.cpu.regs[0];
    let address = system.cpu.regs[1];
    let Some(kind) = ArbitrationType::from_raw(system.cpu.regs[2]) else {
        system.cpu.regs[0] = errors::INVALID_ENUM_VALUE.0;
        return;
    };
    let value = system.cpu.regs[3] as i32;
    let timeout_nanos = ((system.cpu.regs[4] as u64) | ((system.cpu.regs[5] as u64) << 32)) as i64;

    let Some(object) = system.kernel.resolve(handle) else {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcArbitrateAddress");
        return;
    };

    system.cpu.regs[0] = 0;

    log::trace!(
        "svcArbitrateAddress({kind:?}) on 0x{address:08X} value {value} (memory holds {})",
        system.memory.read32(address) as i32
    );

    if kind == ArbitrationType::Signal {
        // wake up to value threads parked on this address, a negative value
        // means all of them.
        let mut woken = 0;
        let unlimited = value < 0;
        let mut to_wake = Vec::new();
        let kernel = &mut system.kernel;
        let threads = &kernel.threads;
        if let Some(KObject::AddressArbiter(arbiter)) = kernel.objects.get_mut(object) {
            arbiter.waiters.retain(|&(thread, addr)| {
                if addr != address {
                    return true;
                }
                // a thread whose wait timed out, or that ended since, left its
                // entry behind, it goes without counting, a dead thread must
                // never run again
                let parked = &threads[thread as usize];
                if parked.status != ThreadStatus::WaitArbiter || parked.wait_address != Some(address) || to_wake.contains(&thread) {
                    return false;
                }
                if unlimited || woken < value {
                    woken += 1;
                    to_wake.push(thread);
                    false
                } else {
                    true
                }
            });
        }
        for thread in to_wake {
            let thread = system.kernel.thread_mut(thread);
            thread.clear_wait();
            thread.wait_result = Some(WaitResult::Signaled(0));
            thread.status = ThreadStatus::Ready;
        }
        system.kernel.reschedule_pending = true;
        return;
    }

    // the waiting forms compare the word at address against value and only
    // sleep when it is smaller.
    let current = system.memory.read32(address) as i32;
    if current >= value {
        return;
    }
    if kind.decrements() {
        system.memory.write32(address, (current - 1) as u32);
    }

    let Some(thread_id) = system.kernel.current_thread else {
        return;
    };
    if let Some(KObject::AddressArbiter(arbiter)) = system.kernel.objects.get_mut(object) {
        arbiter.waiters.push((thread_id, address));
    }
    let now = system.cpu.cycles;
    let thread = system.kernel.thread_mut(thread_id);
    thread.clear_wait();
    thread.wait_address = Some(address);
    thread.wakeup_at = if kind.has_timeout() && timeout_nanos >= 0 {
        Some(now.saturating_add(nanos_to_ticks(timeout_nanos as u64)))
    } else {
        None
    };
    thread.status = ThreadStatus::WaitArbiter;
    thread.wait_syscall = Some(WaitSyscall::ArbitrateAddress);
    system.kernel.reschedule_pending = true;
}

/// svcWaitSynchronization1, r0 = handle, r2:r3 = timeout in nanoseconds.
fn wait_synchronization1(system: &mut System) {
    let handle = system.cpu.regs[0];
    system.kernel.catch_up_timers(system.cpu.cycles);
    let timeout = (system.cpu.regs[2] as u64) | ((system.cpu.regs[3] as u64) << 32);
    let signed_timeout = timeout as i64;

    let Some(object) = system.kernel.resolve(handle) else {
        log::warn!("svcWaitSynchronization1 on invalid handle 0x{handle:X}");
        system.cpu.regs[0] = errors::INVALID_HANDLE.0;
        return;
    };

    let Some(thread_id) = system.kernel.current_thread else {
        system.cpu.regs[0] = 0;
        return;
    };

    if system.kernel.is_signaled(object, thread_id) {
        system.kernel.acquire_public(object, thread_id);
        system.cpu.regs[0] = 0;
        return;
    }

    if signed_timeout == 0 {
        system.cpu.regs[0] = errors::TIMEOUT.0;
        return;
    }

    let tick = system.cpu.cycles;
    let ticks = (signed_timeout > 0).then(|| nanos_to_ticks(timeout));
    system.kernel.begin_wait(vec![object], false, ticks, tick);
    // the result registers are filled in when the wait completes.
    system.kernel.thread_mut(thread_id).wait_syscall = Some(WaitSyscall::WaitSynchronization1);
}

/// svcWaitSynchronizationN, r0 = timeout low, r1 = handle array, r2 = count,
/// r3 = wait-for-all, r4 = timeout high.
fn wait_synchronization_n(system: &mut System) {
    system.kernel.catch_up_timers(system.cpu.cycles);
    let handles_ptr = system.cpu.regs[1];
    let count = system.cpu.regs[2];
    let wait_all = system.cpu.regs[3] != 0;
    let timeout = (system.cpu.regs[0] as u64) | ((system.cpu.regs[4] as u64) << 32);
    let signed_timeout = timeout as i64;

    let mut objects = Vec::with_capacity(count as usize);
    for i in 0..count {
        let handle = system.memory.read32(handles_ptr + i * 4);
        match system.kernel.resolve(handle) {
            Some(object) => objects.push(object),
            None => {
                log::warn!("svcWaitSynchronizationN: invalid handle 0x{handle:X} at index {i}");
                system.cpu.regs[0] = errors::INVALID_HANDLE.0;
                return;
            }
        }
    }

    let Some(thread_id) = system.kernel.current_thread else {
        system.cpu.regs[0] = 0;
        return;
    };

    let kernel = &system.kernel;
    let signaled = |&object: &ObjectId| kernel.is_signaled(object, thread_id);
    let satisfied = if wait_all { objects.iter().all(signaled).then_some(0) } else { objects.iter().position(signaled) };

    if let Some(index) = satisfied {
        if wait_all {
            for &object in &objects {
                system.kernel.acquire_public(object, thread_id);
            }
        } else {
            system.kernel.acquire_public(objects[index], thread_id);
        }
        system.cpu.regs[0] = 0;
        system.cpu.regs[1] = index as u32;
        return;
    }

    if signed_timeout == 0 {
        system.cpu.regs[0] = errors::TIMEOUT.0;
        return;
    }

    let tick = system.cpu.cycles;
    let ticks = (signed_timeout > 0).then(|| nanos_to_ticks(timeout));
    system.kernel.begin_wait(objects, wait_all, ticks, tick);
    system.kernel.thread_mut(thread_id).wait_syscall = Some(WaitSyscall::WaitSynchronizationN);
}

// ---------------------------------------------------------------------------
// Handles, ports and services
// ---------------------------------------------------------------------------

fn close_handle(system: &mut System) {
    let handle = system.cpu.regs[0];
    let csnd_session = system.kernel.resolve(handle).and_then(|object| {
        let last_handle = system.kernel.objects.refcount(object) == 1;
        match system.kernel.objects.get(object) {
            Some(KObject::ClientSession(session))
                if last_handle && session.service == "csnd:SND" => Some(session.subhandle),
            _ => None,
        }
    });
    system.kernel.handles.close(&mut system.kernel.objects, handle);
    if let Some(session) = csnd_session {
        crate::services::csnd::close_session(system, session);
    }
    system.cpu.regs[0] = 0;
}

fn duplicate_handle(system: &mut System) {
    let handle = system.cpu.regs[1];
    match system.kernel.resolve(handle) {
        Some(object) => {
            let label = system.kernel.handles.label(handle).to_owned();
            let new_handle = system.kernel.handles.duplicate_object(
                &mut system.kernel.objects,
                object,
                &label,
            );
            system.cpu.regs[0] = 0;
            system.cpu.regs[1] = new_handle;
        }
        None => {
            log::warn!("svcDuplicateHandle on invalid handle 0x{handle:X}");
            system.cpu.regs[0] = errors::INVALID_HANDLE.0;
        }
    }
}

/// svcConnectToPort, r1 = pointer to the port name.
fn connect_to_port(system: &mut System) {
    let name_ptr = system.cpu.regs[1];
    let name = system.memory.read_cstring(name_ptr, 12);
    log::debug!("svcConnectToPort(\"{name}\")");

    let object = system
        .kernel
        .objects
        .insert(KObject::ClientPort(name.clone()));
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, &name);
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

/// svcSendSyncRequest, r0 = session handle.
fn send_sync_request(system: &mut System) {
    let handle = system.cpu.regs[0];
    let Some(object) = system.kernel.resolve(handle) else {
        log::warn!("svcSendSyncRequest on invalid handle 0x{handle:X}");
        system.cpu.regs[0] = errors::INVALID_HANDLE.0;
        return;
    };

    let target = match system.kernel.objects.get(object) {
        Some(KObject::ClientPort(name)) => crate::services::Target::port(name.clone()),
        Some(KObject::ClientSession(session)) => {
            crate::services::Target::service(session.service.clone(), session.subhandle)
        }
        _ => {
            log::warn!("svcSendSyncRequest on a {} handle", {
                system
                    .kernel
                    .objects
                    .get(object)
                    .map_or("missing", |o| o.type_name())
            });
            system.cpu.regs[0] = errors::INVALID_HANDLE.0;
            return;
        }
    };

    system.cpu.regs[0] = 0;
    crate::services::handle_request(system, target);
    // on the console a service runs in a process of its own and the thread
    // waits for its reply, while the threads below it run. Star Fox 64 3D
    // marks a job running once the more urgent thread doing it is made,
    // which has to be waiting on its first request by then, or the job is
    // done before it is marked and stays running forever
    if system.kernel.current().is_some_and(|thread| thread.status == ThreadStatus::Running) {
        let tick = system.cpu.cycles;
        system.kernel.sleep_current(REQUEST_TICKS, tick);
    }
}

/// how long a request to a service keeps the thread waiting, what Citra
/// measured for one to GSP on a New 3DS.
pub(crate) const REQUEST_TICKS: u64 = nanos_to_ticks(39_000);

// ---------------------------------------------------------------------------
// Plugin loader compatibility
// ---------------------------------------------------------------------------

/// ControlProcess operation used by the 3GX bootloader to make the process
/// address space writable and executable before restoring its entry point.
const PROCESSOP_SET_MMU_TO_RWX: u32 = 1;

/// svcControlProcess, r0 = process handle, r1 = operation, r2/r3 = arguments.
/// The 3GX bootstrap uses operation 1. The emulator has a single guest process,
/// represented by CURRENT_PROCESS just like the console's pseudo-handle.
fn control_process(system: &mut System) {
    let handle = system.cpu.regs[0];
    let operation = system.cpu.regs[1];

    let Some(object) = system.kernel.resolve(handle) else {
        let error = invalid_handle(system, handle, "svcControlProcess");
        system.cpu.regs[0] = error;
        return;
    };
    if !matches!(system.kernel.objects.get(object), Some(KObject::Process)) {
        let error = invalid_handle(system, handle, "svcControlProcess");
        system.cpu.regs[0] = error;
        return;
    }

    match operation {
        PROCESSOP_SET_MMU_TO_RWX => {
            let mappings: Vec<_> = system.memory.mappings().copied().collect();
            let permission = Permission::READ | Permission::WRITE | Permission::EXECUTE;
            for mapping in mappings {
                system.memory.map(
                    mapping.base,
                    mapping.paddr,
                    mapping.size,
                    permission,
                    mapping.state,
                );
            }
            system.cpu.regs[0] = 0;
        }
        _ => {
            log::warn!("svcControlProcess operation {operation} is not implemented");
            system.cpu.regs[0] = errors::UNIMPLEMENTED.0;
        }
    }
}

// ---------------------------------------------------------------------------
// Information
// ---------------------------------------------------------------------------

fn get_system_tick(system: &mut System) {
    let tick = system.cpu.cycles;
    system.cpu.regs[0] = tick as u32;
    system.cpu.regs[1] = (tick >> 32) as u32;
    // the call itself takes this long on the console, two in a row read
    // ticks this far apart. a title spinning on the clock until a frame's
    // time is up would otherwise spin many times longer
    system.cpu.cycles += SYSTEM_TICK_COST;
}

/// ticks between two svcGetSystemTick calls in a row on the console.
pub(crate) const SYSTEM_TICK_COST: u64 = 150;

/// host monotonic time in nanoseconds, like Citra's HOST_TICK value.
fn host_tick() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

/// svcGetSystemInfo, r1 = type, r2 = parameter.
fn get_system_info(system: &mut System) {
    let kind = system.cpu.regs[1];
    let param = system.cpu.regs[2];
    let value: u64 = match (kind, param) {
        // svcGetSystemInfo(REGION_MEMORY_USAGE, region), where 0 is all
        // FCRAM, then APPLICATION, SYSTEM and BASE are 1, 2 and 3.
        (0, 0) => {
            system.memory.phys.region_used(crate::memory::MemoryRegion::Application) as u64
                + system.memory.phys.region_used(crate::memory::MemoryRegion::System) as u64
                + system.memory.phys.region_used(crate::memory::MemoryRegion::Base) as u64
        }
        (0, 1) => system
            .memory
            .phys
            .region_used(crate::memory::MemoryRegion::Application) as u64,
        (0, 2) => system
            .memory
            .phys
            .region_used(crate::memory::MemoryRegion::System) as u64,
        (0, 3) => system
            .memory
            .phys
            .region_used(crate::memory::MemoryRegion::Base) as u64,
        (2, 0) => system.kernel.live_thread_count() as u64,
        // Five core processes are launched directly by the native kernel.
        (26, _) => 5,
        // Citra/Azahar extension used by CTGP-7 and other homebrew.
        // 2 identifies the Azahar-compatible runtime; upstream Citra reports 1.
        (0x0002_0000, 0) => {
            log::info!("svcGetSystemInfo: reporting Azahar-compatible identifier 2 for CTGP-7");
            2
        }
        (0x0002_0000, 1) => host_tick(),
        (0x0002_0000, 2) => u64::from(system.emulation_speed),
        _ => {
            log::debug!("svcGetSystemInfo({kind}, {param}) is not implemented");
            0
        }
    };
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = value as u32;
    system.cpu.regs[2] = (value >> 32) as u32;
}

/// whether handle names this runtime's single guest process.
fn is_process_handle(system: &mut System, handle: u32) -> bool {
    let Some(object) = system.kernel.resolve(handle) else {
        return false;
    };
    matches!(system.kernel.objects.get(object), Some(KObject::Process))
}

/// whether a guest output buffer is fully mapped and writable.
fn process_output_is_writable(memory: &crate::memory::Memory, address: u32, size: usize) -> bool {
    let Ok(size) = u32::try_from(size) else {
        return false;
    };
    let Some(end) = address.checked_add(size) else {
        return false;
    };
    let mut cursor = address;
    while cursor < end {
        let Some(mapping) = memory.mapping_at(cursor) else {
            return false;
        };
        if !mapping.permission.contains(Permission::WRITE) {
            return false;
        }
        let Some(mapping_end) = mapping.base.checked_add(mapping.size) else {
            return false;
        };
        if mapping_end <= cursor {
            return false;
        }
        cursor = end.min(mapping_end);
    }
    true
}

/// writes an SVC result through its guest output pointer, as libctru expects.
fn write_process_output(system: &mut System, address: u32, bytes: &[u8]) -> bool {
    if !process_output_is_writable(&system.memory, address, bytes.len()) {
        return false;
    }
    system.memory.write_bytes(address, bytes);
    true
}

/// svcGetProcessInfo(r0 = output pointer, r1 = process handle, r2 = type).
///
/// In addition to the standard process fields, Luma exposes the executable
/// segment layout to plugins. CTGP-7 uses these values to locate and checksum
/// the live game .code image before it applies its patches.
fn get_process_info(system: &mut System) {
    let output = system.cpu.regs[0];
    let handle = system.cpu.regs[1];
    let kind = system.cpu.regs[2];
    if !is_process_handle(system, handle) {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcGetProcessInfo");
        return;
    }

    let value: u64 = match kind {
        // total memory the process has committed.
        2 => system.memory.phys.region_used(system.kernel.memory_region) as u64,
        // what turns a linear heap address into a physical one, titles
        // work out the addresses the GPU jumps to with it
        20 => 0x2000_0000u32.wrapping_sub(system.kernel.linear_base) as u64,
        // Luma GetProcessInfo extensions used by 3GX plugins.
        0x1_0000 => {
            let mut name = [0u8; 8];
            if let Some(title) = &system.title {
                let source = title.exheader.title.as_bytes();
                let count = source.len().min(name.len());
                name[..count].copy_from_slice(&source[..count]);
            }
            u64::from_le_bytes(name)
        }
        0x1_0001 => system.kernel.program_id,
        0x1_0002 => system.title.as_ref().map_or(0, |title| {
            u64::from(title.exheader.text.num_pages.saturating_mul(PAGE_SIZE))
        }),
        0x1_0003 => system.title.as_ref().map_or(0, |title| {
            u64::from(title.exheader.rodata.num_pages.saturating_mul(PAGE_SIZE))
        }),
        0x1_0004 => system.title.as_ref().map_or(0, |title| {
            let data = title.exheader.data.num_pages.saturating_mul(PAGE_SIZE);
            let bss = title.exheader.bss_size.saturating_add(PAGE_MASK) & !PAGE_MASK;
            u64::from(data.saturating_add(bss))
        }),
        0x1_0005 => system.title.as_ref().map_or(0, |title| u64::from(title.exheader.text.address)),
        0x1_0006 => system.title.as_ref().map_or(0, |title| u64::from(title.exheader.rodata.address)),
        0x1_0007 => system.title.as_ref().map_or(0, |title| u64::from(title.exheader.data.address)),
        _ => {
            log::debug!("svcGetProcessInfo(handle=0x{handle:08X}, type={kind}) is not implemented");
            0
        }
    };
    if !write_process_output(system, output, &value.to_le_bytes()) {
        system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
        return;
    }
    system.cpu.regs[0] = 0;
}

/// Citra/Azahar's extension SVC used by CTGP-7 to set emulation speed.
/// This runtime does not expose a host frame limiter yet, but acknowledges
/// the request so the plugin can complete its initialization sequence.
fn kernel_set_state(system: &mut System) {
    const KERNEL_STATE_REBOOT: u32 = 7;
    const KERNEL_STATE_CITRA_EMULATION_SPEED: u32 = 0x0002_0000;

    let state = system.cpu.regs[0];
    let value = system.cpu.regs[1];
    match state {
        KERNEL_STATE_CITRA_EMULATION_SPEED => {
            let requested = value as u16;
            // Citra/Azahar use 0xFFFF as a reset-to-normal sentinel.
            system.emulation_speed = if requested == u16::MAX { 100 } else { requested };
            log::info!(
                "svcKernelSetState: emulation speed is now {}%",
                system.emulation_speed
            );
        }
        KERNEL_STATE_REBOOT => {
            log::warn!("svcKernelSetState requested a reboot; reboot is not implemented");
        }
        _ => log::debug!("svcKernelSetState({state}, {value}, {})", system.cpu.regs[2]),
    }
    system.cpu.regs[0] = 0;
}

/// svcGetProcessId(r0 = output pointer, r1 = process handle).
fn get_process_id(system: &mut System) {
    let output = system.cpu.regs[0];
    let handle = system.cpu.regs[1];
    if !is_process_handle(system, handle) {
        system.cpu.regs[0] = invalid_handle(system, handle, "svcGetProcessId");
        return;
    }
    let process_id = system.kernel.process_id;
    if !write_process_output(system, output, &process_id.to_le_bytes()) {
        system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
        return;
    }
    system.cpu.regs[0] = 0;
}

/// svcOpenProcess(r0 = handle output pointer, r1 = process ID). The runtime
/// currently owns one guest process, so only that process ID can be opened.
fn open_process(system: &mut System) {
    let output = system.cpu.regs[0];
    let process_id = system.cpu.regs[1];
    if process_id != system.kernel.process_id {
        log::warn!("svcOpenProcess: process 0x{process_id:08X} does not exist");
        system.cpu.regs[0] = PROCESS_NOT_FOUND;
        return;
    }
    if !process_output_is_writable(&system.memory, output, 4) {
        system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
        return;
    }
    let object = system.kernel.process_object();
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "Process");
    system.memory.write_bytes(output, &handle.to_le_bytes());
    system.cpu.regs[0] = 0;
}

/// Luma svcMapProcessMemoryEx. Its custom SVC ABI puts the first four
/// arguments in r0-r3 and stack arguments in r4-r7. Version 2 is selected by
/// the magic value in r0; the actual destination handle is then r6.
fn map_process_memory_ex(system: &mut System) {
    let mut destination_process = system.cpu.regs[0];
    let destination_address = system.cpu.regs[1];
    let source_process = system.cpu.regs[2];
    let source_address = system.cpu.regs[3];
    let requested_size = system.cpu.regs[4];
    let flags = if destination_process == MAP_PROCESS_MEMORY_EX_V2_MAGIC {
        destination_process = system.cpu.regs[6];
        system.cpu.regs[5]
    } else {
        0
    };

    if !is_process_handle(system, destination_process) {
        system.cpu.regs[0] = invalid_handle(system, destination_process, "svcMapProcessMemoryEx destination");
        return;
    }
    if !is_process_handle(system, source_process) {
        system.cpu.regs[0] = invalid_handle(system, source_process, "svcMapProcessMemoryEx source");
        return;
    }
    if destination_address & PAGE_MASK != 0 || source_address & PAGE_MASK != 0 {
        system.cpu.regs[0] = errors::MISALIGNED_ADDRESS.0;
        return;
    }
    if requested_size == 0 {
        system.cpu.regs[0] = errors::MISALIGNED_SIZE.0;
        return;
    }
    let Some(size) = requested_size.checked_add(PAGE_MASK).map(|size| size & !PAGE_MASK) else {
        system.cpu.regs[0] = errors::OUT_OF_RANGE.0;
        return;
    };
    let Some(destination_end) = destination_address.checked_add(size) else {
        system.cpu.regs[0] = errors::OUT_OF_RANGE.0;
        return;
    };

    let Some(source_mapping) = system.memory.mapping_at(source_address).copied() else {
        system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
        return;
    };
    let source_offset = source_address - source_mapping.base;
    if source_offset.checked_add(size).is_none_or(|end| end > source_mapping.size) {
        system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
        return;
    }
    let Some(source_paddr) = source_mapping.paddr.checked_add(source_offset) else {
        system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
        return;
    };

    // Citra's VM manager refuses to replace any mapped destination page.
    let mut page = destination_address;
    while page < destination_end {
        if system.memory.mapping_at(page).is_some() {
            system.cpu.regs[0] = errors::INVALID_ADDRESS_STATE.0;
            return;
        }
        page += PAGE_SIZE;
    }

    let state = if flags & MAP_PROCESS_MEMORY_EX_PRIVATE != 0 {
        MemoryState::Private
    } else {
        MemoryState::Shared
    };
    system.memory.map(
        destination_address,
        source_paddr,
        size,
        Permission::READ | Permission::WRITE | Permission::EXECUTE,
        state,
    );
    system.cpu.regs[0] = 0;
}

/// Luma svcUnmapProcessMemoryEx, r0 = process, r1 = address, r2 = size.
fn unmap_process_memory_ex(system: &mut System) {
    let process = system.cpu.regs[0];
    let address = system.cpu.regs[1];
    let requested_size = system.cpu.regs[2];

    if !is_process_handle(system, process) {
        system.cpu.regs[0] = invalid_handle(system, process, "svcUnmapProcessMemoryEx");
        return;
    }
    if address & PAGE_MASK != 0 {
        system.cpu.regs[0] = errors::MISALIGNED_ADDRESS.0;
        return;
    }
    if requested_size == 0 {
        system.cpu.regs[0] = errors::MISALIGNED_SIZE.0;
        return;
    }
    let Some(size) = requested_size.checked_add(PAGE_MASK).map(|size| size & !PAGE_MASK) else {
        system.cpu.regs[0] = errors::OUT_OF_RANGE.0;
        return;
    };
    let Some(end) = address.checked_add(size) else {
        system.cpu.regs[0] = errors::OUT_OF_RANGE.0;
        return;
    };

    let mut page = address;
    while page < end {
        if system.memory.mapping_at(page).is_none() {
            system.cpu.regs[0] = errors::INVALID_ADDRESS.0;
            return;
        }
        page += PAGE_SIZE;
    }
    // Unmapping an alias must not free the source physical pages; ownership
    // remains with the original mapping, as in Luma/Citra.
    system.memory.unmap(address, size);
    system.cpu.regs[0] = 0;
}

fn get_resource_limit(system: &mut System) {
    let _process = system.cpu.regs[1];
    let object = system.kernel.objects.insert(KObject::ResourceLimit);
    let handle = system
        .kernel
        .handles
        .create(&mut system.kernel.objects, object, "ResourceLimit");
    system.cpu.regs[0] = 0;
    system.cpu.regs[1] = handle;
}

/// resource limit names, as svcGetResourceLimitLimitValues indexes them.
const RESOURCE_PRIORITY: u32 = 0;
const RESOURCE_COMMIT: u32 = 1;
const RESOURCE_THREAD: u32 = 2;
const RESOURCE_EVENT: u32 = 3;
const RESOURCE_MUTEX: u32 = 4;
const RESOURCE_SEMAPHORE: u32 = 5;
const RESOURCE_TIMER: u32 = 6;
const RESOURCE_SHARED_MEMORY: u32 = 7;
const RESOURCE_ADDRESS_ARBITER: u32 = 8;
const RESOURCE_CPU_TIME: u32 = 9;

fn resource_limit_values(system: &mut System, current: bool) {
    let values_ptr = system.cpu.regs[0];
    let names_ptr = system.cpu.regs[2];
    let count = system.cpu.regs[3];

    for i in 0..count {
        let name = system.memory.read32(names_ptr + i * 4);
        let value: i64 = match (name, current) {
            (RESOURCE_COMMIT, false) => {
                system.memory.phys.region_size(system.kernel.memory_region) as i64
            }
            (RESOURCE_COMMIT, true) => {
                system.memory.phys.region_used(system.kernel.memory_region) as i64
            }
            (RESOURCE_PRIORITY, _) => 0x18,
            (RESOURCE_THREAD, false) => 128,
            (RESOURCE_THREAD, true) => system.kernel.live_thread_count() as i64,
            (RESOURCE_EVENT, false) => 128,
            (RESOURCE_MUTEX, false) => 64,
            (RESOURCE_SEMAPHORE, false) => 32,
            (RESOURCE_TIMER, false) => 16,
            (RESOURCE_SHARED_MEMORY, false) => 32,
            (RESOURCE_ADDRESS_ARBITER, false) => 8,
            (RESOURCE_CPU_TIME, _) => 0,
            _ => 0,
        };
        system
            .memory
            .write32(values_ptr + i * 8, value as u32);
        system
            .memory
            .write32(values_ptr + i * 8 + 4, (value >> 32) as u32);
    }
    system.cpu.regs[0] = 0;
}

fn get_resource_limit_limit_values(system: &mut System) {
    resource_limit_values(system, false);
}

fn get_resource_limit_current_values(system: &mut System) {
    resource_limit_values(system, true);
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

fn svc_break(system: &mut System) {
    let reason = system.cpu.regs[0];
    let kind = match reason {
        0 => "panic",
        1 => "assert",
        2 => "user",
        _ => "unknown",
    };
    log::error!(
        "guest called svcBreak ({kind}) at 0x{:08X}",
        system.cpu.current_pc()
    );
    log::error!("{:?}", system.cpu);
    log::error!("the instructions leading here were:");
    let recent = system.recent_instructions();
    for &entry in recent.iter().rev().take(24).rev() {
        log::error!(
            "  0x{:08X} {}",
            entry & !1,
            if entry & 1 != 0 { "T" } else { "A" }
        );
    }
    system.broke = true;
}

/// svcOutputDebugString, r0 = pointer, r1 = length.
fn output_debug_string(system: &mut System) {
    let ptr = system.cpu.regs[0];
    let len = system.cpu.regs[1].min(0x1000) as usize;
    let mut buf = vec![0u8; len];
    system.memory.read_bytes(ptr, &mut buf);
    let text = String::from_utf8_lossy(&buf);
    log::info!("[guest] {}", text.trim_end());
    system.debug_output.push_str(text.trim_end());
    system.debug_output.push('\n');
    system.cpu.regs[0] = 0;
}

/// exposed so the syscall layer can consume a signal it already checked.
impl super::Kernel {
    pub fn acquire_public(&mut self, object: ObjectId, waiter: super::thread::ThreadId) {
        self.acquire(object, waiter)
    }
}

/// the address a thread returns to when its entry point falls off the end.
pub const THREAD_EXIT_ADDRESS: VAddr = THREAD_EXIT_MAGIC;

/// unused placeholder keeping CURRENT_PROCESS referenced until process
/// handles are wired up.
pub const _CURRENT_PROCESS: u32 = CURRENT_PROCESS;

#[cfg(test)]
mod tests {
    use super::*;

    fn map_process_svc_output(system: &mut System) -> u32 {
        let block = system
            .memory
            .phys
            .allocate(crate::memory::MemoryRegion::Application, PAGE_SIZE)
            .unwrap();
        let address = 0x0030_0000;
        system.memory.map(
            address,
            block.addr,
            PAGE_SIZE,
            Permission::RW,
            MemoryState::Private,
        );
        address
    }

    #[test]
    fn open_process_and_get_process_id_write_their_output_pointers() {
        let mut system = System::new(crate::Config::default());
        let output = map_process_svc_output(&mut system);
        let process_id = system.kernel.process_id;

        // An unknown process ID fails without writing an output handle.
        system.cpu.regs[0] = output;
        system.cpu.regs[1] = process_id.wrapping_add(1);
        dispatch(&mut system, 0x33);
        assert_eq!(system.cpu.regs[0], PROCESS_NOT_FOUND);

        // OpenProcess writes its handle through r0, not back into r1.
        system.cpu.regs[0] = output;
        system.cpu.regs[1] = process_id;
        dispatch(&mut system, 0x33);
        assert_eq!(system.cpu.regs[0], 0);
        let mut bytes = [0u8; 4];
        system.memory.read_bytes(output, &mut bytes);
        let handle = u32::from_le_bytes(bytes);
        assert!(is_process_handle(&mut system, handle));

        // GetProcessId likewise writes through its output pointer.
        system.cpu.regs[0] = output + 4;
        system.cpu.regs[1] = handle;
        dispatch(&mut system, 0x35);
        assert_eq!(system.cpu.regs[0], 0);
        system.memory.read_bytes(output + 4, &mut bytes);
        assert_eq!(u32::from_le_bytes(bytes), process_id);
    }

    #[test]
    fn process_svc_rejects_unmapped_output_buffers() {
        let mut system = System::new(crate::Config::default());
        system.cpu.regs[0] = 0x0030_0000;
        system.cpu.regs[1] = system.kernel.process_id;
        dispatch(&mut system, 0x33);
        assert_eq!(system.cpu.regs[0], errors::INVALID_ADDRESS.0);
    }

    #[test]
    fn map_process_memory_ex_v1_and_v2_share_live_bytes_and_unmap_cleanly() {
        let mut system = System::new(crate::Config::default());
        let process_id = system.kernel.process_id;
        let output = map_process_svc_output(&mut system);
        system.cpu.regs[0] = output;
        system.cpu.regs[1] = process_id;
        dispatch(&mut system, 0x33);
        assert_eq!(system.cpu.regs[0], 0);
        let mut handle_bytes = [0u8; 4];
        system.memory.read_bytes(output, &mut handle_bytes);
        let handle = u32::from_le_bytes(handle_bytes);

        let source = system
            .memory
            .phys
            .allocate(crate::memory::MemoryRegion::Application, PAGE_SIZE * 2)
            .unwrap();
        system.memory.map(
            0x0010_0000,
            source.addr,
            source.size,
            Permission::READ | Permission::WRITE | Permission::EXECUTE,
            MemoryState::Code,
        );
        system.memory.write_bytes(0x0010_0000, b"CTGP live .code bytes");

        // An occupied destination is a distinct invalid-address-state error.
        system.cpu.regs[..7].copy_from_slice(&[
            handle,
            0x0010_0000,
            handle,
            0x0010_0000,
            PAGE_SIZE,
            0,
            0,
        ]);
        dispatch(&mut system, 0xA0);
        assert_eq!(system.cpu.regs[0], errors::INVALID_ADDRESS_STATE.0);

        // Version 1 uses the destination process handle directly and always
        // maps the destination as Shared.
        system.cpu.regs[..7].copy_from_slice(&[
            handle,
            0x0020_0000,
            handle,
            0x0010_0000,
            PAGE_SIZE,
            MAP_PROCESS_MEMORY_EX_PRIVATE,
            0,
        ]);
        dispatch(&mut system, 0xA0);
        assert_eq!(system.cpu.regs[0], 0);
        assert_eq!(system.memory.query(0x0020_0000).state, MemoryState::Shared as u32);
        let mut bytes = [0; 21];
        system.memory.read_bytes(0x0020_0000, &mut bytes);
        assert_eq!(&bytes, b"CTGP live .code bytes");
        system.memory.write_bytes(0x0020_0000, b"PATCHED live .code bytes");
        let mut patched = [0; 24];
        system.memory.read_bytes(0x0010_0000, &mut patched);
        assert_eq!(&patched, b"PATCHED live .code bytes");

        // V1 ignores the flags argument; the unmapper only drops the alias.
        system.cpu.regs[..3].copy_from_slice(&[handle, 0x0020_0000, PAGE_SIZE]);
        dispatch(&mut system, 0xA1);
        assert_eq!(system.cpu.regs[0], 0);
        assert!(system.memory.mapping_at(0x0020_0000).is_none());
        assert!(system.memory.mapping_at(0x0010_0000).is_some());

        // Version 2 marks r0 with the magic and supplies the destination
        // process handle in r6; its flags bit selects Private.
        system.cpu.regs[..7].copy_from_slice(&[
            MAP_PROCESS_MEMORY_EX_V2_MAGIC,
            0x0020_0000,
            handle,
            0x0010_0000,
            PAGE_SIZE,
            MAP_PROCESS_MEMORY_EX_PRIVATE,
            handle,
        ]);
        dispatch(&mut system, 0xA0);
        assert_eq!(system.cpu.regs[0], 0);
        assert_eq!(system.memory.query(0x0020_0000).state, MemoryState::Private as u32);

        system.cpu.regs[..3].copy_from_slice(&[handle, 0x0020_0000, PAGE_SIZE]);
        dispatch(&mut system, 0xA1);
        assert_eq!(system.cpu.regs[0], 0);
        assert!(system.memory.mapping_at(0x0020_0000).is_none());
        assert!(system.memory.mapping_at(0x0010_0000).is_some());
    }

    #[test]
    fn luma_process_info_reports_the_running_title_executable_layout() {
        use zakuro_fs::testing::{ncch, write};

        const PROGRAM_ID: u64 = 0x0004_0000_0003_0800;
        let mut image_bytes = ncch(PROGRAM_ID, Some(&[0xEA; 0x1800]), &[]);
        image_bytes[0x23C..0x240].copy_from_slice(&0x1001u32.to_le_bytes());
        let image = write("luma-process-info", "game.cxi", &image_bytes);
        let mut system = System::new(crate::Config::default());
        system.title = Some(zakuro_fs::Title::load(&image).unwrap());
        system.kernel.program_id = PROGRAM_ID;
        let output = map_process_svc_output(&mut system);
        system.cpu.regs[0] = output;
        system.cpu.regs[1] = system.kernel.process_id;
        dispatch(&mut system, 0x33);
        assert_eq!(system.cpu.regs[0], 0);
        let mut handle_bytes = [0u8; 4];
        system.memory.read_bytes(output, &mut handle_bytes);
        let handle = u32::from_le_bytes(handle_bytes);

        for (kind, expected) in [
            (0x1_0001, PROGRAM_ID),
            (0x1_0002, u64::from(PAGE_SIZE)),
            (0x1_0004, 0x2000), // 0x1001 bytes of BSS rounds up to two pages.
            (0x1_0005, 0x0010_0000),
        ] {
            system.cpu.regs[0] = output + 8;
            system.cpu.regs[1] = handle;
            system.cpu.regs[2] = kind;
            dispatch(&mut system, 0x2B);
            let mut actual_bytes = [0u8; 8];
            system.memory.read_bytes(output + 8, &mut actual_bytes);
            let actual = u64::from_le_bytes(actual_bytes);
            assert_eq!(system.cpu.regs[0], 0);
            assert_eq!(actual, expected, "Luma process-info type 0x{kind:X}");
        }

        std::fs::remove_file(image).unwrap();
    }

    /// two reads of the clock in a row are as far apart as on the console,
    /// so a title spinning on it until a frame is over spins no longer.
    #[test]
    fn reading_the_clock_takes_time() {
        let mut system = System::new(crate::Config::default());
        let mut read = || {
            dispatch(&mut system, 0x28);
            system.cpu.regs[0] as u64 | (system.cpu.regs[1] as u64) << 32
        };
        let first = read();
        assert_eq!(read() - first, SYSTEM_TICK_COST);
    }

    #[test]
    fn control_process_sets_all_mapped_pages_to_rwx() {
        let mut system = System::new(crate::Config::default());
        let block = system
            .memory
            .phys
            .allocate(crate::memory::MemoryRegion::Application, PAGE_SIZE)
            .unwrap();
        system.memory.map(
            0x0010_0000,
            block.addr,
            PAGE_SIZE,
            Permission::RX,
            MemoryState::Code,
        );

        system.cpu.regs[..4].copy_from_slice(&[CURRENT_PROCESS, PROCESSOP_SET_MMU_TO_RWX, 0, 0]);
        dispatch(&mut system, 0xB3);

        assert_eq!(system.cpu.regs[0], 0);
        assert_eq!(system.memory.query(0x0010_0000).permission, 7);
    }

    #[test]
    fn system_info_region_memory_usage_uses_all_then_application_system_base() {
        let mut system = System::new(crate::Config::default());
        for region in [
            crate::memory::MemoryRegion::Application,
            crate::memory::MemoryRegion::System,
            crate::memory::MemoryRegion::Base,
        ] {
            system.memory.phys.allocate(region, PAGE_SIZE).unwrap();
        }

        fn query(system: &mut System, region: u32) -> u64 {
            system.cpu.regs[1] = 0; // REGION_MEMORY_USAGE
            system.cpu.regs[2] = region;
            dispatch(system, 0x2A);
            u64::from(system.cpu.regs[1]) | (u64::from(system.cpu.regs[2]) << 32)
        }

        assert_eq!(query(&mut system, 0), 3 * u64::from(PAGE_SIZE));
        assert_eq!(query(&mut system, 1), u64::from(PAGE_SIZE));
        assert_eq!(query(&mut system, 2), u64::from(PAGE_SIZE));
        assert_eq!(query(&mut system, 3), u64::from(PAGE_SIZE));
    }

    #[test]
    fn get_system_info_reports_azahar_compatibility_for_ctgp() {
        let mut system = System::new(crate::Config::default());
        system.cpu.regs[1] = 0x0002_0000; // CITRA_INFORMATION
        system.cpu.regs[2] = 0; // IS_CITRA
        dispatch(&mut system, 0x2A);

        assert_eq!(system.cpu.regs[0], 0);
        assert_eq!(system.cpu.regs[1], 2, "CTGP-7 expects the Azahar compatibility identifier");
        assert_eq!(system.cpu.regs[2], 0);
    }

    #[test]
    fn citra_host_tick_is_monotonic_and_emulation_speed_is_reported() {
        let mut system = System::new(crate::Config::default());

        system.cpu.regs[1] = 0x0002_0000; // CITRA_INFORMATION
        system.cpu.regs[2] = 1; // HOST_TICK
        dispatch(&mut system, 0x2A);
        let first = u64::from(system.cpu.regs[1]) | (u64::from(system.cpu.regs[2]) << 32);
        system.cpu.regs[1] = 0x0002_0000; // restore CITRA_INFORMATION after the previous result
        system.cpu.regs[2] = 1; // restore HOST_TICK
        dispatch(&mut system, 0x2A);
        let second = u64::from(system.cpu.regs[1]) | (u64::from(system.cpu.regs[2]) << 32);
        assert!(second >= first);

        system.cpu.regs[1] = 0x0002_0000; // restore CITRA_INFORMATION after HOST_TICK
        system.cpu.regs[2] = 2; // EMULATION_SPEED
        dispatch(&mut system, 0x2A);
        assert_eq!(system.cpu.regs[1], 100);
    }

    #[test]
    fn kernel_set_state_accepts_ctgp_emulation_speed_reset() {
        let mut system = System::new(crate::Config::default());
        system.cpu.regs[..3].copy_from_slice(&[0x0002_0000, 65_535, 0]);
        dispatch(&mut system, 0x7C);
        assert_eq!(system.cpu.regs[0], 0);
        assert_eq!(system.emulation_speed, 100);
        assert!(!system.unimplemented_svcs.contains(&0x7C));

        system.cpu.regs[..3].copy_from_slice(&[0x0002_0000, 125, 0]);
        dispatch(&mut system, 0x7C);
        assert_eq!(system.emulation_speed, 125);
    }

    #[test]
    fn invalidate_entire_instruction_cache_succeeds() {
        let mut system = System::new(crate::Config::default());
        dispatch(&mut system, 0x94);
        assert_eq!(system.cpu.regs[0], 0);
    }

    /// svcControlMemory with an operation, giving back r0 and r1.
    fn control(system: &mut System, operation: u32, addr0: u32, size: u32) -> (u32, u32) {
        system.cpu.regs[..5].copy_from_slice(&[operation, addr0, 0, size, 3]);
        dispatch(system, 0x01);
        (system.cpu.regs[0], system.cpu.regs[1])
    }

    /// the heap comes from the top of the region and the linear heap from
    /// its bottom, so the first linear block is where the console has it,
    /// and a heap shrunk from its end gives back the pages of its end.
    #[test]
    fn the_linear_heap_starts_where_the_console_has_it() {
        let mut system = System::new(crate::Config::default());
        assert_eq!(control(&mut system, MEMOP_ALLOC, HEAP_VADDR, 0x4000), (0, HEAP_VADDR));
        let linear = control(&mut system, MEMOP_ALLOC | MEMOP_LINEAR_FLAG, 0, 0x2000);
        assert_eq!(linear, (0, system.kernel.linear_base));
        let heap = system.memory.mapping_at(HEAP_VADDR).unwrap().paddr;
        assert!(heap > FCRAM_PADDR + 0x2000);

        assert_eq!(control(&mut system, MEMOP_FREE, HEAP_VADDR + 0x2000, 0x2000).0, 0);
        let kept = system.memory.mapping_at(HEAP_VADDR).unwrap();
        assert_eq!((kept.paddr, kept.size), (heap, 0x2000));
        assert!(system.memory.mapping_at(HEAP_VADDR + 0x2000).is_none());
        // what went back is what the top gives next
        assert_eq!(control(&mut system, MEMOP_ALLOC, HEAP_VADDR + 0x2000, 0x2000).0, 0);
        assert_eq!(system.memory.mapping_at(HEAP_VADDR + 0x2000).unwrap().paddr, heap + 0x2000);
    }
}
