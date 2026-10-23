use {super::*, crate::minidump_cpu::RawContextCPU, std::cmp::min};

// The following kLimit* constants are for when minidump_size_limit_ is set
// and the minidump size might exceed it.
//
// Estimate for how big each thread's stack will be (in bytes).
const LIMIT_AVERAGE_THREAD_STACK_LENGTH: usize = 8 * 1024;
// Number of threads whose stack size we don't want to limit.  These base
// threads will simply be the first N threads returned by the dumper (although
// the crashing thread will never be limited).  Threads beyond this count are
// the extra threads.
const LIMIT_BASE_THREAD_COUNT: usize = 20;
// Maximum stack size to dump for any extra thread (in bytes).
const LIMIT_MAX_EXTRA_THREAD_STACK_LEN: usize = 2 * 1024;
// Make sure this number of additional bytes can fit in the minidump
// (exclude the stack data).
const LIMIT_MINIDUMP_FUDGE_FACTOR: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy)]
enum MaxStackLen {
    None,
    Len(usize),
}

#[derive(Debug, Error, serde::Serialize)]
pub enum SectionThreadListError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] MemoryWriterError),
    #[error("Failed integer conversion")]
    TryFromIntError(
        #[from]
        #[serde(skip)]
        std::num::TryFromIntError,
    ),
    #[error("Failed to copy memory from process")]
    CopyFromProcessError(#[source] CopyFromProcessError),
    #[error("Failed to read stack for thread {thread_id}")]
    StackReadFailed {
        thread_id: u32,
        #[source]
        error: CopyFromProcessError,
    },
    #[error("Failed to get thread info")]
    ThreadInfoError(#[from] ThreadInfoError),
    #[error("Failed to write to memory buffer")]
    IOError(
        #[from]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("Failed to sanitize stack copy")]
    SanitizeStackCopyFailed(#[source] Box<WriterError>),
}

impl MinidumpWriter {
    pub fn write_thread_list_stream(
        &mut self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionThreadListError> {
        self.write_thread_list_stream_with_errors(buffer, error_graph::strategy::DontCare)
    }

    /// Writes thread contexts and records unreadable stacks as non-fatal errors.
    pub(super) fn write_thread_list_stream_with_errors(
        &mut self,
        buffer: &mut DumpBuf,
        mut soft_errors: impl WriteErrorList<SectionThreadListError>,
    ) -> Result<MDRawDirectory, SectionThreadListError> {
        let num_threads = self.threads.len();
        // Memory looks like this:
        // <num_threads><thread_1><thread_2>...

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadListStream as u32,
            location: list_header.location(),
        };

        let mut thread_list = MemoryArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;
        dirent.location.data_size += thread_list.location().data_size;
        // If there's a minidump size limit, check if it might be exceeded.  Since
        // most of the space is filled with stack data, just check against that.
        // If this expects to exceed the limit, set extra_thread_stack_len such
        // that any thread beyond the first kLimitBaseThreadCount threads will
        // have only kLimitMaxExtraThreadStackLen bytes dumped.
        let mut extra_thread_stack_len = MaxStackLen::None; // default to no maximum
        if let Some(minidump_size_limit) = self.minidump_size_limit {
            let estimated_total_stack_size =
                (num_threads * LIMIT_AVERAGE_THREAD_STACK_LENGTH) as u64;
            let curr_pos = buffer.position();
            let estimated_minidump_size =
                curr_pos + estimated_total_stack_size + LIMIT_MINIDUMP_FUDGE_FACTOR;
            if estimated_minidump_size > minidump_size_limit {
                extra_thread_stack_len = MaxStackLen::Len(LIMIT_MAX_EXTRA_THREAD_STACK_LEN);
            }
        }

        for (idx, item) in self.threads.clone().iter().enumerate() {
            let mut thread = MDRawThread {
                thread_id: item.tid.try_into()?,
                suspend_count: 0,
                priority_class: 0,
                priority: 0,
                teb: 0,
                stack: MDMemoryDescriptor::default(),
                thread_context: MDLocationDescriptor::default(),
            };

            // We have a different source of information for the crashing thread. If
            // we used the actual state of the thread we would find it running in the
            // signal handler with the alternative stack, which would be deeply
            // unhelpful.
            if let Some(crash_context) = &self.crash_context
                && thread.thread_id == self.blamed_thread as u32
            {
                let instruction_ptr = crash_context.get_instruction_pointer();
                let stack_pointer = crash_context.get_stack_pointer();
                self.fill_thread_stack(
                    buffer,
                    &mut thread,
                    instruction_ptr,
                    stack_pointer,
                    MaxStackLen::None,
                    &mut soft_errors,
                )?;
                // Copy 256 bytes around crashing instruction pointer to minidump.
                let ip_memory_size: usize = 256;
                // Bound it to the upper and lower bounds of the memory map
                // it's contained within. If it's not in mapped memory,
                // don't bother trying to write it.
                for mapping in &self.mappings {
                    if instruction_ptr < mapping.start_address
                        || instruction_ptr >= mapping.start_address + mapping.size
                    {
                        continue;
                    }
                    // Try to get 128 bytes before and after the IP, but
                    // settle for whatever's available.
                    let mut ip_memory_d = MDMemoryDescriptor {
                        start_of_memory_range: std::cmp::max(
                            mapping.start_address,
                            instruction_ptr - ip_memory_size / 2,
                        ) as u64,
                        ..Default::default()
                    };

                    let end_of_range = std::cmp::min(
                        mapping.start_address + mapping.size,
                        instruction_ptr + ip_memory_size / 2,
                    ) as u64;
                    ip_memory_d.memory.data_size =
                        (end_of_range - ip_memory_d.start_of_memory_range) as u32;

                    let memory_copy = match MinidumpWriter::copy_from_process(
                        &self.process_inspector,
                        ip_memory_d.start_of_memory_range as _,
                        ip_memory_d.memory.data_size as usize,
                    ) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            soft_errors.push(SectionThreadListError::CopyFromProcessError(error));
                            break;
                        }
                    };

                    let mem_section = MemoryArrayWriter::alloc_from_array(buffer, &memory_copy)?;
                    ip_memory_d.memory = mem_section.location();
                    self.memory_blocks.push(ip_memory_d);
                    break;
                }
                // let cpu = MemoryWriter::alloc(buffer, &memory_copy)?;
                let mut cpu: RawContextCPU = Default::default();
                let crash_context = self.crash_context.as_ref().unwrap();
                crash_context.fill_cpu_context(&mut cpu);
                let cpu_section = MemoryWriter::alloc_with_val(buffer, cpu)?;
                thread.thread_context = cpu_section.location();

                self.crashing_thread_context =
                    CrashingThreadContext::CrashContext(cpu_section.location());
            } else {
                let info = self.get_thread_info_by_index(idx)?;
                let max_stack_len =
                    if self.minidump_size_limit.is_some() && idx >= LIMIT_BASE_THREAD_COUNT {
                        extra_thread_stack_len
                    } else {
                        MaxStackLen::None // default to no maximum for this thread
                    };
                let instruction_ptr = info.get_instruction_pointer();
                self.fill_thread_stack(
                    buffer,
                    &mut thread,
                    instruction_ptr,
                    info.stack_pointer,
                    max_stack_len,
                    &mut soft_errors,
                )?;

                let mut cpu = RawContextCPU::default();
                info.fill_cpu_context(&mut cpu);
                let cpu_section = MemoryWriter::<RawContextCPU>::alloc_with_val(buffer, cpu)?;
                thread.thread_context = cpu_section.location();
                if item.tid == self.blamed_thread {
                    // This is the crashing thread of a live process, but
                    // no context was provided, so set the crash address
                    // while the instruction pointer is already here.
                    self.crashing_thread_context = CrashingThreadContext::CrashContextPlusAddress(
                        (cpu_section.location(), instruction_ptr),
                    );
                }
            }
            thread_list.set_value_at(buffer, thread, idx)?;
        }
        Ok(dirent)
    }

    /// Copies the available stack, leaving an empty descriptor if every reader fails.
    fn fill_thread_stack(
        &mut self,
        buffer: &mut DumpBuf,
        thread: &mut MDRawThread,
        instruction_ptr: usize,
        stack_ptr: usize,
        max_stack_len: MaxStackLen,
        mut soft_errors: impl WriteErrorList<SectionThreadListError>,
    ) -> Result<(), SectionThreadListError> {
        thread.stack.start_of_memory_range = stack_ptr.try_into()?;
        thread.stack.memory.data_size = 0;
        thread.stack.memory.rva = buffer.position() as u32;

        if let Ok((valid_stack_ptr, stack_len)) = self.get_stack_info(stack_ptr) {
            let stack_len = if let MaxStackLen::Len(max_stack_len) = max_stack_len {
                min(stack_len, max_stack_len)
            } else {
                stack_len
            };

            let mut stack_bytes = match self.copy_stack(valid_stack_ptr, stack_len) {
                Ok(bytes) if !bytes.is_empty() => bytes,
                Ok(_) => return Ok(()),
                Err(error) => {
                    soft_errors.push(SectionThreadListError::StackReadFailed {
                        thread_id: thread.thread_id,
                        error,
                    });
                    return Ok(());
                }
            };
            let stack_pointer_offset = stack_ptr.saturating_sub(valid_stack_ptr);
            if self.skip_stacks_if_mapping_unreferenced {
                if let Some(principal_mapping) = &self.principal_mapping {
                    let low_addr = principal_mapping.system_mapping_info.start_address;
                    let high_addr = principal_mapping.system_mapping_info.end_address;
                    if (instruction_ptr < low_addr || instruction_ptr > high_addr)
                        && !principal_mapping
                            .stack_has_pointer_to_mapping(&stack_bytes, stack_pointer_offset)
                    {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            }

            if self.sanitize_stack {
                self.sanitize_stack_copy(&mut stack_bytes, stack_ptr, stack_pointer_offset)
                    .map_err(|e| SectionThreadListError::SanitizeStackCopyFailed(Box::new(e)))?;
            }

            let stack_location = MDLocationDescriptor {
                data_size: stack_bytes.len() as u32,
                rva: buffer.position() as u32,
            };
            buffer.write_all(&stack_bytes);
            thread.stack.start_of_memory_range = valid_stack_ptr as u64;
            thread.stack.memory = stack_location;
            self.memory_blocks.push(thread.stack);
        }
        Ok(())
    }

    /// Retries stack reads that a previously selected memory backend cannot satisfy.
    fn copy_stack(&self, start: usize, len: usize) -> Result<Vec<u8>, CopyFromProcessError> {
        use super::super::process_inspection::process_reader::ProcessReader;

        let len = std::num::NonZeroUsize::new(len).ok_or(CopyFromProcessError::InvalidArgument)?;
        self.process_inspector
            .process_reader()
            .read_to_vec(start, len)
            .or_else(|_| {
                ProcessReader::for_file(&self.process_inspector)
                    .map_err(CopyFromProcessError::Backend)?
                    .read_to_vec(start, len)
            })
            .or_else(|_| ProcessReader::for_ptrace(&self.process_inspector).read_to_vec(start, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::maps_reader::SystemMappingInfo;

    /// Builds an unsuspended writer for testing reads from this process only.
    fn stack_writer(start: usize, len: usize, permissions: MMPermissions) -> MinidumpWriter {
        let pid = std::process::id() as Pid;
        let mut writer = MinidumpWriterConfig::new(pid, pid).build();
        // SAFETY: sysconf has no pointer arguments and returns the system page size.
        writer.page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        writer.mappings.push(MappingInfo {
            start_address: start,
            size: len,
            system_mapping_info: SystemMappingInfo {
                start_address: start,
                end_address: start + len,
            },
            offset: 0,
            permissions,
            name: None,
        });
        writer
    }

    /// Creates an empty thread descriptor before filling its stack.
    fn empty_thread() -> MDRawThread {
        MDRawThread {
            thread_id: 0,
            suspend_count: 0,
            priority_class: 0,
            priority: 0,
            teb: 0,
            stack: MDMemoryDescriptor::default(),
            thread_context: MDLocationDescriptor::default(),
        }
    }

    #[test]
    fn stack_guard_search_does_not_return_an_unreadable_mapping() {
        let writer = stack_writer(0x1000, 2 * 1024 * 1024, MMPermissions::PRIVATE);
        assert!(writer.get_stack_info(0x1000).is_err());
    }

    #[test]
    fn stack_guard_search_at_address_limit_does_not_overflow() {
        let start = usize::MAX & !4095;
        let writer = stack_writer(start, usize::MAX - start, MMPermissions::PRIVATE);
        assert!(writer.get_stack_info(start).is_err());
    }

    #[test]
    fn stack_read_failure_keeps_an_empty_descriptor() {
        // An empty file can be mapped, but reading beyond EOF fails through every backend.
        let file = tempfile::tempfile().unwrap();
        // SAFETY: The mapping is never dereferenced; only process-memory readers access it.
        let mapping = unsafe { memmap2::MmapOptions::new().len(4096).map_mut(&file) }.unwrap();
        let start = mapping.as_ptr() as usize;
        let mut writer = stack_writer(start, mapping.len(), MMPermissions::READ);
        let mut buffer = DumpBuf::with_capacity(0);
        let mut thread = empty_thread();
        let mut errors = ErrorList::default();
        writer
            .fill_thread_stack(
                &mut buffer,
                &mut thread,
                0,
                start,
                MaxStackLen::None,
                &mut errors,
            )
            .expect("an unreadable stack must not abort the thread list");
        assert_eq!(thread.stack.start_of_memory_range, start as u64);
        assert_eq!(thread.stack.memory.data_size, 0);
        assert!(writer.memory_blocks.is_empty());
        assert!(!errors.is_empty());
    }

    #[test]
    fn stack_read_retries_a_cached_virtual_memory_backend() {
        let mut mapping = memmap2::MmapOptions::new().len(4096).map_anon().unwrap();
        mapping.fill(0x5a);
        let start = mapping.as_ptr() as usize;
        let writer = stack_writer(start, mapping.len(), MMPermissions::READ);
        // The reader has already selected process_vm_readv when the stack read fails.
        assert_eq!(writer.copy_stack(start, 1).unwrap(), [0x5a]);
        // SAFETY: This mapping is not accessed directly after its protection changes.
        assert_eq!(
            unsafe { libc::mprotect(mapping.as_mut_ptr().cast(), mapping.len(), libc::PROT_NONE) },
            0
        );
        assert_eq!(
            writer.copy_stack(start, mapping.len()).unwrap(),
            vec![0x5a; mapping.len()]
        );
    }

    #[test]
    fn stack_read_keeps_a_readable_prefix() {
        // SAFETY: sysconf has no pointer arguments and returns the system page size.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mut mapping = memmap2::MmapOptions::new()
            .len(2 * page)
            .map_anon()
            .unwrap();
        mapping.fill(0x5a);
        let start = mapping.as_ptr() as usize;
        let mut writer = stack_writer(start, mapping.len(), MMPermissions::READ);
        // SAFETY: The second page belongs to this mapping and is not accessed directly again.
        assert_eq!(
            unsafe { libc::mprotect(mapping.as_mut_ptr().add(page).cast(), page, libc::PROT_NONE) },
            0
        );
        let mut buffer = DumpBuf::with_capacity(0);
        let mut thread = empty_thread();
        writer
            .fill_thread_stack(
                &mut buffer,
                &mut thread,
                0,
                start,
                MaxStackLen::None,
                error_graph::strategy::DontCare,
            )
            .unwrap();
        assert_eq!(thread.stack.start_of_memory_range, start as u64);
        assert_eq!(thread.stack.memory.data_size as usize, page);
        assert_eq!(writer.memory_blocks.len(), 1);
    }
}
