import ida_funcs
import ida_gdl
import ida_kernwin
import ida_ua
import idaapi
import ida_idp
import idc
from collections import defaultdict
from unicorn import *
from unicorn.x86_const import *



STATUS_NORMAL = 0x0000
STATUS_FAKE_JZ = 0x1000
STATUS_MOVDISPIMM_JMP = 0x2000
STATUS_MOVDISPIMM_NOJMP = 0x3000
STATUS_CMOVNZ = 0x4000
STATUS_FIRSTBLOCK_TREAT = 0x5000

class BlockInfomation:
    def __init__(self, block_id, start_ea, end_ea, succ, pred, status):
        self.block_id = block_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.successors = succ  
        self.predecessors = pred
        self.status = status

def sp_based_finder(BlockList):
    blk = BlockList[0]
    list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
    ea, insn = list_insn[-1]
    if insn.Op1.reg == ida_idp.str2reg("rbp"):
        return "rbp"
    else:
        return "rsp"

def print_large_value_keys(d, factor=3):
    dispatcher = []
    if not d:
        return

    values = list(d.values())
    avg = sum(values) / len(values)

    for k, v in d.items():
        print(avg, v)
        if v > avg * factor:
            dispatcher.append(k)
            print(f"Key: {k}, Value: {v}")
    return dispatcher

def normalize_disp(disp):
    # convert unsigned 64 → signed 64
    if disp >= (1 << 63):
        disp -= (1 << 64)
    return disp

def get_ins_from_range(start_ea, end_ea):
    list_insn = []
    ea = start_ea
    while ea < end_ea:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        list_insn.append((ea, insn))
        ea += size

    return list_insn

def get_dest_list_by_address(BlockList, dispatcher_regs, sp):
    MatchJmp = defaultdict(list)
    for blk in BlockList:
        DEST_PATTERN_1 = False
        DEST_PATTERN_2 = False
        DEST_PATTERN_3 = False
        reg = None
        dest = None
        list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
        for ea, insn in list_insn:
            if insn.get_canon_mnem() == "mov" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_displ:
                if insn.Op2.reg == ida_idp.str2reg(sp) and normalize_disp(insn.Op2.addr) in dispatcher_regs:
                    reg = insn.Op1.reg
                    DEST_PATTERN_1 = True

            if insn.get_canon_mnem() == "sub" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                if insn.Op1.reg == reg:
                    if insn.Op2.value > 0xFFFF:
                        dest = insn.Op2.value
                        DEST_PATTERN_2 = True

            if insn.get_canon_mnem() == "jz":
                DEST_PATTERN_3 = True

            if DEST_PATTERN_1 and DEST_PATTERN_2 and DEST_PATTERN_3:
                # print(f"MATCH AT {hex(ea)}")
                if blk not in MatchJmp[dest]:
                    MatchJmp[dest].append(blk)
    return MatchJmp           

def linear_disasm(start_ea, end_ea):
    # xoá sạch code/data cũ
    ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, end_ea - start_ea)

    ea = start_ea
    insn = ida_ua.insn_t()

    while ea < end_ea:
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            ea += 1
            continue

        ida_ua.create_insn(ea)   # <-- ĐÚNG
        ea += size
    
    ida_funcs.add_func(start_ea, end_ea)

def dump_basic_blocks(func_ea):
    AllBlocks = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        print("[!] No function found at 0x%x" % func_ea)
        return


    fc = ida_gdl.FlowChart(func)

    block_id_map = {}
    blocks = list(fc)

    # Gán ID cho mỗi block để dễ đọc
    for idx, block in enumerate(blocks):
        block_id_map[block.id] = idx

    for block in blocks:
        bid = block_id_map[block.id]

        # Successors (block mà block này nhảy tới)
        succ_ids = []
        for succ in block.succs():
            succ_ids.append(block_id_map[succ.id])

        # Predecessors (block nhảy vào block này)
        pred_ids = []
        for pred in block.preds():
            pred_ids.append(block_id_map[pred.id])

        AllBlocks.append(BlockInfomation(bid, block.start_ea, block.end_ea, succ_ids, pred_ids, STATUS_NORMAL))

    return AllBlocks

def dump_dispatcher(BlockList, sp):
    var_count = defaultdict(int)
    for blk in BlockList:
        list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
        for ea, insn in list_insn:
            if insn.get_canon_mnem() == "mov":
                if insn.Op1.type == idaapi.o_displ and insn.Op1.reg == ida_idp.str2reg(sp):
                    disp = normalize_disp(insn.Op1.addr)
                    var_count[disp] += 1
                elif insn.Op2.type == idaapi.o_displ and insn.Op2.reg == ida_idp.str2reg(sp):      
                    disp = normalize_disp(insn.Op2.addr)
                    var_count[disp] += 1


    #MOST COUNT LÀ DISPATCHER MEM
    return print_large_value_keys(var_count, factor=1)

def remove_cff_first_block(BlockList, dispatcher_mem, dest_list, sp):
    start_patch_ea = None
    lock = False
    blk = BlockList[0]
    list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
    for ea, insn in list_insn:
        if insn.get_canon_mnem() == "mov":
            if insn.Op1.type == ida_ua.o_reg:
                if insn.Op2.type == ida_ua.o_mem:
                    if ida_ua.get_dtype_size(insn.Op1.dtype) == 4:
                        if not lock:
                            lock = True
                            start_patch_ea = ea

            if insn.Op1.type == ida_ua.o_displ and insn.Op1.reg == ida_idp.str2reg(sp):
                if insn.Op2.type == ida_ua.o_imm and insn.Op2.value > 0xFFFF:
                    jmp_addr = dest_list[insn.Op2.value][0].start_ea
                    delta = jmp_addr - (start_patch_ea + 5)
                    patch_ins = b"\xE9" + int.to_bytes(delta, 4, 'little', signed=True)
                    patch_ins += b"\x90" * ((ea + insn.size - start_patch_ea) - len(patch_ins))
                    for i in range(len(patch_ins)):
                        idc.patch_byte(start_patch_ea + i, patch_ins[i])
                    BlockList[blk.block_id].status = STATUS_FIRSTBLOCK_TREAT
                    break

def remove_cff_fake_jz(BlockList, dispatcher_mem, sp):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            DEST_PATTERN_1 = False
            DEST_PATTERN_2 = False
            DEST_PATTERN_3 = False
            reg = None
            start_patch_ea = None
            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "mov" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_displ:
                    if insn.Op2.reg == ida_idp.str2reg(sp) and normalize_disp(insn.Op2.addr) == dispatcher_mem:
                        reg = insn.Op1.reg
                        start_patch_ea = ea
                        DEST_PATTERN_1 = True

                if insn.get_canon_mnem() == "sub" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                    if insn.Op1.reg == reg:
                        if insn.Op2.value > 0xFFFF:
                            DEST_PATTERN_2 = True

                if insn.get_canon_mnem() == "jz":
                    DEST_PATTERN_3 = True

                if DEST_PATTERN_1 and DEST_PATTERN_2 and DEST_PATTERN_3:
                    jmp_addr = insn.Op1.addr
                    delta = jmp_addr - (start_patch_ea + 5)
                    patch_ins = b"\xE9" + int.to_bytes(delta, 4, 'little', signed=True)
                    patch_ins += b"\x90" * (ea + insn.size - (start_patch_ea + len(patch_ins)))
                    
                    for i in range(len(patch_ins)):
                        idc.patch_byte(start_patch_ea + i, patch_ins[i])
                    BlockList[blk.block_id].status = STATUS_FAKE_JZ
                    break

def remove_cff_mov_disp_imm_jmp(BlockList, dispatcher_mem, dest_list, sp):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            MOV_DISP_IMM_PATTERN_1 = False
            MOV_DISP_IMM_PATTERN_2 = False
            start_patch_ea = None
            key = None
            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "cmovnz":
                    break
                if insn.get_canon_mnem() == "mov":
                    if insn.Op1.type == ida_ua.o_displ and insn.Op1.reg == ida_idp.str2reg(sp) and normalize_disp(insn.Op1.addr) == dispatcher_mem:
                        if insn.Op2.type == ida_ua.o_imm and insn.Op2.value > 0xFFFF:
                            start_patch_ea = ea
                            key = insn.Op2.value
                            MOV_DISP_IMM_PATTERN_1 = True

                if insn.get_canon_mnem() == "jmp":
                    MOV_DISP_IMM_PATTERN_2 = True

                if MOV_DISP_IMM_PATTERN_1 and MOV_DISP_IMM_PATTERN_2:
                    dest = dest_list[key][0]

                    delta = dest.start_ea - (start_patch_ea + 5)
                    patch_ins = b"\xE9" + int.to_bytes(delta, 4, 'little', signed=True)
                    patch_ins += b"\x90" * (ea + insn.size - (start_patch_ea + len(patch_ins)))
                    for i in range(len(patch_ins)):
                        idc.patch_byte(start_patch_ea + i, patch_ins[i])
                    BlockList[blk.block_id].status = STATUS_MOVDISPIMM_JMP
                    break

def remove_cff_mov_disp_imm_no_jmp(BlockList, dispatcher_mem, dest_list, sp):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            start_patch_ea = None
            key = None
            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "cmovnz":
                    break
                if insn.get_canon_mnem() == "mov":
                    if insn.Op1.type == ida_ua.o_displ and insn.Op1.reg == ida_idp.str2reg(sp) and normalize_disp(insn.Op1.addr) == dispatcher_mem:
                        if insn.Op2.type == ida_ua.o_imm and insn.Op2.value > 0xFFFF:
                            start_patch_ea = ea
                            key = insn.Op2.value

                ea_t, insn_t = list_insn[-1]
                if insn_t.get_canon_mnem().startswith("j"):
                    break
                
                if ea + insn.size == blk.end_ea:
                    if key != None:
                        print(hex(ea))
                        dest = dest_list[key][0]
                        delta = dest.start_ea - (start_patch_ea + 5)
                        patch_ins = b"\xE9" + int.to_bytes(delta, 4, 'little', signed=True)
                        patch_ins += b"\x90" * (ea + insn.size - (start_patch_ea + len(patch_ins)))
                        for i in range(len(patch_ins)):
                            idc.patch_byte(start_patch_ea + i, patch_ins[i])
                        BlockList[blk.block_id].status = STATUS_MOVDISPIMM_NOJMP
                        break

def remove_cff_fake_cmovnz(BlockList, dispatcher_mem, dest_list, sp):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            FAKE_CMOVNZ_PATTERN_1 = False
            FAKE_CMOVNZ_PATTERN_2 = False
            FAKE_CMOVNZ_PATTERN_3 = False
            FAKE_CMOVNZ_PATTERN_4 = False
            FAKE_CMOVNZ_PATTERN_5 = False
            FAKE_CMOVNZ_PATTERN_6 = False
            reg1 = None
            reg2 = None
            start_patch_ea = None
            non_glob_start_patch_ea = None
            key1 = None
            key2 = None
            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            for ea, insn in list_insn:
                        
                if insn.get_canon_mnem() == "cmovnz":
                    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg:
                        reg1 = insn.Op1.reg
                        reg2 = insn.Op2.reg
                        FAKE_CMOVNZ_PATTERN_3 = True
                        for s_ea, s_insn in list_insn:
                            if s_insn.get_canon_mnem() == "mov":
                                if s_insn.Op1.type == ida_ua.o_reg:
                                    if s_insn.Op2.type == ida_ua.o_mem:
                                        if ida_ua.get_dtype_size(s_insn.Op1.dtype) == 4:
                                            if s_insn.Op1.reg == reg1:
                                                start_patch_ea = s_ea
                                                FAKE_CMOVNZ_PATTERN_5 = True
                                            elif s_insn.Op1.reg == reg2:
                                                FAKE_CMOVNZ_PATTERN_6 = True


                                if s_insn.Op1.type == ida_ua.o_reg and s_insn.Op1.reg == reg1:
                                    if s_insn.Op2.type == ida_ua.o_imm:
                                        if s_insn.Op2.value > 0xFFFF:
                                            non_glob_start_patch_ea = s_ea
                                            key1 = s_insn.Op2.value
                                            FAKE_CMOVNZ_PATTERN_1 = True
                                elif s_insn.Op1.type == ida_ua.o_reg and s_insn.Op1.reg == reg2:
                                    if s_insn.Op2.type == ida_ua.o_imm:
                                        if s_insn.Op2.value > 0xFFFF:      
                                            key2 = s_insn.Op2.value
                                            FAKE_CMOVNZ_PATTERN_2 = True

                if insn.get_canon_mnem() == "mov":
                    if insn.Op1.type == ida_ua.o_displ:
                        if insn.Op1.reg == ida_idp.str2reg(sp) and normalize_disp(insn.Op1.addr) == dispatcher_mem:
                            if insn.Op2.type == ida_ua.o_reg and insn.Op2.reg == reg1:
                                FAKE_CMOVNZ_PATTERN_4 = True
                            

            
                if insn.get_canon_mnem() == "jmp":
                    if FAKE_CMOVNZ_PATTERN_1 and FAKE_CMOVNZ_PATTERN_2 and FAKE_CMOVNZ_PATTERN_3 \
                    and FAKE_CMOVNZ_PATTERN_4 and FAKE_CMOVNZ_PATTERN_5 and FAKE_CMOVNZ_PATTERN_6:
                        # Đỡ phải saved ins chunk. Lấy thẳng cái test dl, 1 vào là dc. Giống nhau hết
                        patch_ins = b""
                        blk1 = dest_list[key1][0]
                        blk2 = dest_list[key2][0]

                        jmp_addr_1 = blk1.start_ea
                        jmp_addr_2 = blk2.start_ea

                        delta1 = jmp_addr_1 - (start_patch_ea + 6)      #skip TEST dl,1 với JZ mới.
                        delta2 = jmp_addr_2 - (start_patch_ea + 6 + 5)  #skip TEST dl,1; JZ; JMP.

                        delta = jmp_addr_2 - (start_patch_ea + 5)  #skip TEST dl,1; JZ; JMP.
                        patch_ins += b"\xE9" + int.to_bytes(delta, 4, 'little', signed=True)
                        # patch_ins += b"\x0F\x85"  + int.to_bytes(delta1, 4, 'little', signed=True) # JNZ near
                        # patch_ins += b"\xE9"      + int.to_bytes(delta2, 4, 'little', signed=True)
                        patch_ins += b"\x90" * (ea + insn.size - (start_patch_ea + len(patch_ins)))
                        # print(f"TYPE 1 FROM {hex(start_patch_ea)}, to {hex(ea)}")
                        for i in range(len(patch_ins)):
                            idc.patch_byte(start_patch_ea + i, patch_ins[i])
                        BlockList[blk.block_id].status = STATUS_CMOVNZ
                        break

                    elif FAKE_CMOVNZ_PATTERN_1 and FAKE_CMOVNZ_PATTERN_2 and FAKE_CMOVNZ_PATTERN_3 \
                    and FAKE_CMOVNZ_PATTERN_4 and not FAKE_CMOVNZ_PATTERN_5 and not FAKE_CMOVNZ_PATTERN_6:
                        patch_ins = b""
                        blk1 = dest_list[key1][0]
                        blk2 = dest_list[key2][0]

                        jmp_addr_2 = blk1.start_ea
                        jmp_addr_1 = blk2.start_ea

                        delta1 = jmp_addr_1 - (non_glob_start_patch_ea + 6)
                        delta2 = jmp_addr_2 - (non_glob_start_patch_ea + 6 + 5)

                        patch_ins += b"\x0F\x85" + int.to_bytes(delta1, 4, 'little', signed=True)
                        patch_ins += b"\xE9"     + int.to_bytes(delta2, 4, 'little', signed=True)
                        patch_ins += b"\x90"     * (ea + insn.size - (non_glob_start_patch_ea + len(patch_ins)))
                        for i in range(len(patch_ins)):
                            idc.patch_byte(non_glob_start_patch_ea + i, patch_ins[i])
                        BlockList[blk.block_id].status = STATUS_CMOVNZ
                        break
                        

# def hook(mu, address, size, user_data):
#     print(f"Executing 0x{address:X}")

def emu(CODE):
    CODE_ADDR = 0
    STACK_ADDR = 0x2000000
    STACK_SIZE = 0x10000

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    mu.mem_map(CODE_ADDR, 0x1000)
    mu.mem_write(CODE_ADDR, CODE)

    regs = [
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP, UC_X86_REG_EFLAGS
    ]

    for r in regs:
        mu.reg_write(r, 0)

    mu.reg_write(UC_X86_REG_RCX, 1)
    mu.reg_write(UC_X86_REG_RAX, 1)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    stack_top = STACK_ADDR + STACK_SIZE - 0x10
    mu.reg_write(UC_X86_REG_RIP, CODE_ADDR)
    mu.reg_write(UC_X86_REG_RSP, stack_top)
    # mu.hook_add(UC_HOOK_CODE, hook)



    try:
        mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE))
    except UcError as e:
        print("Emu error:", e)

    reg_names = {
    UC_X86_REG_RAX: "RAX",
    UC_X86_REG_RBX: "RBX",
    UC_X86_REG_RCX: "RCX",
    UC_X86_REG_RDX: "RDX",
    UC_X86_REG_RSI: "RSI",
    UC_X86_REG_RDI: "RDI",
    UC_X86_REG_RBP: "RBP",
    UC_X86_REG_RSP: "RSP",
    UC_X86_REG_R8:  "R8",
    UC_X86_REG_R9:  "R9",
    UC_X86_REG_R10: "R10",
    UC_X86_REG_R11: "R11",
    UC_X86_REG_R12: "R12",
    UC_X86_REG_R13: "R13",
    UC_X86_REG_R14: "R14",
    UC_X86_REG_R15: "R15",
    UC_X86_REG_RIP: "RIP",
    UC_X86_REG_EFLAGS: "EFLAGS"
    }

    print("\n===== REGISTER RESULT =====")
    # for r in regs:
    #     val = mu.reg_read(r)
    #     print(f"{reg_names[r]:<7} = {hex(val)}")
    val = mu.reg_read(UC_X86_REG_RDX)
    print(f"{reg_names[UC_X86_REG_RDX]:<7} = {hex(val)}")
    
def test_emulate(BlockList):
    for blk in BlockList:
        CHECK_1 = False
        CHECK_2 = False
        regs = []
        start_emu = 0
        end_emu = 0
        list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
        for ea, insn in list_insn:
            if insn.get_canon_mnem() == "mov":
                if insn.Op1.type == ida_ua.o_reg:
                    if insn.Op2.type == ida_ua.o_mem:
                        if ida_ua.get_dtype_size(insn.Op1.dtype) == 4:
                            regs.append(insn.Op1.reg)
                            start_emu = ea
                            CHECK_1 = True


            if insn.get_canon_mnem() == "cmovnz":
                if insn.Op1.reg in regs and insn.Op2.reg in regs:
                    end_emu = ea
                    CHECK_2 = True
            
            if CHECK_1 and CHECK_2:
                # print(f"FOUND AT {hex(start_emu)}")
                start_emu += 6 # skip cái move thứ 2
                CODE = idc.get_bytes(start_emu, end_emu - start_emu)
                # print(CODE)
                print(f"[*] START EMULATING FROM {hex(start_emu)} to {hex(end_emu)}")
                emu(CODE)
                break





def main():
    start_ea = 0x180001000
    end_ea = 0x180030F40
    func = ida_funcs.get_next_func(start_ea - 1)

    while func and func.start_ea < end_ea:
        if func.start_ea >= start_ea:
            print("=" * 60)
            print(f"Function: {ida_funcs.get_func_name(func.start_ea)} @ {hex(func.start_ea)} -> {hex(func.end_ea)}")
            print("=" * 60)
            # ea = ida_kernwin.get_screen_ea()
            ea = func.start_ea
            all_blocks = dump_basic_blocks(ea)
            sp = sp_based_finder(all_blocks)
            print(f"SP BASE _______________________________ {sp}")
            Dispatchers = dump_dispatcher(all_blocks, sp)
            dest_list = get_dest_list_by_address(all_blocks, Dispatchers, sp)
            try:
                for disp_mem in Dispatchers:
                    # test_emulate(all_blocks)
                    remove_cff_fake_cmovnz(all_blocks, disp_mem, dest_list, sp)
                    remove_cff_first_block(all_blocks, disp_mem, dest_list, sp)
                    remove_cff_mov_disp_imm_jmp(all_blocks, disp_mem, dest_list, sp)
                    remove_cff_mov_disp_imm_no_jmp(all_blocks, disp_mem, dest_list, sp)
                    remove_cff_fake_jz(all_blocks, disp_mem, sp)

                print("[*] Starting linear disassembly from 0x%x to 0x%x" % (ea, ida_funcs.get_func(ea).end_ea))
                linear_disasm(ea, ida_funcs.get_func(ea).end_ea)
            except Exception as e:
                print(f"ERROR OCCUR: {e}")
                func = ida_funcs.get_next_func(func.start_ea)
                continue

        func = ida_funcs.get_next_func(func.start_ea)

if __name__ == "__main__":
    main()