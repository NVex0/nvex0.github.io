import ida_funcs
import ida_gdl
import ida_kernwin
from collections import defaultdict

STATUS_PATTERN_CMOVZ_CFF = 0x1000
STATUS_PATTERN_CMOVB_CFF = 0x2000
STATUS_PATTERN_MOV_JMP_CFF = 0x3000
STATUS_PATTERN_MOV_NO_JMP_CFF = 0x4000
STATUS_PATTERN_FAKE_JUMP_CFF = 0x5000

STATUS_LOCKED_DESTINATION_CFF = 0x6000
STATUS_NORMAL = 0x0000

class BlockInfomation:
    def __init__(self, block_id, start_ea, end_ea, succ, pred, status):
        self.block_id = block_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.successors = succ  
        self.predecessors = pred
        self.status = status

def get_ins_from_range(start_ea, end_ea):
    list_insn = []
    ea = start_ea
    while ea < end_ea:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        list_insn.append((ea, insn))
        ea += size

    return list_insn

def get_dest_list_by_value(BlockList, dispatcher_reg):
    MatchJmp = {}
    for blk in BlockList:
        list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
        for ea, insn in list_insn:
            if insn.get_canon_mnem() == "cmp" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                if insn.Op1.reg in dispatcher_reg:
                    if insn.Op2.value > 0xFFFF:
                        MatchJmp[(insn.Op2.value, insn.Op1.reg)] = blk

    return MatchJmp

def get_dest_list_by_address(BlockList, dispatcher_reg):
    MatchJmp = defaultdict(list)
    for blk in BlockList:
        list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
        for ea, insn in list_insn:
            if insn.get_canon_mnem() == "cmp" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                if insn.Op1.reg in dispatcher_reg:
                    if insn.Op2.value > 0xFFFF:
                        if blk not in MatchJmp[(insn.Op2.value, insn.Op1.reg)]:
                            MatchJmp[(insn.Op2.value, insn.Op1.reg)].append(blk)
    
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

    print("=" * 60)
    print("Function: %s @ 0x%x" % (ida_funcs.get_func_name(func.start_ea), func.start_ea))
    print("=" * 60)

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

def find_dispatcher(BlockList):
    preds = {}
    dispatcher_reg = []
    for block in BlockList:
        preds[block] = len(block.predecessors)


    values = list(preds.values())
    total = len(values)

    freq = {}
    for v in values:
        freq[v] = freq.get(v, 0) + 1

    for v, cnt in freq.items():
        # Bởi vì block có pred 0,1,2 rất common nên không xét dispatcher trên các block này
        if v not in [0, 1, 2]:
            percent = cnt / total * 100
            print(f"value={v}: {percent:.2f}%")
            if percent <= 20:  # Tỉ lệ xuất hiện (không chắc chắn lắm, có thể false positive)
                # print(f"value={v}: {percent:.2f}%")
                for block, pred_cnt in preds.items():
                    if pred_cnt == v:
                        # print(hex(block.start_ea))
                        insns = get_ins_from_range(block.start_ea, block.end_ea)
                        for ea, insn in insns:
                            # Nếu insn là cmp reg, imm thì reg này là dispatcher register
                            if insn.get_canon_mnem() == "cmp" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                                if insn.Op1.reg not in dispatcher_reg:
                                    dispatcher_reg.append(insn.Op1.reg)
    
    for reg in dispatcher_reg:
        print(f"Dispatcher register: {ida_idp.get_reg_name(reg, 4)}")

    return dispatcher_reg

def remove_cff_condition_blocks_cmovz(BlockList, dispatcher_reg, MatchListEx):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            CFF_CONDITIONAL_BLOCK_COND1 = False
            CFF_CONDITIONAL_BLOCK_COND2 = False
            CFF_CONDITIONAL_BLOCK_COND3 = False
            pattern1_ea = 0
            pattern2_ea = 0
            pattern3_ea = 0
            jmp_ea_1 = 0
            jmp_ea_2 = 0
            tmp_reg = None
            patch_bytes = b""

            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "mov" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                    if insn.Op1.reg == dispatcher_reg:
                        CFF_CONDITIONAL_BLOCK_COND1 = True
                        pattern1_ea = ea
                        jmp_ea_1 = insn.Op2.value
                    else:
                        tmp_reg = insn.Op1.reg
                        CFF_CONDITIONAL_BLOCK_COND2 = True
                        pattern2_ea = ea
                        jmp_ea_2 = insn.Op2.value
                

                if insn.get_canon_mnem() == "cmovz":
                    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg and insn.Op1.reg == dispatcher_reg and insn.Op2.reg == tmp_reg:
                        tmp_reg = insn.Op2.reg
                        CFF_CONDITIONAL_BLOCK_COND3 = True
                        pattern3_ea = ea
                
                if insn.get_canon_mnem() == "jmp":
                    if CFF_CONDITIONAL_BLOCK_COND1 and CFF_CONDITIONAL_BLOCK_COND2 and CFF_CONDITIONAL_BLOCK_COND3:
                        if pattern1_ea > pattern2_ea:
                            temp = pattern1_ea
                            pattern1_ea = pattern2_ea
                            pattern2_ea = temp

                        # print(hex(pattern1_ea), hex(pattern2_ea), hex(pattern3_ea), hex(ea))
                        saved_ins_1 = idc.get_bytes(pattern1_ea + 5, pattern2_ea - (pattern1_ea + 5)) 
                        saved_ins_2 = idc.get_bytes(pattern2_ea + 5, pattern3_ea - (pattern2_ea + 5)) 
                        saved_ins_3 = idc.get_bytes(pattern3_ea + 3, ea - (pattern3_ea + 3))

                        if saved_ins_1 is not None:
                            patch_bytes += saved_ins_1
                        if saved_ins_2 is not None:
                            patch_bytes += saved_ins_2
                        if saved_ins_3 is not None:
                            patch_bytes += saved_ins_3

                        target_list_block_1 = MatchListEx[(jmp_ea_1, dispatcher_reg)]
                        target_list_block_2 = MatchListEx[(jmp_ea_2, dispatcher_reg)]
                        
                        # if len(target_list_block_1) > 1:
                        #     print(f"1. Anomaly multi matches addr at: {hex(ea)} - value: {hex(jmp_ea_1)}")  
                        #     for ad in target_list_block_1:
                        #         print(f"    [+] {hex(ad.start_ea)}")

                        # if len(target_list_block_2) > 1:
                        #     print(f"2. Anomaly multi matches addr at: {hex(ea)} - value: {hex(jmp_ea_2)}")  
                        #     for ad in target_list_block_2:
                        #         print(f"    [+] {hex(ad.start_ea)}")
                        
                        # elif len(target_list_block_2) == 1:
                        #     print(f"0. Normal found at: {hex(ea)} - value: {hex(jmp_ea_2)}")
                        #     for ad in target_list_block_2:
                        #         print(f"    [+] {hex(ad.start_ea)}")

                        # Find nearest block.
                        nearest_blk2 = min(target_list_block_2, key=lambda b: abs(b.start_ea - ea))
                        nearest_blk1 = min(target_list_block_1, key=lambda b: abs(b.start_ea - ea))
                        # print(f"    [-] Nearest: {hex(nearest_blk.start_ea)}")

                        target_addr_2 = nearest_blk2.start_ea
                        target_addr_1 = nearest_blk1.start_ea

                        patch_addr_1 = target_addr_2 - (pattern1_ea + len(patch_bytes) + 6)
                        patch_addr_2 = target_addr_1 - (pattern1_ea + len(patch_bytes) + 11)



                        patch_bytes += b"\x0F\x84"  + int.to_bytes(patch_addr_1, 4, 'little', signed=True) # JZ near
                        patch_bytes += b"\xE9" + int.to_bytes(patch_addr_2, 4, 'little', signed=True) # JMP near
                        if insn.size == 5:
                            patch_bytes += b"\x90" * (ea + 5 - pattern1_ea - len(patch_bytes))
                        elif insn.size == 2:
                            patch_bytes += b"\x90" * (ea + 2 - pattern1_ea - len(patch_bytes))

                            


                        for i in range(len(patch_bytes)):
                            idc.patch_byte(pattern1_ea + i, patch_bytes[i])

                        
                        BlockList[blk.block_id].status = STATUS_PATTERN_CMOVZ_CFF   
                        # print(f"Patched at block 0x{blk.start_ea:x} to jump to 0x{target_addr_1:x}, 0x{target_addr_2:x}")
                        break             

def remove_cff_condition_blocks_cmovb(BlockList, dispatcher_reg, MatchListEx):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            CMOVB_CONDITIONAL_BLOCK_COND1 = False
            CMOVB_CONDITIONAL_BLOCK_COND2 = False
            CMOVB_CONDITIONAL_BLOCK_COND3 = False
            pattern1_ea = 0
            pattern2_ea = 0
            pattern3_ea = 0
            jmp_ea_1 = 0
            jmp_ea_2 = 0
            patch_bytes = b""
            tmp_reg = None

            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "mov" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                    if insn.Op1.reg == dispatcher_reg:
                        pattern1_ea = ea
                        jmp_ea_1 = insn.Op2.value
                        CMOVB_CONDITIONAL_BLOCK_COND1 = True
                    else:
                        tmp_reg = insn.Op1.reg
                        pattern2_ea = ea
                        jmp_ea_2 = insn.Op2.value
                        CMOVB_CONDITIONAL_BLOCK_COND2 = True
                    

                if insn.get_canon_mnem() == "cmovb":
                    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg and insn.Op1.reg == dispatcher_reg and insn.Op2.reg == tmp_reg:
                        tmp_reg = insn.Op2.reg
                        CMOVB_CONDITIONAL_BLOCK_COND3 = True
                        pattern3_ea = ea

                if insn.get_canon_mnem() == "jmp":
                    if CMOVB_CONDITIONAL_BLOCK_COND1 and CMOVB_CONDITIONAL_BLOCK_COND2 and CMOVB_CONDITIONAL_BLOCK_COND3:
                        if pattern1_ea > pattern2_ea:
                            temp = pattern1_ea
                            pattern1_ea = pattern2_ea
                            pattern2_ea = temp

                        saved_ins_1 = idc.get_bytes(pattern1_ea + 5, pattern2_ea - (pattern1_ea + 5)) 
                        saved_ins_2 = idc.get_bytes(pattern2_ea + 5, pattern3_ea - (pattern2_ea + 5)) 
                        saved_ins_3 = idc.get_bytes(pattern3_ea + 3, ea - (pattern3_ea + 3))

                        if saved_ins_1 is not None:
                            patch_bytes += saved_ins_1
                        if saved_ins_2 is not None:
                            patch_bytes += saved_ins_2
                        if saved_ins_3 is not None:
                            patch_bytes += saved_ins_3

                        # value 2 patch thành JB để nó loop, value 1 patch thành JMP để break loop
                        target_list_block_1 = MatchListEx[(jmp_ea_1, dispatcher_reg)]
                        target_list_block_2 = MatchListEx[(jmp_ea_2, dispatcher_reg)]
         
                        nearest_blk_1 = min(target_list_block_2, key=lambda b: abs(b.start_ea - ea))
                        nearest_blk_2 = min(target_list_block_1, key=lambda b: abs(b.start_ea - ea))
                        filter_upper = [b for b in target_list_block_1 if b.start_ea > ea]
                        if filter_upper != []:
                            for ad in filter_upper:
                                nearest_blk_2 = ad
                                break
                        
                        idx = 0
                        for idx in range(len(target_list_block_2)):
                            if target_list_block_2[idx] == nearest_blk_1:
                                break

                        
                        target_addr_1 = nearest_blk_1.start_ea
                        target_addr_2 = target_list_block_1[idx].start_ea
                        # target_addr_2 = nearest_blk_2.start_ea


                        patch_addr_1 = target_addr_1 - (pattern1_ea + len(patch_bytes) + 6)
                        patch_addr_2 = target_addr_2 - (pattern1_ea + len(patch_bytes) + 11)
                        patch_bytes += b"\x0F\x82"  + int.to_bytes(patch_addr_1, 4, 'little', signed=True)
                        patch_bytes += b"\xE9" + int.to_bytes(patch_addr_2, 4, 'little', signed=True)

                        if insn.size == 5: # near jmp
                            patch_bytes += b"\x90" * (ea + 5 - pattern1_ea - len(patch_bytes))
                        else: #short jmp
                            patch_bytes += b"\x90" * (ea + 2 - pattern1_ea - len(patch_bytes))

                        for i in range(len(patch_bytes)):
                            idc.patch_byte(pattern1_ea + i, patch_bytes[i])
      

                        BlockList[blk.block_id].status = STATUS_PATTERN_CMOVB_CFF   
                        # print(f"    [+] Patched at block 0x{blk.start_ea:x} to jump to 0x{target_addr_1:x}, 0x{target_addr_2:x}")
                        break            
    # UNLOCK DEST BLOCK
    for blk in BlockList:
        if blk.status == STATUS_LOCKED_DESTINATION_CFF: 
            BlockList[blk.block_id].status = STATUS_NORMAL

def remove_cff_fake_jmp_jz_jnz(BlockList, dispatcher_reg):
    
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            TRASH_JUMP_BLOCK_COND1 = False  
            TRASH_JUMP_BLOCK_COND2 = False
        
            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            
            # Nếu mà con nào có jz, jnz thì thực hiện xử lý
            # Nếu patch xong thì phải update pred, succ
            # Check xem True False của jz, jnz là block nào
            # Ngoài ra phải lưu imm lại để lát match với mov dispatcher_reg, imm; jmp dispatcher
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "cmp" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                    if insn.Op1.reg == dispatcher_reg:
                        TRASH_JUMP_BLOCK_COND1 = True

                if insn.get_canon_mnem() in ["jz", "jnz"]:
                    if insn.Op1.type == ida_ua.o_near:
                        TRASH_JUMP_BLOCK_COND2 = True
                
                if TRASH_JUMP_BLOCK_COND1 and TRASH_JUMP_BLOCK_COND2:
                    make_ins = b""
                    addr = insn.Op1.addr
                    # Nếu là jz thì patch thành Jmp nhánh true, còn jnz thì Jmp nhánh false
                    # Phải check xem nó là short jmp hay near jmp để patch tương ứng
                    if insn.size == 2:  # short jmp
                        make_ins = b"\xEB"
                        addr = int.to_bytes(addr - (ea + 2), 1, 'little', signed=True)
                    else:
                        make_ins = b"\xE9"
                        addr = int.to_bytes(addr - (ea + 5), 4, 'little', signed=True)

                    if insn.get_canon_mnem() == "jz":
                        make_ins += addr
                        make_ins += b"\x90" * (insn.size - len(make_ins))
                        for i in range(len(make_ins)):
                            idc.patch_byte(ea + i, make_ins[i])

                    elif insn.get_canon_mnem() == "jnz":
                        make_ins = b"\x90" * insn.size
                        for i in range(len(make_ins)):
                            idc.patch_byte(ea + i, make_ins[i])
                    
                    BlockList[blk.block_id].status = STATUS_PATTERN_FAKE_JUMP_CFF
                    break

def remove_cff_mov_disp_imm_jmp(BlockList, dispatcher_reg, MatchListEx):
    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            TRASH_CONN_BLOCK_COND1 = False
            TRASH_CONN_BLOCK_COND2 = False

            saved_jump_addr = None
            pattern1_ea = 0
            pattern2_ea = 0

        # Check xem con nào mov dispatcher_reg, imm; jmp dispatcher block
            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            
            # Nếu mà con nào có jz, jnz thì thực hiện xử lý
            # Nếu patch xong thì phải update pred, succ
            # Check xem True False của jz, jnz là block nào
            # Ngoài ra phải lưu imm lại để lát match với mov dispatcher_reg, imm; jmp dispatcher
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "cmovb" or insn.get_canon_mnem() == "cmovz":
                    break
                if insn.get_canon_mnem() == "mov" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                    if insn.Op1.reg == dispatcher_reg:

                        TRASH_CONN_BLOCK_COND1 = True
                        pattern1_ea = ea
                        saved_jump_addr = insn.Op2.value
                    if blk.block_id == 0:
                        TRASH_CONN_BLOCK_COND2 = True

                if insn.get_canon_mnem() == "jmp" and insn.Op1.type != ida_ua.o_reg:
                    TRASH_CONN_BLOCK_COND2 = True
                    pattern2_ea = ea
                
                if TRASH_CONN_BLOCK_COND1 and TRASH_CONN_BLOCK_COND2:
                    if blk.block_id == 0:
                        pattern2_ea = blk.end_ea

                    # Tìm block tương ứng với imm đã lưu
                    if (saved_jump_addr, dispatcher_reg) in MatchListEx:
                        target_blk_list = MatchListEx[(saved_jump_addr, dispatcher_reg)]
                        if len(target_blk_list) == 1:
                            target_block = target_blk_list[0]
                            make_ins = b""
                            addr = target_block.start_ea

                            # Lấy đoạn giữa mov và jmp để giữ nguyên
                            #print("MOV JMP DEBUG LOG:", hex(pattern1_ea), hex(pattern2_ea))
                            make_ins = idc.get_bytes(pattern1_ea + 5, pattern2_ea - (pattern1_ea + 5))
                            if make_ins == None:
                                make_ins = b""
                            # Patch thành jmp tới block tương ứng
                            make_ins += b"\xE9" + int.to_bytes(addr - (pattern1_ea + len(make_ins) + 5), 4, 'little', signed=True)
                            if blk.block_id == 0:
                                make_ins += b"\x90" * (pattern2_ea - pattern1_ea - len(make_ins))
                            else:   
                                make_ins += b"\x90" * (pattern2_ea + insn.size - pattern1_ea - len(make_ins))
                            for i in range(len(make_ins)):
                                idc.patch_byte(pattern1_ea + i, make_ins[i])
                            
                            BlockList[blk.block_id].status = STATUS_PATTERN_MOV_JMP_CFF
                            # print(f"Patched at block 0x{blk.start_ea:x} to jump to 0x{target_block.start_ea:x}")
                            break
                        
                        # Mấy cái trùng nhiều dest thì giả sử jump backward xem sao
                        elif len(target_blk_list) > 1:

                            target_blk_list = sorted(target_blk_list, key=lambda b: b.start_ea, reverse=False)
                            nearest_upper = target_blk_list[0].start_ea
                            nearest_lower = target_blk_list[0].start_ea
                            for block in target_blk_list:
                                addr = block.start_ea
                                if addr < ea:
                                    nearest_upper = addr

                            for block in target_blk_list:
                                addr = block.start_ea
                                if addr > ea:
                                    nearest_lower = addr
                                    break
                            percent = (abs(ea - nearest_lower) / abs(ea - nearest_upper)) * 100
                
                            # print(f"delta upper: {hex(ea - nearest_upper)}, delta lower: {hex(ea - nearest_lower)}, percent: {percent:.2f}%")
                            # Xa quá thì lấy nearest lower, thường là min delta luôn
                            # if percent < 1:
                            if abs(ea - nearest_upper) - abs(ea - nearest_lower) > 0x400 and percent < 1:
                                # print(f"delta upper: {hex(ea - nearest_upper)}, delta lower: {hex(ea - temp)}, percent: {percent:.2f}%")
                                # nearest_upper = min(target_blk_list, key=lambda b: abs(b.start_ea - ea)).start_ea
                                nearest_upper = nearest_lower

                            patch_bytes = idc.get_bytes(pattern1_ea + 5, pattern2_ea - (pattern1_ea + 5))
                            if patch_bytes == None:
                                patch_bytes = b""
                            patch_bytes += b"\xE9" + int.to_bytes(nearest_upper - (pattern1_ea + len(patch_bytes) + 5), 4, 'little', signed=True)
                            # print(f"Patched at block 0x{blk.start_ea:x} to jump to 0x{nearest_upper:x}")
                            # print()
                            for i in range(len(patch_bytes)):
                                idc.patch_byte(pattern1_ea + i, patch_bytes[i])
                            
                            BlockList[blk.block_id].status = STATUS_PATTERN_MOV_JMP_CFF
                            break

def remove_cff_mov_disp_imm_no_jmp(BlockList, dispatcher_reg, MatchListEx):

    for blk in BlockList:
        if blk.status == STATUS_NORMAL:
            SINGLENODE_COND = False
            target_addr = None
            patch_bytes = b""

            list_insn = get_ins_from_range(blk.start_ea, blk.end_ea)
            if list_insn == []:  # Tại sao lại đọc sang cả block của func khác nhể?
                break
            last_ea, last_insn = list_insn[-1] 
            if "j" in last_insn.get_canon_mnem():
                continue
            for ea, insn in list_insn:
                if insn.get_canon_mnem() == "mov":
                    if insn.Op1.type == ida_ua.o_reg and insn.Op1.reg == dispatcher_reg and insn.Op2.type == ida_ua.o_imm:
                        target_addr = insn.Op2.value

                        SINGLENODE_COND = True

                if SINGLENODE_COND:
                    target_blk_list = MatchListEx[(target_addr, dispatcher_reg)]
                    if len(target_blk_list) == 0:
                        continue
                    
                    target_blk_list = sorted(target_blk_list, key=lambda b: b.start_ea, reverse=False)
                    nearest_blk = min(target_blk_list, key=lambda b: abs(b.start_ea - ea))

                    patch_bytes = idc.get_bytes(ea + 5, blk.end_ea - ea - 5)
                    if patch_bytes == None:
                        patch_bytes = b""
                    patch_bytes += b"\xE9" + int.to_bytes(nearest_blk.start_ea - (ea + len(patch_bytes) + 5), 4, 'little', signed=True)
                    for i in range(len(patch_bytes)):
                        idc.patch_byte(ea + i, patch_bytes[i])



                    # print(f"Start addr: {hex(ea)}, Value: {hex(target_addr)}")
                    BlockList[blk.block_id].status = STATUS_PATTERN_MOV_NO_JMP_CFF
                    break


def main():
    ea = ida_kernwin.get_screen_ea()
    AllBlocks = dump_basic_blocks(ea)
    dispatcher_reg = find_dispatcher(AllBlocks)
    match_list = get_dest_list_by_value(AllBlocks, dispatcher_reg)
    match_list_Ex = get_dest_list_by_address(AllBlocks, dispatcher_reg)
    print(f"block count: {len(AllBlocks)}")
    # for (addr, reg), blk in match_list.items():
    #     print(f"Match JMP: 0x{addr:x} via {ida_idp.get_reg_name(reg, 4)} => Block ID {blk.block_id} (0x{blk.start_ea:x}-0x{blk.end_ea:x})")
    for disp_reg in dispatcher_reg:
        print("[XXX] DISPATCHER REG:", ida_idp.get_reg_name(disp_reg, 4))
        remove_cff_condition_blocks_cmovb(AllBlocks, disp_reg, match_list_Ex)
        remove_cff_condition_blocks_cmovz(AllBlocks, disp_reg, match_list_Ex)
        remove_cff_fake_jmp_jz_jnz(AllBlocks, disp_reg)
        remove_cff_mov_disp_imm_jmp(AllBlocks, disp_reg, match_list_Ex)
        remove_cff_mov_disp_imm_no_jmp(AllBlocks, disp_reg, match_list_Ex)
        # f = ida_funcs.get_func(ea)
        # ida_funcs.reanalyze_function(f)

    print("[*] Starting linear disassembly from 0x%x to 0x%x" % (ea, ida_funcs.get_func(ea).end_ea))
    linear_disasm(ea, ida_funcs.get_func(ea).end_ea)


if __name__ == "__main__":
    main()