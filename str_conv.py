import ida_segment
import ida_bytes
import ida_kernwin
import ida_idaapi
import idautils
import ida_netnode
import time
import idaapi
from enum import Enum

class ActionMode(Enum):
    SINGLE = 1
    ALL = 2

class ActionManager(ida_kernwin.action_handler_t):

    _MODE = ActionMode.SINGLE
    _STR_TYPE = idaapi.STRTYPE_C
    _ACTION_LABEL = "Create C String"

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def register(self, label):
        return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),
                label,
                self()
            ))

    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.get_name())

    @classmethod
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        if self._MODE == ActionMode.SINGLE:
            return self.process_single(ctx)
        elif self._MODE == ActionMode.ALL:
            return self.process_all(ctx)
        return 0

    def process_single(self, ctx):
        ea = idaapi.get_screen_ea()
        if ea != idaapi.BADADDR:
            success = idaapi.create_strlit(ea, 0, self._STR_TYPE)
            if success:
                print(f"Successfully created string at 0x{ea:X}")
            else:
                print(f"Failed to create string at 0x{ea:X}")
            idaapi.refresh_idaview_anyway()
        return 1

    def process_all(self, ctx):
        rdata_seg = ida_segment.get_segm_by_name(".rdata")
        if not rdata_seg:
            print("[-] .rdata segment not found!")
            return 0

        start_ea = rdata_seg.start_ea
        end_ea = rdata_seg.end_ea
        processed = 0

        ida_kernwin.show_wait_box("Processing .rdata segment...")
        time_start = time.time()

        ea = start_ea
        while ea < end_ea:
            if list(idautils.XrefsTo(ea)):
                ida_bytes.create_data(ea, ida_bytes.byte_flag(), 0, ida_netnode.BADNODE)
                length = self.find_length(ea)
                success = ida_bytes.create_strlit(ea, length, self._STR_TYPE)
                if success:
                    processed += 1
                else:
                    print(f"[-] Failed to create string at {hex(ea)}")
            ea = ida_bytes.next_addr(ea)

        ida_kernwin.hide_wait_box()

        print(f"[+] Processed {processed} items in .rdata segment")
        print(f"[+] Time taken: {time.time() - time_start:.2f} seconds")
        return 1

    def find_length(self, ea):
        length = 0
        while True:
            ea = ida_bytes.next_addr(ea)
            length += 1
            if list(idautils.XrefsTo(ea)):
                break
        return length

class SingleCStyleAction(ActionManager):
    _MODE = ActionMode.SINGLE
    _STR_TYPE = idaapi.STRTYPE_C
    _ACTION_LABEL = "C-style"

class SingleCStyle16Action(ActionManager):
    _MODE = ActionMode.SINGLE
    _STR_TYPE = idaapi.STRTYPE_C_16
    _ACTION_LABEL = "C-style (16-bit)"

class SingleCStyle32Action(ActionManager):
    _MODE = ActionMode.SINGLE
    _STR_TYPE = idaapi.STRTYPE_C_32
    _ACTION_LABEL = "C-style (32-bit)"

class CStyleAction(ActionManager):
    _MODE = ActionMode.ALL
    _STR_TYPE = idaapi.STRTYPE_C
    _ACTION_LABEL = "C-style"

class CStyle16Action(ActionManager):
    _MODE = ActionMode.ALL
    _STR_TYPE = idaapi.STRTYPE_C_16
    _ACTION_LABEL = "C-style (16-bit)"

class CStyle32Action(ActionManager):
    _MODE = ActionMode.ALL
    _STR_TYPE = idaapi.STRTYPE_C_32
    _ACTION_LABEL = "C-style (32-bit)"

class UIHandler(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        wt = idaapi.get_widget_type(form)
        if wt == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, SingleCStyleAction.get_name(), 'Convert bytes to/')
            idaapi.attach_action_to_popup(form, popup, SingleCStyle16Action.get_name(), 'Convert bytes to/')
            idaapi.attach_action_to_popup(form, popup, SingleCStyle32Action.get_name(), 'Convert bytes to/')
            idaapi.attach_action_to_popup(form, popup, CStyleAction.get_name(), 'Convert all bytes to/')
            idaapi.attach_action_to_popup(form, popup, CStyle16Action.get_name(), 'Convert all bytes to/')
            idaapi.attach_action_to_popup(form, popup, CStyle32Action.get_name(), 'Convert all bytes to/')

class StrConv(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "Convert bytes to selected string type in .rdata"
    wanted_name = "StrConv"
    wanted_hotkey = ""
    version = "1.0"
    website = "https://github.com/detached64/StrConv"

    def init(self):
        print("-"*80)
        self.print_info();
        print("[+] Initializing...")

        SingleCStyleAction.register("C-style")
        SingleCStyle16Action.register("C-style (16-bit)")
        SingleCStyle32Action.register("C-style (32-bit)")
        CStyleAction.register("C-style")
        CStyle16Action.register("C-style (16-bit)")
        CStyle32Action.register("C-style (32-bit)")

        self.hooks = UIHandler()
        self.hooks.hook()

        print("[+] Plugin initialized.")
        print("-"*80)
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        print("[-] Please use the context menu to run this plugin.")
        pass

    def print_info(self):
        print(f"{self.wanted_name} v{self.version}")
        print(f"Website: {self.website}")

def PLUGIN_ENTRY():
    return StrConv()
