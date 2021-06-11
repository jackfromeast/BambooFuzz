from .taint_tracking import apply_taint, is_tainted
import signal
# import taint_analysis
from .taint_tracking import *
from .dfs import *
from .defines import *
import datetime

l = logging.getLogger("TaintLauncher")
l.setLevel(logging.DEBUG)


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class TaintLauncher:
    """
    Provides an easy interface to run a taint tracking analysis
    """
    def __init__(self, binary_path,
                 log_path='/home/jackfromeast/bamboofuzz/fuzz-scripts/taint_tracing_log',
                 sink_addrs=None,
                 **angr_opts):
        """
        Init method: prepare the angr project.

        :param binary_path: binary path
        :param angr_opts: angr options
        """

        # timeout stuff
        self._force_exit_after = -1
        self._timer = -1

        if not angr_opts:
            angr_opts = {'auto_load_libs': False}

        self._p = angr.Project(binary_path, **angr_opts)
        self._log = open(log_path, 'w')
        self._tt = None
        self._simgr = None

        self.sink_addrs = sink_addrs
        self.current_taint_source = None
        self.current_tracing_info = None

    def run(self,
            start_addr=None,
            taint_source = None,
            check_functions=lambda x: None,
            sym_bss=True,
            use_dfs=True,
            **kwargs):
        """
        Prepare the analysis instance and run the analysis

        :param start_addr: analysis starting address
        :param check_function: callback function that is called for every visited basic block
        :param sym_bss: make bss symbolic
        :param use_dfs: use a depth first seach approach
        :param kwargs
        """
        # tracing_info 初始化
        self.current_tracing_info = {
                        "overflowCount": 0, # 内存溢出类敏感函数操作次数
                        "injectionCount": 0, # 命令注入类敏感函数操作次数
                        "leakCount":0,   # 信息泄漏类敏感函数操作次数
                        }
        # 初始化taint_source
        self.current_taint_source = taint_source

        if not start_addr:
            start_addr = self._p.entry

        # set up the taint tracking exploration technique
        start_state = self._p.factory.call_state(start_addr)
        if sym_bss:
            self._unconstrain_bss(start_state)

        self._tt = TaintTracker(interfunction_level=1, **kwargs)

        # 添加回调函数实现taint policy
        self._tt.add_callback(self.taint_apply, 'mem_read', angr.BP_AFTER)
        self._tt.add_callback(self.taint_check, 'call', angr.BP_AFTER)
        self._tt.add_callback(self.expr_check, 'symbolic_variable', angr.BP_AFTER)

        self._simgr = self._p.factory.simgr(start_state)
        self._simgr.use_technique(self._tt)

        if use_dfs:
            self._simgr.use_technique(DFS())

        try:
            self._simgr.run()
        except TimeOutException:
            l.warning("Hard timeout triggered!")
            self.stop()

    def stop(self):
        l.info("Stopping the analysis")
        self._tt.stop()

    def _handler(self, signum, frame):
        """
        Timeout handler

        :param signum: signal number
        :param frame:  frame
        :return:
        """

        log.info("Timeout triggered, %s left...." % str(self._force_exit_after))
        self.stop()
        self._force_exit_after -= 1
        self.set_timeout(self._timer, self._force_exit_after)
        if self._force_exit_after <= 0:
            # time to stop this non-sense!
            raise TimeOutException("Hard timeout triggered")

    def set_timeout(self, timer, n_tries=0):
        # setup a consistent initial state
        signal.signal(signal.SIGALRM, self._handler)
        signal.alarm(timer)
        self._force_exit_after = n_tries
        self._timer = timer

    def _unconstrain_bss(self, state):
        bss = [s for s in self._p.loader.main_object.sections if s.name == '.bss']
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr
        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def start_logging(self):
        self._log.write("Starts: \n" + str(datetime.datetime.now().time()) + "=================================\n\n")

    def log(self, msg):
        self._log.write(msg)

    def stop_logging(self):
        self._log.write("Ends: \n" + str(datetime.datetime.now().time()) + "=================================\n\n")
        self._log.close()

    # 自定义回调函数
    def taint_apply(self, state):
        # print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
        try:
            if(str(hex(state.solver.eval(state.inspect.mem_read_expr))) == self.current_taint_source):
                print('apply_taint to address: 0x%x' % state.solver.eval(state.inspect.mem_read_expr))
                apply_taint(state, state.inspect.mem_read_expr)
        except(AttributeError):
            pass

    # 自定义回调函数
    def taint_check(self, state):
        # print(hex(state.solver.eval(state.inspect.function_address)))
        sim_args, _ = self._tt._get_calling_convention(state)

        print([is_tainted(sim_arg.get_value(state), state) for sim_arg in sim_args])
        if any([is_tainted(sim_arg.get_value(state), state) for sim_arg in sim_args]):   
            # for l in sim_args[0].get_value(state).recursive_leaf_asts:
            #     print(l.args)
            #     print(l.op)
            #     print(str(l))
            try:
                if(str(hex(state.solver.eval(state.inspect.function_address))) in self.sink_addrs["overflowFunc"].values()):
                    print("Overflow Sensitive Func found in 0x%x" % state.solver.eval(state.inspect.function_address))
                    self.current_tracing_info["overflowCount"] += 1

                if(str(hex(state.solver.eval(state.inspect.function_address))) in self.sink_addrs["injectionFunc"].values()):
                    print("Injection Sensitive Func found in 0x%x" % state.solver.eval(state.inspect.function_address))
                    self.current_tracing_info["injectionCount"] += 1
                    
                if(str(hex(state.solver.eval(state.inspect.function_address))) in self.sink_addrs["leakFunc"].values()):
                    print("Leak Sensitive Func found in 0x%x" % state.solver.eval(state.inspect.function_address))
                    self.current_tracing_info["leakCount"] += 1
            except():
                pass
        
    def expr_check(self, state):
        # print(state.inspect.symbolic_expr)
        # print(state.inspect.symbolic_expr)
        # print(is_tainted(state.inspect.symbolic_expr, state))
        pass
    

if __name__ == '__main__':
    taint_analyzer = TaintLauncher("/home/jackfromeast/bdg_bins/test_arm", sink_addrs=          {"injectionFunc":{},"overflowFunc":{},"leakFunc":{}})
    
    taint_analyzer.run(
            start_addr=0x010590)
    
