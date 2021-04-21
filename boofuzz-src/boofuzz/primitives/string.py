from __future__ import division

import itertools
import math
import random
import re
import six
from future.standard_library import install_aliases
from six.moves import range
from past.builtins import xrange
from ..fuzzable import Fuzzable
import struct 
install_aliases()


class String(Fuzzable):
    """Primitive that cycles through a library of "bad" strings.

    The class variable 'fuzz_library' contains a list of
    smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
    the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
    each instantiated primitive.

    :type name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type default_value: str
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value.
    :type size: int, optional
    :param size: Static size of this field, leave None for dynamic, defaults to None
    :type padding: chr, optional
    :param padding: Value to use as padding to fill static field size, defaults to "\\x00"
    :type encoding: str, optional
    :param encoding: String encoding, ex: utf_16_le for Microsoft Unicode, defaults to ascii
    :type max_len: int, optional
    :param max_len: Maximum string length, defaults to None
    :type fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    # Has to be sorted to avoid duplicates
    
    _fuzz_library = [
    "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
    "%00",
    "%00/",
    "%01%02%03%04%0a%0d%0aADSF",
    "%01%02%03@%04%0a%0d%0aADSF",
    "%\xfe\xf0%\x00\xff",
    "%\xfe\xf0%\x01\xff" * 20,
    "%n" * 100,  # format strings.
    "%n" * 500,
    "%s" * 100,
    "%s" * 500,
    "%u0000",
    "..:..:..:..:..:..:..:..:..:..:..:..:..:",
    "/%00/",
    "/." * 5000,
    "/.../" + "B" * 5000 + "\x00\x00",
    "/.../.../.../.../.../.../.../.../.../.../",
    "/../../../../../../../../../../../../boot.ini",
    "/../../../../../../../../../../../../etc/passwd",
    "/.:/" + "A" * 5000 + "\x00\x00",
    "/\\" * 5000,
    '"%n"' * 500,
       '"%s"' * 500,
    "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
    "\\\\*",
    "\\\\?\\",
    "\r\n" * 100,  # miscellaneous.
]

    long_string_seeds = [
        "C",
        "1",
        "<",
        ">",
        "'",
        '"',
        "/",
        "\\",
        "?",
        "=",
        "a=",
        "&",
        ".",
        ",",
        "(",
        ")",
        "]",
        "[",
        "%",
        "*",
        "-",
        "+",
        "{",
        "}",
        "\x14",
        "\x00",
        "\xFE",  # expands to 4 characters under utf1
        "\xFF",  # expands to 4 characters under utf1
    ]
  
    _cmd_fuzz_library=[]
    with open('./boofuzz-src/boofuzz/primitives/inj_seeds.txt','r') as fi:
        for w in fi.readlines():
            w=w.replace('\n','')
            _cmd_fuzz_library.append(w)

    vul_array=["request_uri","content-Length","datetime","service","submit_button","user_agent","authorization"
    "ping_addr","dnsserver","post_content","cookie","ssid","login","user_pwd","user_name","password","date"
    "html_response_page","src","name","wepencryption","body","jump","request","content","time","submit","addr","post","response"]

    overflow_array=["request_uri","content-Length","datetime","service","submit_button","user_agent","authorization"
    "ping_addr","dnsserver","post_content","cookie","ssid","login","user_pwd","user_name",
    "html_response_page","src","name","require_file","wepencryption","uri","body","jump","request","content","time",
    "submit","addr","post","response"]

    leakage_array=["request_uri","service","ping_addr","dnsserver","post_content","file","addr","path","content","path","link"
    "html_response_page","src","require_file","post","uri","body"]

    _info_library=[
        "/var/etc/httpasswd",
        "/var/etc/passwd",
        "/%3f.jsp",
        "/?M=D",
        "/?S=D", 
        "/"*10,
        "/cgi-bin/test-cgi?/*",
        "/cgi-bin/test-cgi?*",
        "/%2e/",
        "/%2f/",
        "/%5c/",
        "/etc/httpd/logs/acces_log", 
        "/etc/httpd/logs/acces.log",
        "/etc/httpd/logs/error_log",
        "/etc/httpd/logs/error.log", 
        "/var/www/logs/access_log",
        "/var/www/logs/access.log",
        "/var/log/access_log", 
        "/var/log/access.log", 
        "/var/www/logs/error_log", 
        "/var/www/logs/error.log", 
        "/var/log/error_log", 
        "/var/log/error.log", 
        ";dir",
        "`dir`",
        "|dir|",
        "|dir",
        "/%3f.jsp",
        "?M=D",
    ]
    _long_string_lengths = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]
    _long_string_deltas = [-2, -1, 0, 1, 2]
    _extra_long_string_lengths = [99999, 100000, 500000]
    _void_string_num = 10 # num of void string
    _variable_mutation_multipliers = [2, 10, 100]

    def __init__(
        self, brother=0,level=0,name=None, default_value="", size=None, padding=b"\x00", encoding="utf-8", max_len=None, *args, **kwargs
    ):
        super(String, self).__init__(name=name, default_value=default_value, *args, **kwargs)
      
        self.size = size
        self.max_len = max_len
        if self.size is not None:
            self.max_len = self.size
        self.encoding = encoding
        self.padding = padding
        if isinstance(padding, six.text_type):
            self.padding = self.padding.encode(self.encoding)
        self._static_num_mutations = None
        self.random_indices = {}
        self.brother=brother
        self.level=level
        random.seed(0)  # We want constant random numbers to generate reproducible test cases
        previous_length = 0
        # For every length add a random number of random indices to the random_indices dict. Prevent duplicates by
        # adding only indices in between previous_length and current length.
        # 在随机字符中间添加随机数量的随机索引
        for length in self._long_string_lengths:
            self.random_indices[length] = random.sample(
                range(previous_length, length), random.randint(1, self._long_string_lengths[0])
            )
            previous_length = length
    
    
    def _match(self,array,name):
        name=name.lower()
        suggestions = []
        pattern = '.*?'.join(name)    # Converts 'djm' to 'd.*?j.*?m'
        regex = re.compile(pattern)         # Compiles a regex.
        for item in array:
            match = regex.search(item)      # Checks if the current item matches the regex.
            if match:
                suggestions.append((len(match.group()), match.start(), item))
        #  [x for _, _, x in sorted(suggestions)]不用排序
        l=len(suggestions)
        q=len(suggestions)/len(array)#命中率
        return q*(l*10-l*(l-1))*10  #等差数列求和乘以命中率
        

    # 远程命令执行指数计算【与变异个数有关和fuzz库有关】
    def _vuln_compute(self,layer,brother):
        vuln=0.5*(layer+brother)*math.log(0.5*(layer+brother))+self._match(self.vul_array,self._name)
        return vuln

    # 溢出指数排序【与变异长度有关】
    def _overflow_compute(self,layer,brother):
        overflow=0.5*(layer+brother)*math.log(0.5*(layer+brother))+self._match(self.overflow_array,self._name)
        return overflow
    
    # 信息泄露指数计算【与fuzz_library有关】
    def _leak_compute(self,layer,brother):
        leak=0.5*(layer+brother)*math.log(0.5*(layer+brother))+1.5*self._match(self.leakage_array,self._name)
        return leak


    # 给定一个序列，生成若干给定序列的可选字符串长度
    def _yield_long_strings(self, sequences):
        """
        Given a sequence, yield a number of selectively chosen strings lengths of the given sequence.

        @type  sequences: list(str)
        @param sequences: Sequence to repeat for creation of fuzz strings.
        """
        for sequence in sequences:
            # 这个for循环是将种子长度通过乘法扩大为给定size(其实算随机长度)
            for size in [
                length + delta
                for length, delta in itertools.product(self._long_string_lengths, self._long_string_deltas)
            ]:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))#math.ceil(a)大于a的最小整数
                    yield data[:size]
                else:
                    break
            # 长度非常长的string
            for size in self._extra_long_string_lengths:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    #print("size:"+str(size))
                    yield data[:size]
                else:
                    break
            # 产生给定最大长度的string
            if self.max_len is not None:
                data = sequence * math.ceil(self.max_len / len(sequence))
                yield data
        # 用终止符取代loc中的字符
        for size in self._long_string_lengths:
            if self.max_len is None or size <= self.max_len:
                s = "D" * size
                for loc in self.random_indices[size]:
                    yield s[:loc] + "\x00" + s[loc + 1 :]  # Replace character at loc with terminator
            else:
                break
    # 把默认值乘以规定的倍数且不在fuzz的库里
    def _yield_variable_mutations(self, default_value):
        for length in self._variable_mutation_multipliers:
            value = default_value * length
            if value not in self._fuzz_library:
                yield value
                if self.max_len is not None and len(value) >= self.max_len:
                    break
    # 就是把长度太大的数据切了呗
    def _adjust_mutation_for_size(self, fuzz_value):
        if self.max_len is not None and self.max_len < len(fuzz_value):
            return fuzz_value[: self.max_len]
        else:
            return fuzz_value
    # 生成空字符串
    def _yield_void_mutations(self, default_value):
        for i in range(0,self._void_string_num):
            value = ""
            yield value
    # 生成不同类型的数据
    def _yield_diff_type_mutations(self, default_value):
        for length in self._variable_mutation_multipliers:
            v_len = len(default_value) * length
            value = b""
            for _ in xrange(v_len):
                value += struct.pack("B", random.randint(0, 255)) #转换成C语言的无符号字符，16进制
                yield value
                if self.max_len is not None and len(value) >= self.max_len:
                    break
        

    def mutations(self, default_value):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        Args:
            default_value (str): Default value of element.

        Yields:
            str: Mutations
        """
        
        last_val = None
        vuln=self._vuln_compute(self.level,self.brother)
        overflow=self._overflow_compute(self.level,self.brother)
        leak=self._leak_compute(self.level,self.brother)
        # 根据脆弱性指数/增加乘数指数
        #print("vuln:"+str(vuln))
        #print("overflow:"+str(overflow))
        #print("leak:"+str(leak))
        #if(vuln>20):
            # for i in range(2,vuln):
            #     if i!=10 and i!=100:
            #         self._variable_mutation_multipliers.append(i)
        self._fuzz_library.extend(self._cmd_fuzz_library[0:min(math.ceil(vuln)*2,len(self._cmd_fuzz_library))])
        # 根据溢出指数增加长字符串的长度
        self._extra_long_string_lengths.append(math.ceil(overflow*100000)) 
        self._extra_long_string_lengths.append(math.ceil(overflow*200000)) 
        # 根据泄露指数增加fuzz库
        if(leak>20):
            self._fuzz_library=self._info_library
        #print("your algorithm is OK!")
        i=0
        # 产生fuzz_library里的string、string乘以某些倍数之后、长字符
        for val in itertools.chain(
            self._yield_long_strings(self.long_string_seeds),
            self._yield_variable_mutations(default_value),
            self._yield_diff_type_mutations(default_value),
            self._yield_void_mutations(default_value),
            self._fuzz_library,
            # self._yield_void_mutations(default_value),
            # self._yield_diff_type_mutations(default_value),
            # self._yield_variable_mutations(default_value),
            # self._yield_long_strings(self.long_string_seeds),
        ):
            i+=1
            #print("Everything is OK! i="+str(i))
            current_val = self._adjust_mutation_for_size(val)
            if last_val == current_val and current_val!="" :#不能产生和前一个string重复的数据
                continue
            last_val = current_val
            yield current_val
   
        # TODO: Add easy and sane string injection from external file/s
        
    # six是专门用来兼容Python 2 和 Python 3 的库
    def encode(self, value, mutation_context=None):
        value = six.ensure_binary(value, self.encoding, "replace")
        # pad undersized library items.
        if self.size is not None and len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return value

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """
        variable_num_mutations = sum(1 for _ in self._yield_variable_mutations(default_value=default_value))
        if self._static_num_mutations is None:
            #  Counting the number of mutations with default value "" results in 0 variable_num_mutations 3 * "" = ""
            self._static_num_mutations = sum(1 for _ in self.mutations(default_value=""))
        return self._static_num_mutations + variable_num_mutations
