

## Angr-CTF

#### 如何使用Angr-CTF

建议运行环境为Ubuntu 16.04 ,macOS 下安装Angr 存在一些Bug (比如说Angr 库的安装,Mach-O 文件格式的执行程序有Bug)

找到一个空白的目录,执行命令`git clone https://github.com/jakespringer/angr_ctf.git` 下载Angr-CTF 项目

#### 如何编译程序

Angr-CTF 有很多题目,每一个目录是一个独立的题目,题目里面没有现成编译好的程序,需要我们手工来编译,我们以第一题为例子编译测试程序

```shell
root@sec:~/angr_ctf# cd 00_angr_find/
root@sec:~/angr_ctf/00_angr_find# python generate.py 1234 00_angr_find
```

generate.py 是程序生成脚本,它的原理是通过我们输入的一个随机数(这里是1234)来对.c.templite 文件进行混淆,然后编译输出到一个文件名(这里的文件名是00_angr_find ).

Angr-CTF 有一个解题的模版Python 文件(名字为scaffold00.py ),如果我们是在Python3 下安装的Angr 库,那么就需要使用Python3 来执行脚本,效果如下:

```shell
root@sec:~/angr_ctf/00_angr_find# python3 scaffold00.py 
WARNING | 2019-05-11 14:42:28,542 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-05-11 14:42:28,543 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-05-11 14:42:28,543 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-05-11 14:42:28,543 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-05-11 14:42:28,543 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-05-11 14:42:28,543 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x80486b1 (__libc_csu_init+0x1 in test_code (0x80486b1))
WARNING | 2019-05-11 14:42:28,547 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x80486b3 (__libc_csu_init+0x3 in test_code (0x80486b3))
WARNING | 2019-05-11 14:42:30,063 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fff0000 with 83 unconstrained bytes referenced from 0x9074ee0 (strcmp+0x0 in libc.so.6 (0x74ee0))
WARNING | 2019-05-11 14:42:30,064 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff60 with 4 unconstrained bytes referenced from 0x9074ee0 (strcmp+0x0 in libc.so.6 (0x74ee0))
b'FMKGABFY'
```

话不多说,接下来开始体验Angr 符号执行库强大的地方吧~



## 00_angr_find

汇编代码:

```assembly
.text:0804864E                 push    offset s2       ; "FPQPMQXT"
.text:08048653                 lea     eax, [ebp+s1]
.text:08048656                 push    eax             ; s1
.text:08048657                 call    _strcmp
.text:0804865C                 add     esp, 10h
.text:0804865F                 test    eax, eax
.text:08048661                 jz      short loc_8048675
.text:08048663                 sub     esp, 0Ch
.text:08048666                 push    offset s        ; "Try again."
.text:0804866B                 call    _puts
.text:08048670                 add     esp, 10h
.text:08048673                 jmp     short loc_8048685
.text:08048675 ; ---------------------------------------------------------------------------
.text:08048675
.text:08048675 loc_8048675:                            ; CODE XREF: main+9A↑j
.text:08048675                 sub     esp, 0Ch
.text:08048678                 push    offset aGoodJob ; "Good Job."
.text:0804867D                 call    _puts
.text:08048682                 add     esp, 10h
.text:08048685
.text:08048685 loc_8048685:
```

使用explore() 函数探索路径,主要目的是要找到'Good Job'这条路径,所以在expolore(find=???)这里填写的是`0x8048678`这个地址,然后让Angr自己去执行寻找路径

```python
  path_to_binary = './test_code'  # :string
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)
  print_good_address = 0x8048678  # :integer (probably in hexadecimal)
  simulation.explore(find=print_good_address)
```

Angr函数使用总结:

> angr.Project(执行的二进制文件地址)  =>  打开二进制文件
>
> project.factory.entry_state()  =>  创建空白的执行上下文环境
>
> project.factory.simgr(上下文对象)  =>  创建模拟器
>
> simulation.explore(find = 搜索程序执行路径的地址)  =>  执行路径探索



## 01_angr_avoid

汇编代码:

```assembly

.text:0804890F                 jz      short loc_804892E
.text:08048911                 call    avoid_me
.text:08048916                 sub     esp, 8
.text:08048919                 lea     eax, [ebp+var_20]
.text:0804891C                 push    eax
.text:0804891D                 lea     eax, [ebp+var_34]
.text:08048920                 push    eax
.text:08048921                 call    maybe_good
.text:08048926                 add     esp, 10h
.text:08048929                 jmp     loc_80D456F
.text:0804892E ; ---------------------------------------------------------------------------
.text:0804892E
.text:0804892E loc_804892E:                            ; CODE XREF: main+30D↑j
.text:0804892E                 sub     esp, 8
.text:08048931                 lea     eax, [ebp+var_20]
.text:08048934                 push    eax
.text:08048935                 lea     eax, [ebp+var_34]
.text:08048938                 push    eax
.text:08048939                 call    maybe_good
.text:0804893E                 add     esp, 10h
.text:08048941                 jmp     loc_80D456F
.text:08048946 ; ---------------------------------------------------------------------------
.text:08048946
.text:08048946 loc_8048946:                            ; CODE XREF: main+2E5↑j
.text:08048946                 call    avoid_me

.....
```

01_angr_avoid 有很多垃圾代码插入在main() 函数这里,我们没有办法直接在main() 函数的这些分支语句中定位准确的路径,所以我们需要换一个方式,来看一下maybe_good() 函数的代码

```assembly
text:080485B5                 public maybe_good
.text:080485B5 maybe_good      proc near               ; CODE XREF: main+31F↓p
.text:080485B5                                         ; main+337↓p ...
.text:080485B5
.text:080485B5 arg_0           = dword ptr  8
.text:080485B5 arg_4           = dword ptr  0Ch
.text:080485B5
.text:080485B5 ; __unwind {
.text:080485B5                 push    ebp
.text:080485B6                 mov     ebp, esp
.text:080485B8                 sub     esp, 8
.text:080485BB                 movzx   eax, should_succeed
.text:080485C2                 test    al, al
.text:080485C4                 jz      short loc_80485EF
.text:080485C6                 sub     esp, 4
.text:080485C9                 push    8
.text:080485CB                 push    [ebp+arg_4]
.text:080485CE                 push    [ebp+arg_0]
.text:080485D1                 call    _strncmp
.text:080485D6                 add     esp, 10h
.text:080485D9                 test    eax, eax
.text:080485DB                 jnz     short loc_80485EF
.text:080485DD                 sub     esp, 0Ch
.text:080485E0                 push    offset aGoodJob ; "Good Job."
.text:080485E5                 call    _puts
.text:080485EA                 add     esp, 10h
.text:080485ED                 jmp     short loc_80485FF
.text:080485EF ; ---------------------------------------------------------------------------
.text:080485EF
.text:080485EF loc_80485EF:                            ; CODE XREF: maybe_good+F↑j
.text:080485EF                                         ; maybe_good+26↑j
.text:080485EF                 sub     esp, 0Ch
.text:080485F2                 push    offset aTryAgain ; "Try again."
.text:080485F7                 call    _puts
.text:080485FC                 add     esp, 10h
.text:080485FF
.text:080485FF loc_80485FF:                            ; CODE XREF: maybe_good+38↑j
.text:080485FF                 nop
.text:08048600                 leave
.text:08048601                 retn
.text:08048601 ; } // starts at 80485B5
.text:08048601 maybe_good      endp
.text:08048601
```

在maybe_good() 函数的实现里,发现和00_angr_find 一样的逻辑 — 一个分支和两个输出,那么我们就应该知道:"Good Job" 是我们要搜索的目标路径,"Try Again" 是我们要排除的路径,那么用explore() 函数来筛选,方式是用explore(find=0x80485E0,avoid=0x80485F2)来筛选,解答代码如下:

```python
import angr
import sys

def main(argv):
  path_to_binary = './01_angr_avoid'
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  print_good_address = 0x080485DD
  will_not_succeed_address = 0x80485EF
  simulation.explore(find=print_good_address, avoid=will_not_succeed_address)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

Angr函数使用总结:

> simulation.explore(find = 要搜索的路径地址, avoid = 要排除执行路径地址)  =>  路径探索
>
> simulation.found  =>  搜索结果集合,这是一个python list 对象
>
> solution_state.posix.dumps(  =>  获取Payload



## 02_angr_find_condition

汇编代码:

```assembly
.text:0804876B loc_804876B:                            ; CODE XREF: main+112↑j
.text:0804876B                 cmp     [ebp+var_38], 0DEADBEEFh
.text:08048772                 jz      short loc_80487B5
.text:08048774                 sub     esp, 8
.text:08048777                 lea     eax, [ebp+s2]
.text:0804877A                 push    eax             ; s2
.text:0804877B                 lea     eax, [ebp+s1]
.text:0804877E                 push    eax             ; s1
.text:0804877F                 call    _strcmp
.text:08048784                 add     esp, 10h
.text:08048787                 test    eax, eax
.text:08048789                 jz      short loc_80487A0
.text:0804878B                 sub     esp, 0Ch
.text:0804878E                 push    offset s        ; "Try again."
.text:08048793                 call    _puts
.text:08048798                 add     esp, 10h
.text:0804879B                 jmp     loc_804D267
.text:080487A0 ; ---------------------------------------------------------------------------
.text:080487A0
.text:080487A0 loc_80487A0:                            ; CODE XREF: main+1C1↑j
.text:080487A0                 sub     esp, 0Ch
.text:080487A3                 push    offset aGoodJob ; "Good Job."
.text:080487A8                 call    _puts
.text:080487AD                 add     esp, 10h
.text:080487B0                 jmp     loc_804D267
.text:080487B5 ; ---------------------------------------------------------------------------
.text:080487B5
.text:080487B5 loc_80487B5:                            ; CODE XREF: main+1AA↑j
.text:080487B5                 sub     esp, 8
.text:080487B8                 lea     eax, [ebp+s2]
.text:080487BB                 push    eax             ; s2
.text:080487BC                 lea     eax, [ebp+s1]
.text:080487BF                 push    eax             ; s1
.text:080487C0                 call    _strcmp
.text:080487C5                 add     esp, 10h
.text:080487C8                 test    eax, eax
.text:080487CA                 jz      short loc_80487E1
.text:080487CC                 sub     esp, 0Ch
.text:080487CF                 push    offset s        ; "Try again."
.text:080487D4                 call    _puts
.text:080487D9                 add     esp, 10h
.text:080487DC                 jmp     loc_804D267
.text:080487E1 ; ---------------------------------------------------------------------------
.text:080487E1
.text:080487E1 loc_80487E1:                            ; CODE XREF: main+202↑j
.text:080487E1                 sub     esp, 0Ch
.text:080487E4                 push    offset aGoodJob ; "Good Job."
.text:080487E9                 call    _puts
```

02_angr_find_condition 主要是把逻辑判断通过混淆打乱在各个分支上,导致无法使用find 和avoid 直接对单个地址进行定位.explore() 的find 和avoid 可以通过传递回调函数来实现目的地址检验和排除判断.对于这样的混淆思路,解决方法是通过判断控制台输出数据是不是"Good Job" 和"Try again" 来确认执行到了成功还是失败分支.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())

    return 'Good Job' in str(stdout_output) # :boolean

  def should_abort(state): 
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    
    return 'Try again' in str(stdout_output)  # :boolean

  simulation.explore(find=is_successful, avoid=should_abort) 
    
```

Angr函数使用总结:

> simulation.explore(find = 回调函数, avoid = 回调函数)  =>  路径探索
>
> > explore() 函数的回调函数格式为:
> >
> > def recall_explore(state) :
> >
> > ​    ...
> >
> > ​    return True / False  #  True 意思是发现了该路径,False 则是忽略
>
> state.posix.dumps(sys.stdout.fileno())  =>  获取模拟执行的控制台输出



## 03_angr_symbolic_registers

汇编代码:

```assembly
.text:080488E8 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:080488E8                 public main
.text:080488E8 main            proc near               ; DATA XREF: _start+17↑o
.text:080488E8
.text:080488E8 var_14          = dword ptr -14h
.text:080488E8 var_10          = dword ptr -10h
.text:080488E8 var_C           = dword ptr -0Ch
.text:080488E8 var_4           = dword ptr -4
.text:080488E8 argc            = dword ptr  8
.text:080488E8 argv            = dword ptr  0Ch
.text:080488E8 envp            = dword ptr  10h
.text:080488E8
.text:080488E8 ; __unwind {
.text:080488E8                 lea     ecx, [esp+4]
.text:080488EC                 and     esp, 0FFFFFFF0h
.text:080488EF                 push    dword ptr [ecx-4]
.text:080488F2                 push    ebp
.text:080488F3                 mov     ebp, esp
.text:080488F5                 push    ecx
.text:080488F6                 sub     esp, 14h
.text:080488F9                 sub     esp, 0Ch
.text:080488FC                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048901                 call    _printf
.text:08048906                 add     esp, 10h
.text:08048909                 call    get_user_input
.text:0804890E                 mov     [ebp+var_14], eax
.text:08048911                 mov     [ebp+var_10], ebx
.text:08048914                 mov     [ebp+var_C], edx
.text:08048917                 sub     esp, 0Ch
.text:0804891A                 push    [ebp+var_14]
.text:0804891D                 call    complex_function_1
.text:08048922                 add     esp, 10h
.text:08048925                 mov     ecx, eax
.text:08048927                 mov     [ebp+var_14], ecx
.text:0804892A                 sub     esp, 0Ch
.text:0804892D                 push    [ebp+var_10]
.text:08048930                 call    complex_function_2
.text:08048935                 add     esp, 10h
.text:08048938                 mov     ecx, eax
.text:0804893A                 mov     [ebp+var_10], ecx
.text:0804893D                 sub     esp, 0Ch
.text:08048940                 push    [ebp+var_C]
.text:08048943                 call    complex_function_3
.text:08048948                 add     esp, 10h
.text:0804894B                 mov     ecx, eax
.text:0804894D                 mov     [ebp+var_C], ecx
.text:08048950                 cmp     [ebp+var_14], 0
.text:08048954                 jnz     short loc_8048962
.text:08048956                 cmp     [ebp+var_10], 0
.text:0804895A                 jnz     short loc_8048962
.text:0804895C                 cmp     [ebp+var_C], 0
.text:08048960                 jz      short loc_8048974
.text:08048962
.text:08048962 loc_8048962:                            ; CODE XREF: main+6C↑j
.text:08048962                                         ; main+72↑j
.text:08048962                 sub     esp, 0Ch
.text:08048965                 push    offset s        ; "Try again."
.text:0804896A                 call    _puts
.text:0804896F                 add     esp, 10h
.text:08048972                 jmp     short loc_8048984
.text:08048974 ; ---------------------------------------------------------------------------
.text:08048974
.text:08048974 loc_8048974:                            ; CODE XREF: main+78↑j
.text:08048974                 sub     esp, 0Ch
.text:08048977                 push    offset aGoodJob ; "Good Job."
.text:0804897C                 call    _puts
.text:08048981                 add     esp, 10h
.text:08048984
.text:08048984 loc_8048984:                            ; CODE XREF: main+8A↑j
.text:08048984                 mov     ecx, 0
.text:08048989                 mov     eax, ecx
.text:0804898B                 mov     ecx, [ebp+var_4]
.text:0804898E                 leave
.text:0804898F                 lea     esp, [ecx-4]
.text:08048992                 retn
```

03_angr_symbolic_registers 主要是多个complex_function 生成数据然后和用户输入进行判断,然后把输入校验的结果在(0x8048950 - 0x8048960)这几个`cmp + jz/jnz` 判断中进行校验,因为这个时候有三个输入,所以需要分开来求解,我们先来看complex_function() 函数的调用部分

```assembly
.text:0804890E                 mov     [ebp+var_14], eax
.text:08048911                 mov     [ebp+var_10], ebx
.text:08048914                 mov     [ebp+var_C], edx
.text:08048917                 sub     esp, 0Ch
.text:0804891A                 push    [ebp+var_14]
.text:0804891D                 call    complex_function_1
.text:08048922                 add     esp, 10h
.text:08048925                 mov     ecx, eax
.text:08048927                 mov     [ebp+var_14], ecx
.text:0804892A                 sub     esp, 0Ch
.text:0804892D                 push    [ebp+var_10]
.text:08048930                 call    complex_function_2
.text:08048935                 add     esp, 10h
.text:08048938                 mov     ecx, eax
.text:0804893A                 mov     [ebp+var_10], ecx
.text:0804893D                 sub     esp, 0Ch
.text:08048940                 push    [ebp+var_C]
.text:08048943                 call    complex_function_3
```

可以看到,EAX EBX EDX 分别是complex_function1-3 的输入参数,那么我们就需要求解EAX EBX EDX 的值.那么我们就需要从0x804890E 处开始执行代码,并在符合条件的路径("Good Job")处求解EAX EBX EDX 的值.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  start_address = 0x804890E  # :integer (probably hexadecimal)
  initial_state = project.factory.blank_state(addr=start_address)

  password0_size_in_bits = 4 * 8  #  因为complex_function 输出一个int 类型的数据,那就是32bits
  password0 = claripy.BVS('password0', password0_size_in_bits)
  password1 = claripy.BVS('password1', password0_size_in_bits)
  password2 = claripy.BVS('password2', password0_size_in_bits)

  initial_state.regs.eax = password0  #  告诉符号执行引擎这三个寄存器分别是complex_function 的参数
  initial_state.regs.ebx = password1
  initial_state.regs.edx = password2

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)  #  根据输出来判断执行路径

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.se.eval(password0)
    solution1 = solution_state.se.eval(password1)
    solution2 = solution_state.se.eval(password2)

    solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2 ]))  # :string
    print(solution)
  else:
    raise Exception('Could not find the solution')

```

Angr函数使用总结:

> project.factory.blank_state(addr=start_address)  =>  创建自定义入口的状态上下文
>
> initial_state.regs  =>  操作状态上下文的寄存器
>
> claripy.BVS('变量名', 变量大小)  =>  创建求解变量
>
> solution_state.se.eval(变量)  =>  求解符号变量



## 04_angr_symbolic_registers

汇编代码:

```assembly
.text:080486F4 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:080486F4                 public main
.text:080486F4 main            proc near               ; DATA XREF: _start+17↑o
.text:080486F4
.text:080486F4 var_4           = dword ptr -4
.text:080486F4 argc            = dword ptr  8
.text:080486F4 argv            = dword ptr  0Ch
.text:080486F4 envp            = dword ptr  10h
.text:080486F4
.text:080486F4 ; __unwind {
.text:080486F4                 lea     ecx, [esp+4]
.text:080486F8                 and     esp, 0FFFFFFF0h
.text:080486FB                 push    dword ptr [ecx-4]
.text:080486FE                 push    ebp
.text:080486FF                 mov     ebp, esp
.text:08048701                 push    ecx
.text:08048702                 sub     esp, 4
.text:08048705                 sub     esp, 0Ch
.text:08048708                 push    offset aEnterThePasswo ; "Enter the password: "
.text:0804870D                 call    _printf
.text:08048712                 add     esp, 10h
.text:08048715                 call    handle_user
.text:0804871A                 mov     eax, 0
.text:0804871F                 mov     ecx, [ebp+var_4]
.text:08048722                 leave
.text:08048723                 lea     esp, [ecx-4]
.text:08048726                 retn
```

主要的代码逻辑在handle_user() 函数里面,再来看看代码

```assembly
.text:08048679 handle_user     proc near               ; CODE XREF: main+21↓p
.text:08048679
.text:08048679 var_10          = dword ptr -10h
.text:08048679 var_C           = dword ptr -0Ch
.text:08048679
.text:08048679 ; __unwind {
.text:08048679                 push    ebp
.text:0804867A                 mov     ebp, esp
.text:0804867C                 sub     esp, 18h
.text:0804867F                 sub     esp, 4
.text:08048682                 lea     eax, [ebp+var_10]
.text:08048685                 push    eax
.text:08048686                 lea     eax, [ebp+var_C]
.text:08048689                 push    eax
.text:0804868A                 push    offset aUU      ; "%u %u"
.text:0804868F                 call    ___isoc99_scanf
.text:08048694                 add     esp, 10h
.text:08048697                 mov     eax, [ebp+var_C]   ; Argument complex_function0
.text:0804869A                 sub     esp, 0Ch
.text:0804869D                 push    eax
.text:0804869E                 call    complex_function0  ; Call complex_function0
.text:080486A3                 add     esp, 10h
.text:080486A6                 mov     [ebp+var_C], eax
.text:080486A9                 mov     eax, [ebp+var_10]  ; Argument complex_function1
.text:080486AC                 sub     esp, 0Ch
.text:080486AF                 push    eax
.text:080486B0                 call    complex_function1  ; Call complex_function1
.text:080486B5                 add     esp, 10h
.text:080486B8                 mov     [ebp+var_10], eax
.text:080486BB                 mov     eax, [ebp+var_C]
.text:080486BE                 cmp     eax, 0D3062A4Ch
.text:080486C3                 jnz     short loc_80486CF  ; Check Value with input
.text:080486C5                 mov     eax, [ebp+var_10]
.text:080486C8                 cmp     eax, 694E5BA0h
.text:080486CD                 jz      short loc_80486E1
.text:080486CF
.text:080486CF loc_80486CF:                            ; CODE XREF: handle_user+4A↑j
.text:080486CF                 sub     esp, 0Ch
.text:080486D2                 push    offset s        ; "Try again."
.text:080486D7                 call    _puts
.text:080486DC                 add     esp, 10h
.text:080486DF                 jmp     short loc_80486F1
.text:080486E1 ; ---------------------------------------------------------------------------
.text:080486E1
.text:080486E1 loc_80486E1:                            ; CODE XREF: handle_user+54↑j
.text:080486E1                 sub     esp, 0Ch
.text:080486E4                 push    offset aGoodJob ; "Good Job."
.text:080486E9                 call    _puts
.text:080486EE                 add     esp, 10h
.text:080486F1
.text:080486F1 loc_80486F1:                            ; CODE XREF: handle_user+66↑j
.text:080486F1                 nop
.text:080486F2                 leave
.text:080486F3                 retn
```

可以看到,现在complex_function 的参数是通过栈来传输的,complex_function0 主要的代码是运算一些数据保存到arg_0 中,所以我们才需要跟踪执行这个栈上的参数

```assembly
.text:080484A9 complex_function0 proc near             ; CODE XREF: handle_user+25↓p
.text:080484A9
.text:080484A9 arg_0           = dword ptr  8
.text:080484A9
.text:080484A9 ; __unwind {
.text:080484A9                 push    ebp
.text:080484AA                 mov     ebp, esp
.text:080484AC                 xor     [ebp+arg_0], 0D53642BEh
.text:080484B3                 xor     [ebp+arg_0], 58FC2926h
.text:080484BA                 xor     [ebp+arg_0], 25596A36h
.text:080484C1                 xor     [ebp+arg_0], 0A7AFAA43h
.text:080484C8                 xor     [ebp+arg_0], 1559CAFEh
.text:080484CF                 xor     [ebp+arg_0], 0D8D89C66h
.text:080484D6                 xor     [ebp+arg_0], 6B8B30B6h
.text:080484DD                 xor     [ebp+arg_0], 0B5E7C180h
.text:080484E4                 xor     [ebp+arg_0], 1FA429F6h
.text:080484EB                 xor     [ebp+arg_0], 21C70AF4h
.text:080484F2                 xor     [ebp+arg_0], 0B7261E1Dh
.text:080484F9                 xor     [ebp+arg_0], 0ADD88AD8h
.text:08048500                 xor     [ebp+arg_0], 3E16A0F2h
.text:08048507                 xor     [ebp+arg_0], 0DF2308FBh
.text:0804850E                 xor     [ebp+arg_0], 2273AAFh
.text:08048515                 xor     [ebp+arg_0], 8E69AC70h
.text:0804851C                 xor     [ebp+arg_0], 0AC8924h
.text:08048523                 xor     [ebp+arg_0], 561B782h
.text:0804852A                 xor     [ebp+arg_0], 5A64A924h
.text:08048531                 xor     [ebp+arg_0], 0B118005Bh
.text:08048538                 xor     [ebp+arg_0], 61461EA2h
.text:0804853F                 xor     [ebp+arg_0], 0E0E04E79h
.text:08048546                 xor     [ebp+arg_0], 0A8DDACAAh
.text:0804854D                 xor     [ebp+arg_0], 82AF667Dh
.text:08048554                 xor     [ebp+arg_0], 0B3CB4464h
.text:0804855B                 xor     [ebp+arg_0], 43B7BB1Ah
.text:08048562                 xor     [ebp+arg_0], 0DF30F25Bh
.text:08048569                 xor     [ebp+arg_0], 4C0F3376h
.text:08048570                 xor     [ebp+arg_0], 0B2E462E5h
.text:08048577                 xor     [ebp+arg_0], 7BF4CFC3h
.text:0804857E                 xor     [ebp+arg_0], 0C2960388h
.text:08048585                 xor     [ebp+arg_0], 27071524h
.text:0804858C                 mov     eax, [ebp+arg_0]
.text:0804858F                 pop     ebp
.text:08048590                 retn
.text:08048590 ; } // starts at 80484A9
```

再回来看两个函数的调用的栈情况:

```assembly
.text:08048697           >     mov     eax, [ebp+var_C]   ; Argument complex_function0
.text:0804869A                 sub     esp, 0Ch
.text:0804869D                 push    eax
.text:0804869E                 call    complex_function0  ; Call complex_function0
.text:080486A3                 add     esp, 10h
.text:080486A6                 mov     [ebp+var_C], eax
.text:080486A9           >     mov     eax, [ebp+var_10]  ; Argument complex_function1
.text:080486AC                 sub     esp, 0Ch
.text:080486AF                 push    eax
.text:080486B0                 call    complex_function1  ; Call complex_function1
```

此时我们可以知道,var_C 和var_10 都是在栈上是连续的,那么我们就需要构造两个连续的push data ,把password 保存到栈上,并调节esp - 8 .

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  start_address = 0x8048697
  initial_state = project.factory.blank_state(addr=start_address)
  
  initial_state.regs.ebp = initial_state.regs.esp

  password0 = claripy.BVS('password0', 4 * 8)  #  int 
  password1 = claripy.BVS('password1', 4 * 8)
  
  padding_length_in_bytes = 8  # integer * 2
  initial_state.regs.esp -= padding_length_in_bytes

  initial_state.stack_push(password0)  # :bitvector (claripy.BVS, claripy.BVV, claripy.BV)
  initial_state.stack_push(password1)

  simulation = project.factory.simgr(initial_state)

  simulation.explore(find=0x80486E4,avoid=0x80486D2)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.se.eval(password0)
    solution1 = solution_state.se.eval(password1)
    solution = ' '.join(map('{:x}'.format, [ solution0, solution1 ]))  # :string
    print(solution)
  
```



## 05_angr_symbolic_memory

汇编代码:

```assembly
.text:080485E0                 push    offset unk_9FD92B8
.text:080485E5                 push    offset unk_9FD92B0
.text:080485EA                 push    offset unk_9FD92A8
.text:080485EF                 push    offset user_input
.text:080485F4                 push    offset a8s8s8s8s ; "%8s %8s %8s %8s"
.text:080485F9                 call    ___isoc99_scanf  ;  用户输入
.text:080485FE                 add     esp, 20h
.text:08048601                 mov     [ebp+var_C], 0
.text:08048608                 jmp     short loc_8048637  ;  注意这里有一个循环
.text:0804860A ; ---------------------------------------------------------------------------
.text:0804860A
.text:0804860A loc_804860A:                            ; CODE XREF: main+93↓j
.text:0804860A                 mov     eax, [ebp+var_C]
.text:0804860D                 add     eax, 9FD92A0h
.text:08048612                 movzx   eax, byte ptr [eax]  ;  Argument complex_function
.text:08048615                 movsx   eax, al
.text:08048618                 sub     esp, 8
.text:0804861B                 push    [ebp+var_C]
.text:0804861E                 push    eax
.text:0804861F                 call    complex_function  ;  计算函数
.text:08048624                 add     esp, 10h
.text:08048627                 mov     edx, eax
.text:08048629                 mov     eax, [ebp+var_C]
.text:0804862C                 add     eax, 9FD92A0h
.text:08048631                 mov     [eax], dl
.text:08048633                 add     [ebp+var_C], 1
.text:08048637
.text:08048637 loc_8048637:                            ; CODE XREF: main+60↑j
.text:08048637                 cmp     [ebp+var_C], 1Fh
.text:0804863B                 jle     short loc_804860A
.text:0804863D                 sub     esp, 4
.text:08048640                 push    20h             ; n
.text:08048642                 push    offset s2       ; "THNJXTHBJUCDIMEEMLZNGMHISXAIXDQG"
.text:08048647                 push    offset user_input ; s1
.text:0804864C                 call    _strncmp
.text:08048651                 add     esp, 10h
.text:08048654                 test    eax, eax
.text:08048656                 jz      short loc_804866A  ; 判断输入和complex_function是否相等
.text:08048658                 sub     esp, 0Ch
.text:0804865B                 push    offset s        ; "Try again."
.text:08048660                 call    _puts
.text:08048665                 add     esp, 10h
.text:08048668                 jmp     short loc_804867A
.text:0804866A ; ---------------------------------------------------------------------------
.text:0804866A
.text:0804866A loc_804866A:                            ; CODE XREF: main+AE↑j
.text:0804866A                 sub     esp, 0Ch
.text:0804866D                 push    offset aGoodJob ; "Good Job."
.text:08048672                 call    _puts
.text:08048677                 add     esp, 10h
.text:0804867A
.text:0804867A loc_804867A:                            ; CODE XREF: main+C0↑j
.text:0804867A                 mov     eax, 0
.text:0804867F                 mov     ecx, [ebp+var_4]
.text:08048682                 leave
.text:08048683                 lea     esp, [ecx-4]
.text:08048686                 retn
```

那么现在我们的目标就是要关注下面这四块内存

```assembly
.text:080485E0                 push    offset unk_9FD92B8
.text:080485E5                 push    offset unk_9FD92B0
.text:080485EA                 push    offset unk_9FD92A8
.text:080485EF                 push    offset user_input
```

每一块内存的大小是8Byte

```assembly
.text:080485F4                 push    offset a8s8s8s8s ; "%8s %8s %8s %8s"
.text:080485F9                 call    ___isoc99_scanf  ;  用户输入
```

程序执行地址为0x8048601 ,在scanf 调整栈内存之后(`.text:080485FE add esp, 20h`)开始执行.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password0', 8 * 8)
  password1 = claripy.BVS('password1', 8 * 8)
  password2 = claripy.BVS('password2', 8 * 8)
  password3 = claripy.BVS('password3', 8 * 8)

  password0_address = 0x9FD92A0
  initial_state.memory.store(password0_address, password0)
  password1_address = 0x9FD92A8
  initial_state.memory.store(password1_address, password1)
  password2_address = 0x9FD92B0
  initial_state.memory.store(password2_address, password2)
  password3_address = 0x9FD92B8
  initial_state.memory.store(password3_address, password3)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    solution0 = solution_state.se.eval(password0)
    solution1 = solution_state.se.eval(password1)
    solution2 = solution_state.se.eval(password2)
    solution3 = solution_state.se.eval(password3)
    solution = ' '.join(map('{:x}'.format, [ solution0, solution1,solution2,solution3 ]))

    print(solution)
```

Angr函数使用总结:

> initial_state.memory.store(地址,数据)  =>  初始化内存地址中的数据



## 06_angr_symbolic_dynamic_memory

汇编代码:

```assembly
.text:08048621                 push    9               ; size
.text:08048623                 call    _malloc
.text:08048628                 add     esp, 10h
.text:0804862B                 mov     ds:buffer0, eax
.text:08048630                 sub     esp, 0Ch
.text:08048633                 push    9               ; size
.text:08048635                 call    _malloc
.text:0804863A                 add     esp, 10h
.text:0804863D                 mov     ds:buffer1, eax
.text:08048642                 mov     eax, ds:buffer0
.text:08048647                 sub     esp, 4
.text:0804864A                 push    9               ; n
.text:0804864C                 push    0               ; c
.text:0804864E                 push    eax             ; s
.text:0804864F                 call    _memset
.text:08048654                 add     esp, 10h
.text:08048657                 mov     eax, ds:buffer1
.text:0804865C                 sub     esp, 4
.text:0804865F                 push    9               ; n
.text:08048661                 push    0               ; c
.text:08048663                 push    eax             ; s
.text:08048664                 call    _memset
.text:08048669                 add     esp, 10h
.text:0804866C                 sub     esp, 0Ch
.text:0804866F                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048674                 call    _printf
.text:08048679                 add     esp, 10h
.text:0804867C                 mov     edx, ds:buffer1
.text:08048682                 mov     eax, ds:buffer0
.text:08048687                 sub     esp, 4
.text:0804868A                 push    edx
.text:0804868B                 push    eax
.text:0804868C                 push    offset a8s8s    ; "%8s %8s"
.text:08048691                 call    ___isoc99_scanf
```

这次scanf() 有两个输入参数,数据保存的位置是通过全局变量的char* 指针来保存到buffer 中,大小为8 字节.

```assembly
.text:08048699                 mov     [ebp+var_C], 0
.text:080486A0                 jmp     short loc_8048706
.text:080486A2 ; ---------------------------------------------------------------------------
.text:080486A2
.text:080486A2 loc_80486A2:                            ; CODE XREF: main+FE↓j
.text:080486A2                 mov     edx, ds:buffer0
.text:080486A8                 mov     eax, [ebp+var_C]
.text:080486AB                 lea     ebx, [edx+eax]
.text:080486AE                 mov     edx, ds:buffer0
.text:080486B4                 mov     eax, [ebp+var_C]
.text:080486B7                 add     eax, edx
.text:080486B9                 movzx   eax, byte ptr [eax]
.text:080486BC                 movsx   eax, al
.text:080486BF                 sub     esp, 8
.text:080486C2                 push    [ebp+var_C]
.text:080486C5                 push    eax
.text:080486C6                 call    complex_function
.text:080486CB                 add     esp, 10h
.text:080486CE                 mov     [ebx], al
.text:080486D0                 mov     edx, ds:buffer1
.text:080486D6                 mov     eax, [ebp+var_C]
.text:080486D9                 lea     ebx, [edx+eax]
.text:080486DC                 mov     eax, [ebp+var_C]
.text:080486DF                 lea     edx, [eax+20h]
.text:080486E2                 mov     ecx, ds:buffer1
.text:080486E8                 mov     eax, [ebp+var_C]
.text:080486EB                 add     eax, ecx
.text:080486ED                 movzx   eax, byte ptr [eax]
.text:080486F0                 movsx   eax, al
.text:080486F3                 sub     esp, 8
.text:080486F6                 push    edx
.text:080486F7                 push    eax
.text:080486F8                 call    complex_function
.text:080486FD                 add     esp, 10h
.text:08048700                 mov     [ebx], al
.text:08048702                 add     [ebp+var_C], 1
.text:08048706
.text:08048706 loc_8048706:                            ; CODE XREF: main+94↑j
.text:08048706                 cmp     [ebp+var_C], 7
.text:0804870A                 jle     short loc_80486A2
```

接下来就到了complex_function 运算的地方了,我们主要是对buffer0 和buffer1 指向的内存做求解.

```assembly
.bss:09FD92AC buffer0         dd ?                    ; DATA XREF: main+1F↑w
.bss:09FD92AC                                         ; main+36↑r ...
.bss:09FD92B0                 public buffer3
.bss:09FD92B0 buffer3         db    ? ;
.bss:09FD92B1                 db    ? ;
.bss:09FD92B2                 db    ? ;
.bss:09FD92B3                 db    ? ;
```

所以,我们在利用 initial_state.memory.store() 构造内存时,还需要在里面填入指向保存数据的地址,Angr可以不用创建新内存(malloc),直接指向内存中一个任意位置即可,所以我们写0x4444440 和0x44444450 到buffer0 和buffer1 的内存中.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048699
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password0', 4 * 8)
  password1 = claripy.BVS('password1', 4 * 8)

  fake_heap_address0 = 0x4444440
  pointer_to_malloc_memory_address0 = 0x9FD92AC
  initial_state.memory.store(pointer_to_malloc_memory_address0,fake_heap_address0, endness=project.arch.memory_endness)
  fake_heap_address1 = 0x4444450
  pointer_to_malloc_memory_address1 = 0x9FD92B0
  initial_state.memory.store(pointer_to_malloc_memory_address1,fake_heap_address1, endness=project.arch.memory_endness)

  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)

  simulation = project.factory.simgr(initial_state)

  simulation.explore(find=0x8048759, avoid=0x8048747)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.se.eval(password0)
    solution1 = solution_state.se.eval(password1)

    solution = ' '.join(map('{:x}'.format, [ solution0, solution1 ]))

    print(solution)
```

Angr函数使用总结:

> initial_state.memory.store(地址,数据,endness = 数据字节顺序)  =>  设置初始化内存数据
>
> project.arch.memory_endness  =>  指的是内存字节顺序



## 07_angr_symbolic_file

汇编代码:

```assembly
.text:0804888E                 push    40h             ; n
.text:08048890                 push    0               ; c
.text:08048892                 push    offset buffer   ; s
.text:08048897                 call    _memset
.text:0804889C                 add     esp, 10h
.text:0804889F                 sub     esp, 0Ch
.text:080488A2                 push    offset aEnterThePasswo ; "Enter the password: "
.text:080488A7                 call    _printf
.text:080488AC                 add     esp, 10h
.text:080488AF                 sub     esp, 8
.text:080488B2                 push    offset buffer
.text:080488B7                 push    offset a64s     ; "%64s"
.text:080488BC                 call    ___isoc99_scanf
.text:080488C1                 add     esp, 10h
.text:080488C4                 sub     esp, 8
.text:080488C7                 push    40h             ; n
.text:080488C9                 push    offset buffer   ; int
.text:080488CE                 call    ignore_me
.text:080488D3                 add     esp, 10h
.text:080488D6                 sub     esp, 4
.text:080488D9                 push    40h             ; n
.text:080488DB                 push    0               ; c
.text:080488DD                 push    offset buffer   ; s
.text:080488E2                 call    _memset
.text:080488E7                 add     esp, 10h
.text:080488EA                 sub     esp, 8
.text:080488ED                 push    offset aRb      ; "rb"
.text:080488F2                 push    offset name     ; "MRXJKZYR.txt"
.text:080488F7                 call    _fopen
.text:080488FC                 add     esp, 10h
.text:080488FF                 mov     ds:fp, eax
.text:08048904                 mov     eax, ds:fp
.text:08048909                 push    eax             ; stream
.text:0804890A                 push    40h             ; n
.text:0804890C                 push    1               ; size
.text:0804890E                 push    offset buffer   ; ptr
.text:08048913                 call    _fread
.text:08048918                 add     esp, 10h
.text:0804891B                 mov     eax, ds:fp
.text:08048920                 sub     esp, 0Ch
.text:08048923                 push    eax             ; stream
.text:08048924                 call    _fclose
.text:08048929                 add     esp, 10h
.text:0804892C                 sub     esp, 0Ch
.text:0804892F                 push    offset name     ; "MRXJKZYR.txt"
.text:08048934                 call    _unlink
```

程序逻辑是用户输入一串Key之后,经过计算保存到文件里(在ignore_me() 里面实现),然后通过fread() 读取文件获取数据.Angr库中有一个模拟的文件系统,我们可以通过这个文件系统来模拟fread() 出来的数据,继续往下看汇编

```assembly
.text:0804893C                 mov     [ebp+var_C], 0
.text:08048943                 jmp     short loc_8048972
.text:08048945 ; ---------------------------------------------------------------------------
.text:08048945
.text:08048945 loc_8048945:                            ; CODE XREF: main+FC↓j
.text:08048945                 mov     eax, [ebp+var_C]
.text:08048948                 add     eax, 804A0A0h
.text:0804894D                 movzx   eax, byte ptr [eax]  ;  生成数据
.text:08048950                 movsx   eax, al
.text:08048953                 sub     esp, 8
.text:08048956                 push    [ebp+var_C]
.text:08048959                 push    eax
.text:0804895A                 call    complex_function
.text:0804895F                 add     esp, 10h
.text:08048962                 mov     edx, eax
.text:08048964                 mov     eax, [ebp+var_C]
.text:08048967                 add     eax, 804A0A0h
.text:0804896C                 mov     [eax], dl
.text:0804896E                 add     [ebp+var_C], 1
.text:08048972
.text:08048972 loc_8048972:                            ; CODE XREF: main+C9↑j
.text:08048972                 cmp     [ebp+var_C], 7
.text:08048976                 jle     short loc_8048945
.text:08048978                 sub     esp, 4
.text:0804897B                 push    9               ; n
.text:0804897D                 push    offset s2       ; "UKNRZDIR"
.text:08048982                 push    offset buffer   ; s1
.text:08048987                 call    _strncmp
.text:0804898C                 add     esp, 10h
.text:0804898F                 test    eax, eax
.text:08048991                 jz      short loc_80489AD  ;  校验用户输入和生成数据
.text:08048993                 sub     esp, 0Ch
.text:08048996                 push    offset s        ; "Try again."
.text:0804899B                 call    _puts
.text:080489A0                 add     esp, 10h
.text:080489A3                 sub     esp, 0Ch
.text:080489A6                 push    1               ; status
.text:080489A8                 call    _exit
.text:080489AD ; ---------------------------------------------------------------------------
.text:080489AD
.text:080489AD loc_80489AD:                            ; CODE XREF: main+117↑j
.text:080489AD                 sub     esp, 0Ch
.text:080489B0                 push    offset aGoodJob ; "Good Job."
.text:080489B5                 call    _puts
.text:080489BA                 add     esp, 10h
.text:080489BD                 sub     esp, 0Ch
.text:080489C0                 push    0               ; status
.text:080489C2                 call    _exit
```

这段代码并没有什么特别之处,只是简单地对进行数据生成和校验然后输出判断结果.那么现在我们使用Angr的文件系统来进行求解

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x80488D6
  initial_state = project.factory.blank_state(addr=start_address)

  filename = 'MRXJKZYR.txt'  # :string
  symbolic_file_size_bytes = 0x40

  password = claripy.BVS('password', symbolic_file_size_bytes * 8)

  password_file = angr.storage.SimFile(filename, password, size=symbolic_file_size_bytes) # 模拟读文件,默认的文件内容是password,文件大小是symbolic_file_size_bytes

  symbolic_filesystem = {
    filename : password_file
  }
  initial_state.posix.fs = symbolic_filesystem # 构建状态上下文里的文件系统数据

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.se.eval(password)#,cast_to=str)

    print(solution)
```

我们也可以继续用旧的内存跟踪的方法来做,示例代码如下

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x804893C
  initial_state = project.factory.blank_state(addr=start_address)

  password = claripy.BVS('password', 0x40 * 8)

  initial_state.memory.store(0x804A0A0, password)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.se.eval(password)

    print(solution)
```

注意事项:

> 在Angr-CTF 的解题Python 文件中,我们直接执行程序可能会遇到下面这个结果
>
> > Traceback (most recent call last):
> >   File "solve07.py", line 130, in <module>
> >     main(sys.argv)
> >   File "solve07.py", line 91, in main
> >     password_file = angr.storage.SimFile(filename, file_options, content=symbolic_file_backing_memory, size=symbolic_file_size_bytes)
> > TypeError: __init__() got multiple values for argument 'content'
>
> 这是因为Angr-CTF 是使用旧版的Angr 库来实现的,现在SimFile() 函数的声明已经被修改如下
>
> > `SimFile`**(***name***,** *content=None***,** *size=None***,** *has_end=None***,** *seekable=True***,** *writable=True***,** *ident=None***,** *concrete=None***,** ***kwargs***)
>
> 也就是说,SimFile 的第二个参数不再是file_options 了,所以我们可以看到SimFile() 提示content 参数被传递了两个参数;而且新版的SimFile() 函数的content 参数只接受字符串或者BitVector ,所以用solution 中的解题脚本会出问题是因为它传递的是内存对象而不是BitVector ,于是代码修改如下
>
> > password_file = angr.storage.SimFile(filename, password, size=symbolic_file_size_bytes)

Angr函数使用总结:

> angr.storage.SimFile(文件名,文件内容, size = 文件大小)  =>  创建一个模拟文件,当有被执行的程序fopen 打开文件时,我们可以控制其里面的内容
>
> initial_state.posix.fs  =>  状态上下文的文件系统对象



## 08_angr_constraints

汇编代码:

```assembly
.text:080485C4                 mov     ds:password, 4A58524Dh  ;  这个是全局变量:0x804A040
.text:080485CE                 mov     ds:dword_804A044, 52595A4Bh
.text:080485D8                 mov     ds:dword_804A048, 454B4D4Bh
.text:080485E2                 mov     ds:dword_804A04C, 425A464Eh
.text:080485EC                 sub     esp, 4
.text:080485EF                 push    11h             ; n
.text:080485F1                 push    0               ; c
.text:080485F3                 push    offset buffer   ; s
.text:080485F8                 call    _memset
.text:080485FD                 add     esp, 10h
.text:08048600                 sub     esp, 0Ch
.text:08048603                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048608                 call    _printf
.text:0804860D                 add     esp, 10h
.text:08048610                 sub     esp, 8
.text:08048613                 push    offset buffer
.text:08048618                 push    offset a16s     ; "%16s"
.text:0804861D                 call    ___isoc99_scanf  ;  用户输入,这个也是全局变量:0x804A050
.text:08048622                 add     esp, 10h
.text:08048625                 mov     [ebp+var_C], 0
.text:0804862C                 jmp     short loc_8048663
.text:0804862E ; ---------------------------------------------------------------------------
.text:0804862E
.text:0804862E loc_804862E:                            ; CODE XREF: main+B4↓j
.text:0804862E                 mov     eax, 0Fh
.text:08048633                 sub     eax, [ebp+var_C]
.text:08048636                 mov     edx, eax
.text:08048638                 mov     eax, [ebp+var_C]
.text:0804863B                 add     eax, 804A050h
.text:08048640                 movzx   eax, byte ptr [eax]
.text:08048643                 movsx   eax, al
.text:08048646                 sub     esp, 8
.text:08048649                 push    edx
.text:0804864A                 push    eax
.text:0804864B                 call    complex_function  ;  对用户输入进行计算
.text:08048650                 add     esp, 10h
.text:08048653                 mov     edx, eax
.text:08048655                 mov     eax, [ebp+var_C]
.text:08048658                 add     eax, 804A050h
.text:0804865D                 mov     [eax], dl
.text:0804865F                 add     [ebp+var_C], 1
.text:08048663
.text:08048663 loc_8048663:                            ; CODE XREF: main+79↑j
.text:08048663                 cmp     [ebp+var_C], 0Fh
.text:08048667                 jle     short loc_804862E
.text:08048669                 sub     esp, 8
.text:0804866C                 push    10h
.text:0804866E                 push    offset buffer
.text:08048673                 call    check_equals_MRXJKZYRKMKENFZB  ;  check_equals() 函数是把buffer 和password 来对比
.text:08048678                 add     esp, 10h
.text:0804867B                 test    eax, eax
.text:0804867D                 jnz     short loc_8048691  ;  对比校验结果
.text:0804867F                 sub     esp, 0Ch
.text:08048682                 push    offset s        ; "Try again."
.text:08048687                 call    _puts
.text:0804868C                 add     esp, 10h
.text:0804868F                 jmp     short loc_80486A1
.text:08048691 ; ---------------------------------------------------------------------------
.text:08048691
.text:08048691 loc_8048691:                            ; CODE XREF: main+CA↑j
.text:08048691                 sub     esp, 0Ch
.text:08048694                 push    offset aGoodJob ; "Good Job."
.text:08048699                 call    _puts
.text:0804869E                 add     esp, 10h
.text:080486A1
```

主要的思路是把complex_function() 计算的结果和字符串`MRXJKZYRKMKENFZB` 来做对比,我们假定complex_function() 的输入是未知的,check_equals() 函数中对比的内容是已知的,那么我们的关注点就在于对输入进行求解.

首先第一步,我们需要在complex_function() 循环计算之后(地址0x804866C)就可以得到buffer 的符号执行内容,接下来我们需要根据buffer 的内容和对比的字符串`MRXJKZYRKMKENFZB`来计算是否有满足的解.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048625  #  scanf() 之后的位置
  initial_state = project.factory.blank_state(addr=start_address)

  buffer = claripy.BVS('buffer', 0x10* 8)  #  buffer的大小是0x10 字节,也就是0x10 * 8 比特
  buffer_address = 0x804A050
  initial_state.memory.store(buffer_address, buffer)  #  buffer 是全局变量,地址是0x804A050

  simulation = project.factory.simgr(initial_state)
  address_to_check_constraint = 0x804866C
  simulation.explore(find=address_to_check_constraint)  #  compilex_function() 计算结束位置

  if simulation.found:
    solution_state = simulation.found[0]

    constrained_parameter_address = 0x804A050  #  计算约束的内存位置
    constrained_parameter_size_bytes = 0x10    #  计算约束的内存大小
    constrained_parameter_bitvector = solution_state.memory.load(  #  加载内存
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )

    constrained_parameter_desired_value = 'MRXJKZYRKMKENFZB' #  Key-String

    solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)  #  添加约束条件使用求解器求解内存中的bitvector 和Key-String 相等时是否有满足的解

    solution = solution_state.se.eval(buffer)

    print(solution)
```

Angr函数使用总结:

> solution_state.memory.load(内存地址,内存大小)  =>  加载内存
>
> solution_state.add_constraints(约束条件)  =>  添加约束条件



## 09_angr_hooks

汇编代码:

```assembly
.text:08048604                 mov     ds:password, 4A58524Dh
.text:0804860E                 mov     ds:dword_804A048, 52595A4Bh
.text:08048618                 mov     ds:dword_804A04C, 454B4D4Bh
.text:08048622                 mov     ds:dword_804A050, 425A464Eh  ;  Key-String
.text:0804862C                 sub     esp, 4
.text:0804862F                 push    11h             ; n
.text:08048631                 push    0               ; c
.text:08048633                 push    offset buffer   ; s
.text:08048638                 call    _memset         
.text:0804863D                 add     esp, 10h
.text:08048640                 sub     esp, 0Ch
.text:08048643                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048648                 call    _printf
.text:0804864D                 add     esp, 10h
.text:08048650                 sub     esp, 8
.text:08048653                 push    offset buffer
.text:08048658                 push    offset a16s     ; "%16s"
.text:0804865D                 call    ___isoc99_scanf ; 用户输入Key
.text:08048662                 add     esp, 10h
.text:08048665                 mov     [ebp+var_10], 0
.text:0804866C                 jmp     short loc_80486A3
.text:0804866E ; ---------------------------------------------------------------------------
.text:0804866E
.text:0804866E loc_804866E:                            ; CODE XREF: main+B4↓j
.text:0804866E                 mov     eax, 12h
.text:08048673                 sub     eax, [ebp+var_10]
.text:08048676                 mov     edx, eax
.text:08048678                 mov     eax, [ebp+var_10]
.text:0804867B                 add     eax, 804A054h   ;  这个地址是用户输入buffer
.text:08048680                 movzx   eax, byte ptr [eax]
.text:08048683                 movsx   eax, al
.text:08048686                 sub     esp, 8
.text:08048689                 push    edx
.text:0804868A                 push    eax
.text:0804868B                 call    complex_function  ;  对用户输入进行计算
.text:08048690                 add     esp, 10h
.text:08048693                 mov     edx, eax
.text:08048695                 mov     eax, [ebp+var_10]
.text:08048698                 add     eax, 804A054h
.text:0804869D                 mov     [eax], dl
.text:0804869F                 add     [ebp+var_10], 1
.text:080486A3
.text:080486A3 loc_80486A3:                            ; CODE XREF: main+79↑j
.text:080486A3                 cmp     [ebp+var_10], 0Fh
.text:080486A7                 jle     short loc_804866E  ;  这是一个循环complex_function() 计算
.text:080486A9                 sub     esp, 8
.text:080486AC                 push    10h
.text:080486AE                 push    offset buffer
.text:080486B3                 call    check_equals_MRXJKZYRKMKENFZB  ;  check_equals() 对比结果
.text:080486B8                 add     esp, 10h
.text:080486BB                 mov     ds:equals, eax  ;  check_equals 的结果保存在全局变量equals里
.text:080486C0                 mov     [ebp+var_C], 0
.text:080486C7                 jmp     short loc_80486FA
.text:080486C9 ; ---------------------------------------------------------------------------
.text:080486C9
.text:080486C9 loc_80486C9:                            ; CODE XREF: main+10B↓j
.text:080486C9                 mov     eax, [ebp+var_C]
.text:080486CC                 lea     edx, [eax+9]
.text:080486CF                 mov     eax, [ebp+var_C]
.text:080486D2                 add     eax, 804A044h  ;  这个是Key-String
.text:080486D7                 movzx   eax, byte ptr [eax]
.text:080486DA                 movsx   eax, al
.text:080486DD                 sub     esp, 8
.text:080486E0                 push    edx
.text:080486E1                 push    eax
.text:080486E2                 call    complex_function  ;  这次是对Key-String 进行计算了
.text:080486E7                 add     esp, 10h
.text:080486EA                 mov     edx, eax
.text:080486EC                 mov     eax, [ebp+var_C]
.text:080486EF                 add     eax, 804A044h
.text:080486F4                 mov     [eax], dl
.text:080486F6                 add     [ebp+var_C], 1
.text:080486FA
.text:080486FA loc_80486FA:                            ; CODE XREF: main+D4↑j
.text:080486FA                 cmp     [ebp+var_C], 0Fh
.text:080486FE                 jle     short loc_80486C9  ;  comp
.text:08048700                 sub     esp, 8
.text:08048703                 push    offset buffer
.text:08048708                 push    offset a16s     ; "%16s"
.text:0804870D                 call    ___isoc99_scanf
.text:08048712                 add     esp, 10h
.text:08048715                 mov     eax, ds:equals
.text:0804871A                 test    eax, eax
.text:0804871C                 jz      short loc_8048740  ;  对比第二次用户输入
.text:0804871E                 sub     esp, 4
.text:08048721                 push    10h             ; n
.text:08048723                 push    offset password ; s2
.text:08048728                 push    offset buffer   ; s1
.text:0804872D                 call    _strncmp
.text:08048732                 add     esp, 10h
.text:08048735                 test    eax, eax
.text:08048737                 jnz     short loc_8048740
.text:08048739                 mov     eax, 1
.text:0804873E                 jmp     short loc_8048745
.text:08048740 ; ---------------------------------------------------------------------------
.text:08048740
.text:08048740 loc_8048740:                            ; CODE XREF: main+129↑j
.text:08048740                                         ; main+144↑j
.text:08048740                 mov     eax, 0
.text:08048745
.text:08048745 loc_8048745:                            ; CODE XREF: main+14B↑j
.text:08048745                 mov     ds:equals, eax
.text:0804874A                 mov     eax, ds:equals
.text:0804874F                 test    eax, eax
.text:08048751                 jnz     short loc_8048765
.text:08048753                 sub     esp, 0Ch
.text:08048756                 push    offset s        ; "Try again."
.text:0804875B                 call    _puts
.text:08048760                 add     esp, 10h
.text:08048763                 jmp     short loc_8048775
.text:08048765 ; ---------------------------------------------------------------------------
.text:08048765
.text:08048765 loc_8048765:                            ; CODE XREF: main+15E↑j
.text:08048765                 sub     esp, 0Ch
.text:08048768                 push    offset aGoodJob ; "Good Job."
.text:0804876D                 call    _puts
.text:08048772                 add     esp, 10h  
```

由上面的代码我们可以知道基本的逻辑,第一部分是对用户输入进行complex_function() 计算,然后把计算结果传给check_equals() 检查对比;第二部分是把Key-String 传递给complex_function() 计算,再通过第二次用户输入来进行结果对比.

我们来看一下check_equals() 函数的代码,check_equals() 函数主要功能是对比complex_function() 函数计算结果和Key-String 进行对比,相等则返回1 ,不相等返回0 .

```assembly
.text:080485A5 check_equals_MRXJKZYRKMKENFZB proc near ; CODE XREF: main+C0↓p
.text:080485A5
.text:080485A5 var_8           = dword ptr -8
.text:080485A5 var_4           = dword ptr -4
.text:080485A5 arg_0           = dword ptr  8
.text:080485A5 arg_4           = dword ptr  0Ch
.text:080485A5
.text:080485A5 ; __unwind {
.text:080485A5                 push    ebp
.text:080485A6                 mov     ebp, esp
.text:080485A8                 sub     esp, 10h
.text:080485AB                 mov     [ebp+var_8], 0
.text:080485B2                 mov     [ebp+var_4], 0
.text:080485B9                 jmp     short loc_80485DD
.text:080485BB ; ---------------------------------------------------------------------------
.text:080485BB
.text:080485BB loc_80485BB:                            ; CODE XREF: check_equals_MRXJKZYRKMKENFZB+3E↓j
.text:080485BB                 mov     edx, [ebp+var_4]
.text:080485BE                 mov     eax, [ebp+arg_0]
.text:080485C1                 add     eax, edx
.text:080485C3                 movzx   edx, byte ptr [eax]
.text:080485C6                 mov     eax, [ebp+var_4]
.text:080485C9                 add     eax, 804A044h  ;  Key-String ..
.text:080485CE                 movzx   eax, byte ptr [eax]
.text:080485D1                 cmp     dl, al
.text:080485D3                 jnz     short loc_80485D9
.text:080485D5                 add     [ebp+var_8], 1
.text:080485D9
.text:080485D9 loc_80485D9:                            ; CODE XREF: check_equals_MRXJKZYRKMKENFZB+2E↑j
.text:080485D9                 add     [ebp+var_4], 1
.text:080485DD
.text:080485DD loc_80485DD:                            ; CODE XREF: check_equals_MRXJKZYRKMKENFZB+14↑j
.text:080485DD                 mov     eax, [ebp+var_4]
.text:080485E0                 cmp     eax, [ebp+arg_4]
.text:080485E3                 jb      short loc_80485BB
.text:080485E5                 mov     eax, [ebp+var_8]
.text:080485E8                 cmp     eax, [ebp+arg_4]
.text:080485EB                 setz    al
.text:080485EE                 movzx   eax, al
.text:080485F1                 leave
.text:080485F2                 retn
.text:080485F2 ; } // starts at 80485A5
```

在这一题里,使用的方法是Angr Hook .那么我们需要设计一个Hook check_equals() 函数来模拟它的功能.Hook 的插入位置在`.text:080486B3 call check_equals_MRXJKZYRKMKENFZB` .

根据这些信息,构造的solver.py 代码如下:

```python

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  check_equals_called_address = 0x80486B3  #  Hook Call Address
  instruction_to_skip_length = 0x5         #  Call instruction length

  @project.hook(check_equals_called_address, length=instruction_to_skip_length)
  def skip_check_equals_(state):
    user_input_buffer_address = 0x804A054  #  The input buffer address
    user_input_buffer_length = 0x10        #  input buffer length

    user_input_string = state.memory.load( #  load this buffer to check 
      user_input_buffer_address,
      user_input_buffer_length
    )

    check_against_string = 'MRXJKZYRKMKENFZB' # :string

    state.regs.eax = claripy.If(           #  Add a constraint .
      user_input_string == check_against_string,  #  Check condition
      claripy.BVV(1, 32),                  #  The condition is True than return a int value 1
      claripy.BVV(0, 32)                   #  The condition is False than return a int value 0
    )

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)  #  Try Explore Execute Path

  if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(sys.stdin.fileno())  #  Get data ..

    print(solution)
```

Angr函数使用总结:

> Hook回调函数格式:
>
> > @project.hook(Hook地址,执行完Hook函数后指令往后跳转n字节)
> > def skip_check_equals_(state):
> >
> >    pass
>
> claripy.If(条件,条件为True时的返回值,条件为False时的返回值)  =>  创建条件判断
>
> claripy.BVV(值,值大小)  =>  创建一个数值



## 10_angr_simprocedures

汇编代码:

```assembly
.text:08048678                 push    10h             ; n
.text:0804867A                 push    offset aMrxjkzyrkmkenf ; "MRXJKZYRKMKENFZB"
.text:0804867F                 push    offset password ; dest
.text:08048684                 call    _memcpy         ;  Key-String = MRXJKZYRKMKENFZB
.text:08048689                 add     esp, 10h
.text:0804868C                 sub     esp, 4
.text:0804868F                 push    11h             ; n
.text:08048691                 push    0               ; c
.text:08048693                 lea     eax, [ebp+s]
.text:08048696                 push    eax             ; s
.text:08048697                 call    _memset         ;  注意这次buffer 是在栈上的
.text:0804869C                 add     esp, 10h
.text:0804869F                 sub     esp, 0Ch
.text:080486A2                 push    offset aEnterThePasswo ; "Enter the password: "
.text:080486A7                 call    _printf
.text:080486AC                 add     esp, 10h
.text:080486AF                 sub     esp, 8
.text:080486B2                 lea     eax, [ebp+s]
.text:080486B5                 push    eax
.text:080486B6                 push    offset a16s     ; "%16s"
.text:080486BB                 call    ___isoc99_scanf ;  用户输入16 字节大小的内容
.text:080486C0                 add     esp, 10h
.text:080486C3                 mov     [ebp+var_28], 0
.text:080486CA                 jmp     short loc_8048701
.text:080486CC ; ---------------------------------------------------------------------------
.text:080486CC
.text:080486CC loc_80486CC:                            ; CODE XREF: main+C2↓j
.text:080486CC                 mov     eax, 12h
.text:080486D1                 sub     eax, [ebp+var_28]
.text:080486D4                 mov     edx, eax
.text:080486D6                 lea     ecx, [ebp+s]
.text:080486D9                 mov     eax, [ebp+var_28]
.text:080486DC                 add     eax, ecx
.text:080486DE                 movzx   eax, byte ptr [eax]
.text:080486E1                 movsx   eax, al
.text:080486E4                 sub     esp, 8
.text:080486E7                 push    edx
.text:080486E8                 push    eax
.text:080486E9                 call    complex_function  ;  这是复杂的complex_function() 计算操作
.text:080486EE                 add     esp, 10h
.text:080486F1                 mov     ecx, eax
.text:080486F3                 lea     edx, [ebp+s]
.text:080486F6                 mov     eax, [ebp+var_28]
.text:080486F9                 add     eax, edx
.text:080486FB                 mov     [eax], cl
.text:080486FD                 add     [ebp+var_28], 1
.text:08048701
.text:08048701 loc_8048701:                            ; CODE XREF: main+87↑j
.text:08048701                 cmp     [ebp+var_28], 0Fh
.text:08048705                 jle     short loc_80486CC
.text:08048707                 cmp     [ebp+var_24], 0DEADBEEFh
.text:0804870E                 jz      loc_8049847
.text:08048714                 cmp     [ebp+var_24], 0DEADBEEFh
.text:0804871B                 jnz     loc_8048FB4
.text:08048721                 cmp     [ebp+var_24], 0DEADBEEFh
.text:08048728                 jnz     loc_8048B71
.text:0804872E                 cmp     [ebp+var_24], 0DEADBEEFh
.text:08048735                 jnz     loc_8048956
.text:0804873B                 cmp     [ebp+var_24], 0DEADBEEFh
.text:08048742                 jz      loc_804884F
.text:08048748                 cmp     [ebp+var_24], 0DEADBEEFh
.text:0804874F                 jz      short loc_80487D0
.text:08048751                 cmp     [ebp+var_24], 0DEADBEEFh
.text:08048758                 jnz     short loc_8048795
.text:0804875A                 cmp     [ebp+var_24], 0DEADBEEFh
.text:08048761                 jz      short loc_804877C
```

代码的第一部分对用户输入做了一系列复杂的计算操作之后,然后就分别跳转到不同的位置,最后执行check_equals() 函数进行数据校验.

```assembly
.text:08048758                 jnz     short loc_8048795
.text:0804875A                 cmp     [ebp+var_24], 0DEADBEEFh
.text:08048761                 jz      short loc_804877C
.text:08048763                 sub     esp, 8
.text:08048766                 push    10h
.text:08048768                 lea     eax, [ebp+s]
.text:0804876B                 push    eax
.text:0804876C                 call    check_equals_MRXJKZYRKMKENFZB
.text:08048771                 add     esp, 10h
.text:08048774                 mov     [ebp+var_2C], eax
.text:08048777                 jmp     loc_804A969
.text:0804877C ; ---------------------------------------------------------------------------
.text:0804877C
.text:0804877C loc_804877C:                            ; CODE XREF: main+11E↑j
.text:0804877C                 sub     esp, 8
.text:0804877F                 push    10h
.text:08048781                 lea     eax, [ebp+s]
.text:08048784                 push    eax
.text:08048785                 call    check_equals_MRXJKZYRKMKENFZB
.text:0804878A                 add     esp, 10h
.text:0804878D                 mov     [ebp+var_2C], eax
.text:08048790                 jmp     loc_804A969
.text:08048795 ; ---------------------------------------------------------------------------
.text:08048795
.text:08048795 loc_8048795:                            ; CODE XREF: main+115↑j
.text:08048795                 cmp     [ebp+var_24], 0DEADBEEFh
.text:0804879C                 jz      short loc_80487B7
.text:0804879E                 sub     esp, 8
.text:080487A1                 push    10h
.text:080487A3                 lea     eax, [ebp+s]
.text:080487A6                 push    eax
.text:080487A7                 call    check_equals_MRXJKZYRKMKENFZB
.text:080487AC                 add     esp, 10h
.text:080487AF                 mov     [ebp+var_2C], eax
.text:080487B2                 jmp     loc_804A969
.text:080487B7 ; ---------------------------------------------------------------------------
.text:080487B7
.text:080487B7 loc_80487B7:                            ; CODE XREF: main+159↑j
.text:080487B7                 sub     esp, 8
.text:080487BA                 push    10h
.text:080487BC                 lea     eax, [ebp+s]
.text:080487BF                 push    eax
.text:080487C0                 call    check_equals_MRXJKZYRKMKENFZB
.text:080487C5                 add     esp, 10h
.text:080487C8                 mov     [ebp+var_2C], eax
.text:080487CB                 jmp     loc_804A969
```

那么我们来看看check_equals() 的代码:

```assembly
.text:080485F5 check_equals_MRXJKZYRKMKENFZB proc near ; CODE XREF: main+129↓p
.text:080485F5                                         ; main+142↓p ...
.text:080485F5
.text:080485F5 var_8           = dword ptr -8
.text:080485F5 var_4           = dword ptr -4
.text:080485F5 arg_0           = dword ptr  8
.text:080485F5 arg_4           = dword ptr  0Ch
.text:080485F5
.text:080485F5 ; __unwind {
.text:080485F5                 push    ebp
.text:080485F6                 mov     ebp, esp
.text:080485F8                 sub     esp, 10h
.text:080485FB                 mov     [ebp+var_8], 0
.text:08048602                 mov     [ebp+var_4], 0
.text:08048609                 jmp     short loc_804862D
.text:0804860B ; ---------------------------------------------------------------------------
.text:0804860B
.text:0804860B loc_804860B:                            ; CODE XREF: check_equals_MRXJKZYRKMKENFZB+3E↓j
.text:0804860B                 mov     edx, [ebp+var_4]
.text:0804860E                 mov     eax, [ebp+arg_0]
.text:08048611                 add     eax, edx
.text:08048613                 movzx   edx, byte ptr [eax]
.text:08048616                 mov     eax, [ebp+var_4]
.text:08048619                 add     eax, 804C048h   ;  Key-String 的地址
.text:0804861E                 movzx   eax, byte ptr [eax]
.text:08048621                 cmp     dl, al
.text:08048623                 jnz     short loc_8048629 
.text:08048625                 add     [ebp+var_8], 1
.text:08048629
.text:08048629 loc_8048629:                            ; CODE XREF: check_equals_MRXJKZYRKMKENFZB+2E↑j
.text:08048629                 add     [ebp+var_4], 1
.text:0804862D
.text:0804862D loc_804862D:                            ; CODE XREF: check_equals_MRXJKZYRKMKENFZB+14↑j
.text:0804862D                 mov     eax, [ebp+var_4]
.text:08048630                 cmp     eax, [ebp+arg_4]
.text:08048633                 jb      short loc_804860B  ;  这是一个for 循环的Buffer 内容校验逻辑
.text:08048635                 mov     eax, [ebp+var_8]
.text:08048638                 cmp     eax, [ebp+arg_4]
.text:0804863B                 setz    al
.text:0804863E                 movzx   eax, al
.text:08048641                 leave
.text:08048642                 retn
```

所以,我们需要Hook check_equals() 并模拟它的执行,这个题目和09 题不同之处在于,09 题我们可以通过一处指令Hook 来实现,但是10 题我们就不能这么做了,是因为`Call check_equals()` 的地址太多,用09 题的方式不方便,所以我们可以用Angr 的Hook Symbol 来实现对check_equals() 函数的Hook ,而不是想09 题那样只对指令进行Hook .代码如下:

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementCheckEquals(angr.SimProcedure):

    def run(self, check_data_address, check_data_length):  #  基本和09 题的逻辑一样,唯独不同的是我们可以获取check_equals() 的参数
      check_input_string = self.state.memory.load(
        check_data_address,
        check_data_length
      )

      check_against_string = 'MRXJKZYRKMKENFZB'

      return claripy.If(check_input_string == check_against_string, claripy.BVV(1, 32), claripy.BVV(0, 32))

  check_equals_symbol = 'check_equals_MRXJKZYRKMKENFZB' # :string
  project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())  #  Hook Symbol

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print(solution)
```

Angr函数使用总结:

> Hook 回调函数格式:
>
> > class ReplacementCheckEquals(angr.SimProcedure):
> >
> >   def run(self, Hook的函数参数列表):
> >
> > ​    ….
> >
> > ​    return 函数返回值   # 如果是void函数可以省略
>
> project.hook_symbol(要Hook的函数名,SimProcedure类实例)



## 11_angr_sim_scanf

汇编代码:

```assembly
.text:0804862A                 push    14h             ; n
.text:0804862C                 push    0               ; c
.text:0804862E                 lea     eax, [ebp+key_string]
.text:08048631                 push    eax             ; s
.text:08048632                 call    _memset
.text:08048637                 add     esp, 10h
.text:0804863A                 lea     eax, [ebp+key_string]
.text:0804863D                 mov     dword ptr [eax], 444E4848h
.text:08048643                 mov     dword ptr [eax+4], 50484156h  ;  初始化Key-String
.text:0804864A                 mov     [ebp+index], 0
.text:08048651                 jmp     short loc_8048680
.text:08048653 ; ---------------------------------------------------------------------------
.text:08048653
.text:08048653 loc_8048653:                            ; CODE XREF: main+8F↓j
.text:08048653                 lea     edx, [ebp+key_string]
.text:08048656                 mov     eax, [ebp+index]
.text:08048659                 add     eax, edx
.text:0804865B                 movzx   eax, byte ptr [eax]
.text:0804865E                 movsx   eax, al
.text:08048661                 sub     esp, 8
.text:08048664                 push    [ebp+index]
.text:08048667                 push    eax
.text:08048668                 call    complex_function  ;  complex_function() 对key-string 进行计算
.text:0804866D                 add     esp, 10h
.text:08048670                 mov     ecx, eax
.text:08048672                 lea     edx, [ebp+key_string]
.text:08048675                 mov     eax, [ebp+index]
.text:08048678                 add     eax, edx
.text:0804867A                 mov     [eax], cl
.text:0804867C                 add     [ebp+index], 1
.text:08048680
.text:08048680 loc_8048680:                            ; CODE XREF: main+5C↑j
.text:08048680                 cmp     [ebp+index], 7
.text:08048684                 jle     short loc_8048653 ; for (index =0 index <=7 ; ++ index )
```

程序第一步先对Key-String 进行运算,该题的难点在于main() 里面多个scanf() .

```assembly
text:08048689                 push    offset aEnterThePasswo ; "Enter the password: "
.text:0804868E                 call    _printf
.text:08048693                 add     esp, 10h
.text:08048696                 cmp     [ebp+var_24], 0DEADBEEFh
.text:0804869D                 jnz     loc_804C196
.text:080486A3                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486AA                 jnz     loc_804A423
.text:080486B0                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486B7                 jz      loc_8049570
.text:080486BD                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486C4                 jnz     loc_8048E1D
.text:080486CA                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486D1                 jz      loc_8048A7A
.text:080486D7                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486DE                 jz      loc_80488AF
.text:080486E4                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486EB                 jnz     loc_80487D0
.text:080486F1                 cmp     [ebp+var_24], 0DEADBEEFh
.text:080486F8                 jnz     short loc_8048765
.text:080486FA                 sub     esp, 4
.text:080486FD                 push    offset buffer1
.text:08048702                 push    offset buffer0
.text:08048707                 push    offset aUU      ; "%u %u"
.text:0804870C                 call    ___isoc99_scanf
.text:08048711                 add     esp, 10h
.text:08048714                 cmp     [ebp+var_2C], 0
.text:08048718                 jz      short loc_8048758
.text:0804871A                 sub     esp, 4
.text:0804871D                 push    4               ; n
.text:0804871F                 lea     eax, [ebp+key_string]
.text:08048722                 push    eax             ; s2
.text:08048723                 push    offset buffer0  ; s1
.text:08048728                 call    _strncmp
.text:0804872D                 add     esp, 10h
.text:08048730                 test    eax, eax
.text:08048732                 jnz     short loc_8048758
.text:08048734                 sub     esp, 4
.text:08048737                 push    4               ; n
.text:08048739                 lea     eax, [ebp+key_string]
.text:0804873C                 add     eax, 4
.text:0804873F                 push    eax             ; s2
.text:08048740                 push    offset buffer1  ; s1
.text:08048745                 call    _strncmp
.text:0804874A                 add     esp, 10h
.text:0804874D                 test    eax, eax
.text:0804874F                 jnz     short loc_8048758
.text:08048751                 mov     eax, 1
.text:08048756                 jmp     short loc_804875D
.text:08048758 ; ---------------------------------------------------------------------------
.text:08048758
.text:08048758 loc_8048758:                            ; CODE XREF: main+123↑j
.text:08048758                                         ; main+13D↑j ...
.text:08048758                 mov     eax, 0
.text:0804875D
.text:0804875D loc_804875D:                            ; CODE XREF: main+161↑j
.text:0804875D                 mov     [ebp+var_2C], eax
.text:08048760                 jmp     loc_804FC81
.text:08048765 ; ---------------------------------------------------------------------------
.text:08048765
.text:08048765 loc_8048765:                            ; CODE XREF: main+103↑j
.text:08048765                 sub     esp, 4
.text:08048768                 push    offset buffer1
.text:0804876D                 push    offset buffer0
.text:08048772                 push    offset aUU      ; "%u %u"
.text:08048777                 call    ___isoc99_scanf
.text:0804877C                 add     esp, 10h
.text:0804877F                 cmp     [ebp+var_2C], 0
.text:08048783                 jz      short loc_80487C3
.text:08048785                 sub     esp, 4
.text:08048788                 push    4               ; n
.text:0804878A                 lea     eax, [ebp+key_string]
.text:0804878D                 push    eax             ; s2
.text:0804878E                 push    offset buffer0  ; s1
.text:08048793                 call    _strncmp
.text:08048798                 add     esp, 10h
.text:0804879B                 test    eax, eax
.text:0804879D                 jnz     short loc_80487C3
.text:0804879F                 sub     esp, 4
.text:080487A2                 push    4               ; n
.text:080487A4                 lea     eax, [ebp+key_string]
.text:080487A7                 add     eax, 4
.text:080487AA                 push    eax             ; s2
.text:080487AB                 push    offset buffer1  ; s1
.text:080487B0                 call    _strncmp
.text:080487B5                 add     esp, 10h
.text:080487B8                 test    eax, eax
.text:080487BA                 jnz     short loc_80487C3
.text:080487BC                 mov     eax, 1
.text:080487C1                 jmp     short loc_80487C8
```

我们的关注点在于scanf() ,这里标明了用户有两个输入,分别为4 字节.然后我们就需要Hook scanf() 来对buffer 进行符号构造,代码如下:

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):

    def run(self, format_string, scanf0_address, scanf1_address ):
      scanf0 = claripy.BVS('scanf0', 4 * 8)
      scanf1 = claripy.BVS('scanf1', 4 * 8)

      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

      self.state.globals['solution0'] = scanf0
      self.state.globals['solution1'] = scanf1

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    stored_solutions0 = solution_state.globals['solution0']
    stored_solutions1 = solution_state.globals['solution1']
    solution0 = solution_state.se.eval(stored_solutions0)
    solution1 = solution_state.se.eval(stored_solutions1)

    print(solution0,solution1)
```



## 12_angr_veritesting

汇编代码:

```assembly
.text:080485ED                 push    21h             ; n
.text:080485EF                 push    0               ; c
.text:080485F1                 lea     eax, [ebp+input_buffer]
.text:080485F4                 push    eax             ; s
.text:080485F5                 call    _memset
.text:080485FA                 add     esp, 10h
.text:080485FD                 sub     esp, 0Ch
.text:08048600                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048605                 call    _printf
.text:0804860A                 add     esp, 10h
.text:0804860D                 sub     esp, 8
.text:08048610                 lea     eax, [ebp+input_buffer]
.text:08048613                 push    eax
.text:08048614                 push    offset a32s     ; "%32s"
.text:08048619                 call    ___isoc99_scanf  ;  用户输入一个32字节的Buffer
.text:0804861E                 add     esp, 10h
.text:08048621                 mov     [ebp+var_3C], 0
.text:08048628                 mov     [ebp+var_34], 0
.text:0804862F                 mov     [ebp+index], 0
.text:08048636                 jmp     short loc_8048666
.text:08048638 ; ---------------------------------------------------------------------------
.text:08048638
.text:08048638 loc_8048638:                            ; CODE XREF: main+A5↓j
.text:08048638                 lea     edx, [ebp+input_buffer]
.text:0804863B                 mov     eax, [ebp+index]
.text:0804863E                 add     eax, edx
.text:08048640                 movzx   eax, byte ptr [eax]
.text:08048643                 movsx   ebx, al
.text:08048646                 mov     eax, [ebp+index]
.text:08048649                 add     eax, 5Bh
.text:0804864C                 sub     esp, 8
.text:0804864F                 push    eax
.text:08048650                 push    4Fh
.text:08048652                 call    complex_function  ;  对用户输入进行计算
.text:08048657                 add     esp, 10h
.text:0804865A                 cmp     ebx, eax
.text:0804865C                 jnz     short loc_8048662
.text:0804865E                 add     [ebp+var_3C], 1
.text:08048662
.text:08048662 loc_8048662:                            ; CODE XREF: main+97↑j
.text:08048662                 add     [ebp+index], 1
.text:08048666
.text:08048666 loc_8048666:                            ; CODE XREF: main+71↑j
.text:08048666                 cmp     [ebp+index], 1Fh
.text:0804866A                 jle     short loc_8048638
.text:0804866C                 cmp     [ebp+var_3C], ' '
.text:08048670                 jnz     short loc_804868C
.text:08048672                 movzx   eax, byte ptr [ebp+var_C]
.text:08048676                 test    al, al
.text:08048678                 jnz     short loc_804868C  ;  对输入进行计算
.text:0804867A                 sub     esp, 0Ch
.text:0804867D                 push    offset aGoodJob ; "Good Job."
.text:08048682                 call    _puts
.text:08048687                 add     esp, 10h
.text:0804868A                 jmp     short loc_804869C
.text:0804868C ; ---------------------------------------------------------------------------
.text:0804868C
.text:0804868C loc_804868C:                            ; CODE XREF: main+AB↑j
.text:0804868C                                         ; main+B3↑j
.text:0804868C                 sub     esp, 0Ch
.text:0804868F                 push    offset s        ; "Try again."
.text:08048694                 call    _puts
.text:08048699                 add     esp, 10h
```

这个示例和01 题是一样的,唯独不同的一点是这个循环比之前的要大,导致直接用01 题的解题方法不能直接计算出结果,因为循环过大导致路径爆炸,所以在执行的时候会消耗很多资源.

幸运的是,project.factory.simgr() 函数提供veritesting 参数来指定是否要自动合并路径,避免路径爆炸的问题.具体细节参考论文:https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf

```python
import angr
import sys


project = angr.Project(sys.argv[1])
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state,veritesting = True)

def is_successful(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  return 'Good Job.' in str(stdout_output)  # :boolean

def should_abort(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  return 'Try again.' in str(stdout_output)  # :boolean

simulation.explore(find = is_successful,avoid = should_abort)

if simulation.found :
  solution_state = simulation.found[0]
  print(solution_state.posix.dumps(sys.stdin.fileno()))

```

Angr函数使用总结:

> project.factory.simgr(初始化状态,veritesting = True)  =>  veritesting 默认为False



##13_angr_static_binary 

汇编代码:

```assembly
.text:08048953                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048958                 call    printf
.text:0804895D                 add     esp, 10h
.text:08048960                 sub     esp, 8
.text:08048963                 lea     eax, [ebp+s1]
.text:08048966                 push    eax
.text:08048967                 push    offset a8s      ; "%8s"
.text:0804896C                 call    __isoc99_scanf  ;  用户输入
.text:08048971                 add     esp, 10h
.text:08048974                 mov     [ebp+var_38], 0
.text:0804897B                 jmp     short loc_80489AA
.text:0804897D ; ---------------------------------------------------------------------------
.text:0804897D
.text:0804897D loc_804897D:                            ; CODE XREF: main+B0↓j
.text:0804897D                 lea     edx, [ebp+s1]
.text:08048980                 mov     eax, [ebp+var_38]
.text:08048983                 add     eax, edx
.text:08048985                 movzx   eax, byte ptr [eax]
.text:08048988                 movsx   eax, al
.text:0804898B                 sub     esp, 8
.text:0804898E                 push    [ebp+var_38]
.text:08048991                 push    eax
.text:08048992                 call    complex_function
.text:08048997                 add     esp, 10h
.text:0804899A                 mov     ecx, eax
.text:0804899C                 lea     edx, [ebp+s1]
.text:0804899F                 mov     eax, [ebp+var_38]
.text:080489A2                 add     eax, edx
.text:080489A4                 mov     [eax], cl
.text:080489A6                 add     [ebp+var_38], 1
.text:080489AA
.text:080489AA loc_80489AA:                            ; CODE XREF: main+7D↑j
.text:080489AA                 cmp     [ebp+var_38], 7
.text:080489AE                 jle     short loc_804897D  ;  使用for 循环不断调用complex_function() 对数据进行计算
.text:080489B0                 sub     esp, 8
.text:080489B3                 lea     eax, [ebp+s2]
.text:080489B6                 push    eax             ; s2
.text:080489B7                 lea     eax, [ebp+s1]
.text:080489BA                 push    eax             ; s1
.text:080489BB                 call    _strcmp
.text:080489C0                 add     esp, 10h
.text:080489C3                 test    eax, eax
.text:080489C5                 jz      short loc_80489D9
.text:080489C7                 sub     esp, 0Ch
.text:080489CA                 push    offset aTryAgain ; "Try again."
.text:080489CF                 call    puts
.text:080489D4                 add     esp, 10h
.text:080489D7                 jmp     short loc_80489E9
.text:080489D9 ; ---------------------------------------------------------------------------
.text:080489D9
.text:080489D9 loc_80489D9:                            ; CODE XREF: main+C7↑j
.text:080489D9                 sub     esp, 0Ch
.text:080489DC                 push    offset aGoodJob ; "Good Job."
.text:080489E1                 call    puts
.text:080489E6                 add     esp, 10h
.text:080489E9
```

这个示例的逻辑和01 题是一样的,主要不同的地方是在于这个程序是静态链接编译的,所以程序中包含了一些libc 的函数实现,但是这里可能会存在两个问题:1.这些函数里面隐藏一些出题人的坑;2.这些函数里面的实现可能会依赖其他的系统函数或者实现方式不相同.所以12 题主要是让我们通过Hook 的方式重定向函数中被调用的libc 的函数

首先,Linux 下启动main() 函数需要通过`__libc_start_main` 对程序进行初始化,然后再跳转到main() 函数;其次,在main() 函数里面调用了`printf` ,`scanf` ,`puts` ,所以我们需要通过Hook 来重定向它们.

幸运的是,我们不需要重新实现这些函数的实现,Angr 代码库里面已经帮我们实现了一部分libc 的函数库,所以我们只需要倒入它们即可.

```python
import angr
import sys


project = angr.Project(sys.argv[1])
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state,veritesting = True)

project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

def is_successful(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  return 'Good Job.' in str(stdout_output)  # :boolean

def should_abort(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  return 'Try again.' in str(stdout_output)  # :boolean

simulation.explore(find = is_successful,avoid = should_abort)

if simulation.found :
  solution_state = simulation.found[0]
  print(solution_state.posix.dumps(sys.stdin.fileno()))

```

Angr函数使用总结:

> angr.SIM_PROCEDURES[ 系统库名 ] [ 系统函数名 ] ()  =>  获取Angr 内部实现的系统函数



## 14_angr_shared_library

编译14_angr_shared_library 存在一个小坑,就是在执行命令`Python generate.py 1234 14_angr_shared_library` 时会报错,内容如下:

```shell
root@sec:~/angr_ctf/14_angr_shared_library# python generate.py 1234 14_angr_shared_library
gcc: error: 14_angr_shared_library: No such file or directory
```

这是因为generate.py 里面有一个Bug ,在最后的一个gcc 编译命令因为-L 参数缺少了指定当前目录,导致在寻找lib14_angr_shared_library.so 的时候找到了系统库目录,所以gcc 抛出了这个找不到`14_angr_shared_library: No such file or directory` 的问题,代码修改如下:

```python
  with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
    temp.write(c_code)
    temp.seek(0)
-    os.system('gcc -m32 -I . -L ' + '/'.join(output_file.split('/')[0:-1]) + ' -o ' + output_file + ' ' + temp.name + ' -l' + output_file.split('/')[-1])
+    os.system('gcc -m32 -I . -L . ' + '/'.join(output_file.split('/')[0:-1]) + ' -o ' + output_file + ' ' + temp.name + ' -l' + output_file.split('/')[-1])
```

程序汇编代码如下:

```assembly
.text:080486A2                 push    10h             ; n
.text:080486A4                 push    0               ; c
.text:080486A6                 lea     eax, [ebp+s]
.text:080486A9                 push    eax             ; s
.text:080486AA                 call    _memset
.text:080486AF                 add     esp, 10h
.text:080486B2                 sub     esp, 0Ch
.text:080486B5                 push    offset format   ; "Enter the password: "
.text:080486BA                 call    _printf
.text:080486BF                 add     esp, 10h
.text:080486C2                 sub     esp, 8
.text:080486C5                 lea     eax, [ebp+s]
.text:080486C8                 push    eax
.text:080486C9                 push    offset a8s      ; "%8s"
.text:080486CE                 call    ___isoc99_scanf ;  用户输入
.text:080486D3                 add     esp, 10h
.text:080486D6                 sub     esp, 8
.text:080486D9                 push    8
.text:080486DB                 lea     eax, [ebp+s]
.text:080486DE                 push    eax
.text:080486DF                 call    _validate       ;  调用验证
.text:080486E4                 add     esp, 10h
.text:080486E7                 test    eax, eax
.text:080486E9                 jz      short loc_80486FD
.text:080486EB                 sub     esp, 0Ch
.text:080486EE                 push    offset s        ; "Good Job."
.text:080486F3                 call    _puts
```

_validate() 函数是在另一个so 库中存在的,我们继续分析完当前程序的代码

```assembly
.plt:08048550 _validate       proc near               ; CODE XREF: main+64↓p
.plt:08048550                 jmp     ds:off_804A020
.plt:08048550 _validate       endp

.got.plt:0804A020 off_804A020     dd offset validate 

extern:0804A04C                 extrn validate:near 
```

我们来分析一下lib14_angr_shared_library.so 的代码:

```assembly
.text:000006D7                 public validate
.text:000006D7 validate        proc near               ; DATA XREF: LOAD:00000250↑o
.text:000006D7
.text:000006D7 s2              = byte ptr -24h
.text:000006D7 var_10          = dword ptr -10h
.text:000006D7 var_C           = dword ptr -0Ch
.text:000006D7 s1              = dword ptr  8
.text:000006D7 arg_4           = dword ptr  0Ch
.text:000006D7
.text:000006D7 ; __unwind {
.text:000006D7                 push    ebp
.text:000006D8                 mov     ebp, esp
.text:000006DA                 push    esi
.text:000006DB                 push    ebx
.text:000006DC                 sub     esp, 20h
.text:000006DF                 call    __x86_get_pc_thunk_bx
.text:000006E4                 add     ebx, 191Ch
.text:000006EA                 cmp     [ebp+arg_4], 7
.text:000006EE                 jg      short loc_6FA
.text:000006F0                 mov     eax, 0
.text:000006F5                 jmp     loc_77D
.text:000006FA ; ---------------------------------------------------------------------------
.text:000006FA

;  .....
```

14 题主要是把程序逻辑分离在一个执行程序和动态链接库,我们直接对动态链接库中的_validate 函数进行符号执行,解决的solver.py 如下:

```python
def main(argv):
  path_to_binary = sys.argv[1]  #  注意我们是要load so 库而不是执行程序

  base = 0x400000  #  base 基址是随意定的,可以随意修改
  project = angr.Project(path_to_binary, load_options={
    'main_opts' : {
      'custom_base_addr' : base
    }
  })

  buffer_pointer = claripy.BVV(0x3000000, 32)  #  创建一个buffer 指针值
  validate_function_address = base + 0x6D7
  initial_state = project.factory.call_state(validate_function_address, buffer_pointer,claripy.BVV(8, 32))  #  调用validate_function,因为函数声明validata_function(buffer_point,buffer_length) ,所以我们构造出调用validata_function(0x3000000,0x8) .

  password = claripy.BVS('password', 8 * 8)  #  创建一个求解对象,大小为8 字节
  initial_state.memory.store(buffer_pointer, password)  #  保存到0x30000000

  simulation = project.factory.simgr(initial_state)

  simulation.explore(find = base + 0x783)  #  执行到validate 函数的RETN 指令

  if simulation.found:
    solution_state = simulation.found[0]

    solution_state.add_constraints(solution_state.regs.eax != 0)  #  记得,我们要求validate 函数的返回值为1 的时候就是有解的,那么我们就需要在求解的时候添加上这么一个求解约束条件EAX 不能为False .
    solution = solution_state.se.eval(password)
    print(solution)
```



## 15_angr_arbitrary_read

汇编代码:

```assembly
.text:080484C9 main            proc near               ; DATA XREF: _start+17↑o
.text:080484C9
.text:080484C9 input_buffer    = byte ptr -1Ch         ;  注意这个buffer 的大小是16 字节
.text:080484C9 try_again_string_point= dword ptr -0Ch
.text:080484C9 var_4           = dword ptr -4
.text:080484C9 argc            = dword ptr  8
.text:080484C9 argv            = dword ptr  0Ch
.text:080484C9 envp            = dword ptr  10h
.text:080484C9
.text:080484C9 ; __unwind {
.text:080484C9                 lea     ecx, [esp+4]
.text:080484CD                 and     esp, 0FFFFFFF0h
.text:080484D0                 push    dword ptr [ecx-4]
.text:080484D3                 push    ebp
.text:080484D4                 mov     ebp, esp
.text:080484D6                 push    ecx
.text:080484D7                 sub     esp, 24h
.text:080484DA                 mov     eax, try_again 
.text:080484DF                 mov     [ebp+try_again_string_point], eax  ;  把字符串try_again 的指针保存的局部变量try_again_string_point
.text:080484E2                 sub     esp, 0Ch
.text:080484E5                 push    offset aEnterThePasswo ; "Enter the password: "
.text:080484EA                 call    _printf
.text:080484EF                 add     esp, 10h
.text:080484F2                 sub     esp, 4
.text:080484F5                 lea     eax, [ebp+input_buffer]
.text:080484F8                 push    eax
.text:080484F9                 push    offset check_key
.text:080484FE                 push    offset aU20s    ; "%u %20s"
.text:08048503                 call    ___isoc99_scanf  ;  用户input 两个输入:check_key 和20 字节的input_buffer
.text:08048508                 add     esp, 10h
.text:0804850B                 mov     eax, ds:check_key
.text:08048510                 cmp     eax, 228BF7Eh
.text:08048515                 jz      short loc_8048531
.text:08048517                 cmp     eax, 3AD516Ah
.text:0804851C                 jnz     short loc_8048542  ;  这里根据check_key 的输入来进行跳转到不同的puts 中
.text:0804851E                 mov     eax, try_again
.text:08048523                 sub     esp, 0Ch
.text:08048526                 push    eax             ; s
.text:08048527                 call    _puts
.text:0804852C                 add     esp, 10h
.text:0804852F                 jmp     short loc_8048553
.text:08048531 ; ---------------------------------------------------------------------------
.text:08048531
.text:08048531 loc_8048531:                            ; CODE XREF: main+4C↑j
.text:08048531                 mov     eax, [ebp+try_again_string_point]  ;  我们知道,input_buffer 的大小为16 字节,但是scanf() 输入时是20 字节,所以可以导致try_again_string_point 可以被覆盖,于是需要满足条件input_buffer = 0x228BF7E ,我们就可以控制puts 的输出了.
.text:08048534                 sub     esp, 0Ch
.text:08048537                 push    eax             ; s
.text:08048538                 call    _puts
.text:0804853D                 add     esp, 10h
.text:08048540                 jmp     short loc_8048553
.text:08048542 ; ---------------------------------------------------------------------------
.text:08048542
.text:08048542 loc_8048542:                            ; CODE XREF: main+53↑j
.text:08048542                 mov     eax, try_again
.text:08048547                 sub     esp, 0Ch
.text:0804854A                 push    eax             ; s
.text:0804854B                 call    _puts
.text:08048550                 add     esp, 10h
.text:08048553
.text:08048553 loc_8048553:                            ; CODE XREF: main+66↑j
.text:08048553                                         ; main+77↑j
.text:08048553                 nop
```

从代码主要逻辑可以知道,我们关键的一点在于检查puts() 函数是否接受到了可控的输入.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):  #  实现Scanf Hook 函数

    def run(self, format_string, check_key_address,input_buffer_address):
      scanf0 = claripy.BVS('scanf0', 4 * 8)   # check_key
      scanf1 = claripy.BVS('scanf1', 20 * 8)  # input_buffer

      for char in scanf1.chop(bits=8):
        self.state.add_constraints(char >= '0', char <= 'z')  #  对input_buffer 的输入约束

      self.state.memory.store(check_key_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(input_buffer_address, scanf1,endness=project.arch.memory_endness)  #  保存求解变量到指定的内存中

      self.state.globals['solution0'] = scanf0  #  保存这两个变量到state 中,后续求解需要用到
      self.state.globals['solution1'] = scanf1

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())  #  Hook scanf 函数

  def check_puts(state):
    puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)  #  获取puts() 函数的参数

    if state.se.symbolic(puts_parameter):  #  检查这个参数是否为符号化对象
      good_job_string_address = 0x4D525854B

      copied_state = state.copy()  #  复制执行状态上下文进行约束求解,不影响原理的执行上下文

      copied_state.add_constraints(puts_parameter == good_job_string_address)  #  puts 的参数地址是否可以被指定为0x4D525854B ,如果可以的话,那就证明这个值是可控的

      if copied_state.satisfiable():  #  判断添加了上面这个约束是否有解
        state.add_constraints(puts_parameter == good_job_string_address)  #  如果有解的话就保存到我们执行的那个状态对象
        return True 
      else:
        return False
    else:
      return False

  simulation = project.factory.simgr(initial_state)
    
  def is_successful(state):
    puts_address = 0x8048370  #  当程序执行到puts() 函数时,我们就认为路径探索到了这里,然后再去通过check_puts() 判断这里是否存在漏洞,告诉Angr这是不是我们需要找的那条执行路径
    
    if state.addr == puts_address:
      return check_puts(state)
    else:
      return False

  simulation.explore(find=is_successful)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.se.eval(solution_state.globals['solution0'])
    solution1 = solution_state.se.eval(solution_state.globals['solution1'],cast_to=bytes)  #  输出字符串序列化的内容

    print(solution0,solution1)
```

Angr函数使用总结:

> state.copy()  =>  复制状态上下文
>
> state.satisfiable()  =>  判断当前的所有约束是否有解
>
> solution_state.se.eval(求解变量,cast_to=bytes)  =>  序列化变量内容为字符串



## 16_angr_arbitrary_write

汇编代码:

```assembly
.text:08048569 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:08048569                 public main
.text:08048569 main            proc near               ; DATA XREF: _start+17↑o
.text:08048569
.text:08048569 input_buffer    = byte ptr -1Ch
.text:08048569 target_buffer   = dword ptr -0Ch
.text:08048569 var_4           = dword ptr -4
.text:08048569 argc            = dword ptr  8
.text:08048569 argv            = dword ptr  0Ch
.text:08048569 envp            = dword ptr  10h
.text:08048569
.text:08048569 ; __unwind {
.text:08048569                 lea     ecx, [esp+4]
.text:0804856D                 and     esp, 0FFFFFFF0h
.text:08048570                 push    dword ptr [ecx-4]
.text:08048573                 push    ebp
.text:08048574                 mov     ebp, esp
.text:08048576                 push    ecx
.text:08048577                 sub     esp, 24h
.text:0804857A                 mov     [ebp+target_buffer], offset unimportant_buffer
.text:08048581                 sub     esp, 4
.text:08048584                 push    10h             ; n
.text:08048586                 push    0               ; c
.text:08048588                 lea     eax, [ebp+input_buffer]
.text:0804858B                 push    eax             ; s
.text:0804858C                 call    _memset         ;  清空input_buffer 的内容
.text:08048591                 add     esp, 10h
.text:08048594                 sub     esp, 4
.text:08048597                 push    0Ch             ; n
.text:08048599                 push    offset src      ; "PASSWORD"
.text:0804859E                 push    offset password_buffer ; dest
.text:080485A3                 call    _strncpy        ;  复制PASSWORD 到全局内存password_buffer
.text:080485A8                 add     esp, 10h
.text:080485AB                 sub     esp, 0Ch
.text:080485AE                 push    offset aEnterThePasswo ; "Enter the password: "
.text:080485B3                 call    _printf
.text:080485B8                 add     esp, 10h
.text:080485BB                 sub     esp, 4
.text:080485BE                 lea     eax, [ebp+input_buffer]
.text:080485C1                 push    eax
.text:080485C2                 push    offset check_key
.text:080485C7                 push    offset aU20s    ; "%u %20s"
.text:080485CC                 call    ___isoc99_scanf  ;  scanf("%u %20s",check_key,input_buffer) .注意input_buffer 的大小是20 字节,栈上的input_buffer 默认的大小是16 字节,最后4 字节可以覆盖target_buffer .
.text:080485D1                 add     esp, 10h
.text:080485D4                 mov     eax, ds:check_key
.text:080485D9                 cmp     eax, 1A25D71h
.text:080485DE                 jz      short loc_80485E9
.text:080485E0                 cmp     eax, 1CB7D43h
.text:080485E5                 jz      short loc_8048601  ;  根据check_key 的输入来跳转到不同的_strncpy
.text:080485E7                 jmp     short loc_8048618
.text:080485E9 ; ---------------------------------------------------------------------------
.text:080485E9
.text:080485E9 loc_80485E9:                            ; CODE XREF: main+75↑j
.text:080485E9                 sub     esp, 4
.text:080485EC                 push    10h             ; n
.text:080485EE                 lea     eax, [ebp+input_buffer]
.text:080485F1                 push    eax             ; src
.text:080485F2                 push    offset unimportant_buffer ; dest
.text:080485F7                 call    _strncpy
.text:080485FC                 add     esp, 10h
.text:080485FF                 jmp     short loc_804862E
.text:08048601 ; ---------------------------------------------------------------------------
.text:08048601
.text:08048601 loc_8048601:                            ; CODE XREF: main+7C↑j
.text:08048601                 mov     eax, [ebp+target_buffer]  ;  注意这个是MOV 指令,意思是获取EBP + target_buffer 这个地址的内容保存到EAX 中
.text:08048604                 sub     esp, 4
.text:08048607                 push    10h             ; n
.text:08048609                 lea     edx, [ebp+input_buffer]  ;  注意这个是LEA 指令,意思是计算出EBP + input_buffer 的地址保存到EBX 中
.text:0804860C                 push    edx             ; src
.text:0804860D                 push    eax             ; dest
.text:0804860E                 call    _strncpy  ;  漏洞点在这里,strncpy(*target_buffer,input_buffer) ,也就是说input_buffer 最后四字节可以控制对任意地址的_strncpy() .总结起来就是strncpy(input_buffer[ -4 : ],input_buffer,0x10) .
.text:08048613                 add     esp, 10h
.text:08048616                 jmp     short loc_804862E
.text:08048618 ; ---------------------------------------------------------------------------
.text:08048618
.text:08048618 loc_8048618:                            ; CODE XREF: main+7E↑j
.text:08048618                 sub     esp, 4
.text:0804861B                 push    10h             ; n
.text:0804861D                 lea     eax, [ebp+input_buffer]
.text:08048620                 push    eax             ; src
.text:08048621                 push    offset unimportant_buffer ; dest
.text:08048626                 call    _strncpy
.text:0804862B                 add     esp, 10h
.text:0804862E
.text:0804862E loc_804862E:                            ; CODE XREF: main+96↑j
.text:0804862E                                         ; main+AD↑j
.text:0804862E                 nop
.text:0804862F                 sub     esp, 4
.text:08048632                 push    8               ; n
.text:08048634                 push    offset key_string       ; "KZYRKMKE"
.text:08048639                 push    offset password_buffer ; s1
.text:0804863E                 call    _strncmp        ;  我们知道了上面有一个任意地址写之后,我们就需要改写key_string 或者password_buffer 一致,让_strncmp() 返回0 ,跳转到puts("Good Job")
.text:08048643                 add     esp, 10h
.text:08048646                 test    eax, eax
.text:08048648                 jz      short loc_804865C
.text:0804864A                 sub     esp, 0Ch
.text:0804864D                 push    offset s        ; "Try again."
.text:08048652                 call    _puts
.text:08048657                 add     esp, 10h
.text:0804865A                 jmp     short loc_804866C
.text:0804865C ; ---------------------------------------------------------------------------
.text:0804865C
.text:0804865C loc_804865C:                            ; CODE XREF: main+DF↑j
.text:0804865C                 sub     esp, 0Ch
.text:0804865F                 push    offset aGoodJob ; "Good Job."
.text:08048664                 call    _puts
.text:08048669                 add     esp, 10h
```

汇编代码中的注释已经把整体的逻辑和漏洞原理讲解得差不多了,那么我们就需要做两个判断:一是判断input_buffer 后四字节是否可控;二是前八字节是否可以控制内容为"KZYRKMKE" 或者"PASSWORD" .那么得到的solver.py 代码如下:

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):

    def run(self, format_string, check_key ,input_buffer):
      scanf0 = claripy.BVS('scanf0', 4 * 8)
      scanf1 = claripy.BVS('scanf1', 20 * 8)

      for char in scanf1.chop(bits=8):
        self.state.add_constraints(char >= '0', char <= 'z')

      self.state.memory.store(check_key, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(input_buffer, scanf1, endness=project.arch.memory_endness)

      self.state.globals['solution0'] = scanf0
      self.state.globals['solution1'] = scanf1

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  def check_strncpy(state):
    strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)  #  获取strncpy() 的参数,strncpy_dest ..
    strncpy_src  = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
    strncpy_len  = state.memory.load(state.regs.esp + 12, 4, endness=project.arch.memory_endness)
    src_contents = state.memory.load(strncpy_src, strncpy_len)  #  因为参数中只保存了地址,我们需要根据这个地址去获取内容

    if state.se.symbolic(strncpy_dest) and state.se.symbolic(src_contents) :  #  判断dest 和src 的内容是不是符号化对象
      if state.satisfiable(extra_constraints=(src_contents[ -1 : -64 ] == 'KZYRKMKE' ,strncpy_dest == 0x4D52584C)):  #  尝试求解,其中strncpy_dest == 0x4D52584C 的意思是判断dest 是否可控为password 的地址;src_contents[ -1 : -64 ] == 'KZYRKMKE' 是判断input_buffer 的内容是否可控为'KZYRKMKE' ,因为这块内存是倒序,所以需要通过[ -1 : -64 ] 倒转(contentes 的内容是比特,获取8 字节的大小为:8*8 = 64),然后判断该值是否为字符串'KZYRKMKE'
        state.add_constraints(src_contents[ -1 : -64 ] == 'KZYRKMKE',strncpy_dest == 0x4D52584C)
        return True
      else:
        return False
    else:
      return False

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    strncpy_address = 0x8048410

    if state.addr == strncpy_address:
      return check_strncpy(state)
    else:
      return False

  simulation.explore(find=is_successful)

  if simulation.found:
    solution_state = simulation.found[0]
    solution0 = solution_state.se.eval(solution_state.globals['solution0'])
    solution1 = solution_state.se.eval(solution_state.globals['solution1'],cast_to=bytes)

    print(solution0,solution1)
```

Angr函数使用总结:

> state.satisfiable(extra_constraints=(条件1,条件2))  =>  合并多个条件计算是否存在满足约束的解(注意两个或多个条件之间是And 合并判断,不是Or )



## 17_angr_arbitrary_jump

汇编代码:

```assembly
.text:4D525886 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:4D525886                 public main
.text:4D525886 main            proc near               ; DATA XREF: _start+17↑o
.text:4D525886
.text:4D525886 var_C           = dword ptr -0Ch
.text:4D525886 var_4           = dword ptr -4
.text:4D525886 argc            = dword ptr  8
.text:4D525886 argv            = dword ptr  0Ch
.text:4D525886 envp            = dword ptr  10h
.text:4D525886
.text:4D525886 ; __unwind {
.text:4D525886                 lea     ecx, [esp+4]
.text:4D52588A                 and     esp, 0FFFFFFF0h
.text:4D52588D                 push    dword ptr [ecx-4]
.text:4D525890                 push    ebp
.text:4D525891                 mov     ebp, esp
.text:4D525893                 push    ecx
.text:4D525894                 sub     esp, 14h
.text:4D525897                 mov     [ebp+var_C], 0
.text:4D52589E                 sub     esp, 0Ch
.text:4D5258A1                 push    offset aEnterThePasswo ; "Enter the password: "
.text:4D5258A6                 call    _printf
.text:4D5258AB                 add     esp, 10h
.text:4D5258AE                 call    read_input  ;  小细节,注意read_input 是stdcall 的调用方法
.text:4D5258B3                 sub     esp, 0Ch
.text:4D5258B6                 push    offset aTryAgain ; "Try again."
.text:4D5258BB                 call    _puts
.text:4D5258C0                 add     esp, 10h
.text:4D5258C3                 mov     eax, 0
.text:4D5258C8                 mov     ecx, [ebp+var_4]
.text:4D5258CB                 leave
.text:4D5258CC                 lea     esp, [ecx-4]
.text:4D5258CF                 retn
```

main() 函数的逻辑很简单,printf() 输出`Enter the password: ` 然后调用read_input() 函数.继续阅读read_input() 函数的代码:

```assembly
.text:4D525869 read_input      proc near               ; CODE XREF: main+28↓p
.text:4D525869
.text:4D525869 input_buffer    = byte ptr -2Bh   ;  input_buffer 大小为0x2B
.text:4D525869
.text:4D525869 ; __unwind {
.text:4D525869                 push    ebp
.text:4D52586A                 mov     ebp, esp
.text:4D52586C                 sub     esp, 38h  ;  栈空间在这里分配
.text:4D52586F                 sub     esp, 8
.text:4D525872                 lea     eax, [ebp+input_buffer]  
.text:4D525875                 push    eax
.text:4D525876                 push    offset format   ; "%s"
.text:4D52587B                 call    ___isoc99_scanf ; 注意scanf() 的输入长度是没有限制的
.text:4D525880                 add     esp, 10h
.text:4D525883                 nop
.text:4D525884                 leave
.text:4D525885                 retn
```

看完read_input() 的代码之后,我们知道这是一个典型的栈溢出覆盖RET 地址的题目,最后要让RET 地址返回到这个位置

```assembly
.text:4D525849 print_good      proc near
.text:4D525849 ; __unwind {
.text:4D525849                 push    ebp
.text:4D52584A                 mov     ebp, esp
.text:4D52584C                 sub     esp, 8
.text:4D52584F                 sub     esp, 0Ch
.text:4D525852                 push    offset s        ; "Good Job."
.text:4D525857                 call    _puts
.text:4D52585C                 add     esp, 10h
.text:4D52585F                 sub     esp, 0Ch
.text:4D525862                 push    0               ; status
.text:4D525864                 call    _exit
```

Angr-CTF 解题脚本已经不能在当前的Angr 版本中正常执行了,修改的方法是Hook scanf() 在input_buffer 中构造Vector 进行求解.

```python
def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()

  simulation = project.factory.simgr(
    initial_state,
    save_unconstrained=True,
    stashes={
      'active' : [initial_state],
      'unconstrained' : [],
      'found' : [],
      'not_needed' : []
    }
  )

  class ReplacementScanf(angr.SimProcedure):

    def run(self, format_string, input_buffer_address):
      input_buffer = claripy.BVS('input_buffer', 64 * 8)  #  设置一个较大的input_buffer

      for char in input_buffer.chop(bits=8):
        self.state.add_constraints(char >= '0', char <= 'z')

      self.state.memory.store(input_buffer_address, input_buffer, endness=project.arch.memory_endness)

      self.state.globals['solution'] = input_buffer

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())  #  对scanf() 做Hook

  while (simulation.active or simulation.unconstrained) and (not simulation.found):  #  
    for unconstrained_state in simulation.unconstrained:
      def should_move(s):
        return s is unconstrained_state
      
      simulation.move('unconstrained', 'found', filter_func=should_move)  #  保存

    simulation.step()  #  步进执行

  if simulation.found:
    solution_state = simulation.found[0]

    solution_state.add_constraints(solution_state.regs.eip == 0x4D525849)  #  判断EIP 地址是否可控

    solution = solution_state.se.eval(solution_state.globals['solution'],cast_to = bytes)  #  生成Payload
    print(solution)
```

