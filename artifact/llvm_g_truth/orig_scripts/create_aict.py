import os
import json

def process_gtruth_file(file_path):
    def filter_args(args):
        return [arg for arg in args if not arg.isdigit() and '/' not in arg]

    with open(file_path, 'r') as file:
        lines = file.readlines()

    functions_dict = {}
    current_func = None

    for line in lines:
        if line.startswith("Function:"):
            parts = line.split()
            func_name = parts[1].split(".")[0]
            func_args = filter_args(parts[2:])
            functions_dict[func_name] = {"func_args": func_args, "icall_args": []}
            current_func = func_name
        elif line.startswith("Ind-call:") and current_func:
            ind_call_args = filter_args(line.split()[1:])
            functions_dict[current_func]["icall_args"].append(ind_call_args)

    return functions_dict

def main():
    elf_gtruth_file_dict = {
        "libavcodec.so.60@libavcodec60_7:6.1.1-4%2Bb4":"gtruth/libavcodec.so.60.31.102.bc.llvm",
        "libavfilter.so.9@libavfilter9_7:6.1.1-4%2Bb4":"gtruth/libavfilter.so.9.12.100.bc.llvm",
        "libcrypto.so.3@libssl3t64_3.2.2-1":"gtruth/libcrypto.so.3.bc.llvm",
        "libcurl.so.4@libcurl4t64_8.8.0-2":"gtruth/libcurl.so.4.8.0.bc.llvm",
        "libexpat.so.1@libexpat1_2.6.2-1":"gtruth/libexpat.so.1.9.2.bc.llvm",
        "libgnutls.so.30@libgnutls30t64_3.8.5-4":"gtruth/libgnutls.so.30.40.0.bc.llvm",
        "libnetsnmpmibs.so.40@libsnmp40t64_5.9.4%2Bdfsg-1.1%2Bb1":"gtruth/libnetsnmpmibs.so.40.2.1.bc.llvm",
        "libr_bin.so.5.9.2@libradare2-5.0.0t64_5.9.2%2Bdfsg-1":"gtruth/libr_arch.so.5.9.2.bc.llvm",
        "libr_core.so.5.9.2@libradare2-5.0.0t64_5.9.2%2Bdfsg-1":"gtruth/libr_core.so.5.9.2.bc.llvm",
        "libstb.so.0@libstb0t64_0.0%7Egit20230129.5736b15%2Bds-1.2":"gtruth/libstb.so.0.0.bc.llvm",
        "libtiff.so.6@libtiff6_4.5.1%2Bgit230720-4":"gtruth/libtiff.so.6.0.1.bc.llvm",
        "libxml2.so.2@libxml2_2.12.7%2Bdfsg-3":"gtruth/libxml2.so.2.12.7.bc.llvm",
        "libXpm.so.4@libxpm4_1:3.5.17-1%2Bb1":"gtruth/libXpm.so.4.11.0.bc.llvm"
    }
    
    indir_calls_dict = {}

    for elf_key, g_truth_file in elf_gtruth_file_dict.items():
        print(f"Processing {g_truth_file}")
        g_truth_dets = process_gtruth_file(g_truth_file)
        num_icalls = 0
        for func, dets in g_truth_dets.items():
            num_icalls += len(dets['icall_args'])
        indir_calls_dict[elf_key] = num_icalls

    with open("indir_callsite_count.json", "w") as f:
        json.dump(indir_calls_dict, f, indent=4)


if __name__=="__main__":
    main()
