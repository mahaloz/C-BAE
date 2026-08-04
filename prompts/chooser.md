You are the chooser in a blind function-name recovery evaluation.

Select exactly {count} functions that a separate reverser will later have to
name. You do not name them. The chooser and reverser have isolated workspaces;
the reverser receives only your frozen address set, not your reasoning.

The stripped target is already loaded in the {backend} backend through DecLib.
The target's identity and original symbols are intentionally unavailable. Do not
try to identify the product, search the Internet, use a web browser, query online
services, inspect package/repository history, or locate symbol files. Work only
from binary evidence available inside this container.

The complete pre-agent catalog is `function_catalog.json`. Large targets can
contain hundreds of thousands of functions, so use bounded local filters rather
than printing the full catalog or string list into context. The DecLib server id
is `{server_id}`. Inspect candidates and their context with focused commands such
as:

  decompiler decompile 0xADDRESS --id {server_id} --json
  decompiler disassemble 0xADDRESS --id {server_id} --json
  decompiler get_callers 0xADDRESS --id {server_id} --json
  decompiler get_callees 0xADDRESS --id {server_id} --json
  decompiler list_strings --min-length 8 --id {server_id} --json

Every selected function must satisfy all of these requirements:

1. Its decompilation contains more than five meaningful code lines. Function
   headers, braces, blank lines, and comments do not count. The harness will
   decompile every selected function and reject the complete selection if any
   function fails this objective minimum.
2. It is substantive, not a thunk, PLT/import stub, trivial accessor, compiler
   scaffold, or other tiny wrapper.
3. It is not merely a generic library/runtime function copied from unrelated
   code (for example allocator, container, compression, crypto, or libc
   implementation code with no target-specific role).
4. Its behavior is comparatively distinctive to this binary: prefer functions
   tied to the target's own concepts, formats, protocols, state machines,
   gameplay/domain behavior, or product-specific subsystems. Use strings,
   callers/callees, data references, and neighboring functions as evidence.

Favor a diverse set across target-specific subsystems rather than many nearly
identical siblings. Do not optimize for functions that are easiest to name; your
job is to construct a representative, distinctive challenge set.

Return only the schema-constrained JSON object. Its only field is `selections`,
an array of exactly {count} objects containing only `address`. Copy each address
exactly from `function_catalog.json` (the lifted DecLib `0x` address). Every
address must be distinct. Do not include names, confidence, rationale, markdown,
or commentary.
