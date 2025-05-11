
// Extra Pass plugin
#include "stdafx.h"
#include <WaitBoxEx.h>
#include <SegSelect.h>
#include <IdaOgg.h>
#include <unordered_set>
#include <vector>

#include "complete_ogg.h"

//#define VBDEV
//#define LOG_FILE

// TODO: Could be a UI configuration choice
// Now of days most compilers are going to be generating functions at 16 byte boundaries.
// But not always the case for older executables or non-standard configurations.
#define MINIMAL_ALIGNMENT 16  // 4, 8

// Define to dump out problem functions
//#define SHOW_PROBLEMS

// Count of STATE_PASS_1 unknown byte gather passes
#define UNKNOWN_PASSES 8


// Flag defines from SDK "bytes.hpp"
// Duplicated here for cases not exposed by the SDK
#define MS_VAL  0x000000FFLU	// Mask for byte value
#define FF_IVL  0x00000100LU	// Byte has value ?
#define FF_REF  0x00001000LU	// has references
#define FF_0OFF 0x00500000LU	// Offset?

#define DT_TYPE  0xF0000000LU	// Data types
#define FF_QWORD 0x30000000LU
#define FF_ALIGN 0xB0000000LU


// Process states
enum STATES
{
    STATE_INIT,		// Initialize
	STATE_START,	// Start processing

    STATE_PASS_1,	// Find unknown data in code space
    STATE_PASS_2,	// Fix missing "align" blocks
	STATE_PASS_3,	// Fix lost code instructions
	STATE_PASS_4,	// Fix missing functions
	STATE_PASS_5,	// Fix incorrect tail call blocks

    STATE_FINISH,	// Done

    STATE_EXIT,
};

static const char SITE_URL[] = { "https://github.com/kweatherman/IDA_ExtraPass_PlugIn" };

// UI options bit flags
// *** Must be same sequence as check box options
const static WORD OPT_DATATOBYTES = (1 << 0);
const static WORD OPT_ALIGNBLOCKS = (1 << 1);
const static WORD OPT_MISSINGCODE = (1 << 2);
const static WORD OPT_MISSINGFUNC = (1 << 3);
const static WORD OPT_FIXTAILBLKS = (1 << 4);

// === Function Prototypes ===
static void showEndStats();
static void nextState();
static void processFuncGap(ea_t start, ea_t end);
static void processFunc(func_t *f);
static bool idaapi isAlignByte(flags64_t flags, void *ud = NULL);
static bool idaapi isData(flags64_t flags, void *ud = NULL);

// === Data ===
static TIMESTAMP s_startTime = 0, s_stepTime = 0;
static std::vector<func_t*> s_funcList;
static SegSelect::segments codeSegs;
static int segIndex = 0;
static segment_t *s_thisSeg  = NULL;
static ea_t s_segStart       = NULL;
static ea_t s_segEnd         = NULL;
static ea_t s_currentAddress = NULL;
static ea_t s_lastAddress    = NULL;
static BOOL s_isBreak        = FALSE;
#ifdef LOG_FILE
static FILE *s_logFile       = NULL;
#endif
static STATES s_state = STATE_INIT;
static int  s_startFuncCount = 0;
static int  s_pass1Loops     = 0;
static UINT s_funcIndex      = 0;
//
static UINT s_unknownDataCount = 0;
static UINT s_alignFixes       = 0;
static UINT s_codeFixes        = 0;
static UINT s_tailBlckRefFixes = 0;            
//
static BOOL s_doDataToBytes	= FALSE; // Pass 1
static BOOL s_doAlignBlocks	= TRUE;	 // Pass 2
static BOOL s_doMissingCode	= TRUE;	 // Pass 3
static BOOL s_doMissingFunc	= TRUE;	 // Pass 4
static BOOL s_doFixTailBlks	= TRUE;	 // Pass 5
static WORD s_audioAlertWhenDone = 1;

// Options dialog
static const char optionDialog[] =
{
	"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'

	// Help body
	"HELP\n"
	"\"ExtraPass PlugIn\""
	"An IDA Pro Windows executable clean up plugin, by Sirmabus\n\n"

	"See: README.md for more info.\n"

	"ENDHELP\n"

	// Title
	"ExtraPass Plugin\n"

	// Message text
	"Version %Aby Sirmabus\n"
	"<#Click to open site.#ExtraPass Github:k:2:1::>\n\n"

	"Choose processing steps:\n"

	// checkbox -> s_wDoDataToBytes
	"<#Scan the entire code section converting all unknown data declarations to \"unknown\" bytes\n"
	"to be reexamined as possible code, functions, and alignment blocks in the preceding passes."
	"#1 Convert unknown data.                                     :C>\n"

	// checkbox -> s_wDoAlignBlocks
	"<#Fix missing \"align xx\" blocks.#2 Fix align blocks.:C>\n"

	// checkbox -> s_wDoMissingCode
	"<#Fix lost code instructions.#3 Fix missing code.:C>\n"

	// checkbox -> s_wDoMissingFunc
	"<#Fix missing/undeclared functions.#4 Fix missing functions.:C>\n"

	"<#Fix incorrectly defined tail blocks that make some functions non-contiguous.#5 Fix non-contiguous functions.:C>>\n"

	// checkbox -> s_wAudioAlertWhenDone
	"<#Play sound on completion.#Play sound on completion.                                     :C>>\n"


	"<#Choose the code segment(s) to process.\nElse will use the first CODE segment by default.\n#Choose Code Segments:B:1:8::>\n"
    "                      "
};

// Checks and handles if break key pressed; return TRUE on break.
static BOOL checkBreak()
{
    if (!s_isBreak)
    {
        if (WaitBox::isUpdateTime())
        {
            if (WaitBox::updateAndCancelCheck())
            {
                msg("\n*** Aborted ***\n\n");

                // Show stats then directly to exit
                showEndStats();
                s_state = STATE_EXIT;
                s_isBreak = TRUE;
                return TRUE;
            }
        }
    }
    return s_isBreak;
}

// Make and address range "unknown" so it can be set with something else
static void makeUnknown(ea_t start, ea_t end)
{
	auto_wait();
	del_items(start, (DELIT_SIMPLE | DELIT_NOTRUNC), (end - start));
    auto_wait();
}


// Initialize
static plugmod_t* idaapi init()
{
	// Only Intel x86/AMD64 supported
	processor_t &ph = PH;
	if (ph.id != PLFM_386)
		return PLUGIN_SKIP;

    s_state = STATE_INIT;
	return PLUGIN_OK;
}

// Uninitialize
void idaapi term()
{
    try
    {
        #ifdef LOG_FILE
        if(s_logFile)
        {
            qfclose(s_logFile);
            s_logFile = NULL;
        }
        #endif

		s_funcList.clear();
        OggPlay::endPlay();		      
    }
    CATCH()
}

// Handler for choose code and data segment buttons
static void idaapi chooseBtnHandler(int button_code, form_actions_t &fa)
{	
	SegSelect::select(codeSegs, SegSelect::CODE_HINT, "Choose code segments");
}

static void idaapi doHyperlink(int button_code, form_actions_t &fa) { open_url(SITE_URL); }


// Plug-in process
bool idaapi run(size_t arg)
{
    try
    {
        while (TRUE)
        {
            switch (s_state)
            {
                // Initialize
                case STATE_INIT:
                {
					qstring version;
					msg("\n>> ExtraPass: v: %s, built: %s\n", GetVersionString(MY_VERSION, version).c_str(), __DATE__);
                    
					// IDA must be IDLE
					if (!auto_is_ok())
					{
						msg("** Wait for IDA to finish processing before starting plugin! **\n*** Aborted ***\n\n");
						goto exit;
					}

                    // Do UI for process pass selection
					s_doDataToBytes = FALSE;
					s_doAlignBlocks = s_doMissingCode = s_doMissingFunc = s_doFixTailBlks = TRUE;
                    s_audioAlertWhenDone = TRUE;

                    WORD optionFlags = 0;
                    if (s_doDataToBytes) optionFlags |= OPT_DATATOBYTES;
                    if (s_doAlignBlocks) optionFlags |= OPT_ALIGNBLOCKS;
                    if (s_doMissingCode) optionFlags |= OPT_MISSINGCODE;
                    if (s_doMissingFunc) optionFlags |= OPT_MISSINGFUNC;
					if (s_doFixTailBlks) optionFlags |= OPT_FIXTAILBLKS;
					codeSegs.clear();
					segIndex = 0;
					s_isBreak = FALSE;

                    // To add forum URL to help box
                    int result = ask_form(optionDialog, version.c_str(), doHyperlink, &optionFlags, &s_audioAlertWhenDone, chooseBtnHandler);
                    if (!result || (optionFlags == 0))
                    {
                        // User canceled, or no options selected, bail out
                        msg(" - Canceled -\n\n");
						goto exit;
                    }

                    s_doDataToBytes = ((optionFlags & OPT_DATATOBYTES) != 0);
                    s_doAlignBlocks = ((optionFlags & OPT_ALIGNBLOCKS) != 0);
                    s_doMissingCode = ((optionFlags & OPT_MISSINGCODE) != 0);
                    s_doMissingFunc = ((optionFlags & OPT_MISSINGFUNC) != 0);
					s_doFixTailBlks = ((optionFlags & OPT_FIXTAILBLKS) != 0);                                

                    // Ask for the log file name once
                    #ifdef LOG_FILE
                    if(!s_logFile)
                    {
                        if(char *szFileName = askfile_c(1, "*.txt", "Select a log file name:"))
                        {
                            // Open it for appending
                            s_logFile = qfopen(szFileName, "ab");
                        }
                    }
                    if(!s_logFile)
                    {
                        msg("** Log file open failed! Aborted. **\n");
                        return false;
                    }
                    #endif

                    s_thisSeg = NULL;
                    s_unknownDataCount = s_alignFixes = s_codeFixes = s_tailBlckRefFixes = 0;
                    s_pass1Loops = 0; s_funcIndex = 0;
                    s_startFuncCount = (int) get_func_qty();
					if (!s_startFuncCount)
					{
						msg("** No functions in this DB?! **\n*** Aborted ***\n\n");
						goto exit;
					}

                    char buffer[32];
                    msg("Starting function count: %s\n", NumberCommaString(s_startFuncCount, buffer));

                    /*
                    msg("\n=========== Segments ===========\n");
                    int iSegCount = get_segm_qty();
                    for(int i = 0; i < iSegCount; i++)
                    {
                        if(segment_t *pSegInfo = getnseg(i))
                        {
                        char szName[128] = {0};
                        get_segm_name(pSegInfo, szName, (sizeof(szName) - 1));
                        char szClass[16] = {0};
                        get_segm_class(pSegInfo, szClass, (sizeof(szClass) - 1));
                        msg("[%d] \"%s\", \"%s\".\n", i, szName, szClass);
                        }
                    }
                    */

                    // First chosen seg
                    if (!codeSegs.empty())                        
                        s_thisSeg = &codeSegs[segIndex++];                        
                    else
                    // Use the first CODE seg
                    {
                        int segCount = get_segm_qty();
						int i = 0;
                        for (; i < segCount; i++)
                        {
                            if (s_thisSeg = getnseg(i))
                            {
                                qstring sclass;
                                if (get_segm_class(&sclass, s_thisSeg) <= 0)
                                    break;
                                else
                                if (sclass == "CODE")
                                    break;
                            }
                        }

                        if (i >= segCount)
                            s_thisSeg = NULL;
                    }

                    if (s_thisSeg)
                    {
                        WaitBox::show("ExtraPass", "Working..");
                        WaitBox::updateAndCancelCheck(-1);
                        s_segStart = s_thisSeg->start_ea;
                        s_segEnd   = s_thisSeg->end_ea;
                        nextState();
                        break;
                    }
                    else
                        msg("** No code segment found to process! **\n*** Aborted ***\n\n");                  
                   
                    // Canceled error, bail out
					exit:;
                    s_state = STATE_EXIT;
                }
                break;

                // Start up process
                case STATE_START:
                {
                    s_currentAddress = 0;

					qstring name;
                    if (get_segm_name(&name, s_thisSeg) <= 0)
						name = "????";
                    qstring sclass;
                    if(get_segm_class(&sclass, s_thisSeg) <= 0)
						sclass = "????";
                    msg("\nSegment: \"%s\", type: %s, address: %llX-%llX, size: 0x%X\n\n", name.c_str(), sclass.c_str(), s_thisSeg->start_ea, s_thisSeg->end_ea, s_thisSeg->size());

                    // Move to first process state
                    s_startTime = GetTimeStamp();
                    nextState();
                }
                break;


                // Find unknown data runs in code section
                //#define PASS1_DEBUG
                case STATE_PASS_1:
                {
                    if (s_currentAddress < s_segEnd)
                    {
                        // Value at this location data?
                        auto_wait();
						flags64_t flags = get_flags(s_currentAddress);
                        if (isData(flags))
                        {
                            #ifdef PASS1_DEBUG
							msg(" \n");
							qstring tmpStr;
							idaFlags2String(flags, tmpStr);
                            msg("%llX (%s)\n", s_currentAddress, tmpStr.c_str());
                            #endif
                            ea_t end = next_head(s_currentAddress, s_segEnd);

                            // Handle an occasional over run case
                            if (end == BADADDR)
                            {
                                #ifdef PASS1_DEBUG
                                msg("%llX **** abort end\n", s_currentAddress);
                                #endif
                                s_currentAddress = (s_segEnd - 1);
                                break;
                            }

                            // Skip if it has offset reference (most common occurrence)
                            BOOL bSkip = FALSE;
                            if (flags & FF_0OFF)
                            {
                                #ifdef PASS1_DEBUG
                                msg("  skip offset.\n");
                                #endif
                                bSkip = TRUE;
                            }
							else
							// Skip if the value is larger than a QWORD.
							// It's probably an SSE or actual string value embedded data
							if(((flags & DT_TYPE) > FF_QWORD) && ((flags & DT_TYPE) != FF_ALIGN))
							{
								#ifdef PASS1_DEBUG
								msg("  skip by data type.\n");
								#endif
								bSkip = TRUE;
							}
							else
                            // Has a reference?
                            if (flags & FF_REF)
                            {
                                ea_t eaDRef = get_first_dref_to(s_currentAddress);
                                if (eaDRef != BADADDR)
                                {
									#ifdef PASS1_DEBUG
									msg("  has ref.\n");
									#endif

                                    // Ref part an offset?
									flags64_t flags2 = get_flags(eaDRef);
                                    if (is_code(flags2) && is_off1(flags2))
                                    {
                                        // Decide instruction to global "cmd" struct
                                        BOOL bIsByteAccess = FALSE;
										insn_t cmd;
                                        if (decode_insn(&cmd, eaDRef))
                                        {
                                            switch (cmd.itype)
                                            {
												// Assume it's an embedded data array
												case NN_lea:
												{
													#ifdef PASS1_DEBUG
													msg("%llX lea.\n", s_currentAddress);
													#endif
													bSkip = TRUE;
												}
												break;

                                                // movxx style move a byte?
                                                case NN_movzx:
                                                case NN_movsx:
                                                {
                                                    #ifdef PASS1_DEBUG
                                                    msg("%llX movzx.\n", s_currentAddress);
                                                    #endif
                                                    bIsByteAccess = TRUE;
                                                }
                                                break;

                                                case NN_mov:
                                                {
                                                    if ((cmd.ops[0].type == o_reg) && (cmd.ops[1].dtype == dt_byte))
                                                    {
                                                        #ifdef PASS1_DEBUG
                                                        msg("%llX mov.\n", s_currentAddress);
                                                        #endif
                                                        /*
                                                        msg(" [0] T: %d, D: %d, \n", cmd.Operands[0].type, cmd.Operands[0].dtyp);
                                                        msg(" [1] T: %d, D: %d, \n", cmd.Operands[1].type, cmd.Operands[1].dtyp);
                                                        msg(" [2] T: %d, D: %d, \n", cmd.Operands[2].type, cmd.Operands[2].dtyp);
                                                        msg(" [3] T: %d, D: %d, \n", cmd.Operands[3].type, cmd.Operands[3].dtyp);
                                                        */
                                                        bIsByteAccess = TRUE;
                                                    }
                                                }
                                                break;
                                            };
                                        }

                                        // If it's byte access, assume it's a byte switch table
                                        if (bIsByteAccess)
                                        {
                                            #ifdef PASS1_DEBUG
                                            msg("%llX not byte.\n", s_currentAddress);
                                            #endif

                                            makeUnknown(s_currentAddress, end);

                                            // Step through making the array, and any bad size a byte
                                            //for(ea_t i = s_eaCurrentAddress; i < eaEnd; i++){ doByte(i, 1); }
											create_byte(s_currentAddress, (end - s_currentAddress));
                                            auto_wait();
                                            bSkip = TRUE;
                                        }
                                    }
                                }

                            } // if (flags & FF_REF)

                            // Make it unknown bytes
                            if (!bSkip)
                            {
                                #ifdef PASS1_DEBUG
                                msg("%llX %llX %02X unknown\n", s_currentAddress, end, get_flags(s_currentAddress));
                                #endif

                                makeUnknown(s_currentAddress, end);
                                s_unknownDataCount++;
                            }

                            // Advance to next data value, or the end which ever comes first
                            s_currentAddress = end;
                            if (s_currentAddress < s_segEnd)
                            {
                                s_currentAddress = next_that(s_currentAddress, s_segEnd, isData, NULL);
                                break;
                            }

                        } // if (isData(flags))
                        else
                        {
                            // Advance to next data value, or the end which ever comes first
                            s_currentAddress = next_that(s_currentAddress, s_segEnd, isData, NULL);
                            break;
                        }

                    } // if (s_currentAddress < s_segEnd)

                    if (++s_pass1Loops < UNKNOWN_PASSES)
                    {
                        #ifdef PASS1_DEBUG
                        msg("** Pass %d Unknowns: %u\n", s_pass1Loops, s_unknownDataCount);
                        #endif

                        s_currentAddress = s_lastAddress = s_segStart;
                    }
                    else
                    {
                        #ifdef PASS1_DEBUG
                        msg("** Pass %d Unknowns: %u\n", s_pass1Loops, s_unknownDataCount);
                        #endif

                        nextState();
                    }
                }
                break;  // Find unknown data values in code


                // Find missing align blocks
                //#define PASS2_DEBUG
                case STATE_PASS_2:
                {
                    // Still inside this code segment?
                    ea_t end = s_segEnd;
                    if (s_currentAddress < end)
                    {
                        // Look for next unknown alignment type byte
                        // Will return BADADDR if none found which will catch in the endEA test
						flags64_t flags = get_full_flags(s_currentAddress);
                        if (!isAlignByte(flags))
                            s_currentAddress = next_that(s_currentAddress, s_segEnd, isAlignByte, NULL);

                        if (s_currentAddress < end)
                        {
                            // Catch when we get caught up in an array, etc.
                            ea_t startAddress = s_currentAddress;
                            if (s_currentAddress <= s_lastAddress)
                            {
                                // Move to next header and try again..
                                #ifdef PASS2_DEBUG
                                //msg("%llX, F: 0x%X *** Align test in array #1 ***\n", s_currentAddress, flags);
                                #endif

                                s_currentAddress = s_lastAddress = next_addr(s_currentAddress);
                                break;
                            }

                            #ifdef PASS2_DEBUG
                            //msg("%llX Start.\n", startAddress);
                            //msg("%llX, F: %08X.\n", startAddress, get_flags_novalue(startAddress));
                            #endif
                            s_lastAddress = s_currentAddress;

                            // Get run count of this align byte
                            UINT alignByteCount = 1;
                            BYTE startAlignValue = get_byte(startAddress);

                            while (TRUE)
                            {
                                // Next byte
                                s_currentAddress = next_addr(s_currentAddress);
                                #ifdef PASS2_DEBUG
                                //msg("%llX Next.\n", s_currentAddress);
                                //msg("%llX, F: %08X.\n", s_currentAddress, get_flags_novalue(s_currentAddress));
                                #endif

                                if (s_currentAddress < end)
                                {
                                    // Catch when we get caught up in an array, etc.
                                    if (s_currentAddress <= s_lastAddress)
                                    {
                                        #ifdef PASS2_DEBUG
                                        //msg("%llX, F: %08X *** Align test in array #2 ***\n", startAddress, get_flags_novalue(s_currentAddress));
                                        #endif
                                        s_currentAddress = s_lastAddress = next_addr(s_currentAddress);
                                        break;
                                    }
                                    s_lastAddress = s_currentAddress;

                                    // Count if it' still the same byte
                                    if (get_byte(s_currentAddress) == startAlignValue)
                                        alignByteCount++;
                                    else
                                        break;
                                }
                                else
                                    break;
                            };

                            // Do these bytes bring about at least a 16 (could be 32) align?
                            // TODO: Must we consider other alignments such as 4 and 8?
                            //       Probably a compiler option that is not normally used anymore.
                            if (((startAddress + alignByteCount) & (16 - 1)) == 0)
                            {
                                // If short count, only try alignment if the line above or a below us has n xref
                                // We don't want to try to align odd code and switch table bytes, etc.
                                if (alignByteCount <= 2)
                                {
                                    BOOL hasRef = FALSE;

                                    // Before us
                                    ea_t endAddress = (startAddress + alignByteCount);
                                    ea_t ref = get_first_cref_from(endAddress);
                                    if (ref != BADADDR)
                                    {
                                        //msg("%llX cref from end.\n", endAddress);
                                        hasRef = TRUE;
                                    }
                                    else
                                    {
                                        ref = get_first_cref_to(endAddress);
                                        if (ref != BADADDR)
                                        {
                                            //msg("%llX cref to end.\n", endAddress);
                                            hasRef = TRUE;
                                        }
                                    }

                                    // After us
                                    if (ref == BADADDR)
                                    {
                                        ea_t foreAddress = (startAddress - 1);
                                        ref = get_first_cref_from(foreAddress);
                                        if (ref != BADADDR)
                                        {
                                            //msg("%llX cref from start.\n", eaForeAddress);
                                            hasRef = TRUE;
                                        }
                                        else
                                        {
                                            ref = get_first_cref_to(foreAddress);
                                            if (ref != BADADDR)
                                            {
                                                //msg("%llX cref to start.\n", eaForeAddress);
                                                hasRef = TRUE;
                                            }
                                        }
                                    }

                                    // No code ref, now look for a broken code ref
                                    if (ref == BADADDR)
                                    {
                                        // This is still not complete as it could still be code, but pointing to a vftable
                                        // entry in data.
                                        // But should be fixed on more passes.
                                        ea_t endAddress = (startAddress + alignByteCount);
                                        ref = get_first_dref_from(endAddress);
                                        if (ref != BADADDR)
                                        {
                                            // If it the ref points to code assume code is just broken here
                                            if (is_code(get_flags(ref)))
                                            {
                                                //msg("%llX dref from end %08X.\n", eaRef, eaEndAddress);
                                                hasRef = TRUE;
                                            }
                                        }
                                        else
                                        {
                                            ref = get_first_dref_to(endAddress);
                                            if (ref != BADADDR)
                                            {
                                                if (is_code(get_flags(ref)))
                                                {
                                                    //msg("%llX dref to end %08X.\n", eaRef, eaEndAddress);
                                                    hasRef = TRUE;
                                                }
                                            }
                                        }

                                        if (ref == BADADDR)
                                        {
                                            //msg("%llX NO REF.\n", eaStartAddress);
                                        }
                                    }

                                    // Assume it's not an alignment byte(s) and bail out
                                    if (!hasRef) break;
                                }

                                // If it's not an align make block already try to fix it
								flags64_t flags = get_flags(startAddress);
								UINT itemSize = (UINT) get_item_size(startAddress);
								if (!is_align(flags) || (itemSize != alignByteCount))
								{
									makeUnknown(startAddress, ((startAddress + alignByteCount) - 1));
									BOOL result = create_align(startAddress, alignByteCount, 0);
									auto_wait();
									#ifdef PASS2_DEBUG
									msg("%llX %d %d  %d %d %d DO ALIGN.\n", startAddress, alignByteCount, result, isAlign(flags), itemSize, get_item_size(startAddress));
									#endif
									if (result)
									{
										#ifdef PASS2_DEBUG
										//msg("%llX %d ALIGN.\n", startAddress, alignByteCount);
										#endif
										s_alignFixes++;
									}
									else
									{
										// There are cases were IDA will fail even when the alignment block is obvious.
										// Usually when it's an ALIGN(32) and there is a run of 16 align bytes
										// Could at least do a code analyze on it. Then IDA will at least make a mini array of it
										#ifdef PASS2_DEBUG
										msg("%llX %d ALIGN FAIL ***\n", startAddress, alignByteCount);
										//s_alignFails++;
										#endif
									}
								}
                            }
                        }

                        break;
                    }

					// Done, move to next state
                    s_currentAddress = s_segEnd;
                    nextState();
                }
                break; // Find missing align blocks


                // Find missing code
                //#define PASS3_DEBUG
                case STATE_PASS_3:
                {
                    // Still inside segment?
                    if (s_currentAddress < s_segEnd)
                    {
                        // Look for next unknown value
                        ea_t startAddress = next_unknown(s_currentAddress, s_segEnd);
                        if (startAddress < s_segEnd)
                        {
                            s_currentAddress = startAddress;

                            // Catch when we get caught up in an array, etc.
                            if (s_currentAddress <= s_lastAddress)
                            {
                                // Move to next header and try again..
                                s_currentAddress = next_unknown(s_currentAddress, s_segEnd);
                                s_lastAddress = s_currentAddress;
                                break;
                            }
                            s_lastAddress = s_currentAddress;

                            // Try to make code of it
							if (!isAlignByte(get_full_flags(s_currentAddress)))
							{
								auto_wait();
								int result = create_insn(s_currentAddress);
								#ifdef PASS3_DEBUG
								msg("%llX DO CODE %d\n", s_currentAddress, result);
								#endif

								if(result > 0)
									s_codeFixes++;
								else
								{
									#ifdef PASS3_DEBUG
									msg("%llX fix fail.\n", s_currentAddress);
									#endif
								}
							}

                            s_currentAddress++;
                            break;
                        }
                    }

                    // Next state
                    s_currentAddress = s_segEnd;
                    nextState();
                }
                break; // End: Find missing code


                // Discover missing functions part
				//#define PASS4_DEBUG
                case STATE_PASS_4:
                {
                    if (s_funcIndex < (s_funcList.size() - 1))
                    {
						// Process function gap from the end of one function to the start of the next

						// Skip if first function body is not contiguous						
						func_t *f = s_funcList[s_funcIndex + 0];
						if (f->tailqty != 0)
						{
							#ifdef PASS4_DEBUG
							static UINT nonContiguousCount = 0;
							msg("%llX [%d] not contiguous %d\n", f->start_ea, nonContiguousCount++, f->tailqty);
							#endif
						}
						else
						{
							ea_t a_end = f->end_ea;
							ea_t b_start = s_funcList[s_funcIndex + 1]->start_ea;
							processFuncGap(a_end, b_start);
						}

						s_funcIndex++;
                    }
                    else
                    {
                        s_currentAddress = s_segEnd;
                        nextState();
                    }
                }
                break;

				// Fix bad tail blocks				
				case STATE_PASS_5:
				{
					if (s_funcIndex < s_funcList.size())
                    {						
						// Fits not contiguous function problem type??
						func_t *f = s_funcList[s_funcIndex];
						if (f->tailqty == 1)
						{
							// Go check and handle it
							processFunc(f);
						}
							
						s_funcIndex++;
                    }
                    else
                    {
                        s_currentAddress = s_segEnd;
                        nextState();
                    }
				}
				break;

                // Finished processing
                case STATE_FINISH:
                nextState();
                break;

                // Done processing
                case STATE_EXIT:
                {					
                    nextState();
                    goto BailOut;
                }
                break;
            };

            // Check & bail out on 'break' press
			if (checkBreak())				
				goto BailOut;			
        };		
    }
	CATCH()
	BailOut:;
	WaitBox::hide();
	return true;
}


// Get list of current functions prior to a processing pass
static void cacheFunctionList()
{
	int funcCount = (int) get_func_qty();
	s_funcList.clear();
	s_funcList.resize(funcCount);
	s_funcIndex = 0;

	// Must get list of functions BEFORE we start processing since IDA enumeration will break as new functions are added
	for (int i = 0; i < funcCount; i++)
		s_funcList[i] = getn_func(i);
}


// Do next state logic
static void nextState()
{
	// Rewind
	if(s_state < STATE_FINISH)
	{
		// Top of code seg
		s_currentAddress = s_lastAddress = s_segStart;
		auto_wait();
	}

	// Logic
	switch(s_state)
	{
		// Init
		case STATE_INIT:
		{
			s_state = STATE_START;
		}
		break;

		// Start
		case STATE_START:
		{
			if(s_doDataToBytes)
			{
				msg("===== Fixing bad code bytes =====\n");
				s_stepTime = GetTimeStamp();
				s_state = STATE_PASS_1;
			}
			else
			if(s_doAlignBlocks)
			{
				msg("===== Fixing align blocks =====\n");
				s_stepTime = GetTimeStamp();
				s_state = STATE_PASS_2;
			}
			else
			if(s_doMissingCode)
			{
				msg("===== Fixing missing code =====\n");
				s_stepTime = GetTimeStamp();
				s_state = STATE_PASS_3;
			}
			else
			if(s_doMissingFunc)
			{
				msg("===== Fixing missing functions =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_4;
			}
			else
			if (s_doFixTailBlks)
			{
				msg("===== Fixing bad tail blocks =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_5;
			}
			else
				s_state = STATE_FINISH;
		}
		break;

		// Find unknown data in code space
		case STATE_PASS_1:
		{
			msg("Took %s.\n\n", TimeString(GetTimeStamp() - s_stepTime));

			if(s_doAlignBlocks)
			{
				msg("===== Fixing align blocks =====\n");
				s_stepTime = GetTimeStamp();
				s_state = STATE_PASS_2;
			}
			else
			if(s_doMissingCode)
			{
				msg("===== Fixing missing code =====\n");
				s_stepTime = GetTimeStamp();
				s_state = STATE_PASS_3;
			}
			else
			if(s_doMissingFunc)
			{
				msg("===== Fixing missing functions =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_4;
			}
			else
			if (s_doFixTailBlks)
			{
				msg("===== Fixing bad tail blocks =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_5;
			}
			else
				s_state = STATE_FINISH;
		}
		break;


		// From missing align block pass
		case STATE_PASS_2:
		{
			msg("Took %s.\n\n", TimeString(GetTimeStamp() - s_stepTime));

			if(s_doMissingCode)
			{
				msg("===== Fixing missing code =====\n");
				s_stepTime = GetTimeStamp();
				s_state = STATE_PASS_3;
			}
			else
			if(s_doMissingFunc)
			{
				msg("===== Fixing missing functions =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_4;
			}
			else
			if (s_doFixTailBlks)
			{
				msg("===== Fixing bad tail blocks =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_5;
			}
			else
				s_state = STATE_FINISH;
		}
		break;

		// From missing code pass
		case STATE_PASS_3:
		{
			msg("Took %s.\n\n", TimeString(GetTimeStamp() - s_stepTime));

			if(s_doMissingFunc)
			{
				msg("===== Fixing missing functions =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_4;
			}
			else
			if (s_doFixTailBlks)
			{
				msg("===== Fixing bad tail blocks =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_5;
			}
			else
				s_state = STATE_FINISH;
		}
		break;

		// From missing function pass
		case STATE_PASS_4:
		{
			s_funcList.clear();
			msg("Took %s.\n\n", TimeString(GetTimeStamp() - s_stepTime));			

			if (s_doFixTailBlks)
			{
				msg("===== Fixing bad tail blocks =====\n");
				s_stepTime = GetTimeStamp();
				cacheFunctionList();
				s_state = STATE_PASS_5;
			}
			else
				s_state = STATE_FINISH;
		}
		break;

		// From tail block fix pass
		case STATE_PASS_5:
		{
			s_funcList.clear();
			msg("Took %s.\n\n", TimeString(GetTimeStamp() - s_stepTime));
			s_state = STATE_FINISH;
		}
		break;


		// From final pass, we're done
		case STATE_FINISH:
		{
			// If there are more code segments to process, do next
			auto_wait();
            if (!codeSegs.empty() && (segIndex < (int) codeSegs.size()))
			{
				s_thisSeg = &codeSegs[segIndex++];              
				s_segStart = s_thisSeg->start_ea;
				s_segEnd   = s_thisSeg->end_ea;
				s_state = STATE_START;
			}
			else
			{
				msg("\n===== Done =====\n");
				showEndStats();
                refresh_idaview_anyway();
				WaitBox::hide();

				// Optionally play completion sound
				if(s_audioAlertWhenDone)
				{
                    // Only if processing took at least a few seconds
                    if ((GetTimeStamp() - s_startTime) > 2.2)
                    {
                        OggPlay::playFromMemory((const PVOID) complete_ogg, complete_ogg_len);
                        OggPlay::endPlay();
                    }
				}

				s_state = STATE_EXIT;
			}
		}
		break;

		// Exit plugin run back to IDA control
		case STATE_EXIT:
		{          
			s_state = STATE_INIT;
		}
		break;
	};
}


// Print out end stats
static void showEndStats()
{
    char buffer[32];
	int functionsDelta = ((int) get_func_qty() - s_startFuncCount);
	if (functionsDelta != 0)
		msg("Missing functions recovered: %c%s\n", ((functionsDelta >= 0) ? '+' : '-'), NumberCommaString(labs(functionsDelta), buffer)); // Can be negative/worse..

	if(s_tailBlckRefFixes)
		msg("Non-contiguous functions fixed: %s\n", NumberCommaString(s_tailBlckRefFixes, buffer));

	if (s_alignFixes)
		msg("Fixed alignment blocks: %s\n", NumberCommaString(s_alignFixes, buffer));

	msg("Took %s in total.\n", TimeString(GetTimeStamp() - s_startTime));
	msg(" \n");
	refresh_idaview_anyway();
}

// Returns TRUE if flag byte is possibly a typical alignment byte
static bool idaapi isAlignByte(flags64_t flags, void *ud)
{
	const flags64_t ALIGN_VALUE1 = (FF_IVL | 0xCC); // 0xCC (single byte "int 3") byte type
	const flags64_t ALIGN_VALUE2 = (FF_IVL | 0x90); // NOP byte type

	flags &= (FF_IVL | MS_VAL);
	if((flags == ALIGN_VALUE1) || (flags == ALIGN_VALUE2))
		return(TRUE);
	else
		return(FALSE);
}

// Return if flag is data type we want to convert to unknown bytes
static bool idaapi isData(flags64_t flags, void *ud)
{
	return(!is_align(flags) && is_data(flags));
}


static inline BOOL isJmpNotCntl(UINT type) { return((type >= NN_jmp) && (type <= NN_jmpshort)); } // Returns TRUE if is a non-conditional jump instruction type
static inline BOOL isCall(UINT type) { return((type >= NN_call) && (type <= NN_callni)); }        // Returns TRUE if is call instruction type

// Try adding a function at specified address
static BOOL tryFunction(ea_t codeStart, ea_t codeEnd, ea_t &current)
{
	BOOL result = FALSE;

	auto_wait();
	#ifdef LOG_FILE
	Log(s_logFile, "%llX %llX Trying function.\n", codeStart, current);
	#endif
	//msg("  %llX %llX Trying function.\n", codeStart, codeEnd);

	/// *** Don't use "get_func()" it has a bug, use "get_fchunk()" instead ***

	// Could belong as a chunk to an existing function already or already a function here recovered already between steps.
	if(func_t *f = get_fchunk(codeStart))
	{
  		#ifdef LOG_FILE
        Log(s_logFile, "  %llX %llX %llX F: %08X already function.\n", f->endEA, f->startEA, codeStart, get_flags_novalue(codeStart));
		#endif
		//msg("  %llX %llX %llX F: %08X already a function.\n", f->endEA, f->startEA, codeStart, getFlags(codeStart));

		current = prev_head(f->end_ea, codeStart); // Advance to end of the function -1 location (for a follow up "next_head()")
		result = TRUE;
	}
	else
	{
		// Try function here
		//flags_t flags = getFlags(codeEnd);
		//flags = flags;
		//if (add_func(codeStart, codeEnd /*BADADDR*/))

		if(add_func(codeStart, BADADDR))
		{
			// Wait till IDA is done possibly creating the function, then get it's info
			auto_wait();
			if(func_t *f = get_fchunk(codeStart)) // get_func
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %llX function success.\n", codeStart);
				#endif
				#ifdef VBDEV
				msg("  " %llX function success.\n", codeStart);
				#endif

				// Look at function tail instruction
				auto_wait();
				BOOL isExpected = FALSE;
				ea_t tailEa = prev_head(f->end_ea, codeStart);
				if(tailEa != BADADDR)
				{
					insn_t cmd;
					if(decode_insn(&cmd, tailEa))
					{
						switch(cmd.itype)
						{
							// A return?
							case NN_retn: case NN_retf: case NN_iretw: case NN_iret: case NN_iretd:
							case NN_iretq: case NN_syscall:
							case NN_sysret:
							{
								isExpected = TRUE;
							}
							break;

							// A jump? (chain to another function, etc.)
							case NN_jmp: case NN_jmpfi:	case NN_jmpni: case NN_jmpshort:
							// Can be a conditional branch to another incongruent chunk
							case NN_ja:  case NN_jae: case NN_jb:  case NN_jbe:  case NN_jc:   case NN_je:   case NN_jg:
							case NN_jge: case NN_jl:  case NN_jle: case NN_jna:  case NN_jnae: case NN_jnb:  case NN_jnbe:
							case NN_jnc: case NN_jne: case NN_jng: case NN_jnge: case NN_jnl:  case NN_jnle: case NN_jno:
							case NN_jnp: case NN_jns: case NN_jnz: case NN_jo:   case NN_jp:  case NN_jpe:   case NN_jpo:
							case NN_js:  case NN_jz:
							{
								isExpected = TRUE;
							}
							break;

							// A single align byte that was mistakenly made a function?
							case NN_int3:
							case NN_nop:
							if(f->size() == 1)
							{
								// Try to make it an align
                                makeUnknown(tailEa, (tailEa + 1));
								if(!create_align(tailEa, 1, 0))
								{
									// If it fails, make it an instruction at least
									//msg("  %llX ALIGN fail.\n", tailEA);
									create_insn(tailEa);
								}

                                auto_wait();
								//msg("  %llX ALIGN\n", tailEA);
								isExpected = TRUE;
							}
							break;

							// Return-less exception or exit handler?
							case NN_call:
							{
								ea_t eaCRef = get_first_cref_from(tailEa);
								if(eaCRef != BADADDR)
								{
                                    qstring str;
                                    if (get_name(&str, eaCRef) > 0)
                                    {
                                        char name[MAXNAMELEN + 1];
                                        strncpy_s(name, sizeof(name), str.c_str(), SIZESTR(name));
                                        _strlwr(name);

										static const char * const exitNames[] =
										{
											"exception",
											"handler",
											"exitprocess",
											"fatalappexit",
											"_abort",
											"_exit",
										};

										for(int i = 0; i < (sizeof(exitNames) / sizeof(const char *)); i++)
										{
											if(strstr(name, exitNames[i]))
											{
												//msg("  %llX Exception\n", CodeStartEA);
												isExpected = TRUE;
												break;
											}
										}
									}
								}
							}
							// Drop through to default for "call"

							// Allow if function has attribute "noreturn"
							default:
							{
								if(f->flags & FUNC_NORET)
								{
									//msg("  %llX NORETURN\n", tailEA);
									isExpected = TRUE;
								}
							}
							break;
						};
					}

					#ifdef SHOW_PROBLEMS
					if(!isExpected)
					{
                        char name[MAXNAMELEN + 1];
                        qstring str;
                        if (get_name(&str, f->start_ea) > 0)
                            strncpy_s(name, sizeof(name), str.c_str(), SIZESTR(name));
                        else
                            memcpy(name, "unknown", sizeof("unknown"));
						msg("%llX" \"%s\" problem? <click me>\n", tailEa, name);
						//msg("  T: %d\n", cmd.itype);

						#ifdef LOG_FILE
						Log(s_logFile, "%llX \"%s\" problem? <click me>\n", tailEa, name);
						//Log(s_hLogFile, "  T: %d\n", cmd.itype);
						#endif
					}
					#endif
				}

				// Update current look position to the end of this function
				current = tailEa; // Advance to end of the function -1 location (for a follow up "next_head()")
				result = TRUE;
			}
		}
	}

	return(result);
}


// Process the gap from the end of one function to the start of the next
// looking for missing functions in between.
static void processFuncGap(ea_t start, ea_t end)
{
	// Assume function boundaries at alignment
	start = ((start + MINIMAL_ALIGNMENT) & ~((ea_t) (MINIMAL_ALIGNMENT - 1)));
	#define IS_ALIGNED(_addr) (((_addr) & ((ea_t) (MINIMAL_ALIGNMENT - 1))) == 0)
	s_currentAddress = start;

	// Bail out if there is no gap here
	if (end <= start)
		return;

	#ifdef LOG_FILE
	Log(s_logFile, "\nS: %llX, E: %llX ==== PFG START ====\n", start, end);
	#endif
	#ifdef VBDEV
	msg("%llX %llX ==== Gap\n", start, end);
	#endif

	// Walk backwards from the end to trim possible alignment section at the end
	auto_wait();
	ea_t ea = prev_head(end, start);
	if (ea == BADADDR)
		return;
	else
	{
		ea_t endSave = end;

		while (ea >= start)
		{
			flags64_t flags = get_full_flags(ea);
			if (isAlignByte(flags) || is_align(flags))
			{
				ea = prev_head(ea, start);
				if (ea == BADADDR)
					return;
			}
			else
			{
				end = next_head(ea, end);
				// Can fail in some odd circumstances, so reset it back to whole gap size
				if (end == BADADDR)
					end = endSave;
				break;
			}
		};
	}


    // Traverse gap
	ea_t codeStart = BADADDR;
	ea = start;

    while(ea < end)
    {
		// Info flags for this address
		flags64_t flags = get_full_flags(ea);
		#ifdef LOG_FILE
		Log(s_logFile, "  C: %llX, F: %08X, \"%s\".\n", ea, flags, getDisasmText(ea));
		#endif
		#ifdef VBDEV
		qstring disStr;
		getDisasmText(ea, disStr);
		msg(" C: %llX, F: %08X, \"%s\".\n", ea, flags, disStr.c_str());
		#endif

		if(ea < start)
		{
			#ifdef LOG_FILE
			Log(s_logFile, "**** Out of start range! %llX %llX %llX ****\n", ea, start, end);
			#endif
			return;
		}
        else
		if(ea > end)
		{
			#ifdef LOG_FILE
			Log(s_logFile, "**** Out of end range! %llX %llX %llX ****\n", ea, start, end);
			#endif
			return;
		}

		// Skip over "align" blocks.
		// #1 we will typically see more of these then anything else
		if(isAlignByte(flags) || is_align(flags))
		{
			// Function between code start?
			if((codeStart != BADADDR) && IS_ALIGNED(codeStart))
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %llX Trying function #1\n", codeStart);
				#endif
				#ifdef VBDEV
				msg(">%llX Trying function #1\n", codeStart);
				#endif

				tryFunction(codeStart, end, ea);
				codeStart = BADADDR;
			}
		}
		else
		// #2 case, we'll typically see data
		if(isData(flags))
		{
			// Function between code start?
			if((codeStart != BADADDR) && IS_ALIGNED(codeStart))
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %llX Trying function #2\n", codeStart);
				#endif
				#ifdef VBDEV
				msg(">%llX Trying function #2\n", codeStart);
				#endif

				tryFunction(codeStart, end, ea);
				codeStart = BADADDR;
			}
		}
		else
		// Hit some code?
		if(is_code(flags))
		{
			// Yes, mark the start of a possible code block
			if(codeStart == BADADDR)
			{
				codeStart = ea;

				#ifdef LOG_FILE
				Log(s_logFile, "  %llX Trying function #3, assumed func start\n", codeStart);
				#endif
				#ifdef VBDEV
				msg(">%llX Trying function #3, assumed func start\n", codeStart);
				#endif

				if (IS_ALIGNED(codeStart))
				{
					if (tryFunction(codeStart, end, ea))
						codeStart = BADADDR;
				}
			}
		}
		else
		// Undefined?
		// Usually 0xCC align bytes
		if(is_unknown(flags))
		{
			#ifdef LOG_FILE
			Log(s_logFile, "  C: %llX, Unknown type.\n", ea);
			#endif
			#ifdef VBDEV
			msg("  C: %llX, Unknown type.\n", ea);
			#endif

			codeStart = BADADDR;
		}
		else
		{
			#ifdef LOG_FILE
			Log(s_logFile, "  %llX ** unknown data type! **\n", ea);
			#endif
			#ifdef VBDEV
			msg("  %llX ** unknown data type! **\n", ea);
			#endif

			codeStart = BADADDR;
		}

		// Next item
		auto_wait();
		ea_t nextEa = BADADDR;
		if(ea != BADADDR)
		{
			nextEa = next_head(ea, end);
			if(nextEa != BADADDR)
				ea = nextEa;
		}

		if((nextEa == BADADDR) || (ea == BADADDR))
		{
			// If have code and at the end, try a function from the start
			if ((codeStart != BADADDR) && IS_ALIGNED(codeStart))
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %llX Trying function #4\n", codeStart);
				#endif
				#ifdef VBDEV
				msg(">%llX Trying function #4\n", codeStart);
				#endif

				tryFunction(codeStart, end, ea);
				auto_wait();
			}

			#ifdef LOG_FILE
			Log(s_logFile, " Gap end: %llX.\n", ea);
			#endif
			#ifdef VBDEV
			msg(" Gap end: %llX.\n", ea);
			#endif

            break;
		}

    }; // while(ea < start)
}


// Process suspected bad tail block, non-contiguous, function
//#define PROCESSFUNC_DEBUG
static void processFunc(func_t *f)
{
	const int MAX_INST_COUNT = 16;

	// We're looking for a code pattern that:
	// 1) At least 2 and up to MAX_INST_COUNT instructions max for the entry chunk
	// 2) Has a single direct JMP to a tail block

	int instsToJmp = 0;
	ea_t jmpAddr = BADADDR;
	ea_t ea = f->start_ea;

	for (; instsToJmp <= MAX_INST_COUNT; ++instsToJmp)
	{
		insn_t cmd;
		if (decode_insn(&cmd, ea))
		{
			// Is it a non-conditional jump?
			if (cmd.itype == NN_jmp)
			{
				if (jmpAddr == BADADDR)
					jmpAddr = ea;
				else
				{
					// Already seen a jump, bail out
					jmpAddr = BADADDR;
					break;
				}
			}

			// Next instruction									
			ea = next_head(ea, f->end_ea);

			// End of the entry part reached
			if (ea == BADADDR)
				break;
		}
		else
		{
			#ifdef PROCESSFUNC_DEBUG
			msg("%llX bad instruction decode.\n", ea);
			#endif
			jmpAddr = BADADDR;
			break;
		}

	}

	if ((jmpAddr != BADADDR) && (ea == BADADDR) && (instsToJmp >= 1))
	{
		// Analise the jump target..
		insn_t cmd;
		if (decode_insn(&cmd, jmpAddr))
		{
			ea_t jmpTarget = cmd.ops[0].addr;
			flags64_t flags = get_flags(jmpTarget);

			// Skip if already a function, happens in odd cases but more likely we processed it's tail already
			// Also should be code and have xrefs
			if (!is_func(flags) && is_code(flags) && has_xref(flags))
			{							
				int xrefMinCount = 0;
				xrefblk_t xb;
				if (xb.first_to(jmpTarget, XREF_ALL))
				{
					do 
					{ 
						xrefMinCount++; 
					} while (xb.next_to());
				}

				// Limit to those that more than one reference, or with only two instructions
				// Somewhat contentious as there is still a good chance the target should be function still with just one xref still.
				// But then the main reason to fix these is because of the ambiguity, much less of a problem for following/other function
				// analysis tools.
				if ((instsToJmp == 1) || (xrefMinCount > 1))
				{
					#ifdef PROCESSFUNC_DEBUG
					qstring tmp;
					idaFlags2String(flags, tmp);
					static int tailFixCount = 0;
					msg(" %llX %llX [%d] JMP refs: %d, inst2j: %d (%s)\n", jmpAddr, jmpTarget, tailFixCount++, xrefMinCount, instsToJmp, tmp.c_str());
					#endif
				
					// Attempt to remove all function tail refs
					xrefblk_t xb;
					if (xb.first_to(jmpTarget, XREF_ALL))
					{
						do
						{
							if (xb.iscode)
							{
								s_tailBlckRefFixes++;

								if (func_t *rf = get_func(xb.from))
								{
									if (!remove_func_tail(rf, jmpTarget))
									{
										#ifdef PROCESSFUNC_DEBUG										
										msg("  %llX %llX ** remove_func_tail() failed! **\n", xb.from, jmpTarget);
										#endif
									}									
								}
								else
								{
									// Usually where IDA totally gets a function body wrong, or other odd cases where there is a undeclared function inside another function body
									// Not a problem here since it doesn't cause the add_func() to fail.
									// #TODO: This would be a good one to report back to the user as a problem area with SHOW_PROBLEMS on
									#ifdef PROCESSFUNC_DEBUG
									msg("  %llX %llX ** no function **\n", xb.from, jmpTarget);
									#endif
								}
							}

						} while (xb.next_to());
					}

					// Attempt to convert the former tail block init to a function
					if (!add_func(jmpTarget, BADADDR))
					{
						#ifdef PROCESSFUNC_DEBUG
						msg("  %llX ** add_func() failed! **\n", jmpTarget);
						#endif
					}
				}
			}
		}
	}
}

// ============================================================================

const char PLUGIN_NAME[] = "ExtraPass";

// Plug-in description block
__declspec(dllexport) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	PLUGIN_UNL,				// Plug-in flags
	init,					// Initialization function
	term,					// Clean-up function
	run,					// Main plug-in body
	PLUGIN_NAME,	        // Comment - unused
	PLUGIN_NAME,	        // As above - unused
	PLUGIN_NAME,	        // Plug-in name shown in Edit->Plugins menu
	NULL                    // Hot key to run the plug-in
};
