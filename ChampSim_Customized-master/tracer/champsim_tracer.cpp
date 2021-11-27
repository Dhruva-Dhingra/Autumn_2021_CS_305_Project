
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "graph.h"
//#define POPT

typedef CSRGraph<int32_t> Graph;

int* m_tidMapAddrStart {nullptr};
int m_numThreads {-1};
int* m_threadMap {nullptr};

#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4

typedef struct trace_instr_format {
    unsigned long long int ip;  // instruction pointer (program counter) value

    // unsigned char is_branch;    // is this branch
    // unsigned char branch_taken; // if so, is this taken

    // unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    // unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers

    // unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    // unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory


    uint8_t is_branch;
  uint8_t branch_taken;

  uint8_t destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
  uint8_t source_registers[NUM_INSTR_SOURCES];           // input registers

  uint64_t destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
  uint64_t source_memory[NUM_INSTR_SOURCES];           // input memory
  
    #ifdef POPT
    int is_special_instruction;
    // 0 for not special instruction
    // 1 for registerDataType
    // 2 for registerGraph
    // 3 for offsetMatrix
    // 4 for updateRegIndex
    // 5 for updateIrregRanges


    // Variables for registerDataType
    intptr_t addr; 
    int dType; 
    int numElements;
    size_t elemSz;
    int totalDataTypes;

    // Variables for registerGraph;
    //Graph g;
    //std::string graph_file_name;
    bool isPull;

    

    // Variables for updateRegIndex
    int32_t index;
    int tid;

    // Variables for updateIrregRanges
    int32_t startID;
    int32_t endID;

    // Variables for registerOffsetMatrix
    int32_t numEpochs;
    int32_t numCacheLines;
    int vtxPerLine;
    int dTypeID;
    // uint8_t *offsetMatrix;
    #endif

} trace_instr_format_t;

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 instrCount = 0;

FILE* out;

bool output_file_closed = false;
bool tracing_on = false;
bool tracing = false;

trace_instr_format_t curr_instr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "champsim.trace", 
        "specify file name for Champsim tracer output");

KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", 
        "How many instructions to skip before tracing begins");

KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "t", "1000000", 
        "How many instructions to trace");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    std::cerr << "This tool creates a register and memory access trace" << std::endl 
        << "Specify the output trace file with -o" << std::endl 
        << "Specify the number of instructions to skip before tracing with -s" << std::endl
        << "Specify the number of instructions to trace with -t" << std::endl << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

#ifdef POPT
void replacementFunction(intptr_t addr, int dType, int numElements, size_t elemSz, int totalDataTypes)
{
    curr_instr.is_special_instruction = 1;
    curr_instr.addr = addr;
    curr_instr.dType = dType;
    curr_instr.numElements = numElements;
    curr_instr.elemSz = elemSz;
    curr_instr.totalDataTypes = totalDataTypes;
    std::cout << "Current Instruction special " << curr_instr.is_special_instruction << std::endl;
    fwrite(&curr_instr, sizeof(trace_instr_format_t), 1, out);

    curr_instr.is_special_instruction = 0;
    curr_instr.addr = -1;
    curr_instr.dType = -1;
    curr_instr.numElements = -1;
    curr_instr.elemSz = 0;
    curr_instr.totalDataTypes = -1;
    std::cout << "Exiting replacementFunction" << std::endl;
    
}

void registerGraph(std::string graph_file_name, bool isPull)
{
    std::cout << "Entering registerGraph" << std::endl;
    curr_instr.is_special_instruction = 2;
    //curr_instr.g.setGraphProperties(g.num_nodes(), g.num_edges(), g.directed());
    //curr_instr.g.setGraphDatastructures(g.out_index(), g.out_neighbors(), g.in_index(), g.in_neighbors());
    //std::cout << graph_file_name << std::endl;
    //std::cout << "------------" << std::endl;
    //std::cout << curr_instr.graph_file_name << std::endl;
    //curr_instr.graph_file_name = graph_file_name;
    curr_instr.isPull = isPull;
    std::cout << "Current Instruction special " << curr_instr.is_special_instruction << std::endl;
    //std::cout << g << std::endl;
    fwrite(&curr_instr, sizeof(trace_instr_format_t), 1, out);
    //std::cout << "After fwrite" << std::endl;

    curr_instr.is_special_instruction = 0;
    curr_instr.isPull = false;
    std::cout << "Exiting registerGraph" << std::endl;
}

void registerOffsetMatrix(int32_t numEpochs, int32_t numCacheLines, int vtxPerLine, int dTypeID)
{
    std::cout << "Entering registerOffsetMatrix" << std::endl;
    curr_instr.is_special_instruction = 3;
    /*if(curr_instr.offsetMatrix != nullptr){
        delete[] curr_instr.offsetMatrix;
        //delete curr_instr.offsetMatrix;
        curr_instr.offsetMatrix = nullptr;
    }*/
    // curr_instr.offsetMatrix = new uint8_t[numEpochs * numCacheLines];
        std::cout<<"OffsetMatrix[i] "<<std::endl;
    // for(int i = 0; i < numEpochs * numCacheLines; i++){
    //     std::cout<<offsetMatrix[i]
    //     curr_instr.offsetMatrix[i] = offsetMatrix[i];
    //     std::cout<<curr_instr.offsetMatrix[i]
    // }
    curr_instr.numEpochs = numEpochs;
    curr_instr.numCacheLines = numCacheLines;
    curr_instr.vtxPerLine = vtxPerLine;
    curr_instr.dTypeID = dTypeID;
    std::cout << "Current Instruction special " << curr_instr.is_special_instruction << std::endl;
    fwrite(&curr_instr, sizeof(trace_instr_format_t), 1, out);
    
    curr_instr.is_special_instruction = 0;
    // if(curr_instr.offsetMatrix != nullptr){
    //     delete[] curr_instr.offsetMatrix;
    //     //delete curr_instr.offsetMatrix;
    //     curr_instr.offsetMatrix = nullptr;
    // }
    //curr_instr.offsetMatrix = nullptr;
    std::cout << "Exiting registerOffsetMatrix" << std::endl;
}

void updateRegIndex(int32_t index, int tid)
{
    //std::cout << "Entering updateRegIndex" << std::endl;
    curr_instr.is_special_instruction = 4;
    curr_instr.index = index;
    curr_instr.tid = tid;
    //std::cout << "Current Instruction special " << curr_instr.is_special_instruction << std::endl;
    fwrite(&curr_instr, sizeof(trace_instr_format_t), 1, out);

    curr_instr.is_special_instruction = 0;
    curr_instr.index = -1;
    curr_instr.tid = -1;
    //std::cout << "Exiting updateRegIndex" << std::endl;
}

void updateIrregRanges(int32_t startID, int32_t endID)
{
    std::cout << "Entering updateIrregRanges" << std::endl;
    curr_instr.is_special_instruction = 5;
    curr_instr.startID = startID;
    curr_instr.endID = endID;
    std::cout << "Current Instruction special " << curr_instr.is_special_instruction << std::endl;
    fwrite(&curr_instr, sizeof(trace_instr_format_t), 1, out);

    curr_instr.is_special_instruction = 0;
    curr_instr.startID = -1;
    curr_instr.endID = -1;
    std::cout << "Exiting updateIrregRanges" << std::endl;
}
#endif

void TracingOn(){
    tracing = true;
    std::cout << "Set tracing to true" << std::endl;
}

void TracingOff(){
    tracing = false;
    std::cout << "Set tracing to false" << std::endl;
}


//--------------------------------------------------------------------------------------------------
void SpecialInstruction(RTN rtn, void* v)
{
   std::string rtn_name = RTN_Name(rtn);
   

   if(rtn_name.find("PIN_Start") != std::string::npos){
       std::cout << "Intercepted routine" << rtn_name << std::endl;
       RTN_Replace(rtn, AFUNPTR(TracingOn));
       //tracing = true;
       //std::cout << "Set tracing to true" << std::endl;
   }
   
    if(rtn_name.find("PIN_Stop") != std::string::npos){
        std::cout << "Intercepted routine" << rtn_name << std::endl;
        RTN_Replace(rtn, AFUNPTR(TracingOff));
        //tracing = false;
   }
   
   #ifdef POPT
   if (rtn_name.find("PIN_RegisterDataType") != std::string::npos)
   {
        std::cout << "Intercepted routine" << rtn_name << std::endl;
        RTN_Replace(rtn, AFUNPTR(replacementFunction));
   }

   if (rtn_name.find("PIN_RegisterGraph") != std::string::npos)
   {
        std::cout << "Intercepted routine" << rtn_name << std::endl;
        RTN_Replace(rtn, AFUNPTR(registerGraph));
   }
   if (rtn_name.find("PIN_RegisterOffsetMatrix") != std::string::npos)
   {
        std::cout << "Intercepted routine" << rtn_name << std::endl;
        RTN_Replace(rtn, AFUNPTR(registerOffsetMatrix));
   }
  if (rtn_name.find("PIN_UpdateRegIndex") != std::string::npos)
   {
        std::cout << "Intercepted routine" << rtn_name << std::endl;
        RTN_Replace(rtn, AFUNPTR(updateRegIndex));
   }
   if (rtn_name.find("PIN_UpdateIrregRanges") != std::string::npos)
   {
        std::cout << "Intercepted routine" << rtn_name << std::endl;
        RTN_Replace(rtn, AFUNPTR(updateIrregRanges));
   }
   #endif
   
}

void BeginInstruction(VOID *ip, UINT32 op_code, VOID *opstring)
{
    //std::cout << "Entering Begin Instruction" << std::endl;
    if(!tracing){
        return;
    }
    //std::cout << "Entered Begin Instruction" << std::endl;
    instrCount++;
    //printf("[%p %u %s ", ip, opcode, (char*)opstring);

    if(instrCount > KnobSkipInstructions.Value()) 
    {
        tracing_on = true;

        if(instrCount > (KnobTraceInstructions.Value()+KnobSkipInstructions.Value()))
            tracing_on = false;
    }

    if(!tracing_on) 
        return;

    // reset the current instruction
    ////std::cout << "ip = " << ip << std::endl;
    curr_instr.ip = (unsigned long long int)ip;

    curr_instr.is_branch = 0;
    curr_instr.branch_taken = 0;

    for(int i=0; i<NUM_INSTR_DESTINATIONS; i++) 
    {
        curr_instr.destination_registers[i] = 0;
        curr_instr.destination_memory[i] = 0;
    }

    for(int i=0; i<NUM_INSTR_SOURCES; i++) 
    {
        curr_instr.source_registers[i] = 0;
        curr_instr.source_memory[i] = 0;
    }

    #ifdef POPT
    curr_instr.is_special_instruction = 0;

    curr_instr.addr = -1;
    curr_instr.dType = -1;
    curr_instr.numElements = -1;
    curr_instr.elemSz = 0;
    curr_instr.totalDataTypes = -1;

    // Variables for registerGraph;
    //Graph g;
    curr_instr.isPull = false;

    

    // Variables for updateRegIndex
    curr_instr.index = -1;
    curr_instr.tid = -1;

    // Variables for updateIrregRanges
    curr_instr.startID = 0;
    curr_instr.endID = 0;

    // Variables for registerOffsetMatrix
    curr_instr.numEpochs = 0;
    curr_instr.numCacheLines = 0;
    curr_instr.vtxPerLine = 0;
    curr_instr.dTypeID = 0;
    /*if(curr_instr.offsetMatrix != nullptr){
        delete[] curr_instr.offsetMatrix;
        //delete curr_instr.offsetMatrix;
        curr_instr.offsetMatrix = nullptr;
    }*/
    #endif
}

void EndInstruction()
{
    //printf("%d]\n", (int)instrCount);

    //printf("\n");

    if(instrCount > KnobSkipInstructions.Value())
    {
        tracing_on = true;

        if(instrCount <= (KnobTraceInstructions.Value()+KnobSkipInstructions.Value()))
        {
            // keep tracing
            //std::cout << "Current Instruction special " << curr_instr.is_special_instruction << std::endl;
            fwrite(&curr_instr, sizeof(trace_instr_format_t), 1, out);
        }
        else
        {
            std::cout << "Closing File " << std::endl;
            tracing_on = false;
            // close down the file, we're done tracing
            if(!output_file_closed)
            {
                fclose(out);
                output_file_closed = true;
            }
            std::cout << "Exiting Pin" << std::endl;
            exit(0);
        }
    }
}

void BranchOrNot(UINT32 taken)
{
    //printf("[%d] ", taken);

    curr_instr.is_branch = 1;
    if(taken != 0)
    {
        curr_instr.branch_taken = 1;
    }
}

void RegRead(UINT32 i, UINT32 index)
{
    if(!tracing_on) return;

    REG r = (REG)i;

    /*
       if(r == 26)
       {
    // 26 is the IP, which is read and written by branches
    return;
    }
    */

    //cout << r << " " << REG_StringShort((REG)r) << " " ;
    //cout << REG_StringShort((REG)r) << " " ;

    //printf("%d ", (int)r);

    // check to see if this register is already in the list
    int already_found = 0;
    for(int i=0; i<NUM_INSTR_SOURCES; i++)
    {
        if(curr_instr.source_registers[i] == ((unsigned char)r))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_SOURCES; i++)
        {
            if(curr_instr.source_registers[i] == 0)
            {
                curr_instr.source_registers[i] = (unsigned char)r;
                break;
            }
        }
    }
}

void RegWrite(REG i, UINT32 index)
{
    if(!tracing_on) return;

    REG r = (REG)i;

    /*
       if(r == 26)
       {
    // 26 is the IP, which is read and written by branches
    return;
    }
    */

    //cout << "<" << r << " " << REG_StringShort((REG)r) << "> ";
    //cout << "<" << REG_StringShort((REG)r) << "> ";

    //printf("<%d> ", (int)r);

    int already_found = 0;
    for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
    {
        if(curr_instr.destination_registers[i] == ((unsigned char)r))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
        {
            if(curr_instr.destination_registers[i] == 0)
            {
                curr_instr.destination_registers[i] = (unsigned char)r;
                break;
            }
        }
    }
    /*
       if(index==0)
       {
       curr_instr.destination_register = (unsigned long long int)r;
       }
       */
}

void MemoryRead(VOID* addr, UINT32 index, UINT32 read_size)
{
    if(!tracing_on) return;

    //printf("0x%llx,%u ", (unsigned long long int)addr, read_size);

    // check to see if this memory read location is already in the list
    int already_found = 0;
    for(int i=0; i<NUM_INSTR_SOURCES; i++)
    {
        if(curr_instr.source_memory[i] == ((unsigned long long int)addr))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_SOURCES; i++)
        {
            if(curr_instr.source_memory[i] == 0)
            {
                curr_instr.source_memory[i] = (unsigned long long int)addr;
                break;
            }
        }
    }
}

void MemoryWrite(VOID* addr, UINT32 index)
{
    if(!tracing_on) return;

    //printf("(0x%llx) ", (unsigned long long int) addr);

    // check to see if this memory write location is already in the list
    int already_found = 0;
    for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
    {
        if(curr_instr.destination_memory[i] == ((unsigned long long int)addr))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
        {
            if(curr_instr.destination_memory[i] == 0)
            {
                curr_instr.destination_memory[i] = (unsigned long long int)addr;
                break;
            }
        }
    }
    /*
       if(index==0)
       {
       curr_instr.destination_memory = (long long int)addr;
       }
       */
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    if(!tracing){
        return;
    }
    //std::cout << "Entered Instruction" << std::endl;
    // begin each instruction with this function
    UINT32 opcode = INS_Opcode(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeginInstruction, IARG_INST_PTR, IARG_UINT32, opcode, IARG_END);

    // instrument branch instructions
    if(INS_IsBranch(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);

    // instrument register reads
    UINT32 readRegCount = INS_MaxNumRRegs(ins);
    for(UINT32 i=0; i<readRegCount; i++) 
    {
        UINT32 regNum = INS_RegR(ins, i);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegRead,
                IARG_UINT32, regNum, IARG_UINT32, i,
                IARG_END);
    }

    // instrument register writes
    UINT32 writeRegCount = INS_MaxNumWRegs(ins);
    for(UINT32 i=0; i<writeRegCount; i++) 
    {
        UINT32 regNum = INS_RegW(ins, i);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegWrite,
                IARG_UINT32, regNum, IARG_UINT32, i,
                IARG_END);
    }

    // instrument memory reads and writes
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
    {
        if (INS_MemoryOperandIsRead(ins, memOp)) 
        {
            UINT32 read_size = INS_MemoryReadSize(ins);

            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemoryRead,
                    IARG_MEMORYOP_EA, memOp, IARG_UINT32, memOp, IARG_UINT32, read_size,
                    IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, memOp)) 
        {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemoryWrite,
                    IARG_MEMORYOP_EA, memOp, IARG_UINT32, memOp,
                    IARG_END);
        }
    }

    // finalize each instruction with this function
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EndInstruction, IARG_END);
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    std::cout << "Reached Fini" << std::endl;
    // close the file if it hasn't already been closed
    if(!output_file_closed) 
    {
        fclose(out);
        output_file_closed = true;
    }
    std::cout << "Exited Fini" << std::endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
        return Usage();

    const char* fileName = KnobOutputFile.Value().c_str();

    out = fopen(fileName, "ab");
    if (!out) 
    {
        //std::cout << "Couldn't open output trace file. Exiting." << std::endl;
        exit(1);
    }

    // Register function to be called for function replacement
    RTN_AddInstrumentFunction(SpecialInstruction, 0);
    
    // Register function to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    //cerr <<  "===============================================" << endl;
    //cerr <<  "This application is instrumented by the Champsim Trace Generator" << endl;
    //cerr <<  "Trace saved in " << KnobOutputFile.Value() << endl;
    //cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
