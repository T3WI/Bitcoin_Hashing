/*
  Name: Karlo Gregorio
  Variables: 
  clk - clock
  rest_n - negedge reset
  start - signal to start reading message
  output_addr - address to store the final hash function
  done - signal when SHA-256 algorithm is done
  mem_clk - clock of memory
  mem_we - WRITE enable to memory

  mem_addr - memory address to communicate between module and testbench
  mem_write_data - the data to be WRITTEN to memory

  message_addr - address of the message (where to start READing from)
  mem_read_data - the data being READ at message_addr
*/
module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,                  
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [3:0] {IDLE, WAIT, READ, BLOCK1, COMPUTE1, SETAH, BLOCK2, COMPUTE2, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
/* Variables:
  w - 64 rows of 32 bits, one row to store each wt processed
  message - 20 rows of 32 bits, each row stores one word of the message
  wt - a 32-bit word from the message
  hx - the original message digest
  a,b,c,d,e,f,g,h - temporary variables to store modifications of the digest
  i,j - index variables
  offset - address offset for READing
  num_blocks - number of 512-bit blocks necessary to process the message
  cur_we - current state of the WRITE enable
  cur_addr - the current address being READ from memory
  cur_write_data - the data that should be WRITTEN to memory at this current time
  memory_block - the memory block to be used for processing
  tstep -  
*/
logic [31:0] w[16];
logic [31:0] message[NUM_OF_WORDS];                                   
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i;
logic [15:0] offset; 
logic [ 15:0] num_blocks;                 // CHANGED TO 16 BITS TO FIT OUTPUT OF determine_num_blocks
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;


// Added vars



// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
// assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch

/*
  Explanation:
    To find the number of blocks the following calculation must be performed: 
    determine_num_blocks = ceil(size*32/512);
    This can be simplified to:
    determine_num_blocks = ceil(size/16);

    We need to only add 1 when size does not perfectly divide 16. The size 
    perfectly divides 16 when there are no nonzero bits in the 4 least 
    significant bits. Therefore, we can check if this happens by
    shifting size to the right by 4, and then back to the left by 
    4, and checking if it matches its original value.
*/
// TRUNCATED VALUE WARNING SINCE 32 -> 16 ???
function logic [15:0] determine_num_blocks(input logic [31:0] size);
  determine_num_blocks = ((size >> 4) << 4 == size) ? (size >> 4) : (size >> 4) + 1'b1;
  
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    // Student to add remaning code below
    // Refer to SHA256 discussion slides to get logic for this function
    ch = (e&f) ^ (~e&g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a&b) ^ (a&c) ^ (b&c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// wtnew function
// Using a 16-word array, this calculates the new word to be inserted into w.
// This then shifts the array by 1, losing w[0], and adding wtnew to the 
// end of the array. This gives w a queue functionality,and since sha256_op
// only acts on a single value of w, once we're finished with w[0] in 
// sha256_op, we can just shift the array and calculate a new value for w to 
// store
function logic [31:0] wtnew; 
  logic [31:0] s0, s1;
  s0 = rightrotate(w[1], 7)^rightrotate(w[1], 18)^(w[1] >> 3);
  s1 = rightrotate(w[14], 17)^rightrotate(w[14], 19)^(w[14] >> 10);
  wtnew = w[0] + s0 + w[9] + s1;
endfunction

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory


parameter BITS_IN_WORD = 32;
parameter WORDS_IN_BLOCK = 16;
parameter WORDS_REMAINING_AFTER_COMPUTE1 = 4;
parameter WORDS_IN_TOTAL_MESSAGE = 1024/BITS_IN_WORD; 
parameter WORDS_PER_BLOCK = WORDS_IN_TOTAL_MESSAGE / 2;
parameter MESSAGE_SIZE = NUM_OF_WORDS*BITS_IN_WORD;


// Main FSM
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
       // Student to add rest of the code  
        h0 <= 32'h6a09e667;
        h1 <= 32'hbb67ae85;
        h2 <= 32'h3c6ef372;
        h3 <= 32'ha54ff53a;
        h4 <= 32'h510e527f;
        h5 <= 32'h9b05688c;
        h6 <= 32'h1f83d9ab;
        h7 <= 32'h5be0cd19;

        a <= 32'h0;
        b <= 32'h0;
        c <= 32'h0;
        d <= 32'h0;
        e <= 32'h0;
        f <= 32'h0;
        g <= 32'h0;
        h <= 32'h0;

        cur_we <= 0;             // should be 0 for reading
        offset <= 16'b0;             // starts as 0 for the first part of the message
        cur_addr <= message_addr;   // reading should start at the message address
        i <= 0;
        state <= WAIT;

       end
       else begin 
        state <= state;
       end
    end
    // WAIT State is needed to allow proper time for the above values to update
    WAIT: begin  
      cur_addr <= cur_addr + 16'b1;  // need to make sure the correct addresses are synched
      state <= READ;
    end

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory

    /*
      Retrieve the message from the testbench into chunks 
      of 32-bit words

      mem_addr gets automatically updated when offset gets updated. So whenever
      the offset updates, the pointer to the current address in ram gets updated
      to the next read location. Each value of mem_addr corresponds to a row
      in RAM
    */
    READ: begin 
      // Reading data
      if(offset < NUM_OF_WORDS) begin 
        message[offset] <= mem_read_data;
        offset <= offset + 16'b1;
        state <= READ;
      end
      // Initialize a-h, w, and index to keep track of words.
      else begin 
        offset <= 0;
        a <= h0;                  // set up a-h
        b <= h1;
        c <= h2;
        d <= h3;
        e <= h4;
        f <= h5;
        g <= h6;
        h <= h7;  
        w[0] <= message[0];      // load the first word to be available for a-h calc
        i <= 8'b0;
        state <= BLOCK1;
      end
    end

    // Fetch message in 512-bit block size
    BLOCK1: begin
      // Load message in while computing the new a-h for the previous word loaded 
      if(i < WORDS_IN_BLOCK - 1) begin  
        w[i + 1] <= message[i + 1];
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
        i <= i + 8'b1;
        state <= BLOCK1;
      end
      // After the first 16 words have their SHA256 computed and loaded,
      // get the first word expansion word, and shift the w array in preparation
      // for computing the SHA256 value of the first word expansion word. 
      // Move to compute.
      else begin 
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
        for(int n = 0; n < 15; n++) begin 
          w[n] <= w[n + 1];
        end
        w[15] <= wtnew();
        i <= i + 8'b1;
        state <= COMPUTE1;
      end
    end 
      
      

    // Calculate the SHA256 of the word expanded words, and update message digest
    COMPUTE1: begin
	    // Compute the SHA256 of the previous word expanded word, and shift the array
      // and calculate the new word expanded word.
      if (i < 64) begin
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i); 
        for(int n = 0; n < 15; n++) begin 
          w[n] <= w[n + 1];
        end
        w[15] <= wtnew();
        i <= i + 8'b1;
        state <= COMPUTE1;
      end
      // Update h0-h7, and prepare to read the next word in the message.
      else begin 
        h0 <= h0 + a;
        h1 <= h1 + b;
        h2 <= h2 + c;
        h3 <= h3 + d;
        h4 <= h4 + e;
        h5 <= h5 + f;
        h6 <= h6 + g;
        h7 <= h7 + h;
        i <= 8'b0;       // begin where it left off previously
        state <= SETAH;
      end
    end

    // Update a-h to the current h0-h7
    SETAH: begin 
      a <= h0;
      b <= h1;
      c <= h2;
      d <= h3;
      e <= h4;
      f <= h5;
      g <= h6;
      h <= h7;   
      w[0] <= message[16];
      state <= BLOCK2;
    end

    
    // TODO After Bitcoin is done: Try to implement parallelism by computing 
    // the sum of the first block 
    // and second block individually, and then sum each of their h0-h7. Prob won't work
    // since I'm missing carries (try to take carries into account?)

    // Fetch the next 512-bit block
    BLOCK2: begin 
      if(i < WORDS_REMAINING_AFTER_COMPUTE1 - 1) begin      // copy remaining words until the last one, and update a-h
        w[i + 1] <= message[16 + (i + 1)];
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i); 
        i <= i + 1'b1;
        state <= BLOCK2;
      end
      else if(i == WORDS_REMAINING_AFTER_COMPUTE1 - 1) begin // copy last one, setup 1 bit followed by 0s
        w[i + 1] <= {1'b1, {31{1'b0}}};
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i); 
        i <= i + 8'b1;
        state <= BLOCK2;
      end
      else if(i < WORDS_IN_BLOCK - 2) begin   // Pad with 0s until just before the last one
        w[i + 1] <= 32'b0;
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i); 
        i <= i + 8'b1;
        state <= BLOCK2;
      end
      else if(i == WORDS_IN_BLOCK - 2) begin // Insert size into the last one
        w[i + 1] <= 32'b10_1000_0000;
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
        i <= i + 8'b1;
        state <= BLOCK2;
      end
      else begin  // i = 15, sha(a-h, w[15]), shift w to fit next word expansion word on w[15]
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
        for(int n = 0; n < 15; n++) begin 
          w[n] <= w[n + 1];
        end
        w[15] <= wtnew();
        i <= i + 8'b1;
        state <= COMPUTE2;
      end
    end

    // TODO: Try to combine compute states?
    // COMPUTE SHA256 for word expansion bits
    COMPUTE2: begin 
      if (i < 64) begin
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i); 
        for(int n = 0; n < 15; n++) begin 
          w[n] <= w[n + 1];
        end
        w[15] <= wtnew();
        i <= i + 8'b1;
        state <= COMPUTE2;
      end
      else begin 
        h0 <= h0 + a;
        h1 <= h1 + b;
        h2 <= h2 + c;
        h3 <= h3 + d;
        h4 <= h4 + e;
        h5 <= h5 + f;
        h6 <= h6 + g;
        h7 <= h7 + h;
        i <= 8'b0;      
        cur_we <= 8'b1;
        state <= WRITE;
      end
    end

    
    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr

    
    WRITE: begin
      if(i <= 7) begin 
        state <= WRITE;
        i <= i + 8'b1;
        offset <= i;
        cur_addr <= output_addr;
        if(i == 0) cur_write_data <= h0;
        else if(i == 1) cur_write_data <= h1;
        else if(i == 2) cur_write_data <= h2;
        else if(i == 3) cur_write_data <= h3;
        else if(i == 4) cur_write_data <= h4;
        else if(i == 5) cur_write_data <= h5;
        else if(i == 6) cur_write_data <= h6;
        else if(i == 7) cur_write_data <= h7;
      end
      else begin 
        offset <= 16'b0;
        state <= IDLE;
      end
    end
   endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
