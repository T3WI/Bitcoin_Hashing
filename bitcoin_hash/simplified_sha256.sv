/*
  Name: Karlo Gregorio
  Variables: 
  clk - clock
  reset_n - negedge reset
  start - signal to start reading message
  message - the input message
  g0-g7 - the input message digest
  done - signal when SHA-256 algorithm is done
  h0-h1 - the output message digest
  
*/
module simplified_sha256 #(parameter integer NUM_OF_WORDS = 16)(
 input logic  clk, reset_n, start,
 input logic [31:0] message[NUM_OF_WORDS],
 input logic [31:0] g0, g1, g2, g3, g4, g5, g6, g7,     // input message digest
 output logic done, 
 output logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7,   // output hash
 input logic  [31:0] k[0:63]
);
// FSM state variables 
enum logic [2:0] {IDLE, WAIT, BLOCK, COMPUTE, DONE} state;

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
logic [31:0] w[NUM_OF_WORDS];                             
logic [ 7:0] i;
// logic [ 15:0] num_blocks;                 // CHANGED TO 16 BITS TO FIT OUTPUT OF determine_num_blocks
logic [31:0] a, b, c, d, e, f, g, h;
logic [31:0] intermediate;

// Added vars



// assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 

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

// function logic [15:0] determine_num_blocks(input logic [31:0] size);
//   determine_num_blocks = ((size >> 4) << 4 == size) ? (size >> 4) : (size >> 4) + 1'b1;
  
// endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, inter);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e&f) ^ (~e&g);
    t1 = h + S1 + ch + inter;
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
// TODO: Try to start off with w[16] already filled with the first 16 words from
// message. Use the circular array to start from the beginning of w[16], and then 
// rotate the array to move onto the next value.
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    h0 <= 32'h0;
    h1 <= 32'h0;
    h2 <= 32'h0;
    h3 <= 32'h0;
    h4 <= 32'h0;
    h5 <= 32'h0;
    h6 <= 32'h0;
    h7 <= 32'h0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
        a <= g0;                  // set up a-h
        b <= g1;
        c <= g2;
        d <= g3;
        e <= g4;
        f <= g5;
        g <= g6;
        h <= g7;  
        w[0] <= message[0];
        i <= 0;
        state <= WAIT;
       end
       else begin 
        state <= IDLE;
       end
    end
    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory

    WAIT: 
    begin
      intermediate <= w[i] + k[i];
      w[i + 1] <= message[i + 1];
      i <= i + 8'b1;
      state <= BLOCK;
    end

    // Fetch message in 512-bit block size
    BLOCK: begin
      // Load message in while computing the new a-h for the previous word loaded 
      if(i < NUM_OF_WORDS - 1) begin  
        w[i + 1] <= message[i + 1];
        intermediate <= w[i] + k[i];
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, intermediate);
        i <= i + 8'b1;
        state <= BLOCK;
      end
      // After the first 16 words have their SHA256 computed and loaded,
      // get the first word expansion word, and shift the w array in preparation
      // for computing the SHA256 value of the first word expansion word. 
      // Move to compute.
      else begin 
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, intermediate);
        for(int n = 0; n < 15; n++) begin 
          w[n] <= w[n + 1];
        end
        intermediate <= w[15] + k[i];
        w[15] <= wtnew();
        i <= i + 8'b1;
        state <= COMPUTE;
      end
    end 
      
      

    // Calculate the SHA256 of the word expanded words, and update message digest
    COMPUTE: begin
	    // Compute the SHA256 of the previous word expanded word, and shift the array
      // and calculate the new word expanded word.
      if (i <= 64) begin
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, intermediate); 
        for(int n = 0; n < 15; n++) begin 
          w[n] <= w[n + 1];
        end
        intermediate <= w[15] + k[i];
        w[15] <= wtnew();
        i <= i + 8'b1;
        state <= COMPUTE;
      end
      // Update h0-h7, and prepare to read the next word in the message.
      else begin 
        h0 <= g0 + a;
        h1 <= g1 + b;
        h2 <= g2 + c;
        h3 <= g3 + d;
        h4 <= g4 + e;
        h5 <= g5 + f;
        h6 <= g6 + g;
        h7 <= g7 + h;
        i <= 8'b0;       // begin where it left off previously
        state <= DONE;
      end
    end
    DONE: 
    begin 
      state <= IDLE;
    end
  endcase
end


assign done = (state == DONE);

endmodule
